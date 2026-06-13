"""Background asyncio runtime that drives the dashboard.

A single OS thread owns an asyncio event loop. Inside that loop we spin up the
exact same stack the Phase 6 demo uses (BB84 + abstract link -> shared queue
-> fan-out feeder -> KME-A/B; QTLS server + client over an in-process socket;
a tiny chat loop) and instrument each layer to publish events onto the
:class:`~viz.bus.EventBus`.

Streamlit must NOT call asyncio code on its main thread: every interaction
reruns the script and there is no persistent loop. So the loop lives here,
inside :class:`Runtime`, which is created once and stashed in
``st.session_state``. Stop/start of the runtime is driven by the user via the
dashboard's header controls.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from dataclasses import dataclass

import httpx

from kme.api import create_kme_app
from kme.network import fan_out_feeder, make_kme_pair
from kme.store import KeyStore
from qkd.abstract_link import abstract_qkd_link
from qkd.bb84 import bb84_round
from qkd.keyblock import KeyBlock
from qkd.reconciliation import (
    DEFAULT_QBER_ABORT,
    QBERTooHighError,
    reconcile_and_amplify,
)
from qtls.connection import accept, connect
from qtls.kme_client import KMEClient

from viz.bus import EventBus

# Smaller than the Phase 6 default: we want the viz to *show* the producer
# ticking visibly rather than dump a megabyte every second.
VIZ_KEY_RATE_BPS = 32_768
VIZ_QBER = 0.02
VIZ_BB84_QUBITS = 32           # per-round, drives the photon panel cadence
_QBER_WINDOW = 15              # rounds averaged for the reported QBER
VIZ_BB84_TARGET_SIFTED = 512   # bits per emitted KeyBlock from the BB84 source


@dataclass
class RuntimeConfig:
    client_sae: str = "SAE-CLIENT"
    server_sae: str = "SAE-SERVER"
    key_rate_bps: int = VIZ_KEY_RATE_BPS
    qber: float = VIZ_QBER
    chat_interval_s: float = 1.0


class Runtime:
    """Owns the background event loop and the QTLS-over-QKD stack.

    Lifecycle: :meth:`start` spawns the thread and brings everything up;
    :meth:`stop` cancels the tasks and joins the thread. The instance can be
    started exactly once -- if the user clicks Stop and then Start again the
    Streamlit page creates a fresh Runtime, which is the simpler model.
    """

    def __init__(self, bus: EventBus, config: RuntimeConfig | None = None) -> None:
        self.bus = bus
        self.config = config or RuntimeConfig()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._stopped = threading.Event()
        # Mutable flag the BB84 producer reads each round so the user can toggle
        # the Eve attack live without restarting the runtime.
        self._eve_flag = False
        # Per-round sleep for the BB84 producer. The quantum sim itself is very
        # fast (<10 ms for 32 qubits), so without a cap it floods the photon
        # panel faster than a human can read. Tunable live from the dashboard.
        self._bb84_delay_s = 0.6

    # -- public control ----------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("Runtime already started")
        self._thread = threading.Thread(
            target=self._thread_main, name="qtls-viz-runtime", daemon=True
        )
        self._thread.start()
        self._ready.wait(timeout=15.0)

    def stop(self) -> None:
        if self._loop is None or self._thread is None:
            return
        self._loop.call_soon_threadsafe(self._stopped.set)
        self._thread.join(timeout=10.0)

    def set_bb84_delay(self, seconds: float) -> None:
        """Set the per-round delay of the BB84 producer (live-tunable)."""
        self._bb84_delay_s = max(0.0, float(seconds))

    def set_eve(self, present: bool) -> None:
        self._eve_flag = present
        self.bus.set_eve(present)
        self.bus.publish("log", level="warn" if present else "info",
                         msg=f"Eve attack {'engaged' if present else 'disengaged'}")

    # -- thread / loop entry ----------------------------------------------

    def _thread_main(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._async_main())
        finally:
            self._loop.close()

    async def _async_main(self) -> None:
        cfg = self.config
        kme_a, kme_b = make_kme_pair(key_size_bits=2048)
        kme_a.authorise(cfg.client_sae, cfg.server_sae)
        kme_b.authorise(cfg.client_sae, cfg.server_sae)

        key_queue: asyncio.Queue[KeyBlock] = asyncio.Queue()
        stop_event = asyncio.Event()

        async def stopper() -> None:
            # Bridge between the threading.Event the foreground thread sets and
            # our asyncio.Event the producers wait on.
            while not self._stopped.is_set():
                await asyncio.sleep(0.1)
            stop_event.set()

        # Wrap the BB84 producer so we can publish per-round photon events.
        # The abstract bulk producer is left untouched -- it's already silent
        # at the API level; we just observe its output in `instrumented_fanout`.
        tasks = [
            asyncio.create_task(stopper(), name="stopper"),
            asyncio.create_task(
                _instrumented_bb84_source(
                    key_queue, self.bus,
                    lambda: self._eve_flag,
                    lambda: self._bb84_delay_s,
                    stop_event,
                ),
                name="bb84",
            ),
            asyncio.create_task(
                abstract_qkd_link(
                    key_queue, key_rate_bps=cfg.key_rate_bps, qber=cfg.qber,
                    stop_event=stop_event,
                ),
                name="bulk",
            ),
            asyncio.create_task(
                _instrumented_fanout(
                    key_queue, kme_a, kme_b, self.bus, stop_event
                ),
                name="fanout",
            ),
            asyncio.create_task(
                _pool_monitor(kme_a, kme_b, self.bus, stop_event),
                name="pool",
            ),
        ]

        # Wait until both KMEs have material before announcing readiness, so
        # the dashboard's first handshake doesn't race the producers.
        await _await_keys_ready(kme_a, kme_b)
        self.bus.publish("log", level="info", msg="QKD pool primed; runtime ready")

        # Chat session: a single long-running server + a client that sends
        # one message per chat_interval_s, instrumented at every step.
        tasks.append(asyncio.create_task(
            _chat_session(kme_a, kme_b, cfg, self.bus, stop_event),
            name="chat",
        ))

        self._ready.set()

        # Park until shutdown.
        await stop_event.wait()
        for t in tasks:
            t.cancel()
        for t in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t


# -- producers / observers --------------------------------------------------


async def _instrumented_bb84_source(
    out_queue: "asyncio.Queue[KeyBlock]",
    bus: EventBus,
    eve_flag: "callable",
    delay_getter: "callable",
    stop_event: asyncio.Event,
) -> None:
    """BB84 producer that publishes one ``photon_round`` event per round.

    Inlined (rather than reusing ``qkd.bb84_source.bb84_source``) because we
    need the full :class:`BB84Round` record to drive the photon panel, not
    just the distilled :class:`KeyBlock`.
    """
    alice_buf: list[int] = []
    bob_buf: list[int] = []
    qber_window: list[float] = []
    qber_running = 0.0
    rounds_accum = 0

    while not stop_event.is_set():
        # Pace the producer so the photon panel stays human-readable; the
        # quantum sim itself takes <10 ms, which is far faster than the eye.
        delay = delay_getter()
        if delay > 0:
            await asyncio.sleep(delay)
        eve = eve_flag()
        try:
            # VIZ_QBER models baseline channel noise (detector imperfections,
            # fibre): a real link shows a non-zero QBER even with no attacker.
            # Eve's intercept-resend then stacks ~25% on top of this floor.
            r = await asyncio.to_thread(bb84_round, VIZ_BB84_QUBITS, eve, VIZ_QBER)
        except Exception as exc:
            bus.publish("log", level="error", msg=f"bb84 round failed: {exc!r}")
            await asyncio.sleep(0.5)
            continue

        # Emit a compact photon-round event: just what panel B needs.
        bus.publish(
            "photon_round",
            n=r.n_qubits,
            alice_bits=r.alice_bits,
            alice_bases=r.alice_bases,
            bob_bases=r.bob_bases,
            bob_bits=r.bob_bits,
            sifted_indices=r.sifted_indices,
            eve_present=eve,
            observed_qber=r.observed_qber(),
        )

        alice_buf.extend(r.alice_sifted)
        bob_buf.extend(r.bob_sifted)
        rounds_accum += 1
        if r.sifted_length:
            # A single 32-qubit round has ~16 sifted bits, so its QBER jumps
            # between 0% and ~10%. Report the mean over a sliding window of
            # recent rounds instead, which tracks the true channel QBER.
            qber_window.append(r.observed_qber())
            del qber_window[:-_QBER_WINDOW]
            qber_running = sum(qber_window) / len(qber_window)
            bus.update_counter("qber_last", qber_running)

        # Once we have enough sifted bits, distil one KeyBlock and feed the queue.
        if len(alice_buf) >= VIZ_BB84_TARGET_SIFTED:
            try:
                material = await asyncio.to_thread(
                    reconcile_and_amplify,
                    alice_buf, bob_buf, qber_running, DEFAULT_QBER_ABORT,
                )
            except QBERTooHighError:
                # Eve / noise pushed QBER above 11%: abort this block, signal
                # the viz, and start a fresh accumulation buffer.
                bus.publish("log", level="error",
                            msg=f"BB84 ABORT: QBER {qber_running:.1%} > {DEFAULT_QBER_ABORT:.0%}")
                alice_buf.clear()
                bob_buf.clear()
                # Brief cooldown so a sustained Eve attack doesn't spam logs.
                await asyncio.sleep(0.2)
                continue
            block = KeyBlock(material=material, source="bb84-visual", qber=qber_running)
            await out_queue.put(block)
            alice_buf.clear()
            bob_buf.clear()


async def _instrumented_fanout(
    in_queue: "asyncio.Queue[KeyBlock]",
    kme_a: KeyStore,
    kme_b: KeyStore,
    bus: EventBus,
    stop_event: asyncio.Event,
) -> None:
    """Variant of :func:`kme.network.fan_out_feeder` that emits key_block events."""
    while not stop_event.is_set():
        try:
            block = await asyncio.wait_for(in_queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        kme_a.add_block(block)
        kme_b.add_block(block)
        bus.publish(
            "key_block",
            key_id=str(block.key_id),
            length=block.length_bytes,
            source=block.source,
            qber=block.qber,
        )
        bus.add_counter("key_bytes_produced", block.length_bytes)


async def _pool_monitor(
    kme_a: KeyStore, kme_b: KeyStore, bus: EventBus, stop_event: asyncio.Event,
) -> None:
    """Sample pool depth at 2 Hz so the metrics panel has a time series."""
    while not stop_event.is_set():
        a = kme_a.fresh_key_count()
        b = kme_b.fresh_key_count()
        bus.update_counter("pool_a_fresh", a)
        bus.update_counter("pool_b_fresh", b)
        bus.publish("pool", kme_a=a, kme_b=b)
        await asyncio.sleep(0.5)


async def _await_keys_ready(kme_a: KeyStore, kme_b: KeyStore, timeout: float = 30.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if kme_a.fresh_key_count() > 0 and kme_b.fresh_key_count() > 0:
            return
        await asyncio.sleep(0.1)
    raise TimeoutError("QKD key pool did not fill in time")


# -- chat session over real loopback QTLS -----------------------------------


def _kme_client(store: KeyStore, sae_id: str, http_holder: list) -> KMEClient:
    app = create_kme_app(store, peer_kme_id="peer")
    transport = httpx.ASGITransport(app=app)
    http = httpx.AsyncClient(transport=transport, base_url="http://kme.local")
    http_holder.append(http)
    return KMEClient(http, sae_id)


async def _chat_session(
    kme_a: KeyStore,
    kme_b: KeyStore,
    cfg: RuntimeConfig,
    bus: EventBus,
    stop_event: asyncio.Event,
) -> None:
    """Run a persistent QTLS chat that performs one fresh handshake per minute
    (visible cadence for the handshake panel) and sends a chat record every
    ``chat_interval_s`` seconds."""
    http_clients: list[httpx.AsyncClient] = []
    try:
        # Start a TCP server on an ephemeral loopback port and connect to it
        # from the same loop -- exactly the Phase 6 chat topology.
        async def server_handler(reader, writer):
            try:
                bus.publish("handshake", step="server_recv_clienthello")
                t0 = time.perf_counter()
                conn = await accept(
                    reader, writer,
                    _kme_client(kme_b, cfg.server_sae, http_clients),
                    cfg.server_sae,
                )
                bus.publish("handshake", step="server_finished",
                            elapsed_ms=(time.perf_counter() - t0) * 1000)
                bus.add_counter("handshakes_completed", 1)
                while not stop_event.is_set():
                    try:
                        data = await asyncio.wait_for(conn.recv(), timeout=5.0)
                    except (asyncio.TimeoutError, ConnectionError):
                        return
                    # Echo back, doubling key consumption visibly.
                    await conn.send(b"ACK:" + data)
                    bus.publish("record", direction="s->c", length=len(data) + 4)
                    bus.add_counter("records_sent", 1)
                    bus.add_counter("key_bytes_consumed", len(data) + 4)
            except Exception as exc:
                bus.publish("log", level="error", msg=f"server: {exc!r}")
            finally:
                with contextlib.suppress(Exception):
                    writer.close()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        bus.publish("log", level="info", msg=f"QTLS server listening on 127.0.0.1:{port}")

        async def client_driver() -> None:
            seq = 0
            while not stop_event.is_set():
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    bus.publish("handshake", step="client_send_clienthello")
                    t0 = time.perf_counter()
                    conn = await connect(
                        reader, writer,
                        _kme_client(kme_a, cfg.client_sae, http_clients),
                        cfg.client_sae, cfg.server_sae,
                    )
                    dt_ms = (time.perf_counter() - t0) * 1000
                    bus.publish("handshake", step="client_finished", elapsed_ms=dt_ms)
                    bus.update_counter("last_handshake_ms", dt_ms)

                    # Send a few records (each consumes payload+16 OTP bytes
                    # from a per-direction stream of ~112 bytes), then close
                    # and re-handshake. The deliberately tight budget is what
                    # makes the pool-drain dynamic visible on the metrics panel
                    # -- it's the thesis's central QKD constraint, not a bug.
                    for _ in range(3):
                        if stop_event.is_set():
                            break
                        seq += 1
                        msg = f"hello-{seq:04d}".encode()
                        await conn.send(msg)
                        bus.publish("record", direction="c->s", length=len(msg))
                        bus.add_counter("records_sent", 1)
                        bus.add_counter("key_bytes_consumed", len(msg))
                        try:
                            reply = await asyncio.wait_for(conn.recv(), timeout=2.0)
                            bus.publish("log", level="info",
                                        msg=f"chat reply: {reply.decode(errors='replace')}")
                        except asyncio.TimeoutError:
                            break
                        await asyncio.sleep(cfg.chat_interval_s)
                    await conn.close()
                except Exception as exc:
                    # OTP exhaustion is the expected end-of-session signal --
                    # not an error, just "time to re-handshake".
                    name = type(exc).__name__
                    if name == "OTPKeyExhaustedError":
                        bus.publish("log", level="info",
                                    msg="session OTP budget spent -- re-handshaking")
                    else:
                        bus.publish("log", level="error", msg=f"client: {exc!r}")
                    await asyncio.sleep(0.5)

        driver = asyncio.create_task(client_driver(), name="chat-client")
        await stop_event.wait()
        driver.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await driver
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()
    finally:
        for http in http_clients:
            with contextlib.suppress(Exception):
                await http.aclose()
