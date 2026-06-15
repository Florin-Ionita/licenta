"""Pool depth under sustained chat-style load.

Spins up the standard QTLS stack with a live producer running at the demo's
key rate, then drives one chat session for ``cfg.pool_drain_seconds``,
sampling the KME pool depth every 250 ms. The plot tells the QKD story
directly: how fast does sustained load drain the pool, and does the producer
keep up?
"""

from __future__ import annotations

import asyncio
import time

import contextlib
import secrets

from benchmarks.common import BenchConfig, _BenchStack, write_csv
from benchmarks.throughput import HANDSHAKE_TIMEOUT
from qkd.keyblock import KeyBlock
from qtls.connection import accept, connect

# Paced-consumer parameters (tunable). A realistic chat sends a few small
# messages slowly, not a saturating stream. The dominant cost is actually the
# per-session handshake (it pulls a key), so keeping sessions long and
# infrequent keeps consumption well below the producer's rate, letting the pool
# fill from its small prefill up to the cap and then stay full. To rebalance:
# raise _PACE_SECONDS / _MESSAGES_PER_SESSION (slower, fewer handshakes) to make
# the pool fill faster; lower them to make it drain.
_PACE_SECONDS = 0.5          # gap between messages (2 messages/s)
_MESSAGES_PER_SESSION = 20   # long session -> few handshakes -> low key cost
_BURST_FRACTION = 0.6        # at 60% of the run, fire one heavy burst
_BURST_SESSIONS = 30         # burst: many back-to-back sessions, each pulls a key


async def _paced_session(stack: _BenchStack, msg: bytes, n_messages: int,
                         pace_s: float) -> int:
    """Open one QTLS session and send ``n_messages`` paced chat messages.

    Unlike the throughput session, which streams as fast as the OTP budget
    allows, this sends one small message every ``pace_s`` seconds, modelling a
    human chat rather than a saturating sender. Returns the number of bytes the
    receiver acknowledged. Ends early if the OTP budget runs out.
    """
    received = 0
    received_done = asyncio.Event()

    async def server_handler(reader, writer):
        nonlocal received
        try:
            conn = await asyncio.wait_for(
                accept(reader, writer,
                       stack.kme_client(stack.kme_b, stack.server_sae),
                       stack.server_sae),
                timeout=HANDSHAKE_TIMEOUT)
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()
            received_done.set()
            return
        try:
            while True:
                try:
                    data = await conn.recv()
                except Exception:
                    break
                received += len(data)
        finally:
            with contextlib.suppress(Exception):
                await conn.close()
            received_done.set()

    server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client_conn = await asyncio.wait_for(
            connect(reader, writer,
                    stack.kme_client(stack.kme_a, stack.client_sae),
                    stack.client_sae, stack.server_sae),
            timeout=HANDSHAKE_TIMEOUT)
        try:
            for _ in range(n_messages):
                try:
                    await client_conn.send(msg)
                except Exception as exc:
                    if type(exc).__name__ == "OTPKeyExhaustedError":
                        break
                    raise
                await asyncio.sleep(pace_s)
        finally:
            with contextlib.suppress(Exception):
                await client_conn.close()
    finally:
        with contextlib.suppress(Exception):
            server.close()
    return received


async def _chatter(stack: _BenchStack, payload_size: int, stop: asyncio.Event,
                   counters: dict, total_seconds: float = 0.0) -> None:
    """Drive a realistic, paced chat: short sessions of a few small messages,
    sent slowly enough that consumption stays below the key-generation rate.
    Partway through the run it fires one heavy burst (an unpaced session that
    sends many messages) so the plot also shows the pool being drawn down before
    it refills."""
    msg = b"x" * payload_size
    burst_at = total_seconds * _BURST_FRACTION
    burst_done = False
    start = time.perf_counter()
    while not stop.is_set():
        elapsed = time.perf_counter() - start
        if not burst_done and total_seconds and elapsed >= burst_at:
            # Heavy burst: many back-to-back sessions with no pacing, each one
            # pulling a fresh key, so the pool is visibly drawn down.
            burst_done = True
            for _ in range(_BURST_SESSIONS):
                if stop.is_set():
                    break
                try:
                    shipped = await _paced_session(stack, msg, 4, 0.0)
                except Exception:
                    break
                counters["handshakes"] += 1
                if shipped > 0:
                    counters["records"] += max(1, shipped // payload_size)
                    counters["bytes"] += shipped
            continue
        try:
            shipped = await _paced_session(stack, msg, _MESSAGES_PER_SESSION,
                                           _PACE_SECONDS)
        except Exception:
            # Producer hasn't refilled yet, or something transient: wait and
            # retry rather than aborting the bench.
            await asyncio.sleep(0.1)
            continue
        counters["handshakes"] += 1
        if shipped > 0:
            counters["records"] += max(1, shipped // payload_size)
            counters["bytes"] += shipped


async def _fast_producer(stack: _BenchStack, blocks_per_sec: float,
                          stop: asyncio.Event) -> None:
    """A bench-only key producer that bypasses Cascade for speed.

    ``qkd.abstract_link.abstract_qkd_link`` emits one (potentially huge) block
    per simulated second and runs Cascade reconciliation, which is too slow to
    expose a meaningful drain-vs-refill dynamic on the second-scale of the
    plot. For this bench we synthesise byte-identical pairs directly (same
    correctness rationale as ``_BenchStack``'s prefill) at a controllable rate.
    """
    period = 1.0 / max(blocks_per_sec, 0.1)
    key_bytes = stack.key_size_bits // 8
    while not stop.is_set():
        await asyncio.sleep(period)
        material = secrets.token_bytes(key_bytes)
        blk = KeyBlock(material=material, source="abstract-bulk", qber=stack.qber)
        stack.kme_a.add_block(blk)
        stack.kme_b.add_block(blk)


async def run(cfg: BenchConfig) -> dict:
    # Start the pool nearly empty. The producer outpaces the paced consumer, so
    # under the light chat load the pool simply climbs; the mid-run burst is
    # what draws it down. The store keeps its default (large) capacity, so no
    # artificial cap shapes the curve. The replacement producer (below) emits N
    # blocks/s without Cascade overhead, giving an honest, observable loop.
    async with _BenchStack(prefill_blocks=4, key_size_bits=64 * 1024) as stack:
        feeder_stop = asyncio.Event()
        feeder = asyncio.create_task(_fast_producer(stack, 4.0, feeder_stop))
        counters = {"handshakes": 0, "records": 0, "bytes": 0}
        stop = asyncio.Event()
        chatter = asyncio.create_task(
            _chatter(stack, 256, stop, counters, cfg.pool_drain_seconds))

        rows = []
        start = time.perf_counter()
        next_sample = start
        while time.perf_counter() - start < cfg.pool_drain_seconds:
            await asyncio.sleep(max(0.0, next_sample - time.perf_counter()))
            t = time.perf_counter() - start
            rows.append([t, stack.kme_a.fresh_key_count(),
                         stack.kme_b.fresh_key_count(),
                         counters["handshakes"], counters["records"],
                         counters["bytes"]])
            next_sample += 0.25
        stop.set()
        feeder_stop.set()
        chatter.cancel()
        feeder.cancel()
        with contextlib.suppress(BaseException):
            await chatter
        with contextlib.suppress(BaseException):
            await feeder

    write_csv("pool_drain",
              ["seconds", "kme_a_fresh", "kme_b_fresh",
               "handshakes_cum", "records_cum", "bytes_cum"], rows)
    return {"seconds": rows[-1][0] if rows else 0.0,
            "handshakes": counters["handshakes"],
            "records": counters["records"],
            "bytes": counters["bytes"],
            "samples": rows}
