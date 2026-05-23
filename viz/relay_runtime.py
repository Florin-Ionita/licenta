"""Background runtime for the Phase 8 multi-hop relay demo.

Separate from :mod:`viz.runtime` on purpose: the relay demo is optional and
must not couple to the point-to-point demo. It spins up its own
:class:`~qkd.relay.RelayNetwork`, primes every link's pool, and on demand
delivers an end-to-end key across the chosen src->dst pair, publishing the
route + per-hop reports onto the same :class:`~viz.bus.EventBus` the rest of
the dashboard consumes.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time

from qkd.relay import RelayError, RelayNetwork, default_topology

from viz.bus import EventBus


class RelayRuntime:
    """Owns the asyncio thread that drives the relay demo."""

    def __init__(self, bus: EventBus, network: RelayNetwork | None = None,
                 deliver_interval_s: float = 2.5) -> None:
        self.bus = bus
        self.network = network or default_topology()
        self.deliver_interval_s = deliver_interval_s
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stopped = threading.Event()
        self._ready = threading.Event()
        # Mutable demand: the user picks src/dst from the sidebar; the loop
        # re-reads this on each tick.
        self._pair = ("A", "B")

    # -- public control ----------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("RelayRuntime already started")
        self._thread = threading.Thread(
            target=self._thread_main, name="qtls-relay-runtime", daemon=True,
        )
        self._thread.start()
        self._ready.wait(timeout=20.0)

    def stop(self) -> None:
        if self._loop is None or self._thread is None:
            return
        self._loop.call_soon_threadsafe(self._stopped.set)
        self._thread.join(timeout=10.0)

    def set_pair(self, src: str, dst: str) -> None:
        self._pair = (src, dst)

    def nodes(self) -> list[str]:
        return sorted(self.network.graph.nodes)

    def edges(self) -> list[tuple[str, str]]:
        return [(u, v) for u, v in self.network.graph.edges]

    def edge_pool_depths(self) -> dict[tuple[str, str], tuple[int, int]]:
        """For the topology panel: fresh-key count on each endpoint of each edge."""
        depths: dict[tuple[str, str], tuple[int, int]] = {}
        for (a, b), (store_a, store_b) in self.network._edge_stores.items():
            depths[(a, b)] = (store_a.fresh_key_count(), store_b.fresh_key_count())
        return depths

    # -- thread / loop -----------------------------------------------------

    def _thread_main(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._async_main())
        finally:
            self._loop.close()

    async def _async_main(self) -> None:
        stop_event = asyncio.Event()

        async def bridge() -> None:
            while not self._stopped.is_set():
                await asyncio.sleep(0.1)
            stop_event.set()

        bridge_task = asyncio.create_task(bridge(), name="relay-stopper")
        await self.network.start_feeders(stop_event)

        # Wait until every edge has at least one key.
        await self._await_primed(timeout=20.0)
        self.bus.publish("log", level="info",
                         msg="Relay network primed; routes available")
        self._ready.set()

        try:
            while not stop_event.is_set():
                src, dst = self._pair
                if src != dst:
                    try:
                        result = self.network.deliver_key(src, dst, n_bytes=32)
                        self.bus.publish(
                            "relay_delivery",
                            src=result.src, dst=result.dst,
                            path=result.path,
                            hops=[(h.from_node, h.to_node, h.edge_key_bytes)
                                  for h in result.hops],
                            key_hex=result.delivered_key.hex(),
                        )
                    except RelayError as exc:
                        # Most often: one link's pool is dry. The producers
                        # will refill -- just log and retry on the next tick.
                        self.bus.publish("log", level="warn",
                                         msg=f"relay {src}->{dst}: {exc}")
                await asyncio.sleep(self.deliver_interval_s)
        finally:
            bridge_task.cancel()
            with contextlib.suppress(BaseException):
                await bridge_task
            await self.network.stop_feeders()

    async def _await_primed(self, timeout: float = 20.0) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            ok = all(
                sa.fresh_key_count() > 0 and sb.fresh_key_count() > 0
                for (sa, sb) in self.network._edge_stores.values()
            )
            if ok:
                return
            await asyncio.sleep(0.1)
        raise TimeoutError("relay network never primed")
