"""Shared helpers for the Phase 9 benchmarks.

Centralises:
  * filesystem paths under ``docs/benchmarks/``
  * CSV writing with a consistent schema
  * a `BenchConfig` profile so --lite / --full / --extreme share the same code
  * one helper that builds a QTLS connection (client+server in-process) since
    every bench needs that and it's three dozen lines of asyncio plumbing.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from kme.api import create_kme_app
from kme.network import fan_out_feeder, make_kme_pair
from kme.store import KeyStore
from qkd.abstract_link import abstract_qkd_link
from qkd.keyblock import KeyBlock
from qtls.connection import QTLSConnection, accept, connect
from qtls.kme_client import KMEClient

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "docs" / "benchmarks" / "raw"
PLOT_DIR = ROOT / "docs" / "benchmarks" / "plots"
RAW_DIR.mkdir(parents=True, exist_ok=True)
PLOT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class BenchConfig:
    """Iteration counts and durations, scaled by profile.

    Profiles map roughly to time budgets:
      * lite     : ~2 min total -- for iterating on bench code
      * full     : ~15 min      -- thesis-quality, as called for in the plan
      * extreme  : ~45-60 min   -- conference-paper rigour
    """
    name: str
    handshake_iters: int
    handshake_warmup: int
    throughput_bytes: list[int]          # payload sizes to measure
    pool_drain_seconds: float
    qber_sweep_seconds: float            # per QBER value
    qber_sweep_values: list[float]
    keyconsumption_payloads: list[int]   # payload sizes for the ratio plot


PROFILES = {
    "lite": BenchConfig(
        name="lite",
        handshake_iters=200, handshake_warmup=20,
        throughput_bytes=[1 << 16, 1 << 20],            # 64 KB, 1 MB
        pool_drain_seconds=20.0,
        qber_sweep_seconds=40.0,
        qber_sweep_values=[0.005, 0.01, 0.02, 0.03, 0.05, 0.08, 0.10],
        keyconsumption_payloads=[64, 256, 1024, 4096],
    ),
    "full": BenchConfig(
        name="full",
        handshake_iters=5000, handshake_warmup=200,
        throughput_bytes=[1 << 20, 1 << 23, 1 << 26],   # 1 MB, 8 MB, 64 MB
        pool_drain_seconds=180.0,
        qber_sweep_seconds=120.0,
        qber_sweep_values=[0.005, 0.01, 0.015, 0.02, 0.025, 0.03, 0.04,
                           0.05, 0.07, 0.08, 0.10],
        keyconsumption_payloads=[16, 64, 256, 1024, 4096, 16384],
    ),
    "extreme": BenchConfig(
        name="extreme",
        handshake_iters=20000, handshake_warmup=1000,
        throughput_bytes=[1 << 20, 1 << 23, 1 << 26, 1 << 27],  # +128 MB
        pool_drain_seconds=600.0,
        qber_sweep_seconds=240.0,
        qber_sweep_values=[0.005, 0.01, 0.015, 0.02, 0.025, 0.03, 0.035,
                           0.04, 0.045, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10],
        keyconsumption_payloads=[8, 16, 32, 64, 128, 256, 1024, 4096, 16384, 65536],
    ),
}


def write_csv(name: str, header: list[str], rows: list[list]) -> Path:
    path = RAW_DIR / f"{name}.csv"
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return path


# -- one-call stack helper -------------------------------------------------


@dataclass
class _BenchStack:
    """A QTLS-over-QKD stack tuned for benchmarks.

    Differences from :class:`app.demo_runtime.DemoStack`:
      * key_size_bits is parameterised (benches pull huge keys)
      * pre-fills the KME with a known number of blocks synchronously to
        eliminate priming time from the measurements
      * exposes both KME clients eagerly
    """
    client_sae: str = "SAE-CLIENT"
    server_sae: str = "SAE-SERVER"
    key_size_bits: int = 8192          # 1 KiB per block
    prefill_blocks: int = 64           # ~64 KiB of fresh key on each side
    qber: float = 0.02
    feed_in_background: bool = False   # start a producer task too?
    key_rate_bps: int = 1_048_576

    kme_a: KeyStore | None = None
    kme_b: KeyStore | None = None
    _tasks: list[asyncio.Task] = field(default_factory=list)
    _stop: asyncio.Event | None = None
    _http: list[httpx.AsyncClient] = field(default_factory=list)
    _queue: "asyncio.Queue[KeyBlock] | None" = None

    async def __aenter__(self) -> "_BenchStack":
        self.kme_a, self.kme_b = make_kme_pair(key_size_bits=self.key_size_bits)
        self.kme_a.authorise(self.client_sae, self.server_sae)
        self.kme_b.authorise(self.client_sae, self.server_sae)

        # Synchronous prefill. We deliberately *skip* the Cascade
        # reconciliation pipeline here: it is O(n*passes) and the largest
        # benches need megabytes of key material, which would take minutes
        # just to prime the stack. The reconciliation correctness is already
        # exercised by the Phase 1-2 unit tests; what the bench needs is
        # cryptographically-strong, byte-identical key blocks on both sides,
        # which token_bytes() provides directly.
        import secrets
        from qkd.keyblock import KeyBlock
        key_bytes = self.key_size_bits // 8
        for _ in range(self.prefill_blocks):
            blk = KeyBlock(material=secrets.token_bytes(key_bytes),
                           source="abstract-bulk", qber=self.qber)
            self.kme_a.add_block(blk)
            self.kme_b.add_block(blk)

        if self.feed_in_background:
            self._stop = asyncio.Event()
            self._queue = asyncio.Queue()
            self._tasks.append(asyncio.create_task(abstract_qkd_link(
                self._queue, key_rate_bps=self.key_rate_bps, qber=self.qber,
                stop_event=self._stop,
            ), name="bench-bulk"))
            self._tasks.append(asyncio.create_task(fan_out_feeder(
                self._queue, self.kme_a, self.kme_b, stop_event=self._stop,
            ), name="bench-fanout"))
        return self

    async def __aexit__(self, *exc) -> None:
        if self._stop is not None:
            self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(BaseException):
                await t
        for h in self._http:
            with contextlib.suppress(Exception):
                await h.aclose()

    def kme_client(self, store: KeyStore, sae: str) -> KMEClient:
        app = create_kme_app(store, peer_kme_id="peer")
        http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://kme.local",
        )
        self._http.append(http)
        return KMEClient(http, sae)


async def open_qtls_pair(
    stack: _BenchStack,
) -> tuple[QTLSConnection, QTLSConnection, asyncio.AbstractServer]:
    """Open one client+server QTLS connection over loopback.

    Returns (client_conn, server_conn, server_object). Caller owns shutdown.
    """
    accepted: asyncio.Future[QTLSConnection] = asyncio.get_event_loop().create_future()

    async def handler(reader, writer):
        try:
            conn = await accept(
                reader, writer,
                stack.kme_client(stack.kme_b, stack.server_sae),
                stack.server_sae,
            )
            accepted.set_result(conn)
        except Exception as exc:
            if not accepted.done():
                accepted.set_exception(exc)

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    client_conn = await connect(
        reader, writer,
        stack.kme_client(stack.kme_a, stack.client_sae),
        stack.client_sae, stack.server_sae,
    )
    server_conn = await asyncio.wait_for(accepted, timeout=10.0)
    return client_conn, server_conn, server


__all__ = [
    "BenchConfig", "PROFILES", "ROOT", "RAW_DIR", "PLOT_DIR",
    "write_csv", "_BenchStack", "open_qtls_pair",
]
