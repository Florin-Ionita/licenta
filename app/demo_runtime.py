"""Single-process orchestration of the whole QTLS-over-QKD stack.

This module wires together every phase so a demo (or a test) can spin up the
*entire* system in one process and one event loop:

    QKD bulk feed  -->  fan-out feeder  -->  KME-A / KME-B  (ETSI REST)
                                                  |
                       QTLS server  <-- KMEClient -+-> QTLS client
                                                  |
                              real loopback TCP socket

It deliberately reuses the existing components unchanged (the bulk producer
from Phase 2, the linked KME pair and feeder from Phase 3, the QTLS
connection from Phase 5). Nothing here is new protocol logic -- it is only
assembly -- which keeps the demo honest: what runs in the defense is exactly
the code the earlier phases' tests already validate.
"""

from __future__ import annotations

import asyncio
import contextlib

import httpx

from kme.api import create_kme_app
from kme.network import fan_out_feeder, make_kme_pair
from kme.store import KeyStore
from qkd.abstract_link import abstract_qkd_link
from qkd.keyblock import KeyBlock
from qtls.kme_client import KMEClient

# Per-tick raw-bit size for the bulk QKD feed. Kept tractable on purpose:
# reconciliation (Cascade) is ~O(n*passes), so a half-megabit list would take
# tens of seconds per block. 131072 raw bits distils to ~8 KB of final key in
# ~1 s -- enough OTP budget for a chat session and for the file-transfer demo
# to *visibly hit back-pressure*, which is precisely the QKD constraint the
# thesis sets out to show. (See design_notes Phase 6 for why this is the
# honest choice rather than faking a huge instantaneous key rate.)
DEMO_KEY_RATE_BPS = 131_072
DEMO_QBER = 0.02


class DemoStack:
    """Owns every background task of the running system and tears them down.

    Use as an async context manager::

        async with DemoStack() as stack:
            client_kme = stack.client_kme()
            server_kme = stack.server_kme()
            ...
    """

    def __init__(
        self,
        client_sae: str = "SAE-CLIENT",
        server_sae: str = "SAE-SERVER",
        key_rate_bps: int = DEMO_KEY_RATE_BPS,
        qber: float = DEMO_QBER,
    ) -> None:
        self.client_sae = client_sae
        self.server_sae = server_sae
        self._key_rate = key_rate_bps
        self._qber = qber

        self.kme_a: KeyStore | None = None
        self.kme_b: KeyStore | None = None
        self._queue: asyncio.Queue[KeyBlock] | None = None
        self._stop: asyncio.Event | None = None
        self._tasks: list[asyncio.Task] = []
        self._http_clients: list[httpx.AsyncClient] = []

    async def __aenter__(self) -> "DemoStack":
        self.kme_a, self.kme_b = make_kme_pair(key_size_bits=2048)
        # Authorise the client SAE to obtain keys destined for the server SAE
        # on *both* KMEs (the master pulls from A, the slave fetches from B).
        self.kme_a.authorise(self.client_sae, self.server_sae)
        self.kme_b.authorise(self.client_sae, self.server_sae)

        self._queue = asyncio.Queue()
        self._stop = asyncio.Event()

        # Phase 2 bulk producer -> shared queue.
        self._tasks.append(
            asyncio.create_task(
                abstract_qkd_link(
                    self._queue,
                    key_rate_bps=self._key_rate,
                    qber=self._qber,
                    stop_event=self._stop,
                )
            )
        )
        # Phase 3 fan-out feeder: shared queue -> both KMEs (synchronised).
        self._tasks.append(
            asyncio.create_task(
                fan_out_feeder(
                    self._queue, self.kme_a, self.kme_b, stop_event=self._stop
                )
            )
        )
        # Wait until at least one key block is available on both KMEs so the
        # first handshake does not race the producer.
        await self._await_keys_ready()
        return self

    async def _await_keys_ready(self, timeout: float = 10.0) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if (
                self.kme_a.fresh_key_count() > 0
                and self.kme_b.fresh_key_count() > 0
            ):
                return
            await asyncio.sleep(0.1)
        raise TimeoutError("QKD key pool did not fill in time")

    def _kme_client(self, store: KeyStore, sae_id: str) -> KMEClient:
        """A KMEClient over httpx's in-process ASGI transport.

        The KME REST path is fully exercised; only the socket is short-
        circuited (same decision as the Phase 5 tests, documented there).
        """
        app = create_kme_app(store, peer_kme_id="peer")
        transport = httpx.ASGITransport(app=app)
        http = httpx.AsyncClient(
            transport=transport, base_url="http://kme.local"
        )
        self._http_clients.append(http)
        return KMEClient(http, sae_id)

    def client_kme(self) -> KMEClient:
        return self._kme_client(self.kme_a, self.client_sae)

    def server_kme(self) -> KMEClient:
        return self._kme_client(self.kme_b, self.server_sae)

    async def __aexit__(self, *exc) -> None:
        if self._stop is not None:
            self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        for http in self._http_clients:
            await http.aclose()
