"""Thin SAE-side client for the ETSI GS QKD 014 KME REST API (Phase 3).

The QTLS client and server are *Secure Application Entities* (SAEs): during
the handshake they call their local KME over HTTP to obtain the shared QKD
key. This wraps the two calls they need:

  * ``request_key``  -> POST .../enc_keys   (master pulls a fresh key)
  * ``fetch_key``    -> POST .../dec_keys   (slave fetches it by key_ID)

Transport is real HTTP via ``httpx`` (the plan's requirement -- it exercises
the full ETSI path). Tests inject httpx's in-process ASGI transport so they
hit the same FastAPI app without a real socket; production would point at the
KME's URL over mTLS. The SAE identity is sent in the ``X-SAE-ID`` header,
matching the single authentication seam the KME exposes (Phase 3, §5.5).
"""

from __future__ import annotations

import base64

import httpx


class KMEClientError(RuntimeError):
    """The KME refused or could not satisfy a key request."""


class KMEClient:
    """One SAE's view of its local KME.

    ``client`` is an ``httpx.AsyncClient`` already configured with the KME
    base URL (and, in production, the mTLS client cert). Injecting it keeps
    this class transport-agnostic and trivially testable.
    """

    def __init__(self, client: httpx.AsyncClient, sae_id: str) -> None:
        self._http = client
        self._sae_id = sae_id

    async def request_key(self, slave_sae_id: str) -> tuple[str, bytes]:
        """Master role: pull one fresh key destined for ``slave_sae_id``.

        Returns ``(key_id, key_material)``. The ``key_id`` is what the client
        puts in its ClientHello so the server can fetch the same key.
        """
        resp = await self._http.post(
            f"/api/v1/keys/{slave_sae_id}/enc_keys",
            json={"number": 1},
            headers={"X-SAE-ID": self._sae_id},
        )
        if resp.status_code != 200:
            raise KMEClientError(
                f"enc_keys failed: {resp.status_code} {resp.text}"
            )
        key = resp.json()["keys"][0]
        return key["key_ID"], base64.b64decode(key["key"])

    async def fetch_key(self, master_sae_id: str, key_id: str) -> bytes:
        """Slave role: fetch, by ``key_id``, the key a master reserved for us.

        Returns the byte-identical material the master received (Phase 3
        guarantees this via the synchronised KMEs).
        """
        resp = await self._http.post(
            f"/api/v1/keys/{master_sae_id}/dec_keys",
            json={"key_IDs": [{"key_ID": key_id}]},
            headers={"X-SAE-ID": self._sae_id},
        )
        if resp.status_code != 200:
            raise KMEClientError(
                f"dec_keys failed: {resp.status_code} {resp.text}"
            )
        return base64.b64decode(resp.json()["keys"][0]["key"])
