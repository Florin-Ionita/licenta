"""FastAPI application implementing the ETSI GS QKD 014 V1.1.1 REST interface.

Three endpoints, exactly as the standard defines them:

    GET  /api/v1/keys/{slave_SAE_ID}/status      -> Status
    POST /api/v1/keys/{slave_SAE_ID}/enc_keys    -> KeyContainer  (master pull)
    POST /api/v1/keys/{master_SAE_ID}/dec_keys   -> KeyContainer  (slave fetch)

SAE identity. ETSI 014 authenticates SAEs with mTLS and derives the SAE ID
from the client certificate's Common Name. uvicorn does not surface the peer
certificate to the route handler conveniently, so SAE identity is resolved by
a single injectable dependency :func:`current_sae`:

  * In production/mTLS mode the reverse path would read the verified client
    cert CN (the cert machinery is built in Phase 3's `certs` helper and
    documented in design_notes).
  * For tests and local runs the dependency falls back to the
    ``X-SAE-ID`` header.

Keeping identity in one dependency means the endpoint logic is identical
regardless of how the SAE was authenticated -- a clean seam, documented as a
deliberate simplification rather than a security claim.
"""

from __future__ import annotations

import base64
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Path

from kme.models import (
    ErrorMessage,
    Key,
    KeyContainer,
    KeyIDsRequest,
    KeyRequest,
    Status,
)
from kme.store import (
    AccessDeniedError,
    KeyNotFoundError,
    KeyPoolEmptyError,
    KeyStore,
)


def current_sae(x_sae_id: str | None = Header(default=None)) -> str:
    """Resolve the calling SAE's ID.

    Single authentication seam (see module docstring). Without an identity the
    request is rejected, mirroring mTLS refusing an unauthenticated client.
    """
    if not x_sae_id:
        raise HTTPException(status_code=401, detail="missing SAE identity")
    return x_sae_id


def create_kme_app(store: KeyStore, peer_kme_id: str) -> FastAPI:
    """Build a FastAPI app bound to one :class:`KeyStore`.

    ``peer_kme_id`` is the ID of the *other* KME, reported in the Status
    response's ``target_KME_ID`` field per the standard.
    """
    app = FastAPI(
        title=f"KME {store.kme_id} -- ETSI GS QKD 014",
        version="1.1.1",
    )

    @app.get(
        "/api/v1/keys/{slave_SAE_ID}/status",
        response_model=Status,
        responses={401: {"model": ErrorMessage}},
    )
    def get_status(
        slave_SAE_ID: str = Path(...),
        sae: str = Depends(current_sae),
    ) -> Status:
        """Report availability for the (caller -> slave) key flow."""
        return Status(
            source_KME_ID=store.kme_id,
            target_KME_ID=peer_kme_id,
            master_SAE_ID=sae,
            slave_SAE_ID=slave_SAE_ID,
            key_size=store.key_size_bits,
            stored_key_count=store.fresh_key_count(),
            max_key_count=store.max_key_count,
            max_key_per_request=128,
            max_key_size=store.key_size_bits,
            min_key_size=store.key_size_bits,
            max_SAE_ID_count=0,
        )

    @app.post(
        "/api/v1/keys/{slave_SAE_ID}/enc_keys",
        response_model=KeyContainer,
        responses={
            400: {"model": ErrorMessage},
            401: {"model": ErrorMessage},
            403: {"model": ErrorMessage},
        },
    )
    def post_enc_keys(
        body: KeyRequest,
        slave_SAE_ID: str = Path(...),
        sae: str = Depends(current_sae),
    ) -> KeyContainer:
        """Master SAE pulls fresh keys destined for ``slave_SAE_ID``."""
        try:
            blocks = store.take_keys(sae, slave_SAE_ID, body.number)
        except AccessDeniedError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except KeyPoolEmptyError as e:
            # 503: the key pool is temporarily exhausted -- this is the
            # *expected* QKD back-pressure behaviour, not a server fault.
            raise HTTPException(status_code=503, detail=str(e))
        return KeyContainer(
            keys=[
                Key(
                    key_ID=str(b.key_id),
                    key=base64.b64encode(b.material).decode("ascii"),
                )
                for b in blocks
            ]
        )

    @app.post(
        "/api/v1/keys/{master_SAE_ID}/dec_keys",
        response_model=KeyContainer,
        responses={
            400: {"model": ErrorMessage},
            401: {"model": ErrorMessage},
            403: {"model": ErrorMessage},
        },
    )
    def post_dec_keys(
        body: KeyIDsRequest,
        master_SAE_ID: str = Path(...),
        sae: str = Depends(current_sae),
    ) -> KeyContainer:
        """Slave SAE fetches, by key_ID, the keys a master reserved for it."""
        try:
            ids = [uuid.UUID(entry.key_ID) for entry in body.key_IDs]
        except ValueError:
            raise HTTPException(status_code=400, detail="malformed key_ID")
        try:
            blocks = store.get_keys_by_id(sae, ids)
        except KeyNotFoundError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except AccessDeniedError as e:
            raise HTTPException(status_code=403, detail=str(e))
        return KeyContainer(
            keys=[
                Key(
                    key_ID=str(b.key_id),
                    key=base64.b64encode(b.material).decode("ascii"),
                )
                for b in blocks
            ]
        )

    return app
