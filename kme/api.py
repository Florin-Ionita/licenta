"""FastAPI application implementing the ETSI GS QKD 014 V1.1.1 REST interface.

Three endpoints, exactly as the standard defines them (clauses 5.2-5.4):

    GET  /api/v1/keys/{slave_SAE_ID}/status
    GET  /api/v1/keys/{slave_SAE_ID}/enc_keys?number=N&size=S   (simple only)
    POST /api/v1/keys/{slave_SAE_ID}/enc_keys
    GET  /api/v1/keys/{master_SAE_ID}/dec_keys?key_ID=...        (single ID)
    POST /api/v1/keys/{master_SAE_ID}/dec_keys

Authentication scope. ETSI 014 (clause 5.1) mandates mTLS with the SAE ID
derived from the client certificate's Common Name. The cryptographic machinery
for that mTLS is built in `kme/certs.py` and exercised by
`test_mtls_cert_chain_round_trip`, but at runtime SAE identity is resolved
through the `current_sae` dependency, which reads an `X-SAE-ID` header. This is
a documented simplification (see the thesis "Authentication scope" paragraph);
a production deployment would replace the header lookup with a middleware that
extracts the CN from the verified peer certificate, leaving the rest of the
KeyStore and API code unchanged.

Error body. ETSI 014 clause 6.5 prescribes `{"message": ..., "details": ...}`.
FastAPI's `HTTPException` default body is `{"detail": ...}`; we install a
custom exception handler that translates it to the spec wire format.
"""

from __future__ import annotations

import base64
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse

from kme.models import (
    ErrorMessage,
    Key,
    KeyContainer,
    KeyIDs,
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


async def _etsi_http_exception_handler(
    request: Request, exc: HTTPException
) -> JSONResponse:
    """Convert FastAPI's default `{detail: ...}` body to ETSI 014 §6.5 shape.

    Spec wire format is `{"message": str, "details": list[dict] | null}`. If
    the caller passed a dict as the HTTPException detail (so it could carry
    structured `details`), respect that; otherwise treat the string as the
    `message` and emit `details: null`.
    """
    detail = exc.detail
    if isinstance(detail, dict) and "message" in detail:
        body = {
            "message": detail["message"],
            "details": detail.get("details"),
        }
    else:
        body = {"message": str(detail), "details": None}
    return JSONResponse(status_code=exc.status_code, content=body)


def create_kme_app(store: KeyStore, peer_kme_id: str) -> FastAPI:
    """Build a FastAPI app bound to one :class:`KeyStore`.

    ``peer_kme_id`` is the ID of the *other* KME, reported in the Status
    response's ``target_KME_ID`` field per the standard.
    """
    app = FastAPI(
        title=f"KME {store.kme_id} -- ETSI GS QKD 014",
        version="1.1.1",
    )
    app.add_exception_handler(HTTPException, _etsi_http_exception_handler)

    _std_responses = {
        400: {"model": ErrorMessage},
        401: {"model": ErrorMessage},
        503: {"model": ErrorMessage},
    }

    @app.get(
        "/api/v1/keys/{slave_SAE_ID}/status",
        response_model=Status,
        responses=_std_responses,
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

    def _serve_enc_keys(
        sae: str, slave_SAE_ID: str, number: int, size: int | None
    ) -> KeyContainer:
        """Shared body for GET and POST variants of enc_keys."""
        # ETSI 014 §6.2: if the KME only supports keys whose size is a
        # multiple of 8, it shall reject other sizes with this exact message.
        if size is not None and size % 8 != 0:
            raise HTTPException(
                status_code=400,
                detail="size shall be a multiple of 8",
            )
        try:
            blocks = store.take_keys(sae, slave_SAE_ID, number)
        except AccessDeniedError as e:
            # Spec lists only 400/401/503 for these endpoints; ACL refusal
            # is reported as 401 (the SAE is "not authenticated for this
            # request"), matching how the spec uses 401 in §5.4.
            raise HTTPException(status_code=401, detail=str(e))
        except KeyPoolEmptyError as e:
            # 503: pool temporarily exhausted -- expected QKD back-pressure.
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

    @app.get(
        "/api/v1/keys/{slave_SAE_ID}/enc_keys",
        response_model=KeyContainer,
        responses=_std_responses,
    )
    def get_enc_keys(
        slave_SAE_ID: str = Path(...),
        number: int = Query(1, ge=1),
        size: int | None = Query(None),
        sae: str = Depends(current_sae),
    ) -> KeyContainer:
        """Master SAE pulls fresh keys via GET (simple-request variant).

        Per ETSI 014 §6.2, when ``number`` and/or ``size`` are the only
        request items, the SAE may use GET with URL query parameters instead
        of POST.
        """
        return _serve_enc_keys(sae, slave_SAE_ID, number, size)

    @app.post(
        "/api/v1/keys/{slave_SAE_ID}/enc_keys",
        response_model=KeyContainer,
        responses=_std_responses,
    )
    def post_enc_keys(
        body: KeyRequest,
        slave_SAE_ID: str = Path(...),
        sae: str = Depends(current_sae),
    ) -> KeyContainer:
        """Master SAE pulls fresh keys destined for ``slave_SAE_ID``."""
        return _serve_enc_keys(sae, slave_SAE_ID, body.number, body.size)

    def _serve_dec_keys(sae: str, key_id_strings: list[str]) -> KeyContainer:
        """Shared body for GET and POST variants of dec_keys."""
        try:
            ids = [uuid.UUID(s) for s in key_id_strings]
        except ValueError:
            # Spec §6.4: if a requested key is not present, the message must
            # be exactly this string. A malformed UUID is treated as "key
            # not found on this KME" for the purpose of the error body.
            raise HTTPException(
                status_code=400,
                detail="one or more keys specified are not found on KME",
            )
        try:
            blocks = store.get_keys_by_id(sae, ids)
        except KeyNotFoundError:
            raise HTTPException(
                status_code=400,
                detail="one or more keys specified are not found on KME",
            )
        except AccessDeniedError as e:
            # Spec §5.4: "The KME shall reject the request with a 401 HTTP
            # status code if the SAE ID of the requestor was not an SAE ID
            # supplied to the 'Get key' method ..."
            raise HTTPException(status_code=401, detail=str(e))
        return KeyContainer(
            keys=[
                Key(
                    key_ID=str(b.key_id),
                    key=base64.b64encode(b.material).decode("ascii"),
                )
                for b in blocks
            ]
        )

    @app.get(
        "/api/v1/keys/{master_SAE_ID}/dec_keys",
        response_model=KeyContainer,
        responses=_std_responses,
    )
    def get_dec_keys(
        master_SAE_ID: str = Path(...),
        key_ID: str = Query(..., description="UUID of a single requested key"),
        sae: str = Depends(current_sae),
    ) -> KeyContainer:
        """Slave SAE fetches a single key via GET (single-ID variant).

        Per ETSI 014 §6.4, when a single key_ID is specified and no extension
        fields are needed, the SAE may use GET with a URL query parameter
        instead of POST.
        """
        return _serve_dec_keys(sae, [key_ID])

    @app.post(
        "/api/v1/keys/{master_SAE_ID}/dec_keys",
        response_model=KeyContainer,
        responses=_std_responses,
    )
    def post_dec_keys(
        body: KeyIDsRequest,
        master_SAE_ID: str = Path(...),
        sae: str = Depends(current_sae),
    ) -> KeyContainer:
        """Slave SAE fetches, by key_ID, the keys a master reserved for it."""
        return _serve_dec_keys(sae, [entry.key_ID for entry in body.key_IDs])

    return app
