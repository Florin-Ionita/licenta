"""Pydantic v2 schemas for ETSI GS QKD 014 V1.1.1.

These models intentionally mirror the JSON data formats defined in the ETSI
standard *exactly*, including the standard's field names (``key_ID``,
``key_size``, ``stored_key_count`` ...). Conforming to the published interface
verbatim is a deliberate decision: it lets the thesis claim genuine standards
compliance, and the auto-generated OpenAPI schema (FastAPI) can be shown in
the appendix as evidence.

Reference: ETSI GS QKD 014 V1.1.1 (2019-02), section 6 "Data format".
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Status(BaseModel):
    """Response of ``GET /api/v1/keys/{slave_SAE_ID}/status``.

    Tells a master SAE how many keys are available for a given peer and the
    per-request limits, so it can size its requests correctly.
    """

    source_KME_ID: str = Field(..., description="KME ID serving this SAE")
    target_KME_ID: str = Field(..., description="KME ID serving the peer SAE")
    master_SAE_ID: str = Field(..., description="SAE ID of the calling master")
    slave_SAE_ID: str = Field(..., description="SAE ID of the peer (slave)")
    key_size: int = Field(..., description="Size of each key, in bits")
    stored_key_count: int = Field(..., description="Keys currently available")
    max_key_count: int = Field(..., description="Maximum keys the KME can store")
    max_key_per_request: int = Field(
        ..., description="Max keys returnable in one request"
    )
    max_key_size: int = Field(..., description="Max supported key size, bits")
    min_key_size: int = Field(..., description="Min supported key size, bits")
    max_SAE_ID_count: int = Field(
        0, description="Max additional SAE IDs per request (0 = no multicast)"
    )


class KeyRequest(BaseModel):
    """Body of ``POST .../enc_keys``: how many keys, and how big.

    Per the standard both fields are optional with KME defaults; we follow the
    spec's defaults (one key of the KME's configured size).
    """

    number: int = Field(1, ge=1, description="Number of keys requested")
    size: int | None = Field(
        None, description="Size of each key in bits (defaults to KME key_size)"
    )


class KeyIDs(BaseModel):
    """One key_ID entry inside a :class:`KeyIDsRequest`."""

    key_ID: str = Field(..., description="UUID of a previously delivered key")


class KeyIDsRequest(BaseModel):
    """Body of ``POST .../dec_keys``: which key_IDs the slave wants."""

    key_IDs: list[KeyIDs] = Field(..., min_length=1)


class Key(BaseModel):
    """One key entry in a :class:`KeyContainer`.

    ``key`` is the key material **base64-encoded**, as mandated by the
    standard (the wire format is JSON, which cannot carry raw bytes).
    """

    key_ID: str = Field(..., description="UUID identifying this key")
    key: str = Field(..., description="Base64-encoded key material")


class KeyContainer(BaseModel):
    """Response of both ``enc_keys`` and ``dec_keys``: a list of keys."""

    keys: list[Key]


class ErrorMessage(BaseModel):
    """Standard ETSI error body (section 6.5)."""

    message: str
    details: list[dict] | None = None
