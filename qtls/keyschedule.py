"""TLS 1.3-style HKDF key schedule (RFC 8446 section 7.1).

Real TLS 1.3 feeds the (EC)DHE shared secret into an HKDF-based key schedule
to derive all traffic keys. We keep that exact schedule structure -- the
``HKDF-Extract`` / ``Derive-Secret`` / ``HKDF-Expand-Label`` shape from
RFC 8446 -- but the input secret is the **QKD key obtained from the KME**
instead of a Diffie-Hellman output. Keeping the schedule faithful is what
lets the thesis honestly call the protocol "TLS 1.3-shaped".

The HMAC/HKDF primitives themselves come from the ``cryptography`` library
(production-grade); only the labelling/structure is reimplemented so it can be
shown to match the RFC.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

_HASH = hashes.SHA256()
_HASH_LEN = 32  # SHA-256 output size in bytes


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869): HMAC(salt, ikm) -> a pseudorandom key.

    Salt defaults (per the TLS schedule) to a string of zero bytes when there
    is no previous secret.
    """
    if not salt:
        salt = b"\x00" * _HASH_LEN
    h = hmac.HMAC(salt, _HASH)
    h.update(ikm)
    return h.finalize()


def hkdf_expand_label(
    secret: bytes,
    label: str,
    context: bytes,
    length: int,
) -> bytes:
    """HKDF-Expand-Label exactly as defined in RFC 8446 section 7.1.

    The label is prefixed with ``"tls13 "`` and packed together with the
    context into the ``HkdfLabel`` structure the RFC specifies, so the derived
    bytes match a real TLS 1.3 implementation's structure.
    """
    full_label = b"tls13 " + label.encode("ascii")
    # struct HkdfLabel { uint16 length; opaque label<7..255>;
    #                     opaque context<0..255>; }
    hkdf_label = (
        struct.pack(">H", length)
        + struct.pack("B", len(full_label))
        + full_label
        + struct.pack("B", len(context))
        + context
    )
    return HKDFExpand(
        algorithm=_HASH, length=length, info=hkdf_label
    ).derive(secret)


def derive_secret(secret: bytes, label: str, transcript_hash: bytes) -> bytes:
    """Derive-Secret(secret, label, Messages) from RFC 8446 section 7.1.

    The "Messages" argument is passed already-hashed (the running transcript
    hash), as the RFC prescribes.
    """
    return hkdf_expand_label(secret, label, transcript_hash, _HASH_LEN)


def transcript_hash(*messages: bytes) -> bytes:
    """SHA-256 over the concatenated handshake messages (the transcript).

    Binding traffic keys to the transcript is what makes the handshake
    tamper-evident: any modification of a handshake message changes every
    subsequently derived key, so the Finished check (Phase 5) fails.
    """
    digest = hashes.Hash(_HASH)
    for m in messages:
        digest.update(m)
    return digest.finalize()


class KeySchedule:
    """The QTLS key schedule seeded by a QKD key instead of (EC)DHE output.

    Mirrors the TLS 1.3 early/handshake/master progression but simplified to
    the secrets this protocol actually uses:

      * ``handshake secret`` = Extract(salt=0, ikm = QKD key)
      * client/server handshake traffic secrets via Derive-Secret
      * a master secret and client/server application traffic secrets

    From each traffic secret we expand the concrete keying material the record
    layer needs: an OTP key-stream segment and a 16-byte Wegman-Carter hash
    key. (The per-record one-time MAC mask ``r`` is taken directly from the
    OTP stream by the record layer, never from a PRF -- that is what keeps the
    MAC information-theoretic.)
    """

    def __init__(self, qkd_key: bytes, transcript: bytes) -> None:
        if len(qkd_key) < _HASH_LEN:
            raise ValueError(
                "QKD key too short for the key schedule "
                f"(need >= {_HASH_LEN} bytes)"
            )
        # RFC 8446 Derive-Secret takes Transcript-Hash(Messages), not the raw
        # messages: hash the transcript *once* here so every Derive-Secret
        # call binds to a fixed-size 32-byte digest (and fits HkdfLabel's
        # 1-byte context length field).
        self._transcript = transcript_hash(transcript)
        self._handshake_secret = hkdf_extract(salt=b"", ikm=qkd_key)
        self._master_secret = derive_secret(
            self._handshake_secret, "derived", self._transcript
        )

    # -- handshake traffic secrets ----------------------------------------

    def client_handshake_secret(self) -> bytes:
        return derive_secret(
            self._handshake_secret, "c hs traffic", self._transcript
        )

    def server_handshake_secret(self) -> bytes:
        return derive_secret(
            self._handshake_secret, "s hs traffic", self._transcript
        )

    # -- application traffic secrets --------------------------------------

    def client_app_secret(self) -> bytes:
        return derive_secret(
            self._master_secret, "c ap traffic", self._transcript
        )

    def server_app_secret(self) -> bytes:
        return derive_secret(
            self._master_secret, "s ap traffic", self._transcript
        )

    # -- concrete keying material for the record layer --------------------

    @staticmethod
    def wc_hash_key(traffic_secret: bytes) -> bytes:
        """16-byte Wegman-Carter hash key k_H for this direction.

        k_H may be reused across many records (Portmann key recycling), so it
        is derived once per traffic secret rather than per record.
        """
        return hkdf_expand_label(traffic_secret, "wc key", b"", 16)

    @staticmethod
    def finished_key(traffic_secret: bytes) -> bytes:
        """Key for the Finished MAC (RFC 8446: a separate Expand-Label)."""
        return hkdf_expand_label(traffic_secret, "finished", b"", _HASH_LEN)
