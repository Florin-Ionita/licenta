"""The QTLS record layer: framing, OTP encryption, Wegman-Carter authentication.

A *record* is the unit the protocol puts on the wire. Its layout mirrors a
TLS 1.3 record's spirit (a type byte, a length, then the protected payload),
but the protection is this thesis's information-theoretic combination instead
of an AEAD:

    plaintext  --OTP-->  ciphertext
    tag = WegmanCarter_{k_H}(type || length || ciphertext, r)

Both the OTP key and the fresh 16-byte WC mask ``r`` are consumed, in order,
from a single :class:`~qtls.crypto.otp.OTPKeyStream` that both endpoints
derived from the *same* QKD key during the handshake. Because the stream's
offset only advances and both sides consume it in lockstep (records are
processed in order over TCP), the sender and receiver always use identical key
material for the same record, and never reuse any of it.

The tag covers the header *and* the ciphertext, so an attacker cannot tamper
with the record type or length either -- this closes the malleability that
OTP-alone would otherwise have.
"""

from __future__ import annotations

import struct
from enum import IntEnum

from qtls.crypto.otp import OTPCipher, OTPKeyStream
from qtls.crypto.wc_mac import WegmanCarterMAC

_MASK_LEN = 16   # Wegman-Carter one-time mask r
_TAG_LEN = 16    # Wegman-Carter tag
# Header: 1-byte type + 4-byte big-endian payload length.
_HEADER = struct.Struct(">BI")
_MAX_PAYLOAD = 1 << 24  # 16 MiB sanity cap per record


class RecordType(IntEnum):
    """Mirrors TLS 1.3's content types, trimmed to what QTLS uses."""

    HANDSHAKE = 22
    APPLICATION_DATA = 23
    ALERT = 21


class RecordAuthenticationError(RuntimeError):
    """The Wegman-Carter tag did not verify: the record was forged or
    corrupted, or the two key streams desynchronised. The connection must be
    torn down -- a failed information-theoretic MAC is unrecoverable."""


class RecordProtector:
    """Encrypts/decrypts records for **one direction** of the connection.

    Each direction has its own OTP stream and its own (reusable) WC hash key
    ``k_H``; the per-record mask ``r`` is pulled fresh from the OTP stream.
    The sender uses a protector built from the *send* stream; the peer uses a
    protector built from the byte-identical *receive* stream. They stay in
    lockstep because every record consumes exactly ``len(payload) + 16`` bytes
    in the same order on both sides.
    """

    def __init__(self, otp_stream: OTPKeyStream, wc_hash_key: bytes) -> None:
        self._cipher = OTPCipher(otp_stream)
        self._mac = WegmanCarterMAC(WegmanCarterMAC.key_from_bytes(wc_hash_key))

    @property
    def key_bytes_remaining(self) -> int:
        return self._cipher.key_bytes_remaining

    def seal(self, rtype: RecordType, plaintext: bytes) -> bytes:
        """Produce a wire record: ``header || ciphertext || tag``.

        Key consumption order (must match :meth:`open` exactly):
          1. ``len(plaintext)`` bytes -> OTP key for the payload.
          2. 16 bytes               -> fresh one-time mask ``r``.
        """
        if len(plaintext) >= _MAX_PAYLOAD:
            raise ValueError("record payload too large")

        ciphertext = self._cipher.encrypt(plaintext)
        r = self._cipher.take_raw(_MASK_LEN)  # fresh, never-reused QKD mask

        header = _HEADER.pack(int(rtype), len(ciphertext))
        tag = self._mac.tag(header + ciphertext, r)
        return header + ciphertext + tag

    def open(self, record: bytes) -> tuple[RecordType, bytes]:
        """Parse and authenticate a wire record, returning ``(type, plaintext)``.

        Verifies the tag *before* trusting any field. Consumes the receive
        stream in the exact same order as :meth:`seal` consumed the send
        stream, so the OTP key and mask line up byte-for-byte.
        """
        if len(record) < _HEADER.size + _TAG_LEN:
            raise RecordAuthenticationError("record too short to be valid")

        header = record[: _HEADER.size]
        rtype_int, clen = _HEADER.unpack(header)
        body = record[_HEADER.size : -_TAG_LEN]
        tag = record[-_TAG_LEN:]
        if len(body) != clen:
            raise RecordAuthenticationError("declared length mismatch")

        # Same consumption order as seal(): payload key first, then mask r.
        plaintext = self._cipher.decrypt(body)
        r = self._cipher.take_raw(_MASK_LEN)

        if not self._mac.verify(header + body, r, tag):
            raise RecordAuthenticationError(
                "Wegman-Carter tag verification failed"
            )
        try:
            rtype = RecordType(rtype_int)
        except ValueError:
            raise RecordAuthenticationError(
                f"unknown record type {rtype_int}"
            )
        return rtype, plaintext


def read_record(buffer: bytes) -> tuple[bytes, bytes] | None:
    """Split one complete record off the front of ``buffer``.

    Returns ``(record_bytes, remaining_buffer)`` or ``None`` if a full record
    is not yet buffered. Used by the asyncio transport to frame the TCP byte
    stream (TCP has no message boundaries of its own).
    """
    if len(buffer) < _HEADER.size:
        return None
    _, clen = _HEADER.unpack(buffer[: _HEADER.size])
    total = _HEADER.size + clen + _TAG_LEN
    if len(buffer) < total:
        return None
    return buffer[:total], buffer[total:]
