"""One-Time Pad cipher with strict, enforced no-reuse.

The One-Time Pad (Vernam, 1917; proven perfectly secret by Shannon, 1949) is
``ciphertext = plaintext XOR key`` where the key is uniformly random, at least
as long as the plaintext, and **used exactly once**. If any byte of key is
ever reused, Shannon secrecy collapses completely (XOR of two ciphertexts
leaks the XOR of the two plaintexts). The plan calls OTP reuse "the worst
possible bug -- it destroys your thesis if discovered at review."

This module therefore makes reuse *structurally impossible* rather than a
matter of caller discipline: key material lives in a :class:`OTPKeyStream`
that hands out each byte at most once and raises if anyone asks for more than
remains. The cipher cannot encrypt without consuming fresh stream, so there is
no API path that reuses a byte.

OTP provides confidentiality only, never integrity -- a flipped ciphertext bit
flips the corresponding plaintext bit undetectably. It is therefore *always*
combined with the Wegman-Carter MAC (see ``wc_mac.py``); this module
deliberately does not authenticate anything on its own.
"""

from __future__ import annotations

import threading


class OTPKeyExhaustedError(RuntimeError):
    """Not enough unused key material remains for the requested operation.

    This is a *normal, expected* condition for OTP over QKD (the key budget is
    finite); callers are meant to handle it as back-pressure, not treat it as
    a programming error.
    """


class OTPKeyReuseError(RuntimeError):
    """An attempt was made to consume key material that was already used.

    Raising here means a real reuse bug was caught before any ciphertext could
    leak -- exactly the safety net the thesis review demands.
    """


class OTPKeyStream:
    """A finite pool of one-time key bytes with a strictly advancing offset.

    Bytes ``[0, offset)`` have been consumed and can never be returned again.
    ``take(n)`` returns the next ``n`` unused bytes and advances the offset;
    there is no method to rewind or re-read consumed material.
    """

    def __init__(self, material: bytes) -> None:
        if not material:
            raise ValueError("OTP key stream cannot be empty")
        self._material = material
        self._offset = 0
        self._lock = threading.Lock()

    @property
    def remaining(self) -> int:
        with self._lock:
            return len(self._material) - self._offset

    @property
    def consumed(self) -> int:
        with self._lock:
            return self._offset

    def take(self, n: int) -> bytes:
        """Return the next ``n`` unused key bytes and mark them consumed.

        Raises :class:`OTPKeyExhaustedError` if fewer than ``n`` bytes remain.
        The consumed region only ever grows, so the same byte is never handed
        out twice.
        """
        if n <= 0:
            raise ValueError("must take a positive number of bytes")
        with self._lock:
            end = self._offset + n
            if end > len(self._material):
                raise OTPKeyExhaustedError(
                    f"requested {n} bytes, only "
                    f"{len(self._material) - self._offset} remain"
                )
            chunk = self._material[self._offset:end]
            self._offset = end
            return chunk


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class OTPCipher:
    """Encrypt/decrypt with a One-Time Pad backed by an :class:`OTPKeyStream`.

    Encryption consumes ``len(plaintext)`` fresh key bytes. Decryption is the
    *same* XOR with the *same* stream position, so the sender and receiver
    must consume their (identical) streams in lockstep -- which the QTLS
    record layer guarantees by deriving both streams from the same QKD key and
    processing records in order. There is intentionally no nonce or IV: an OTP
    needs none, because the key is never reused in the first place.
    """

    def __init__(self, key_stream: OTPKeyStream) -> None:
        self._stream = key_stream

    @property
    def key_bytes_remaining(self) -> int:
        return self._stream.remaining

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return ``plaintext XOR k`` where ``k`` is fresh, never-reused key.

        Consuming the stream *before* producing ciphertext means a reuse or
        exhaustion error is raised instead of emitting an insecure ciphertext.
        """
        if not plaintext:
            return b""
        key = self._stream.take(len(plaintext))
        return _xor(plaintext, key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Inverse of :meth:`encrypt`; XOR is its own inverse for the OTP."""
        if not ciphertext:
            return b""
        key = self._stream.take(len(ciphertext))
        return _xor(ciphertext, key)

    def take_raw(self, n: int) -> bytes:
        """Consume ``n`` raw key bytes for non-encryption use.

        Used by the record layer to pull the per-record Wegman-Carter
        one-time mask ``r`` from the *same* stream as the payload key, so the
        mask is genuine never-reused QKD material rather than a PRF output --
        this is what keeps the MAC information-theoretically secure.
        """
        return self._stream.take(n)
