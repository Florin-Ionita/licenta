"""Wegman-Carter message authentication with information-theoretic security.

The Wegman-Carter (1981) construction is::

    tag = H_{k_H}(message)  XOR  r

where ``H`` is drawn from an epsilon-almost-universal hash family keyed by
``k_H``, and ``r`` is a *fresh one-time pad* (consumed from the QKD key pool,
never reused). Portmann (2014) proves this construction is universally
composable -- the correct security notion for the QKD setting.

Concrete hash: a polynomial evaluation hash over the finite field GF(2^128),
using the same field and reduction polynomial as GHASH inside AES-GCM. The
*structure* is identical to GCM's authenticator; the crucial difference is the
final mask: GCM uses ``E_K(nonce)`` (a block-cipher output, hence only
*computationally* secure), whereas we use a true one-time pad ``r``. That
single substitution is what turns a computational MAC into an
*information-theoretically* secure one: an adversary's forgery probability is
bounded by ``(n_blocks + 1) / 2^128`` **regardless of computing power**.

Key-recycling insight (Portmann): the hash key ``k_H`` may be safely reused
across many messages; only the mask ``r`` must be fresh per message. This is
what makes the QKD key budget for authentication affordable (128 fresh bits
per message instead of a full-length pad).

Pure-Python ``gf128_mul`` is intentionally not micro-optimised; the thesis
notes this is the known hot path and that real deployments use the hardware
GHASH/AES-NI instructions.
"""

from __future__ import annotations

# GHASH reduction polynomial x^128 + x^7 + x^2 + x + 1, with bits taken in the
# big-endian / "reflected" convention GCM uses: the constant is 0xE1 placed in
# the top byte of a 128-bit word.
_R = 0xE1 << 120
_MASK128 = (1 << 128) - 1
_BLOCK = 16  # 128 bits


def gf128_mul(x: int, y: int) -> int:
    """Multiply two elements of GF(2^128) in the GCM bit convention.

    Both inputs and the result are 128-bit integers whose *most significant*
    bit is the field's bit 0 (GCM's reflected convention). The routine is the
    standard shift-and-add multiplication with reduction by ``_R`` whenever a
    1 is shifted out of the low end -- the same algorithm GHASH uses.
    """
    z = 0
    v = x
    for i in range(128):
        # Process bits of y from the most significant downward.
        if (y >> (127 - i)) & 1:
            z ^= v
        # Shift v right by one; if a 1 falls off, reduce by the polynomial.
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z & _MASK128


def _blocks(msg: bytes) -> list[int]:
    """Split ``msg`` into 128-bit big-endian integers, zero-padding the last
    block. (Length is bound separately, see :func:`poly_hash`.)"""
    out = []
    for i in range(0, len(msg), _BLOCK):
        chunk = msg[i:i + _BLOCK].ljust(_BLOCK, b"\x00")
        out.append(int.from_bytes(chunk, "big"))
    return out


def poly_hash(k_h: int, msg: bytes) -> int:
    """Evaluate the GHASH-style polynomial hash of ``msg`` under key ``k_h``.

    Computes ``(... (b1 * k) XOR b2) * k ... ) * k`` over GF(2^128), then
    folds in a final block encoding the message bit-length. Binding the length
    prevents trivial extension/truncation forgeries that a pure
    block-by-block hash would allow -- the same reason GCM appends a length
    block.
    """
    h = 0
    for b in _blocks(msg):
        h = gf128_mul(h ^ b, k_h)
    # Length block: message length in *bits*, in the high 64 bits (mirrors the
    # GCM len(A)||len(C) trailer; we only have one data field here).
    length_block = (len(msg) * 8) << 64
    h = gf128_mul(h ^ length_block, k_h)
    return h & _MASK128


class WegmanCarterMAC:
    """Information-theoretically secure MAC: ``tag = poly_hash(k_H, m) XOR r``.

    ``k_h`` is a 128-bit hash key that may be reused across messages. Each
    :meth:`tag` / :meth:`verify` call consumes a fresh 16-byte one-time mask
    ``r`` -- the caller supplies it from the QKD key pool. Reusing an ``r``
    across two messages would break the unconditional guarantee, so the API
    forces the caller to pass ``r`` explicitly per call rather than hiding it.
    """

    def __init__(self, k_h: int) -> None:
        if not 0 <= k_h <= _MASK128:
            raise ValueError("k_h must be a 128-bit integer")
        if k_h == 0:
            # A zero hash key makes poly_hash identically zero -> every
            # message would have tag == r, trivially forgeable. Reject it.
            raise ValueError("k_h must be non-zero")
        self._k_h = k_h

    @staticmethod
    def key_from_bytes(material: bytes) -> int:
        """Interpret 16 key bytes as the 128-bit hash key ``k_H``."""
        if len(material) != _BLOCK:
            raise ValueError("k_H requires exactly 16 bytes")
        return int.from_bytes(material, "big")

    def tag(self, message: bytes, r: bytes) -> bytes:
        """Return the 16-byte authentication tag for ``message``.

        ``r`` must be exactly 16 fresh, never-before-used one-time-pad bytes.
        """
        if len(r) != _BLOCK:
            raise ValueError("r (one-time mask) must be exactly 16 bytes")
        h = poly_hash(self._k_h, message)
        t = h ^ int.from_bytes(r, "big")
        return t.to_bytes(_BLOCK, "big")

    def verify(self, message: bytes, r: bytes, received_tag: bytes) -> bool:
        """Return True iff ``received_tag`` is the valid tag for ``message``.

        Recomputes the tag with the same ``r`` and compares in constant time.
        The caller is responsible for using the *same* ``r`` the sender used
        for this message (the QTLS record layer derives it deterministically
        from the per-record key stream).
        """
        if len(received_tag) != _BLOCK:
            return False
        expected = self.tag(message, r)
        # Constant-time comparison: do not leak where a forgery first differs.
        diff = 0
        for a, b in zip(expected, received_tag):
            diff |= a ^ b
        return diff == 0
