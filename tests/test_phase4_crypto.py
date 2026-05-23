"""Phase 4 acceptance tests.

'Done' criteria from the thesis plan:
  * OTP correctness (round-trip).
  * Wegman-Carter tag verification correctness.
  * Forgery rejection.
  * Any attempt to reuse OTP material throws an exception.

Extra: a GF(2^128) correctness cross-check, and the algebraic property that
makes the WC security proof work (the hash is XOR-linear in the message under
a fixed key, masked into unconditional security by a fresh r).
"""

from __future__ import annotations

import os

import pytest

from qtls.crypto.otp import (
    OTPCipher,
    OTPKeyExhaustedError,
    OTPKeyStream,
)
from qtls.crypto.wc_mac import WegmanCarterMAC, gf128_mul, poly_hash


# --------------------------------------------------------------------------
# One-Time Pad
# --------------------------------------------------------------------------

def test_otp_round_trip():
    key = os.urandom(256)
    msg = b"Hello, server -- this is an information-theoretic secret."
    # Sender and receiver derive identical streams from the same QKD key.
    enc = OTPCipher(OTPKeyStream(key))
    dec = OTPCipher(OTPKeyStream(key))
    ct = enc.encrypt(msg)
    assert ct != msg
    assert dec.decrypt(ct) == msg


def test_otp_ciphertext_is_plaintext_xor_key():
    key = bytes(range(64))
    pt = bytes([0xFF]) * 16
    ct = OTPCipher(OTPKeyStream(key)).encrypt(pt)
    assert ct == bytes(p ^ k for p, k in zip(pt, key))


def test_otp_consumes_stream_strictly_forward():
    key = os.urandom(64)
    s = OTPKeyStream(key)
    c = OTPCipher(s)
    c.encrypt(b"abcdefgh")          # consumes 8
    assert s.consumed == 8
    c.encrypt(b"ijkl")              # consumes 4 more
    assert s.consumed == 12
    assert s.remaining == 64 - 12


def test_otp_reuse_is_structurally_impossible():
    """Two messages drawn from one stream must use disjoint key regions, so a
    single key byte is never applied twice (the thesis-killing bug)."""
    key = os.urandom(64)
    s = OTPKeyStream(key)
    c = OTPCipher(s)
    m1 = b"AAAAAAAA"
    m2 = b"AAAAAAAA"
    ct1 = c.encrypt(m1)
    ct2 = c.encrypt(m2)
    # Identical plaintexts MUST give different ciphertexts: proof that the
    # second message used fresh, non-reused key material.
    assert ct1 != ct2


def test_otp_exhaustion_raises_before_emitting_ciphertext():
    s = OTPKeyStream(os.urandom(16))
    c = OTPCipher(s)
    c.encrypt(b"0123456789ABCDEF")  # exactly 16 bytes -> stream empty
    with pytest.raises(OTPKeyExhaustedError):
        c.encrypt(b"x")            # nothing left; must raise, not reuse
    assert s.remaining == 0


def test_empty_keystream_rejected():
    with pytest.raises(ValueError):
        OTPKeyStream(b"")


# --------------------------------------------------------------------------
# GF(2^128) arithmetic correctness
# --------------------------------------------------------------------------

def test_gf128_multiplicative_identity():
    """In GCM's bit convention the multiplicative identity is the element
    whose top bit is set (0x80....00)."""
    one = 1 << 127
    for _ in range(20):
        a = int.from_bytes(os.urandom(16), "big")
        assert gf128_mul(a, one) == a
        assert gf128_mul(one, a) == a


def test_gf128_commutative_and_distributive():
    for _ in range(20):
        a = int.from_bytes(os.urandom(16), "big")
        b = int.from_bytes(os.urandom(16), "big")
        c = int.from_bytes(os.urandom(16), "big")
        assert gf128_mul(a, b) == gf128_mul(b, a)
        # Field multiplication distributes over XOR (field addition).
        assert gf128_mul(a, b ^ c) == gf128_mul(a, b) ^ gf128_mul(a, c)


def test_gf128_zero():
    a = int.from_bytes(os.urandom(16), "big")
    assert gf128_mul(a, 0) == 0
    assert gf128_mul(0, a) == 0


# --------------------------------------------------------------------------
# Wegman-Carter MAC
# --------------------------------------------------------------------------

def _fresh_kh() -> int:
    return WegmanCarterMAC.key_from_bytes(os.urandom(16))


def test_wc_tag_verifies():
    mac = WegmanCarterMAC(_fresh_kh())
    msg = b"authenticated but not secret"
    r = os.urandom(16)
    tag = mac.tag(msg, r)
    assert len(tag) == 16
    assert mac.verify(msg, r, tag) is True


def test_wc_rejects_modified_message():
    mac = WegmanCarterMAC(_fresh_kh())
    r = os.urandom(16)
    tag = mac.tag(b"transfer 100 to alice", r)
    # Attacker flips the message; tag must no longer verify.
    assert mac.verify(b"transfer 999 to alice", r, tag) is False


def test_wc_rejects_modified_tag():
    mac = WegmanCarterMAC(_fresh_kh())
    msg = b"some payload"
    r = os.urandom(16)
    tag = bytearray(mac.tag(msg, r))
    tag[0] ^= 0x01  # single-bit forgery attempt
    assert mac.verify(msg, r, bytes(tag)) is False


def test_wc_wrong_mask_fails():
    mac = WegmanCarterMAC(_fresh_kh())
    msg = b"payload"
    tag = mac.tag(msg, os.urandom(16))
    assert mac.verify(msg, os.urandom(16), tag) is False


def test_wc_length_binding_prevents_zero_extension():
    """Appending zero bytes must change the tag (length is bound in)."""
    mac = WegmanCarterMAC(_fresh_kh())
    r = os.urandom(16)
    t1 = mac.tag(b"data", r)
    t2 = mac.tag(b"data\x00\x00\x00\x00", r)
    assert t1 != t2


def test_wc_rejects_bad_key_and_mask_sizes():
    with pytest.raises(ValueError):
        WegmanCarterMAC(0)  # zero hash key is trivially forgeable
    mac = WegmanCarterMAC(_fresh_kh())
    with pytest.raises(ValueError):
        mac.tag(b"x", os.urandom(8))   # r must be 16 bytes
    with pytest.raises(ValueError):
        WegmanCarterMAC.key_from_bytes(os.urandom(8))


def test_wc_information_theoretic_structure():
    """The defining WC property: with the *same* (k_H, r), the tag is an
    affine function of the message hash -- tag XOR r == poly_hash(k_H, m).
    The fresh r is exactly what hides poly_hash and yields unconditional
    security; this test documents that structure explicitly."""
    kh = _fresh_kh()
    mac = WegmanCarterMAC(kh)
    msg = b"structural check"
    r = os.urandom(16)
    tag = int.from_bytes(mac.tag(msg, r), "big")
    assert tag ^ int.from_bytes(r, "big") == poly_hash(kh, msg)
