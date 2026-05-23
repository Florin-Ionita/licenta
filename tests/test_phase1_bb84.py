"""Phase 1 acceptance tests.

'Done' criteria from the thesis plan:
  * BB84 + sifting + reconciliation + privacy amplification yields a
    *bit-identical* key for Alice and Bob at QBER 0% and ~5%.
  * The pipeline aborts (raises) when QBER is at/above the configurable
    Shor-Preskill threshold (~11%), e.g. under an Eve attack (~25%).
"""

from __future__ import annotations

import pytest

from qkd.bb84 import bb84_round, collect_sifted_key
from qkd.reconciliation import (
    DEFAULT_QBER_ABORT,
    QBERTooHighError,
    reconcile_and_amplify,
)

# Enough sifted bits that, after entropy loss, a non-empty byte key remains.
TARGET_SIFTED_BITS = 4096


# --------------------------------------------------------------------------
# BB84 quantum core
# --------------------------------------------------------------------------

def test_bb84_round_structure():
    """A clean round must satisfy the basic BB84 invariants."""
    r = bb84_round(n_qubits=64)
    assert r.n_qubits == 64
    assert len(r.alice_bits) == 64
    assert len(r.bob_bits) == 64
    # Every sifted position must have matching bases.
    for idx in r.sifted_indices:
        assert r.alice_bases[idx] == r.bob_bases[idx]
    # Roughly half the qubits survive sifting (bases agree ~50% of the time).
    assert 10 <= r.sifted_length <= 60


def test_bb84_noiseless_no_eve_is_error_free():
    """Without noise or Eve, every sifted bit must agree (QBER == 0)."""
    r = bb84_round(n_qubits=128)
    assert r.alice_sifted == r.bob_sifted
    assert r.observed_qber() == 0.0


def test_bb84_eve_injects_detectable_errors():
    """Intercept-and-resend should push the sifted QBER toward ~25%."""
    _, _, qber = collect_sifted_key(TARGET_SIFTED_BITS, eve_present=True)
    assert 0.15 < qber < 0.35  # generous band around the 25% expectation


# --------------------------------------------------------------------------
# Full pipeline: identical keys at low QBER
# --------------------------------------------------------------------------

def test_pipeline_qber_zero_produces_identical_key():
    alice, bob, qber = collect_sifted_key(TARGET_SIFTED_BITS)
    assert qber == 0.0
    key = reconcile_and_amplify(alice, bob, qber)
    # After reconciliation Alice's and Bob's bit lists must match exactly ...
    assert alice == bob
    # ... and the amplified key must be a non-empty byte string.
    assert isinstance(key, bytes) and len(key) > 0


def test_pipeline_qber_five_percent_produces_identical_key():
    alice, bob, qber = collect_sifted_key(TARGET_SIFTED_BITS, noise=0.05)
    assert 0.02 < qber < 0.09  # sampled QBER lands near 5%
    key = reconcile_and_amplify(alice, bob, qber)
    assert alice == bob, "reconciliation must make the keys bit-identical"
    assert len(key) > 0


def test_alice_and_bob_derive_the_same_secret():
    """The whole point: both parties end with the *same* bytes.

    Privacy amplification is a deterministic hash of the reconciled key, so
    once reconciliation has made Alice's and Bob's bit lists identical, the
    same extractor applied to each side must yield byte-identical keys.
    """
    from qkd.reconciliation import privacy_amplification

    alice, bob, qber = collect_sifted_key(TARGET_SIFTED_BITS, noise=0.03)
    key = reconcile_and_amplify(alice, bob, qber)
    assert alice == bob  # reconciliation converged

    # Same leak parameter on both sides => identical extractor output.
    alice_key = privacy_amplification(alice, qber, leaked_bits=0)
    bob_key = privacy_amplification(bob, qber, leaked_bits=0)
    assert alice_key == bob_key
    assert len(key) > 0


# --------------------------------------------------------------------------
# Abort above the Shor-Preskill threshold
# --------------------------------------------------------------------------

def test_pipeline_aborts_under_eve_attack():
    """Eve's ~25% QBER must trip the abort gate."""
    alice, bob, qber = collect_sifted_key(TARGET_SIFTED_BITS, eve_present=True)
    assert qber >= DEFAULT_QBER_ABORT
    with pytest.raises(QBERTooHighError):
        reconcile_and_amplify(alice, bob, qber)


def test_pipeline_aborts_above_high_noise():
    """A 20% noisy channel exceeds the 11% threshold and must abort."""
    alice, bob, qber = collect_sifted_key(TARGET_SIFTED_BITS, noise=0.20)
    assert qber >= DEFAULT_QBER_ABORT
    with pytest.raises(QBERTooHighError):
        reconcile_and_amplify(alice, bob, qber)


def test_abort_threshold_is_configurable():
    """A 5% channel passes the default gate but fails a strict 3% gate."""
    alice, bob, qber = collect_sifted_key(TARGET_SIFTED_BITS, noise=0.05)
    # Passes with the default 11% threshold ...
    reconcile_and_amplify(list(alice), list(bob), qber)
    # ... but a deliberately strict 3% threshold must reject it.
    with pytest.raises(QBERTooHighError):
        reconcile_and_amplify(alice, bob, qber, qber_abort=0.03)
