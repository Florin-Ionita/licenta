"""Information reconciliation (Cascade-lite) and privacy amplification.

After sifting, Alice and Bob hold *almost* identical bit strings that still
differ in a few positions because of channel noise / eavesdropping. Two more
classical steps are needed before the result is a usable secret key:

1. **Reconciliation** -- correct the remaining mismatches so that Alice and
   Bob hold *bit-identical* strings. We implement a simplified version of the
   *Cascade* protocol (Brassard & Salvail, 1994): split the key into blocks,
   compare parities, and use binary search to locate and fix each error,
   repeating over several passes with shuffled block boundaries.

2. **Privacy amplification** -- reconciliation leaks parity information over
   the public channel, and an eavesdropper may also hold partial knowledge.
   We compress the reconciled key with a hash function (SHAKE-128) down to a
   length below the estimated *secure* entropy, which exponentially shrinks
   any adversary's knowledge (Bennett, Brassard, Crepeau, Maurer, 1995).

This is deliberately a teaching-grade implementation: faithful in structure to
real QKD post-processing, but not finite-key-rigorous (that is explicitly
out of scope for the thesis and listed under Future Work).
"""

from __future__ import annotations

import hashlib
import math
import secrets

# Shor-Preskill asymptotic threshold: above this QBER, no positive secret-key
# rate can be extracted, so the protocol must abort. Configurable per call.
DEFAULT_QBER_ABORT = 0.11

# Binary entropy is used to estimate how many bits privacy amplification must
# discard. h2(p) = -p log2 p - (1-p) log2 (1-p).
def binary_entropy(p: float) -> float:
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


class QBERTooHighError(RuntimeError):
    """Raised when the estimated QBER exceeds the abort threshold."""


def _block_parity(bits: list[int], start: int, end: int) -> int:
    """Parity (XOR) of ``bits[start:end]``. This is what is exchanged publicly
    in Cascade -- a single bit per block."""
    p = 0
    for i in range(start, end):
        p ^= bits[i]
    return p


def _fix_one_error(
    alice: list[int],
    bob: list[int],
    start: int,
    end: int,
) -> None:
    """Binary-search a block known to contain an odd number of errors and flip
    the single differing bit in Bob's copy.

    Cascade's key trick: if a block's parities disagree there is at least one
    error in it; recursively halving the block and comparing the parity of one
    half isolates one error in ``log2(blocksize)`` public parity exchanges.
    (This simplified version assumes exactly one error per flagged block, which
    holds when the block size is chosen ~ 1/QBER as Cascade prescribes.)
    """
    while end - start > 1:
        mid = (start + end) // 2
        if _block_parity(alice, start, mid) != _block_parity(bob, start, mid):
            end = mid  # error is in the left half
        else:
            start = mid  # error is in the right half
    bob[start] ^= 1  # flip the located bit so Bob now matches Alice


def _reconcile_one_pass(
    alice: list[int],
    bob: list[int],
    indices: list[int],
    block_size: int,
) -> int:
    """One Cascade pass over the permutation ``indices``.

    The key list is viewed in the shuffled order given by ``indices``, cut
    into blocks of ``block_size``, and every block whose parity disagrees has
    exactly one error located and fixed by binary search. A parity check only
    reveals an *odd* number of errors, so blocks with 2, 4, ... errors slip
    through this pass -- that is expected; a later pass with a *different*
    shuffle splits those pairs into different blocks and catches them. Returns
    how many bits this pass corrected.
    """
    n = len(alice)
    a_perm = [alice[i] for i in indices]
    b_perm = [bob[i] for i in indices]

    corrected = 0
    for start in range(0, n, block_size):
        end = min(start + block_size, n)
        if _block_parity(a_perm, start, end) != _block_parity(b_perm, start, end):
            _fix_one_error(a_perm, b_perm, start, end)
            corrected += 1

    # Write Bob's corrected bits back through the permutation.
    for pos, original_index in enumerate(indices):
        bob[original_index] = b_perm[pos]
    return corrected


def cascade_reconcile(
    alice: list[int],
    bob: list[int],
    qber: float,
    passes: int = 4,
    max_extra_rounds: int = 32,
) -> int:
    """Correct mismatches between ``alice`` and ``bob`` *in place* (Bob's copy
    is modified to match Alice). Returns the number of bits corrected.

    Algorithm (simplified Cascade, Brassard & Salvail 1994):

      * The initial block size is ~``0.73 / QBER`` (the standard Cascade
        heuristic: on average ~one error per block, so most blocks have an
        odd -- hence detectable -- error count).
      * ``passes`` scheduled passes are run; the block size doubles each pass
        and the bit order is freshly shuffled, so error pairs that hid in one
        pass land in different blocks in the next.
      * Because a single parity check cannot see an even number of errors,
        scheduled passes alone may leave a few residual errors. We therefore
        follow them with up to ``max_extra_rounds`` *convergence* passes using
        small shuffled blocks, stopping as soon as Alice and Bob match. The
        cap guarantees termination instead of looping forever on a pathologic
        (very high QBER) input -- the caller treats non-convergence as abort.
    """
    if len(alice) != len(bob):
        raise ValueError("Alice and Bob keys must have equal length")
    n = len(alice)
    if n == 0:
        return 0

    effective_qber = max(qber, 1e-3)
    block_size = max(1, int(0.73 / effective_qber))

    corrected = 0
    indices = list(range(n))
    rng = secrets.SystemRandom()

    # --- Scheduled Cascade passes -----------------------------------------
    for p in range(passes):
        if p > 0:
            rng.shuffle(indices)
        corrected += _reconcile_one_pass(alice, bob, indices, block_size)
        block_size = min(block_size * 2, n)

    # --- Convergence passes: keep shuffling with small blocks until equal --
    # Small blocks make it very unlikely for two residual errors to share a
    # block, so each extra round removes essentially all remaining errors.
    small_block = max(1, int(0.73 / max(effective_qber, 0.05)))
    extra = 0
    while alice != bob and extra < max_extra_rounds:
        rng.shuffle(indices)
        corrected += _reconcile_one_pass(alice, bob, indices, small_block)
        extra += 1

    return corrected


def privacy_amplification(
    reconciled_key: list[int],
    qber: float,
    leaked_bits: int,
) -> bytes:
    """Compress a reconciled bit list into a shorter, secure byte string.

    The output length is the *smooth min-entropy* estimate: starting from the
    sifted length we subtract (a) the entropy an eavesdropper could hold,
    bounded by ``h2(qber)`` per bit, and (b) the bits leaked during
    reconciliation. The remaining bits are extracted by hashing the whole key
    with SHAKE-128, a variable-length cryptographic hash that acts here as a
    (computationally strong, structurally universal) randomness extractor.
    """
    n = len(reconciled_key)
    if n == 0:
        return b""

    # Bits we must throw away: adversary information + reconciliation leakage.
    eve_information = math.ceil(n * binary_entropy(qber))
    secure_bits = n - eve_information - leaked_bits
    if secure_bits <= 0:
        raise QBERTooHighError(
            f"No secure key left after privacy amplification "
            f"(n={n}, eve={eve_information}, leaked={leaked_bits})"
        )

    secure_bytes = secure_bits // 8
    if secure_bytes == 0:
        raise QBERTooHighError(
            "Secure key shorter than one byte; gather more sifted bits"
        )

    # Pack the reconciled bits into bytes, then hash to the secure length.
    raw = bytearray()
    for i in range(0, n - (n % 8), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | reconciled_key[i + j]
        raw.append(byte)

    return hashlib.shake_128(bytes(raw)).digest(secure_bytes)


def reconcile_and_amplify(
    alice: list[int],
    bob: list[int],
    qber: float,
    qber_abort: float = DEFAULT_QBER_ABORT,
) -> bytes:
    """Full post-processing pipeline used by the Phase 1 acceptance test.

    Aborts (raises :class:`QBERTooHighError`) if the estimated QBER is at or
    above ``qber_abort`` -- this is the configurable Shor-Preskill gate. On
    success, returns the final shared secret key as bytes, guaranteed
    bit-identical for Alice and Bob.
    """
    if qber >= qber_abort:
        raise QBERTooHighError(
            f"QBER {qber:.3f} >= abort threshold {qber_abort:.3f}: "
            f"eavesdropping suspected or channel too noisy"
        )

    before = sum(1 for a, b in zip(alice, bob) if a != b)
    corrected = cascade_reconcile(alice, bob, qber)
    if alice != bob:
        # Cascade-lite did not fully converge (rare for low QBER, more likely
        # near the threshold). Treat as an abort rather than emit a bad key.
        raise QBERTooHighError(
            f"Reconciliation failed to converge "
            f"({before} initial errors, {corrected} corrected, residual remain)"
        )

    # Each corrected error cost roughly one binary-search worth of public
    # parity bits; approximate the reconciliation leakage as corrected *
    # log2(blocksize). We use a simple, slightly conservative estimate.
    leaked_bits = corrected * max(1, int(math.log2(max(2, len(alice)))))
    return privacy_amplification(alice, qber, leaked_bits)
