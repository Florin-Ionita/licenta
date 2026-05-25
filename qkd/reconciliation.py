"""Information reconciliation (full Cascade) and privacy amplification.

After sifting, Alice and Bob hold *almost* identical bit strings that still
differ in a few positions because of channel noise / eavesdropping. Two more
classical steps are needed before the result is a usable secret key:

1. **Reconciliation** -- correct the remaining mismatches so that Alice and
   Bob hold *bit-identical* strings. We implement the full **Cascade**
   protocol (Brassard & Salvail, 1994) with back-propagation: split the key
   into blocks, compare parities, binary-search each odd-error block, then
   for each fixed bit revisit every prior pass to detect newly-exposed
   odd-error blocks (the eponymous "cascade").

2. **Privacy amplification** -- reconciliation leaks parity information over
   the public channel, and an eavesdropper may also hold partial knowledge.
   We compress the reconciled key with a hash function (SHAKE-128) down to a
   length below the estimated *secure* entropy, which exponentially shrinks
   any adversary's knowledge (Bennett, Brassard, Crepeau, Maurer, 1995).

The implementation tallies the *exact* number of parity bits announced --
block parities plus every BINCONF halving -- so privacy amplification can
subtract the real leak rather than a conservative estimate. Combined with
Cascade back-propagation this brings the secret-key rate close to the
Shannon limit (~1.05 * h2(QBER) leakage in practice).

The reconciliation hot loop is implemented in C (``qkd/_cascade.c``) and
loaded via ctypes on first import (see ``qkd/_cascade.py``). The project
requires a working C compiler at first import; there is no Python fallback
because the benchmarks and Phase 6/8 tests rely on the C speed to stay
inside their timeouts, and a single backend keeps results reproducible.
"""

from __future__ import annotations

import hashlib
import math

import numpy as np

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


# The C extension (see qkd/_cascade.c and qkd/_cascade.py) is compiled on
# first import. Importing _cascade raises ImportError if no compiler is
# available -- the project requires the C backend, with no Python fallback.
from qkd._cascade import cascade_reconcile_c as cascade_reconcile


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

    # Pack the reconciled bits into bytes (NumPy packbits is one C call) and
    # hash to the secure length with SHAKE-128.
    usable_bits = n - (n % 8)
    bits = np.asarray(reconciled_key[:usable_bits], dtype=np.uint8)
    raw = np.packbits(bits, bitorder="big").tobytes()
    return hashlib.shake_128(raw).digest(secure_bytes)


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
    corrected, leaked_bits = cascade_reconcile(alice, bob, qber)
    if alice != bob:
        # Full Cascade failed to converge -- pathological QBER. Treat as an
        # abort rather than emit a bad key.
        raise QBERTooHighError(
            f"Reconciliation failed to converge "
            f"({before} initial errors, {corrected} corrected, residual remain)"
        )

    # leaked_bits is the *exact* number of parity bits announced on the public
    # channel (block parities + every BINCONF step), tallied by cascade_reconcile
    # itself. This is what privacy amplification subtracts to bound Eve's
    # information, getting us close to the Shannon-limit secret rate.
    return privacy_amplification(alice, qber, leaked_bits)
