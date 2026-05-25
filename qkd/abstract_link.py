"""High-volume "abstract" QKD key generator (Phase 2).

The quantum BB84 simulation (Phase 1) is faithful but slow: running real
Qiskit circuits to produce the *megabytes* of key that a One-Time Pad consumes
would be hopelessly impractical. Real QKD research code solves this exactly the
same way -- a detailed physical model for demonstration, and an abstract
high-rate model for throughput experiments.

This module is that abstract model. It does **not** simulate qubits. Instead
it generates raw key material at a configurable rate, injects errors at a
configurable QBER (as if a noisy quantum channel had produced them), and then
runs that material through the **same** reconciliation + privacy-amplification
pipeline as BB84 (`qkd.reconciliation`). The output is therefore a stream of
:class:`~qkd.keyblock.KeyBlock` objects that are indistinguishable in form and
correctness from BB84's output -- only faster and tagged ``"abstract-bulk"``.

Design note (deviation from the thesis-plan pseudocode): the plan's sketch
hashed raw bits directly and never modelled Bob's *errored* copy, which would
have produced keys inconsistent with the BB84 path. We instead reuse the real
reconciliation pipeline so both sources are cryptographically identical. This
is documented in `docs/design_notes.md`.
"""

from __future__ import annotations

import asyncio
import secrets

from qkd.keyblock import KeyBlock
from qkd.reconciliation import (
    DEFAULT_QBER_ABORT,
    QBERTooHighError,
    reconcile_and_amplify,
)

_rng = secrets.SystemRandom()


def _random_bits(n: int) -> list[int]:
    """``n`` cryptographically-strong random bits -- the abstract stand-in for
    the raw sifted key a quantum channel would have yielded."""
    return [secrets.randbits(1) for _ in range(n)]


def _apply_qber(bits: list[int], qber: float) -> list[int]:
    """Return a copy of ``bits`` with each bit independently flipped with
    probability ``qber`` -- this is "Bob's" noisy copy of "Alice's" raw key,
    modelling a binary-symmetric quantum channel (same model as the BB84
    ``noise`` parameter, so the two sources behave identically)."""
    return [b ^ 1 if _rng.random() < qber else b for b in bits]


def generate_block(
    raw_bits: int,
    qber: float,
    qber_abort: float = DEFAULT_QBER_ABORT,
) -> KeyBlock:
    """Produce one finished :class:`KeyBlock` from abstract raw material.

    Steps mirror the QKD post-processing pipeline exactly:
      1. Draw ``raw_bits`` random bits  -> Alice's raw key.
      2. Flip bits at rate ``qber``     -> Bob's noisy copy.
      3. Cascade reconciliation + SHAKE-128 privacy amplification (shared code
         with BB84), which also enforces the Shor-Preskill abort gate.

    Raises :class:`QBERTooHighError` (propagated from the pipeline) when the
    QBER is at/above ``qber_abort`` -- identical failure behaviour to BB84.
    """
    if raw_bits <= 0:
        raise ValueError("raw_bits must be positive")
    if not 0.0 <= qber < 1.0:
        raise ValueError("qber must be in [0, 1)")

    alice = _random_bits(raw_bits)
    bob = _apply_qber(alice, qber)
    material = reconcile_and_amplify(alice, bob, qber, qber_abort=qber_abort)
    return KeyBlock(material=material, source="abstract-bulk", qber=qber)


async def abstract_qkd_link(
    out_queue: "asyncio.Queue[KeyBlock]",
    key_rate_bps: int = 100_000,
    qber: float = 0.02,
    distance_km: float = 0.0,
    qber_abort: float = DEFAULT_QBER_ABORT,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Continuously feed finished key blocks into ``out_queue``.

    Once per simulated second it produces roughly ``key_rate_bps`` raw bits,
    distils them, and enqueues the resulting :class:`KeyBlock`. It runs until
    ``stop_event`` is set (or forever if none is given) and is designed to run
    concurrently with the BB84 producer feeding the *same* queue.

    Parameters:
        key_rate_bps: target raw bits generated per second (the secret-key
            output is smaller after entropy loss -- exactly the real QKD
            constraint the thesis highlights).
        qber:        injected error rate (default 2%, a realistic fibre value).
        distance_km: not physically modelled; recorded for realism and used
            only to *attenuate* the effective rate (longer fibre -> fewer
            bits), so distance/rate plots have something to show. Documented
            as an abstraction, not a physical channel model.
        qber_abort:  Shor-Preskill abort threshold (default 0.11).

    Errors from a single distillation (e.g. a transient QBER spike above the
    abort gate) are swallowed so one bad second does not kill the producer;
    the link simply skips that block, mirroring a real system that would
    discard an unusable frame and continue.
    """
    if key_rate_bps <= 0:
        raise ValueError("key_rate_bps must be positive")

    # Crude distance attenuation: ~3% effective-rate loss per km, floored so a
    # long link still trickles. Purely illustrative for distance/rate plots.
    attenuation = max(0.05, 1.0 - 0.03 * distance_km)
    effective_bits = max(8, int(key_rate_bps * attenuation))

    while stop_event is None or not stop_event.is_set():
        await asyncio.sleep(1.0)
        try:
            # Cascade reconciliation is CPU-bound and (for large blocks)
            # takes hundreds of milliseconds. Run it in a worker thread so
            # the asyncio event loop stays responsive: handshakes, KME REST
            # calls, and the dashboard can all keep ticking while one block
            # distils. Without this offload the producer's per-iteration
            # sleep(1.0) silently stretches to sleep(1.0) + cascade_time,
            # making the apparent key rate up to several times lower than
            # the physical channel would yield.
            block = await asyncio.to_thread(
                generate_block, effective_bits, qber, qber_abort,
            )
        except QBERTooHighError:
            # Unusable second (QBER above the security gate): skip and retry,
            # exactly as a real deployment would discard the frame.
            continue
        await out_queue.put(block)
