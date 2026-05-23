"""Adapter that turns the BB84 quantum core into a KeyBlock producer.

`qkd.bb84` deliberately stays focused on the *quantum* protocol (circuits,
sifting, Eve). This thin module wraps it so that the visual BB84 source emits
exactly the same :class:`~qkd.keyblock.KeyBlock` objects as the abstract bulk
generator, lets both feed a single shared queue, and tags its output
``"bb84-visual"``.
"""

from __future__ import annotations

import asyncio

from qkd.bb84 import collect_sifted_key
from qkd.keyblock import KeyBlock
from qkd.reconciliation import (
    DEFAULT_QBER_ABORT,
    QBERTooHighError,
    reconcile_and_amplify,
)


def generate_block(
    target_sifted_bits: int = 4096,
    n_qubits: int = 64,
    eve_present: bool = False,
    noise: float = 0.0,
    qber_abort: float = DEFAULT_QBER_ABORT,
) -> KeyBlock:
    """Run BB84 until enough sifted bits exist, distil them, return a KeyBlock.

    Uses the *same* reconciliation + privacy-amplification pipeline as every
    other source, so the result is interchangeable with an abstract-bulk
    block. Propagates :class:`QBERTooHighError` when eavesdropping/noise pushes
    the QBER above the abort gate.
    """
    alice, bob, qber = collect_sifted_key(
        target_sifted_bits, n_qubits=n_qubits, eve_present=eve_present, noise=noise
    )
    material = reconcile_and_amplify(alice, bob, qber, qber_abort=qber_abort)
    return KeyBlock(material=material, source="bb84-visual", qber=qber)


async def bb84_source(
    out_queue: "asyncio.Queue[KeyBlock]",
    target_sifted_bits: int = 4096,
    n_qubits: int = 64,
    eve_present: bool = False,
    noise: float = 0.0,
    qber_abort: float = DEFAULT_QBER_ABORT,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Continuously distil BB84 key blocks into ``out_queue`` until stopped.

    Runs the (CPU-bound) quantum simulation in a worker thread via
    ``asyncio.to_thread`` so it does not block the event loop shared with the
    bulk producer. A block whose QBER trips the abort gate is skipped, exactly
    like the bulk link, so an Eve attack degrades the stream rather than
    crashing the producer.
    """
    while stop_event is None or not stop_event.is_set():
        try:
            block = await asyncio.to_thread(
                generate_block,
                target_sifted_bits,
                n_qubits,
                eve_present,
                noise,
                qber_abort,
            )
        except QBERTooHighError:
            # Eavesdropping / excessive noise: discard and keep trying.
            await asyncio.sleep(0.05)
            continue
        await out_queue.put(block)
