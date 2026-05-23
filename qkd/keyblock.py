"""The unified key-block type produced by every QKD source.

Both QKD sources in this project -- the quantum BB84 simulation (Phase 1) and
the high-volume "abstract" bulk generator (Phase 2) -- ultimately emit the
*same* product: a chunk of final, post-processed secret-key bytes that is
already bit-identical for Alice and Bob. Downstream components (the KME in
Phase 3, the visualization later) should not care which source a block came
from; they only need a consistent container.

:class:`KeyBlock` is that container. The ``source`` field records the origin
("bb84-visual" or "abstract-bulk") purely so the visualization can colour the
two streams differently -- it has no cryptographic meaning.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True)
class KeyBlock:
    """One finished block of shared secret key.

    Attributes:
        key_id:    Unique identifier. The KME will later hand this ID to SAEs
                   so the two endpoints can request *the same* key.
        material:  The final secret-key bytes, already reconciled and privacy-
                   amplified -- identical on Alice's and Bob's side.
        source:    Provenance tag for visualization only:
                   "bb84-visual" or "abstract-bulk".
        qber:      The (estimated) quantum bit error rate this block was
                   distilled at -- kept for metrics/plots, not security use.
        created_at: Unix timestamp (seconds) when the block was produced.
    """

    material: bytes
    source: str
    qber: float
    key_id: uuid.UUID = field(default_factory=uuid.uuid4)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.material:
            raise ValueError("KeyBlock.material must be non-empty")
        if self.source not in ("bb84-visual", "abstract-bulk"):
            raise ValueError(f"unknown KeyBlock source: {self.source!r}")

    @property
    def length_bytes(self) -> int:
        return len(self.material)
