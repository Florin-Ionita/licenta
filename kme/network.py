"""Wiring two KMEs that share one synchronised key feed.

In a real QKD link the two KMEs at the endpoints obtain *the same* key
material from the quantum channel. We reproduce that here by fanning the
single :class:`~qkd.keyblock.KeyBlock` stream (from the Phase 1 BB84 source
and the Phase 2 bulk source) into *both* stores. Because each KME stores the
identical block object -- same UUID, same bytes -- a later lookup by
``key_ID`` on either side returns byte-identical material. This is the
concrete mechanism behind the key_ID-synchronisation guarantee.
"""

from __future__ import annotations

import asyncio

from kme.store import KeyStore
from qkd.keyblock import KeyBlock


def make_kme_pair(
    kme_a_id: str = "KME-A",
    kme_b_id: str = "KME-B",
    key_size_bits: int = 256,
    max_key_count: int = 10_000,
) -> tuple[KeyStore, KeyStore]:
    """Create two empty, mutually-aware KME key stores."""
    a = KeyStore(kme_id=kme_a_id, key_size_bits=key_size_bits,
                 max_key_count=max_key_count)
    b = KeyStore(kme_id=kme_b_id, key_size_bits=key_size_bits,
                 max_key_count=max_key_count)
    # Link the pair so a reservation on one side is mirrored to the other
    # (the simulated ETSI KME-to-KME synchronisation channel).
    a.link_peer(b)
    b.link_peer(a)
    return a, b


async def fan_out_feeder(
    in_queue: "asyncio.Queue[KeyBlock]",
    kme_a: KeyStore,
    kme_b: KeyStore,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Drain the shared key queue, copying every block into *both* KMEs.

    Runs until ``stop_event`` is set. The same block object is inserted into
    both stores, which is what keeps key_ID lookups consistent across the
    pair.
    """
    while stop_event is None or not stop_event.is_set():
        try:
            block = await asyncio.wait_for(in_queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        # Both add_block calls run under the shared lock (the pair adopted one
        # RLock via link_peer), but we hold it explicitly here so the two
        # inserts commit as a single atomic step -- no take_keys can observe
        # the block in one KME but not the other.
        with kme_a._lock:
            kme_a.add_block(block)
            kme_b.add_block(block)
