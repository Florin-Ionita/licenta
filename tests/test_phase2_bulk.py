"""Phase 2 acceptance tests.

'Done' criteria from the thesis plan:
  * A high-rate "abstract QKD" source exists with configurable
    key_rate_bps / qber / distance_km.
  * Its material goes through the *same* reconciliation + privacy-
    amplification path as BB84.
  * A unified KeyBlock type is emitted by both sources.
  * Running both producers concurrently yields a stream of timestamped
    KeyBlocks ready for the KME.

The literal "30 seconds" run is provided as a `slow` test; an equivalent
short-window test proves the same concurrency property quickly for CI.
"""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest

from qkd.abstract_link import abstract_qkd_link, generate_block
from qkd.bb84_source import bb84_source
from qkd.keyblock import KeyBlock
from qkd.reconciliation import QBERTooHighError


# --------------------------------------------------------------------------
# KeyBlock: the unified type
# --------------------------------------------------------------------------

def test_keyblock_validates_fields():
    kb = KeyBlock(material=b"\x01\x02\x03", source="abstract-bulk", qber=0.02)
    assert kb.length_bytes == 3
    assert isinstance(kb.key_id, uuid.UUID)
    assert kb.created_at <= time.time()

    with pytest.raises(ValueError):
        KeyBlock(material=b"", source="abstract-bulk", qber=0.0)
    with pytest.raises(ValueError):
        KeyBlock(material=b"x", source="not-a-source", qber=0.0)


def test_keyblock_ids_are_unique():
    a = KeyBlock(material=b"a", source="bb84-visual", qber=0.0)
    b = KeyBlock(material=b"b", source="bb84-visual", qber=0.0)
    assert a.key_id != b.key_id


# --------------------------------------------------------------------------
# Bulk generator: shared pipeline, configurable params
# --------------------------------------------------------------------------

def test_bulk_block_uses_shared_pipeline_and_is_nonempty():
    block = generate_block(raw_bits=8192, qber=0.03)
    assert block.source == "abstract-bulk"
    assert block.length_bytes > 0
    assert block.qber == 0.03


def test_bulk_generator_aborts_above_threshold():
    """Same Shor-Preskill failure behaviour as BB84."""
    with pytest.raises(QBERTooHighError):
        generate_block(raw_bits=8192, qber=0.20)


def test_bulk_generator_rejects_bad_params():
    with pytest.raises(ValueError):
        generate_block(raw_bits=0, qber=0.02)
    with pytest.raises(ValueError):
        generate_block(raw_bits=1024, qber=1.0)


# --------------------------------------------------------------------------
# Concurrency: both producers feed the same queue
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_both_producers_feed_one_queue_concurrently():
    """Short-window equivalent of the 30s criterion.

    Both the BB84 source and the abstract bulk link run concurrently and push
    into a single shared queue. We require that within a few seconds we see
    blocks from *both* sources, each with a sane timestamp and non-empty
    material -- i.e. a unified, timestamped KeyBlock stream ready for the KME.
    """
    queue: asyncio.Queue[KeyBlock] = asyncio.Queue()
    stop = asyncio.Event()

    bulk = asyncio.create_task(
        abstract_qkd_link(
            queue, key_rate_bps=20_000, qber=0.02, stop_event=stop
        )
    )
    quantum = asyncio.create_task(
        bb84_source(
            queue, target_sifted_bits=2048, n_qubits=64, stop_event=stop
        )
    )

    collected: list[KeyBlock] = []
    started = time.time()
    try:
        # Collect for up to ~6s or until we have both sources represented.
        while time.time() - started < 6.0:
            try:
                kb = await asyncio.wait_for(queue.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue
            collected.append(kb)
            sources = {k.source for k in collected}
            if {"abstract-bulk", "bb84-visual"} <= sources:
                break
    finally:
        stop.set()
        bulk.cancel()
        quantum.cancel()
        await asyncio.gather(bulk, quantum, return_exceptions=True)

    sources = {k.source for k in collected}
    assert "abstract-bulk" in sources, "bulk producer never emitted a block"
    assert "bb84-visual" in sources, "BB84 producer never emitted a block"
    for kb in collected:
        assert kb.length_bytes > 0
        assert kb.created_at >= started - 1.0  # timestamps are sane
        assert isinstance(kb.key_id, uuid.UUID)
    # Blocks arrive time-ordered enough to be a "stream".
    ts = [k.created_at for k in collected]
    assert ts == sorted(ts) or len(ts) <= 2


@pytest.mark.slow
@pytest.mark.asyncio
async def test_both_producers_run_for_30_seconds():
    """Literal Phase 2 'Done' criterion: 30s concurrent run -> KeyBlock stream.

    Marked `slow`; run with `pytest -m slow`.
    """
    queue: asyncio.Queue[KeyBlock] = asyncio.Queue()
    stop = asyncio.Event()

    bulk = asyncio.create_task(
        abstract_qkd_link(queue, key_rate_bps=50_000, qber=0.02, stop_event=stop)
    )
    quantum = asyncio.create_task(
        bb84_source(queue, target_sifted_bits=4096, stop_event=stop)
    )

    collected: list[KeyBlock] = []
    try:
        await asyncio.sleep(30.0)
    finally:
        stop.set()
        # Drain whatever is queued.
        while not queue.empty():
            collected.append(queue.get_nowait())
        bulk.cancel()
        quantum.cancel()
        await asyncio.gather(bulk, quantum, return_exceptions=True)

    assert len(collected) > 0
    sources = {k.source for k in collected}
    assert "abstract-bulk" in sources
    for kb in collected:
        assert kb.length_bytes > 0
