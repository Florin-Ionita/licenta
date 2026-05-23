"""Pool depth under sustained chat-style load.

Spins up the standard QTLS stack with a live producer running at the demo's
key rate, then drives one chat session for ``cfg.pool_drain_seconds``,
sampling the KME pool depth every 250 ms. The plot tells the QKD story
directly: how fast does sustained load drain the pool, and does the producer
keep up?
"""

from __future__ import annotations

import asyncio
import time

import contextlib
import secrets

from benchmarks.common import BenchConfig, _BenchStack, write_csv
from benchmarks.throughput import _one_qtls_session
from qkd.keyblock import KeyBlock


async def _chatter(stack: _BenchStack, payload_size: int, stop: asyncio.Event,
                   counters: dict) -> None:
    """Open one QTLS session after another, sending fixed-size chat messages.

    Each session ends when its per-direction OTP budget is spent (the
    record-layer raises ``OTPKeyExhaustedError`` and ``_one_qtls_session``
    returns). The next iteration opens a fresh session, which is the realistic
    chat-app pattern -- a long conversation comprises many short sessions.
    """
    msg = b"x" * payload_size
    while not stop.is_set():
        # We don't know up-front how many bytes one session can carry; ask for
        # a large quota and the session will return as much as it actually
        # shipped before OTP exhaustion.
        try:
            shipped = await _one_qtls_session(stack, msg, 1 << 20)
        except Exception:
            # Producer hasn't refilled yet, or something transient -- wait and
            # retry rather than aborting the bench.
            await asyncio.sleep(0.1)
            continue
        counters["handshakes"] += 1
        if shipped > 0:
            # The session shipped ``shipped`` bytes in CHUNK-sized records;
            # we report records as ceil(shipped/payload) which matches the
            # bench's framing intent even though _one_qtls_session uses its
            # own CHUNK internally.
            counters["records"] += max(1, shipped // payload_size)
            counters["bytes"] += shipped


async def _fast_producer(stack: _BenchStack, blocks_per_sec: float,
                          stop: asyncio.Event) -> None:
    """A bench-only key producer that bypasses Cascade for speed.

    ``qkd.abstract_link.abstract_qkd_link`` emits one (potentially huge) block
    per simulated second and runs Cascade reconciliation, which is too slow to
    expose a meaningful drain-vs-refill dynamic on the second-scale of the
    plot. For this bench we synthesise byte-identical pairs directly (same
    correctness rationale as ``_BenchStack``'s prefill) at a controllable rate.
    """
    period = 1.0 / max(blocks_per_sec, 0.1)
    key_bytes = stack.key_size_bits // 8
    while not stop.is_set():
        await asyncio.sleep(period)
        material = secrets.token_bytes(key_bytes)
        blk = KeyBlock(material=material, source="abstract-bulk", qber=stack.qber)
        stack.kme_a.add_block(blk)
        stack.kme_b.add_block(blk)


async def run(cfg: BenchConfig) -> dict:
    # Tight prefill so the consumer-vs-producer race is visible from t=0.
    # The replacement producer (below) emits N blocks/s without Cascade
    # overhead, giving the metrics panel an honest, observable feedback loop.
    async with _BenchStack(prefill_blocks=16) as stack:
        feeder_stop = asyncio.Event()
        feeder = asyncio.create_task(_fast_producer(stack, 4.0, feeder_stop))
        counters = {"handshakes": 0, "records": 0, "bytes": 0}
        stop = asyncio.Event()
        chatter = asyncio.create_task(_chatter(stack, 256, stop, counters))

        rows = []
        start = time.perf_counter()
        next_sample = start
        while time.perf_counter() - start < cfg.pool_drain_seconds:
            await asyncio.sleep(max(0.0, next_sample - time.perf_counter()))
            t = time.perf_counter() - start
            rows.append([t, stack.kme_a.fresh_key_count(),
                         stack.kme_b.fresh_key_count(),
                         counters["handshakes"], counters["records"],
                         counters["bytes"]])
            next_sample += 0.25
        stop.set()
        feeder_stop.set()
        chatter.cancel()
        feeder.cancel()
        with contextlib.suppress(BaseException):
            await chatter
        with contextlib.suppress(BaseException):
            await feeder

    write_csv("pool_drain",
              ["seconds", "kme_a_fresh", "kme_b_fresh",
               "handshakes_cum", "records_cum", "bytes_cum"], rows)
    return {"seconds": rows[-1][0] if rows else 0.0,
            "handshakes": counters["handshakes"],
            "records": counters["records"],
            "bytes": counters["bytes"],
            "samples": rows}
