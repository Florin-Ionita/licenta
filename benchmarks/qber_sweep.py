"""Secret-key rate as a function of channel QBER.

We measure the *theoretical* asymptotic secret-key rate of BB84 given the
Shor-Preskill bound::

    r(QBER) = 1 - 2 * h_2(QBER)

(where ``h_2`` is the binary entropy). That curve is the standard graph in
QKD textbooks (Scarani et al. 2009, eq. 30) and it is what every BB84
implementation is measured against. The rate is positive up to the
Shor-Preskill threshold (~11%) and zero above it.

We do NOT use this bench to validate our particular Cascade-lite
implementation: at QBER >= 5% the simplified Cascade leaks more bits than the
asymptotically optimal protocol would, so its empirical rate is pessimistic.
That is documented in the thesis under "implementation limitations". The
purpose of this plot is to show the *physics* the protocol respects, not the
quality of one reconciliation implementation.

For honesty, we also report the *measured* throughput of our pipeline at
QBER=2% as a single overlay point, so the figure shows both the theoretical
curve and "where we actually live" at the demo's operating point.
"""

from __future__ import annotations

import asyncio
import math
import time

import secrets

from kme.network import fan_out_feeder, make_kme_pair
from qkd.abstract_link import abstract_qkd_link
from qkd.keyblock import KeyBlock
from qkd.reconciliation import binary_entropy

from benchmarks.common import BenchConfig, write_csv


# Reference channel: 1 Mbit/s of raw sifted bits. The curve is dimensionless;
# we multiply by this to give the plot a concrete-looking y-axis.
REF_RAW_RATE_BPS = 1_048_576


def _theoretical_secret_rate_Bps(qber: float, raw_rate_bps: int) -> float:
    """Shor-Preskill asymptotic secret-key rate.

    r = max(0, 1 - 2 * h2(QBER))   (bits of secret per bit of sifted key)

    Multiplied by ``raw_rate_bps`` and converted to bytes per second.
    """
    if qber <= 0.0:
        r = 1.0
    elif qber >= 0.5:
        r = 0.0
    else:
        r = max(0.0, 1.0 - 2.0 * binary_entropy(qber))
    return r * raw_rate_bps / 8.0


async def _measure_one(qber: float, duration: float) -> dict:
    """Empirical measurement at the demo's operating point (QBER=2%).

    Runs the *actual* abstract_qkd_link producer and tallies KeyBlock bytes
    for ``duration`` seconds. Used only as a sanity overlay on the theoretical
    curve at QBER=2%; at higher QBER the simplified Cascade implementation
    over-leaks, which is a property of the implementation, not the physics.
    """
    queue: asyncio.Queue[KeyBlock] = asyncio.Queue()
    stop = asyncio.Event()
    bytes_so_far = 0

    async def fanout() -> None:
        nonlocal bytes_so_far
        while not stop.is_set():
            try:
                blk = await asyncio.wait_for(queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            bytes_so_far += blk.length_bytes

    producer = asyncio.create_task(abstract_qkd_link(
        queue, key_rate_bps=REF_RAW_RATE_BPS, qber=qber, stop_event=stop,
    ))
    consumer = asyncio.create_task(fanout())
    t0 = time.perf_counter()
    try:
        await asyncio.sleep(duration)
    finally:
        stop.set()
        for t in (producer, consumer):
            t.cancel()
            with __import__("contextlib").suppress(BaseException):
                await t
    elapsed = time.perf_counter() - t0
    return {"qber": qber, "seconds": elapsed,
            "bytes": bytes_so_far,
            "measured_key_rate_Bps": bytes_so_far / elapsed if elapsed else 0.0,
            "theoretical_key_rate_Bps":
                _theoretical_secret_rate_Bps(qber, REF_RAW_RATE_BPS)}


async def run(cfg: BenchConfig) -> dict:
    rows = []
    summary = []
    # Theoretical curve at dense sampling (cheap, no I/O).
    for i in range(0, 121):
        q = i / 1000.0  # 0.000, 0.001, ..., 0.120
        r = _theoretical_secret_rate_Bps(q, REF_RAW_RATE_BPS)
        rows.append(["theoretical", q, 0.0, 0, r])
        summary.append({"qber": q, "theoretical_key_rate_Bps": r,
                        "measured_key_rate_Bps": None})
    # Empirical measurements at multiple QBER points so the implementation has
    # a *shape* on the plot next to the theoretical curve, not a single dot.
    # cfg.qber_sweep_values comes from the bench profile. The Cascade-lite
    # path will abort at higher QBER (the over-leak documented elsewhere); we
    # honestly report rate=0 there -- it's the implementation's behaviour, not
    # a measurement gap.
    duration_each = max(2.0, cfg.qber_sweep_seconds / max(1, len(cfg.qber_sweep_values)))
    for q in cfg.qber_sweep_values:
        m = await _measure_one(q, duration_each)
        rows.append(["measured", m["qber"], m["seconds"], m["bytes"],
                     m["measured_key_rate_Bps"]])
        summary.append({"qber": m["qber"],
                        "theoretical_key_rate_Bps": m["theoretical_key_rate_Bps"],
                        "measured_key_rate_Bps": m["measured_key_rate_Bps"]})
    write_csv("qber_sweep",
              ["series", "qber", "seconds", "secret_bytes",
               "secret_key_rate_Bps"], rows)
    return {"samples": summary}
