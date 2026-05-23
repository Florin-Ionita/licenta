"""Phase 9 entry point.

Usage::

    python -m benchmarks.runner --profile lite
    python -m benchmarks.runner --profile full
    python -m benchmarks.runner --profile extreme
    python -m benchmarks.runner --only handshake throughput      # subset

Each bench writes raw CSVs to ``docs/benchmarks/raw/`` and PDFs to
``docs/benchmarks/plots/``. The runner is robust by design: a failure in one
bench prints a stack trace but does not abort the rest -- you can iterate on
one bench at a time without re-running the whole sweep.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
import traceback
from typing import Any, Awaitable, Callable

from benchmarks import handshake, key_consumption, pool_drain, plotting, \
    qber_sweep, throughput
from benchmarks.common import PROFILES, RAW_DIR


BenchFn = Callable[[Any], Awaitable[dict]]

BENCHES: dict[str, tuple[BenchFn, Callable[[dict], Any] | None]] = {
    "handshake":       (handshake.run,        None),
    "throughput":      (throughput.run,       None),
    "pool_drain":      (pool_drain.run,       None),
    "key_consumption": (key_consumption.run,  None),
    "qber_sweep":      (qber_sweep.run,       None),
}

PLOTS: dict[str, list[Callable[[dict], Any]]] = {
    "handshake":       [plotting.latency_histogram, plotting.latency_summary_table],
    "throughput":      [plotting.throughput_bars],
    "pool_drain":      [plotting.pool_drain_plot],
    "key_consumption": [plotting.key_consumption_plot],
    "qber_sweep":      [plotting.qber_sweep_plot],
}


async def _amain(args) -> int:
    cfg = PROFILES[args.profile]
    selected = args.only or list(BENCHES.keys())
    print(f"\nProfile: {cfg.name}    benches: {', '.join(selected)}\n")

    summary: dict[str, dict] = {}
    failures: list[str] = []
    for name in selected:
        bench_fn, _ = BENCHES[name]
        print(f"=== {name} ===")
        t0 = time.perf_counter()
        try:
            result = await bench_fn(cfg)
            dt = time.perf_counter() - t0
            print(f"    completed in {dt:.1f}s")
            summary[name] = result
            for plot_fn in PLOTS.get(name, []):
                try:
                    out = plot_fn(result)
                    print(f"    plot -> {out}")
                except Exception as exc:
                    print(f"    !! plot {plot_fn.__name__} failed: {exc!r}")
        except Exception as exc:
            failures.append(name)
            print(f"    !! bench failed:")
            traceback.print_exc()
        print()

    summary_path = RAW_DIR / "summary.json"
    serialisable = json.loads(json.dumps(summary, default=lambda o: list(o)
                              if isinstance(o, (set, tuple)) else str(o)))
    with summary_path.open("w") as f:
        json.dump(serialisable, f, indent=2)
    print(f"summary -> {summary_path}")
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=list(PROFILES.keys()),
                        default="lite",
                        help="lite (fast iteration), full (thesis), extreme (paper).")
    parser.add_argument("--only", nargs="*", choices=list(BENCHES.keys()),
                        help="Run only the named benches (default: all).")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_amain(args)))


if __name__ == "__main__":
    main()
