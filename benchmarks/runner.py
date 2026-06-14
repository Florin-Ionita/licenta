"""Phase 9 entry point.

Usage::

    python -m benchmarks.runner --profile lite
    python -m benchmarks.runner --profile full
    python -m benchmarks.runner --profile full-fast --jobs 6   # parallel
    python -m benchmarks.runner --profile extreme
    python -m benchmarks.runner --only handshake throughput      # subset

Each bench writes raw CSVs to ``docs/benchmarks/raw/`` and PDFs to
``docs/benchmarks/plots/``. The runner is robust by design: a failure in one
bench prints a stack trace but does not abort the rest -- you can iterate on
one bench at a time without re-running the whole sweep.

Parallelism (``--jobs N``)
--------------------------
The independent benches are spread across N worker *processes* (one bench per
core), because each bench is single-threaded asyncio and otherwise pins just
one core. This is safe for the latency benches (handshake / keyexchange):
each one still has its own process and event loop, so it is NOT competing for
CPU with another bench, and the measured percentiles stay clean. Each CSV is
written by exactly one bench, so the files never collide; ``summary.json`` is
aggregated *in the parent* after all workers return, so it is never the
victim of a last-writer-wins race. Plots are rendered in the parent too,
once the results are back -- matplotlib/plotly export is not process-safe to
fan out.

Note on wall-clock-bound benches: ``qber_sweep`` and ``pool_drain`` pace
themselves against a 1 block/sec simulated channel, so they are limited by
the clock, not the CPU. Parallelism makes them overlap with the CPU-bound
benches (so they stop dominating total wall-clock); it does NOT make them
individually faster, and giving them more iterations would not improve them.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Any, Awaitable, Callable

from benchmarks import handshake, key_consumption, keyexchange, pool_drain, \
    plotting, qber_sweep, throughput
from benchmarks.common import PROFILES, RAW_DIR


BenchFn = Callable[[Any], Awaitable[dict]]

BENCHES: dict[str, tuple[BenchFn, Callable[[dict], Any] | None]] = {
    "handshake":       (handshake.run,        None),
    "keyexchange":     (keyexchange.run,      None),
    "throughput":      (throughput.run,       None),
    "pool_drain":      (pool_drain.run,       None),
    "key_consumption": (key_consumption.run,  None),
    "qber_sweep":      (qber_sweep.run,       None),
}

PLOTS: dict[str, list[Callable[[dict], Any]]] = {
    "handshake":       [plotting.latency_histogram, plotting.latency_summary_table],
    "keyexchange":     [plotting.keyexchange_latency_bars,
                        plotting.keyexchange_wire_bars],
    "throughput":      [plotting.throughput_bars],
    "pool_drain":      [plotting.pool_drain_plot],
    "key_consumption": [plotting.key_consumption_plot],
    "qber_sweep":      [plotting.qber_sweep_plot],
}


# -- worker (runs in a separate process) -----------------------------------

# The PATH that lets the on-Windows gcc driver find cc1.exe so qkd._cascade
# can (re)compile on import inside a fresh worker process. Mirrors the PATH
# the parent process needs; harmless on POSIX (the dir simply won't exist).
_GCC_BIN = r"C:\msys64\ucrt64\bin"


def _run_one_bench(name: str, cfg) -> dict:
    """Run a single bench to completion in this (worker) process.

    Top-level and picklable so it can be dispatched to a ProcessPoolExecutor.
    Returns the bench's result dict. Plotting is intentionally NOT done here --
    the parent renders plots once results are collected.
    """
    if os.name == "nt" and os.path.isdir(_GCC_BIN):
        os.environ["PATH"] = _GCC_BIN + os.pathsep + os.environ.get("PATH", "")
    # Imported lazily so the cascade compile (if needed) happens with PATH set.
    from benchmarks.runner import BENCHES as _B
    bench_fn, _ = _B[name]
    return asyncio.run(bench_fn(cfg))


def _emit_plots(name: str, result: dict) -> None:
    for plot_fn in PLOTS.get(name, []):
        try:
            out = plot_fn(result)
            print(f"    [{name}] plot -> {out}")
        except Exception as exc:
            print(f"    [{name}] !! plot {plot_fn.__name__} failed: {exc!r}")


# -- sequential path (original behaviour) ----------------------------------


async def _run_sequential(cfg, selected) -> tuple[dict, list[str]]:
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
            _emit_plots(name, result)
        except Exception:
            failures.append(name)
            print(f"    !! bench failed:")
            traceback.print_exc()
        print()
    return summary, failures


# -- parallel path ---------------------------------------------------------


def _run_parallel(cfg, selected, jobs: int) -> tuple[dict, list[str]]:
    summary: dict[str, dict] = {}
    failures: list[str] = []
    starts: dict[str, float] = {}
    print(f"Dispatching {len(selected)} benches across {jobs} worker(s)...\n")
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = {}
        for name in selected:
            starts[name] = time.perf_counter()
            futures[pool.submit(_run_one_bench, name, cfg)] = name
        for fut in as_completed(futures):
            name = futures[fut]
            dt = time.perf_counter() - starts[name]
            try:
                result = fut.result()
                print(f"=== {name} completed in {dt:.1f}s ===")
                summary[name] = result
                _emit_plots(name, result)
            except Exception:
                failures.append(name)
                print(f"=== {name} FAILED after {dt:.1f}s ===")
                traceback.print_exc()
            print()
    return summary, failures


# -- entry point -----------------------------------------------------------


def _write_summary(summary: dict) -> None:
    summary_path = RAW_DIR / "summary.json"
    serialisable = json.loads(json.dumps(summary, default=lambda o: list(o)
                              if isinstance(o, (set, tuple)) else str(o)))
    with summary_path.open("w") as f:
        json.dump(serialisable, f, indent=2)
    print(f"summary -> {summary_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=list(PROFILES.keys()),
                        default="lite",
                        help="lite (fast), full (thesis), full-fast "
                             "(more iters, run with --jobs), extreme (paper).")
    parser.add_argument("--only", nargs="*", choices=list(BENCHES.keys()),
                        help="Run only the named benches (default: all).")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Run benches in parallel across N worker "
                             "processes (default 1 = sequential). Use the "
                             "core count for the fastest wall-clock.")
    args = parser.parse_args()

    cfg = PROFILES[args.profile]
    selected = args.only or list(BENCHES.keys())
    jobs = max(1, min(args.jobs, len(selected)))
    mode = "sequential" if jobs == 1 else f"parallel x{jobs}"
    print(f"\nProfile: {cfg.name}    mode: {mode}    "
          f"benches: {', '.join(selected)}\n")

    if jobs == 1:
        summary, failures = asyncio.run(_run_sequential(cfg, selected))
    else:
        summary, failures = _run_parallel(cfg, selected, jobs)

    _write_summary(summary)
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        raise SystemExit(1)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
