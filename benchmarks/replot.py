"""Regenerate every PDF plot from the saved CSVs.

Useful when iterating on plot styling without rerunning the (long) bench
sweep. Reads each ``docs/benchmarks/raw/*.csv``, reconstructs the dict shape
each plot function in :mod:`benchmarks.plotting` expects, and writes the PDFs
back to ``docs/benchmarks/plots/``. Plots whose CSV is missing are skipped
with a one-line warning -- this is intentional, so you can replot a single
bench's output without all of them being present.

Entry point::

    python -m benchmarks.replot                # regenerate every available plot
    python -m benchmarks.replot --only handshake throughput
"""

from __future__ import annotations

import argparse
import csv
import statistics
import traceback
from collections import defaultdict
from pathlib import Path

from benchmarks import plotting
from benchmarks.common import RAW_DIR


def _read_csv(name: str) -> list[dict[str, str]] | None:
    path = RAW_DIR / f"{name}.csv"
    if not path.exists():
        return None
    with path.open() as f:
        return list(csv.DictReader(f))


# -- per-bench loaders -----------------------------------------------------


def _load_handshake() -> dict | None:
    rows = _read_csv("handshake_latency")
    if not rows:
        return None
    by_proto: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        by_proto[r["protocol"]].append(int(r["elapsed_ns"]))

    def _stats(samples: list[int]) -> dict:
        s = sorted(samples)
        n = len(s)
        return {
            "n": n,
            "mean_ms":   statistics.fmean(s) / 1e6,
            "stdev_ms":  (statistics.pstdev(s) / 1e6) if n > 1 else 0.0,
            "median_ms": statistics.median(s) / 1e6,
            "p95_ms":    s[min(n - 1, int(n * 0.95))] / 1e6,
            "p99_ms":    s[min(n - 1, int(n * 0.99))] / 1e6,
            "min_ms":    s[0] / 1e6,
            "max_ms":    s[-1] / 1e6,
        }
    return {
        "qtls":  _stats(by_proto.get("qtls", [])) if by_proto.get("qtls") else None,
        "tls13": _stats(by_proto.get("tls13", [])) if by_proto.get("tls13") else None,
        "qtls_samples_ns":  by_proto.get("qtls", []),
        "tls13_samples_ns": by_proto.get("tls13", []),
    }


def _load_throughput() -> dict | None:
    rows = _read_csv("throughput")
    if not rows:
        return None
    out: dict[str, list[dict]] = {"qtls": [], "tls13": []}
    for r in rows:
        out[r["protocol"]].append({
            "bytes":   int(r["requested_bytes"]),
            "seconds": float(r["seconds"]),
            "mbps":    float(r["MB_per_s"]),
        })
    return out


def _load_pool_drain() -> dict | None:
    rows = _read_csv("pool_drain")
    if not rows:
        return None
    samples = [[float(r["seconds"]),
                int(r["kme_a_fresh"]),
                int(r["kme_b_fresh"]),
                int(r["handshakes_cum"]),
                int(r["records_cum"]),
                int(r["bytes_cum"])] for r in rows]
    return {"samples": samples}


def _load_key_consumption() -> dict | None:
    rows = _read_csv("key_consumption")
    if not rows:
        return None
    return {"samples": [{
        "payload":  int(r["payload_bytes"]),
        "key_bytes": int(r["key_bytes_consumed"]),
        "ratio":    float(r["key_per_plaintext_ratio"]),
    } for r in rows]}


def _load_qber_sweep() -> dict | None:
    rows = _read_csv("qber_sweep")
    if not rows:
        return None
    # The CSV records three series: theoretical (Shor-Preskill), cascade
    # (Shannon + 15% leak), and measured. The plot expects each sample row
    # to potentially carry both "theoretical" and "cascade" keys, so we
    # merge rows that share the same QBER.
    merged: dict[float, dict] = {}
    for r in rows:
        q = float(r["qber"])
        rate = float(r["secret_key_rate_Bps"])
        slot = merged.setdefault(q, {"qber": q,
                                      "theoretical_key_rate_Bps": None,
                                      "cascade_key_rate_Bps": None,
                                      "measured_key_rate_Bps": None})
        series = r.get("series", "theoretical")
        if series == "theoretical":
            slot["theoretical_key_rate_Bps"] = rate
        elif series == "cascade":
            slot["cascade_key_rate_Bps"] = rate
        else:
            slot["measured_key_rate_Bps"] = rate
    return {"samples": list(merged.values())}


LOADERS = {
    "handshake":       (_load_handshake,
                        [plotting.latency_histogram, plotting.latency_summary_table]),
    "throughput":      (_load_throughput,       [plotting.throughput_bars]),
    "pool_drain":      (_load_pool_drain,       [plotting.pool_drain_plot]),
    "key_consumption": (_load_key_consumption,  [plotting.key_consumption_plot]),
    "qber_sweep":      (_load_qber_sweep,       [plotting.qber_sweep_plot]),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="*", choices=list(LOADERS.keys()),
                        help="Plot only the named benches (default: every CSV present).")
    args = parser.parse_args()

    targets = args.only or list(LOADERS.keys())
    rendered: list[Path] = []
    skipped: list[str] = []
    failed: list[str] = []

    for name in targets:
        loader, plot_fns = LOADERS[name]
        try:
            data = loader()
        except Exception:
            failed.append(name)
            print(f"!! {name}: loader crashed")
            traceback.print_exc()
            continue
        if data is None:
            skipped.append(name)
            print(f"-- {name}: no CSV in {RAW_DIR}, skipping")
            continue
        for fn in plot_fns:
            try:
                out = fn(data)
                rendered.append(out)
                print(f"   {name}: {fn.__name__} -> {out}")
            except Exception:
                failed.append(f"{name}.{fn.__name__}")
                traceback.print_exc()

    print(f"\n{len(rendered)} rendered, {len(skipped)} skipped, {len(failed)} failed.")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
