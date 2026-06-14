"""Plotly -> PDF rendering for the Phase 9 evaluation chapter.

One function per artefact. Every plot uses the same dark template the
dashboard does, so the thesis chapter has a uniform visual language. We
require ``kaleido`` for PDF export -- if missing, we fall back to PNG so the
suite still completes.
"""

from __future__ import annotations

from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from benchmarks.common import PLOT_DIR

_TEMPLATE = "plotly_white"


def _save(fig: go.Figure, name: str) -> Path:
    pdf = PLOT_DIR / f"{name}.pdf"
    try:
        fig.write_image(pdf, format="pdf", width=900, height=520)
    except Exception:
        pdf = PLOT_DIR / f"{name}.png"
        fig.write_image(pdf, format="png", width=900, height=520)
    return pdf


def latency_histogram(stats: dict) -> Path:
    """Stacked subplots with independent *linear* x-axes per protocol.

    QTLS (~15 ms) and TLS 1.3 (~1.5 ms) live on different scales; cramming
    both into one linear axis crushes TLS into a single bar, while a shared
    log axis distorts the QTLS distribution shape. Separate panels at full
    linear resolution show each distribution honestly. Per-axis ranges are
    clipped to the 99.5th percentile so a single outlier doesn't stretch the
    plot and bury the modal shape.
    """
    q_ms = sorted(x / 1e6 for x in stats["qtls_samples_ns"])
    t_ms = sorted(x / 1e6 for x in stats["tls13_samples_ns"])
    q_max = q_ms[min(len(q_ms) - 1, int(len(q_ms) * 0.995))]
    t_max = t_ms[min(len(t_ms) - 1, int(len(t_ms) * 0.995))]
    fig = make_subplots(rows=2, cols=1, shared_xaxes=False,
                        subplot_titles=("QTLS (over QKD)",
                                        "TLS 1.3 (X25519 + AES-GCM)"),
                        vertical_spacing=0.2)
    fig.add_trace(go.Histogram(x=q_ms, name="QTLS",
                               marker_color="#1f77b4", nbinsx=60),
                  row=1, col=1)
    fig.add_trace(go.Histogram(x=t_ms, name="TLS 1.3",
                               marker_color="#ff7f0e", nbinsx=60),
                  row=2, col=1)
    fig.update_xaxes(title_text="ms per handshake",
                     range=[0, q_max * 1.05], row=1, col=1)
    fig.update_xaxes(title_text="ms per handshake",
                     range=[0, t_max * 1.05], row=2, col=1)
    fig.update_yaxes(title_text="count", row=1, col=1)
    fig.update_yaxes(title_text="count", row=2, col=1)
    fig.update_layout(template=_TEMPLATE, showlegend=False,
                      title="Handshake latency distribution "
                            "(independent x-axes; 99.5th percentile clipped)",
                      height=720)
    return _save(fig, "01_handshake_latency_histogram")


def latency_summary_table(stats: dict) -> Path:
    rows = [["protocol", "n", "mean (ms)", "stdev", "median",
             "p95", "p99", "min", "max"]]
    for proto in ("qtls", "tls13"):
        s = stats[proto]
        rows.append([proto, s["n"], f"{s['mean_ms']:.3f}", f"{s['stdev_ms']:.3f}",
                     f"{s['median_ms']:.3f}", f"{s['p95_ms']:.3f}",
                     f"{s['p99_ms']:.3f}", f"{s['min_ms']:.3f}",
                     f"{s['max_ms']:.3f}"])
    fig = go.Figure(data=[go.Table(
        header=dict(values=rows[0], fill_color="#1f77b4",
                    font=dict(color="white"), align="left"),
        cells=dict(values=list(zip(*rows[1:])),
                   fill_color=["#f2f6fa", "white"], font=dict(color="#111"),
                   align="left"),
    )])
    fig.update_layout(template=_TEMPLATE, title="Handshake latency summary")
    return _save(fig, "02_handshake_latency_table")


def throughput_bars(summary: dict) -> Path:
    """Two-panel split: each protocol on its own linear y-axis.

    QTLS (~0.2 MB/s, OTP-bound by KME bandwidth) and TLS 1.3 (~120-180 MB/s,
    AES-GCM-bound) live three decades apart. Plotting them on a shared linear
    axis hides QTLS entirely; a shared log axis distorts both. Stacked
    panels with independent y-axes show each at full resolution while still
    being read side-by-side. Each bar is annotated with its numeric value so
    the absolute gap is unmistakable.
    """
    def _xs(rows):
        return [f"{r['bytes'] // (1<<20)} MB" if r['bytes'] >= 1<<20
                else f"{r['bytes'] // 1024} KiB"
                for r in rows]

    fig = make_subplots(rows=2, cols=1, shared_xaxes=True,
                        subplot_titles=("QTLS (over QKD)",
                                        "TLS 1.3 (X25519 + AES-GCM)"),
                        vertical_spacing=0.18)
    q_ys = [s["mbps"] for s in summary["qtls"]]
    t_ys = [s["mbps"] for s in summary["tls13"]]
    fig.add_trace(go.Bar(x=_xs(summary["qtls"]), y=q_ys,
                         marker_color="#1f77b4",
                         text=[f"{y:.2f}" for y in q_ys],
                         textposition="outside",
                         hovertemplate="QTLS<br>%{x}: %{y:.3f} MB/s<extra></extra>",
                         showlegend=False),
                  row=1, col=1)
    fig.add_trace(go.Bar(x=_xs(summary["tls13"]), y=t_ys,
                         marker_color="#ff7f0e",
                         text=[f"{y:.1f}" for y in t_ys],
                         textposition="outside",
                         hovertemplate="TLS 1.3<br>%{x}: %{y:.1f} MB/s<extra></extra>",
                         showlegend=False),
                  row=2, col=1)
    fig.update_yaxes(title_text="MB / s", range=[0, max(q_ys) * 1.25 if q_ys else 1],
                     row=1, col=1)
    fig.update_yaxes(title_text="MB / s", range=[0, max(t_ys) * 1.15 if t_ys else 1],
                     row=2, col=1)
    fig.update_xaxes(title_text="payload size", row=2, col=1)
    fig.update_layout(template=_TEMPLATE,
                      title="Bulk throughput (independent y-axes)",
                      height=620)
    return _save(fig, "03_throughput_bars")


def keyexchange_latency_bars(summary: dict) -> Path:
    """Key-establishment primitive latency: QKD fetch vs X25519 vs ML-KEM-768.

    A single linear-y bar chart of median latency with p95 error bars. The
    three primitives live within one decade (~180-720 us), so one axis is
    honest here -- unlike the handshake/throughput plots that needed split
    panels.

    IMPORTANT (and stated in the title so a reader can't miss it): these are
    *primitive* costs, comparable to each other but NOT to the full-handshake
    numbers in the handshake plot. ML-KEM is the standalone KEM, not a TLS
    handshake (the test host's OpenSSL 3.0 cannot negotiate ML-KEM in TLS).
    """
    order = ["qkd_fetch", "x25519", "mlkem768"]
    labels = {"qkd_fetch": "QKD fetch<br>(KME key_ID)",
              "x25519": "X25519<br>(ECDHE)",
              "mlkem768": "ML-KEM-768<br>(KEM)"}
    colors = {"qkd_fetch": "#ff7f0e", "x25519": "#888888", "mlkem768": "#2ca02c"}

    xs, meds, errs, present = [], [], [], []
    for k in order:
        s = summary.get(k)
        if not s:
            continue
        present.append(k)
        xs.append(labels[k])
        meds.append(s["median_us"])
        errs.append(max(0.0, s["p95_us"] - s["median_us"]))

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=xs, y=meds,
        marker_color=[colors[k] for k in present],
        error_y=dict(type="data", array=errs, visible=True, color="#bbb"),
        text=[f"{m:.0f} us" for m in meds], textposition="outside",
        hovertemplate="%{x}<br>median %{y:.1f} us<extra></extra>",
        showlegend=False,
    ))
    fig.update_layout(
        template=_TEMPLATE,
        title="Key-establishment primitive latency "
              "(median, p95 error bars; primitive cost, not a TLS handshake)",
        yaxis_title="microseconds (lower is faster)",
        xaxis_title="key-establishment approach",
        height=520,
    )
    return _save(fig, "07_keyexchange_latency")


def keyexchange_wire_bars(summary: dict) -> Path:
    """Bytes on the wire to establish one key: QKD vs X25519 vs ML-KEM-768.

    Log y-axis: the values span 16 B to 2272 B, two orders of magnitude, so a
    linear axis would crush QKD and X25519 to invisible slivers next to
    ML-KEM. This is the plot where QKD's advantage is structural and exact --
    only a 16-byte key_ID crosses the wire; the key material never does.
    """
    wire = summary.get("wire_bytes", {})
    order = ["qkd_fetch", "x25519", "mlkem768"]
    labels = {"qkd_fetch": "QKD<br>(key_ID)",
              "x25519": "X25519",
              "mlkem768": "ML-KEM-768"}
    colors = {"qkd_fetch": "#ff7f0e", "x25519": "#888888", "mlkem768": "#2ca02c"}

    xs, totals, present = [], [], []
    for k in order:
        v = wire.get(k)
        if not v:
            continue
        # v may be a (offer, response, note) tuple or list after JSON round-trip.
        offer, response = int(v[0]), int(v[1])
        present.append(k)
        xs.append(labels[k])
        totals.append(offer + response)

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=xs, y=totals,
        marker_color=[colors[k] for k in present],
        text=[f"{t} B" for t in totals], textposition="outside",
        hovertemplate="%{x}<br>%{y} bytes total<extra></extra>",
        showlegend=False,
    ))
    fig.update_layout(
        template=_TEMPLATE,
        title="Bytes on the wire to establish one shared key (log scale)",
        yaxis_title="total bytes exchanged (log)",
        yaxis_type="log",
        xaxis_title="key-establishment approach",
        height=520,
    )
    return _save(fig, "08_keyexchange_wire")


# Pool-drain runs for the full profile duration (up to 600 s), which packs
# hundreds of identical drain/refill cycles into the figure -- a dense "forest"
# of vertical spikes that dominates the page without adding information. We
# render only the opening window: a handful of cycles is enough to show the
# steady-state behaviour, and an annotation states that the pattern repeats
# unchanged for the rest of the run.
_POOL_DRAIN_WINDOW_S = 60.0


def pool_drain_plot(result: dict) -> Path:
    all_samples = result["samples"]
    total_s = all_samples[-1][0] if all_samples else 0.0
    # Zoom to the opening window so individual cycles are legible. If the run is
    # already short (e.g. the lite profile), just show all of it.
    samples = [r for r in all_samples if r[0] <= _POOL_DRAIN_WINDOW_S] \
        if total_s > _POOL_DRAIN_WINDOW_S else all_samples
    windowed = total_s > _POOL_DRAIN_WINDOW_S
    ts = [r[0] for r in samples]
    # KME-A and KME-B are fed by a symmetric fan-out, so their fresh-key pool
    # depths are identical at every sample. Drawing them naively makes the
    # second trace sit exactly on top of the first, hiding it. We draw KME-B as
    # a thick solid baseline and KME-A as a thinner dashed line on top, so both
    # are visible *and* the reader can see they coincide by design.
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(go.Scatter(x=ts, y=[r[2] for r in samples],
                             mode="lines", name="KME-B fresh",
                             line=dict(color="#1f77b4", width=3)),
                  secondary_y=False)
    fig.add_trace(go.Scatter(x=ts, y=[r[1] for r in samples],
                             mode="lines", name="KME-A fresh (overlaps B)",
                             line=dict(color="#2ca02c", width=1.5, dash="dash")),
                  secondary_y=False)
    fig.add_trace(go.Scatter(x=ts, y=[r[5] / 1024 for r in samples],
                             mode="lines", name="cumulative KiB sent",
                             line=dict(dash="dot", color="#ff7f0e")),
                  secondary_y=True)
    title = ("Pool depth under sustained QTLS chat load "
             "(KME-A and KME-B coincide by symmetric fan-out)")
    if windowed:
        title += f"<br><sub>first {_POOL_DRAIN_WINDOW_S:.0f} s shown; " \
                 f"the drain/refill cycle repeats unchanged through " \
                 f"{total_s:.0f} s</sub>"
    fig.update_layout(template=_TEMPLATE, title=title,
                      xaxis_title="seconds",
                      legend=dict(orientation="h"))
    fig.update_yaxes(title_text="fresh keys in pool", secondary_y=False)
    fig.update_yaxes(title_text="cumulative payload KiB",   secondary_y=True)
    return _save(fig, "04_pool_drain")


def key_consumption_plot(result: dict) -> Path:
    s = result["samples"]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=[r["payload"] for r in s],
                             y=[r["ratio"] for r in s],
                             mode="lines+markers",
                             name="key bytes / plaintext byte"))
    fig.add_hline(y=1.0, line_dash="dash", line_color="#888",
                  annotation_text="OTP lower bound (1.0)")
    fig.update_layout(template=_TEMPLATE,
                      title="Per-record key consumption ratio",
                      xaxis_title="record payload (bytes, log)",
                      xaxis_type="log",
                      yaxis_title="key bytes consumed / plaintext byte")
    return _save(fig, "05_key_consumption_ratio")


def qber_sweep_plot(result: dict) -> Path:
    """Secret-key rate vs QBER: three curves so the comparison is honest.

      * Blue (solid)  -- Shor-Preskill physics ceiling: any *optimal* protocol's
                         maximum. Assumes Shannon-optimal reconciliation.
      * Green (dashed) -- realistic Cascade: ceiling minus the well-documented
                         ~15% Cascade leakage overhead. This is what a textbook
                         Cascade implementation should plausibly achieve.
      * Orange (diamonds) -- this implementation's measured throughput.

    The thesis-relevant gap is "orange vs green" -- both run Cascade and
    should be close. "Blue vs green" is the structural Cascade penalty,
    closed only by LDPC reconciliation (Future Work).
    """
    s = result["samples"]
    theoretical = [r for r in s if r.get("theoretical_key_rate_Bps") is not None
                   and r.get("measured_key_rate_Bps") is None]
    measured = [r for r in s if r.get("measured_key_rate_Bps") is not None]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=[r["qber"] * 100 for r in theoretical],
        y=[r["theoretical_key_rate_Bps"] / 1024 for r in theoretical],
        mode="lines", name="Shor-Preskill bound (physics ceiling)",
        line=dict(color="#1f77b4", width=2),
    ))
    cascade = [r for r in theoretical if r.get("cascade_key_rate_Bps") is not None]
    if cascade:
        fig.add_trace(go.Scatter(
            x=[r["qber"] * 100 for r in cascade],
            y=[r["cascade_key_rate_Bps"] / 1024 for r in cascade],
            mode="lines", name="realistic Cascade (Shannon + 15% leak)",
            line=dict(color="#2ca02c", width=2, dash="dash"),
        ))
    if measured:
        measured = sorted(measured, key=lambda r: r["qber"])
        fig.add_trace(go.Scatter(
            x=[r["qber"] * 100 for r in measured],
            y=[r["measured_key_rate_Bps"] / 1024 for r in measured],
            mode="lines+markers", name="this implementation (measured)",
            line=dict(color="#ff7f0e", width=2, dash="dot"),
            marker=dict(color="#ff7f0e", size=12, symbol="diamond"),
        ))
    fig.add_vline(x=11, line_dash="dash", line_color="#d62728",
                  annotation_text="Shor-Preskill abort (11%)")
    fig.update_layout(template=_TEMPLATE,
                      title="Secret-key rate vs QBER (asymptotic, "
                            f"raw rate {(1 << 20) / 1e6:.1f} Mbps)",
                      xaxis_title="QBER (%)",
                      yaxis_title="secret-key rate (KiB / s)",
                      legend=dict(orientation="h"))
    return _save(fig, "06_qber_vs_rate")
