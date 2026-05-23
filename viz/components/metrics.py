"""Panel D: live metrics -- key rate, QBER, pool depth, throughput, latency.

Two stacked plots:
  * pool depth over time (Alice + Bob), with the key-rate trace overlaid
  * a small "stat strip" with the headline numbers

Time series come from the ``pool`` and ``key_block`` event buffers; the strip
reads aggregate counters that the runtime maintains cheaply.
"""

from __future__ import annotations

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from viz.bus import EventBus


def build_timeseries(bus: EventBus) -> go.Figure:
    pool_events = bus.snapshot("pool", limit=400)
    key_events = bus.snapshot("key_block", limit=400)

    ts0 = pool_events[0].ts if pool_events else (key_events[0].ts if key_events else 0.0)

    pool_times = [ev.ts - ts0 for ev in pool_events]
    pool_a = [ev.data["kme_a"] for ev in pool_events]
    pool_b = [ev.data["kme_b"] for ev in pool_events]

    # Instantaneous key-block bytes/sec via rolling 5s window.
    rate_times: list[float] = []
    rate_values: list[float] = []
    window_s = 5.0
    for i, ev in enumerate(key_events):
        cutoff = ev.ts - window_s
        bytes_in_window = sum(e.data["length"] for e in key_events[:i + 1]
                              if e.ts >= cutoff)
        rate_values.append(bytes_in_window / window_s)
        rate_times.append(ev.ts - ts0)

    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(go.Scatter(x=pool_times, y=pool_a, mode="lines",
                             name="KME-A fresh keys", line=dict(color="#1f77b4")),
                  secondary_y=False)
    fig.add_trace(go.Scatter(x=pool_times, y=pool_b, mode="lines",
                             name="KME-B fresh keys", line=dict(color="#9467bd")),
                  secondary_y=False)
    fig.add_trace(go.Scatter(x=rate_times, y=rate_values, mode="lines",
                             name="key throughput (B/s, 5s avg)",
                             line=dict(color="#2ca02c", dash="dot")),
                  secondary_y=True)
    fig.update_xaxes(title_text="seconds since start", color="#bbb")
    fig.update_yaxes(title_text="fresh keys in pool", secondary_y=False, color="#bbb")
    fig.update_yaxes(title_text="bytes / sec", secondary_y=True, color="#bbb")
    fig.update_layout(
        height=300, margin=dict(l=10, r=10, t=10, b=40),
        plot_bgcolor="#0e1117", paper_bgcolor="#0e1117",
        legend=dict(orientation="h", y=1.0, x=0.0, font=dict(color="#bbb")),
    )
    return fig


def stat_strip(bus: EventBus) -> list[tuple[str, str]]:
    """Return a list of (label, value) pairs to render with st.metric."""
    c = bus.counters()
    return [
        ("Last handshake", f"{c.get('last_handshake_ms', 0):.1f} ms"),
        ("Handshakes ✓",   f"{int(c.get('handshakes_completed', 0))}"),
        ("Records sent",   f"{int(c.get('records_sent', 0))}"),
        ("Key bytes produced", f"{int(c.get('key_bytes_produced', 0)):,}"),
        ("Key bytes consumed", f"{int(c.get('key_bytes_consumed', 0)):,}"),
        ("Observed QBER",  f"{c.get('qber_last', 0) * 100:.2f} %"),
    ]
