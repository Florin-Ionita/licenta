"""Panel A: QKD network topology.

For the single-link demo we draw Alice -- (QKD fibre) -- Bob with node colour
encoding pool depth and edge width encoding instantaneous key rate. The shape
generalises naturally to the multi-node Phase 8 graph if/when added.
"""

from __future__ import annotations

import plotly.graph_objects as go

from viz.bus import EventBus

_MAX_POOL_FOR_COLOUR = 50  # keys; above this the node is "full" green


def _pool_colour(fresh: int) -> str:
    """Map fresh-key count to a colour: red (empty) -> amber -> green (full)."""
    ratio = min(1.0, fresh / _MAX_POOL_FOR_COLOUR)
    if ratio < 0.2:
        return "#d62728"   # depleted
    if ratio < 0.6:
        return "#ff7f0e"   # moderate
    return "#2ca02c"       # healthy


def build(bus: EventBus) -> go.Figure:
    counters = bus.counters()
    a_pool = int(counters.get("pool_a_fresh", 0))
    b_pool = int(counters.get("pool_b_fresh", 0))

    # Estimate keys/sec from the last few key_block events.
    blocks = bus.snapshot("key_block", limit=10)
    if len(blocks) >= 2:
        span = max(0.5, blocks[-1].ts - blocks[0].ts)
        rate = (len(blocks) - 1) / span
    else:
        rate = 0.0

    eve = bus.get_eve()
    edge_colour = "#d62728" if eve else "#1f77b4"
    edge_width = max(2.0, min(14.0, 2.0 + rate * 2.0))

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=[0.15, 0.85], y=[0.5, 0.5],
        mode="lines",
        line=dict(color=edge_colour, width=edge_width),
        hoverinfo="text",
        text=[f"QKD link ({rate:.1f} blocks/s)", ""],
        showlegend=False,
    ))
    fig.add_trace(go.Scatter(
        x=[0.15, 0.85], y=[0.5, 0.5],
        mode="markers+text",
        marker=dict(
            size=70,
            color=[_pool_colour(a_pool), _pool_colour(b_pool)],
            line=dict(width=2, color="#222"),
        ),
        text=[f"Alice<br>KME-A<br>{a_pool} keys",
              f"Bob<br>KME-B<br>{b_pool} keys"],
        textposition="middle center",
        textfont=dict(color="white", size=11),
        hoverinfo="text",
        showlegend=False,
    ))
    if eve:
        fig.add_annotation(
            x=0.5, y=0.72, text="⚠ Eve intercepting",
            showarrow=False, font=dict(color="#d62728", size=14),
        )
    fig.update_layout(
        xaxis=dict(visible=False, range=[0, 1]),
        yaxis=dict(visible=False, range=[0, 1]),
        margin=dict(l=10, r=10, t=10, b=10),
        height=240,
        plot_bgcolor="#0e1117",
        paper_bgcolor="#0e1117",
    )
    return fig
