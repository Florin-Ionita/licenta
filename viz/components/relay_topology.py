"""Phase 8 panel: multi-node topology with the active route highlighted.

Renders the relay network as a Plotly graph. Each edge's colour encodes the
*lower* fresh-key count of its two endpoints (saturated edges = bottleneck);
the most recent delivered route is overlaid in green; node labels show the
node id and the sum of fresh keys it holds across all its links.
"""

from __future__ import annotations

import math

import networkx as nx
import plotly.graph_objects as go

from viz.bus import EventBus


def _pool_colour(fresh: int) -> str:
    if fresh < 5:
        return "#d62728"
    if fresh < 20:
        return "#ff7f0e"
    return "#2ca02c"


def _circular_layout(nodes: list[str]) -> dict[str, tuple[float, float]]:
    """Lay nodes out on a circle (stable, deterministic, label-friendly)."""
    n = len(nodes)
    pos: dict[str, tuple[float, float]] = {}
    for i, name in enumerate(sorted(nodes)):
        angle = 2 * math.pi * i / max(n, 1)
        pos[name] = (0.5 + 0.35 * math.cos(angle),
                     0.5 + 0.35 * math.sin(angle))
    return pos


def build(
    bus: EventBus,
    graph: nx.Graph,
    edge_depths: dict[tuple[str, str], tuple[int, int]],
) -> go.Figure:
    pos = _circular_layout(list(graph.nodes))
    fig = go.Figure()

    # Most recent delivery, if any, to highlight the active path.
    deliveries = bus.snapshot("relay_delivery", limit=1)
    active_edges: set[tuple[str, str]] = set()
    if deliveries:
        path = deliveries[-1].data["path"]
        for u, v in zip(path[:-1], path[1:]):
            active_edges.add(tuple(sorted((u, v))))

    # Edges.
    for u, v in graph.edges:
        a, b = sorted((u, v))
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        depth_pair = edge_depths.get((a, b), (0, 0))
        bottleneck = min(depth_pair)
        is_active = (a, b) in active_edges
        colour = "#2ca02c" if is_active else _pool_colour(bottleneck)
        width = 6 if is_active else 3
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1], mode="lines",
            line=dict(color=colour, width=width),
            hoverinfo="text",
            text=[f"{u}-{v}: {depth_pair[0]}/{depth_pair[1]} keys", ""],
            showlegend=False,
        ))

    # Nodes.
    xs, ys, labels = [], [], []
    for name in graph.nodes:
        x, y = pos[name]
        xs.append(x); ys.append(y)
        # Sum the fresh keys this node holds across all its links.
        held = 0
        for nb in graph.neighbors(name):
            a, b = sorted((name, nb))
            depths = edge_depths.get((a, b), (0, 0))
            held += depths[0] if name == a else depths[1]
        labels.append(f"<b>{name}</b><br>{held} keys")
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text",
        marker=dict(size=58, color="#1f77b4",
                    line=dict(width=2, color="#222")),
        text=labels, textposition="middle center",
        textfont=dict(color="white", size=11),
        hoverinfo="text", showlegend=False,
    ))

    fig.update_layout(
        xaxis=dict(visible=False, range=[0, 1]),
        yaxis=dict(visible=False, range=[0, 1]),
        margin=dict(l=10, r=10, t=10, b=10),
        height=420,
        plot_bgcolor="#0e1117", paper_bgcolor="#0e1117",
    )
    return fig
