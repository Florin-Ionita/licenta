"""Panel C: QTLS handshake sequence diagram.

Two vertical lifelines (Client, Server). Each handshake event from the bus
highlights one arrow. We render the *most recent* handshake -- once Finished
arrives, the diagram shows the full successful sequence; in flight, partial.
"""

from __future__ import annotations

import plotly.graph_objects as go

from viz.bus import EventBus

# Canonical sequence drawn top-to-bottom. The label drives a y-coordinate.
_STEPS = [
    ("client_send_clienthello", "ClientHello (key_ID)", "c->s"),
    ("server_recv_clienthello", "(server fetches same key)", "internal"),
    ("server_finished",          "ServerHello + Finished", "s->c"),
    ("client_finished",          "Finished", "c->s"),
]


def build(bus: EventBus) -> go.Figure:
    # Use the latest event per step kind.
    events = bus.snapshot("handshake", limit=200)
    seen: dict[str, float] = {}
    for ev in events:
        seen[ev.data["step"]] = ev.ts

    fig = go.Figure()
    # Lifelines.
    fig.add_shape(type="line", x0=0.2, x1=0.2, y0=0, y1=1,
                  line=dict(color="#888", width=2))
    fig.add_shape(type="line", x0=0.8, x1=0.8, y0=0, y1=1,
                  line=dict(color="#888", width=2))
    fig.add_annotation(x=0.2, y=1.05, text="Client (SAE)", showarrow=False,
                       font=dict(color="#ddd"))
    fig.add_annotation(x=0.8, y=1.05, text="Server (SAE)", showarrow=False,
                       font=dict(color="#ddd"))

    n = len(_STEPS)
    for idx, (key, label, direction) in enumerate(_STEPS):
        y = 0.9 - (idx + 1) * (0.85 / (n + 1))
        active = key in seen
        colour = "#2ca02c" if active else "#444"
        if direction == "c->s":
            fig.add_annotation(x=0.8, y=y, ax=0.2, ay=y,
                               xref="x", yref="y", axref="x", ayref="y",
                               showarrow=True, arrowhead=3, arrowsize=1.4,
                               arrowwidth=2, arrowcolor=colour, text="")
            fig.add_annotation(x=0.5, y=y + 0.025, text=label, showarrow=False,
                               font=dict(color=colour, size=11))
        elif direction == "s->c":
            fig.add_annotation(x=0.2, y=y, ax=0.8, ay=y,
                               xref="x", yref="y", axref="x", ayref="y",
                               showarrow=True, arrowhead=3, arrowsize=1.4,
                               arrowwidth=2, arrowcolor=colour, text="")
            fig.add_annotation(x=0.5, y=y + 0.025, text=label, showarrow=False,
                               font=dict(color=colour, size=11))
        else:
            fig.add_annotation(x=0.8, y=y, text=f"  {label}",
                               showarrow=False, xanchor="left",
                               font=dict(color=colour, size=10, family="monospace"))

    fig.update_layout(
        xaxis=dict(visible=False, range=[0, 1]),
        yaxis=dict(visible=False, range=[0, 1.1]),
        height=260, margin=dict(l=10, r=10, t=30, b=10),
        plot_bgcolor="#0e1117", paper_bgcolor="#0e1117",
        showlegend=False,
    )
    return fig
