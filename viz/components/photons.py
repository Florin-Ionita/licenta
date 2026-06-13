"""Panel B: BB84 photon stream with polarization glyphs.

Each photon = one qubit prepared by Alice and measured by Bob. We render the
*latest* round as glyphs flying along a horizontal fibre:

  * symbol encodes Alice's preparation basis (circle = Z, diamond = X)
  * rotation/colour encodes the bit value (0 = blue, 1 = orange)
  * an outline marks photons that survived sifting (bases agreed)
  * if Eve is intercepting, a faint red marker at fibre mid-point

Plotly's `Scatter` is enough -- no need for an animation frame loop, since
Streamlit reruns at 5-10 Hz and each rerun just renders the *current* round.
That's smoother than batched animation and dramatically simpler.
"""

from __future__ import annotations

import plotly.graph_objects as go

from viz.bus import EventBus

_BIT_COLOR = {0: "#1f77b4", 1: "#ff7f0e"}
_BASIS_SYMBOL = {0: "circle", 1: "diamond"}   # Z, X


def build(bus: EventBus, height: int = 260) -> go.Figure:
    rounds = bus.snapshot("photon_round", limit=1)
    fig = go.Figure()
    fig.add_shape(
        type="line", x0=0, x1=1, y0=0.5, y1=0.5,
        line=dict(color="#444", width=2, dash="dot"),
    )
    if not rounds:
        fig.add_annotation(
            x=0.5, y=0.5, text="waiting for BB84 rounds...",
            showarrow=False, font=dict(color="#888"),
        )
        fig.update_layout(
            xaxis=dict(visible=False, range=[0, 1]),
            yaxis=dict(visible=False, range=[0, 1]),
            height=height, margin=dict(l=10, r=10, t=10, b=10),
            plot_bgcolor="#0e1117", paper_bgcolor="#0e1117",
        )
        return fig

    r = rounds[0].data
    n = r["n"]
    sifted = set(r["sifted_indices"])
    xs = [(i + 0.5) / n for i in range(n)]

    # Alice's prepared photons on the upper half of the fibre.
    fig.add_trace(go.Scatter(
        x=xs, y=[0.75] * n, mode="markers",
        marker=dict(
            symbol=[_BASIS_SYMBOL[b] for b in r["alice_bases"]],
            color=[_BIT_COLOR[b] for b in r["alice_bits"]],
            size=18,
            line=dict(width=[2 if i in sifted else 0 for i in range(n)],
                      color="white"),
        ),
        name="Alice (prep)",
        hovertext=[f"i={i} bit={r['alice_bits'][i]} basis={'Z' if r['alice_bases'][i]==0 else 'X'}"
                   for i in range(n)],
        hoverinfo="text",
    ))
    # Bob's measured outcomes on the lower half.
    fig.add_trace(go.Scatter(
        x=xs, y=[0.25] * n, mode="markers",
        marker=dict(
            symbol=[_BASIS_SYMBOL[b] for b in r["bob_bases"]],
            color=[_BIT_COLOR[b] for b in r["bob_bits"]],
            size=18,
            line=dict(width=[2 if i in sifted else 0 for i in range(n)],
                      color="white"),
        ),
        name="Bob (meas)",
        hovertext=[f"i={i} bit={r['bob_bits'][i]} basis={'Z' if r['bob_bases'][i]==0 else 'X'}"
                   for i in range(n)],
        hoverinfo="text",
    ))
    # Connect sifted (matching-basis) pairs with a faint line -- visually
    # explains "we keep the qubits where the bases agreed".
    for i in sifted:
        fig.add_shape(
            type="line", x0=xs[i], x1=xs[i], y0=0.30, y1=0.70,
            line=dict(color="#2ca02c", width=1),
        )
    if r["eve_present"]:
        fig.add_annotation(
            x=0.5, y=0.5, text="⚠ Eve",
            font=dict(color="#d62728", size=18),
            showarrow=False, bgcolor="#0e1117",
        )

    fig.update_layout(
        xaxis=dict(visible=False, range=[0, 1]),
        yaxis=dict(visible=False, range=[0, 1]),
        height=height, margin=dict(l=70, r=10, t=10, b=40),
        showlegend=False,
        plot_bgcolor="#0e1117", paper_bgcolor="#0e1117",
        annotations=list(fig.layout.annotations) + [
            # Row labels (kept inside the [0,1] plot area).
            dict(x=0.01, y=0.88, text="Alice (prepares)", showarrow=False,
                 xanchor="left", font=dict(color="#bbb", size=16)),
            dict(x=0.01, y=0.12, text="Bob (measures)", showarrow=False,
                 xanchor="left", font=dict(color="#bbb", size=16)),
            # Big sifted / QBER readout, top-left inside the plot.
            dict(x=0.01, y=0.99, xanchor="left", showarrow=False,
                 text=f"sifted {len(sifted)}/{n}   QBER {r['observed_qber']:.1%}",
                 font=dict(color="#7fd97f", size=22)),
            # Encoding legend, bottom of the plot. Colour words are coloured
            # via Plotly's <span> (no inline CSS style attr, which it ignores).
            dict(x=0.5, y=0.50, xanchor="center", showarrow=False,
                 text="circle = Z basis    diamond = X basis    "
                      "<span style=\"color:#1f77b4\">blue = bit 0</span>    "
                      "<span style=\"color:#ff7f0e\">orange = bit 1</span>    "
                      "white ring = sifted",
                 font=dict(color="#bbb", size=15), bgcolor="rgba(14,17,23,0.7)"),
        ],
    )
    return fig
