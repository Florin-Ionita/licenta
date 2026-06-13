"""Panel A: the QKD mechanism (BB84) for the single link.

This panel does NOT draw "key material flowing down a wire" -- in QKD the key
never travels. It shows the two real channels between Alice and Bob:

  * a quantum channel (top), one-way, carrying polarised photons Alice -> Bob;
  * a public classical channel (bottom), two-way, carrying basis reconciliation
    (sifting), which leaks bases but never the sifted bits.

The shared key is *derived* independently at both ends from the photons that
survived sifting; that is stated explicitly in the centre. Eve can only tap the
quantum channel, and doing so disturbs the photons and raises the QBER -- she
gains no key. The animation therefore carries photons (qubits), not key bytes.
"""

from __future__ import annotations

import math
import time

import plotly.graph_objects as go

from viz.bus import EventBus

_AX = 0.12          # Alice x
_BX = 0.88          # Bob x
_NODE_PAD = 0.05    # gap so channel lines stop short of the node discs
_QY = 0.70          # quantum channel y (top)
_CY = 0.30          # classical public channel y (bottom)
_N_PHOTONS = 5      # photons shown in flight on the quantum channel
_PHOTON_PERIOD = 2.5  # seconds for a photon to cross the link


def _photon_positions(active: bool, eve: bool) -> tuple[list[float], list[float]]:
    """Photon x-positions on the quantum channel, phase derived from wall time.

    With Eve tapping, photons are measured (and destroyed) at the tap point, so
    none reach Bob intact -- the visual cue for "interception disturbs photons".
    """
    if not active:
        return [], []
    now = time.time()
    lx, rx = _AX + _NODE_PAD, _BX - _NODE_PAD
    tap = (lx + rx) / 2.0
    xs: list[float] = []
    for i in range(_N_PHOTONS):
        phase = ((now / _PHOTON_PERIOD) + i / _N_PHOTONS) % 1.0
        x = lx + (rx - lx) * phase
        if eve and x >= tap:
            continue
        xs.append(x)
    return xs, [_QY] * len(xs)


def build(bus: EventBus, height: int = 240) -> go.Figure:
    counters = bus.counters()
    a_pool = int(counters.get("pool_a_fresh", 0))
    b_pool = int(counters.get("pool_b_fresh", 0))
    qber = float(counters.get("qber_last", 0.0))

    # Is the protocol actually producing photons right now?
    blocks = bus.snapshot("key_block", limit=10)
    active = len(blocks) >= 2 and (time.time() - blocks[-1].ts) < 5.0

    eve = bus.get_eve()
    fig = go.Figure()

    lx, rx = _AX + _NODE_PAD, _BX - _NODE_PAD  # channel ends, clear of nodes

    # --- Quantum channel (top, one-way Alice -> Bob) ---
    # Lines run node-to-node (x positions); they sit above/below the discs in
    # y, so they meet the vertical node connectors without crossing the discs.
    fig.add_shape(type="line", x0=_AX, x1=_BX, y0=_QY, y1=_QY,
                  line=dict(color="#2a3f5f", width=3))
    fig.add_annotation(x=(_AX + _BX) / 2, y=_QY + 0.14, showarrow=False,
                       text="Quantum channel (one-way)",
                       font=dict(color="#7fb3ff", size=17))
    # Direction arrowhead near Bob.
    fig.add_annotation(x=rx, y=_QY, ax=rx - 0.08, ay=_QY,
                       xref="x", yref="y", axref="x", ayref="y",
                       showarrow=True, arrowhead=2, arrowsize=1.4,
                       arrowwidth=2, arrowcolor="#7fb3ff", text="")

    px, py = _photon_positions(active, eve)
    if px:
        fig.add_trace(go.Scatter(
            x=px, y=py, mode="markers",
            marker=dict(size=15, color="#00d2ff", symbol="circle",
                        line=dict(width=1, color="#bff")),
            hoverinfo="skip", showlegend=False,
        ))

    # --- Public classical channel (bottom, two-way reconciliation) ---
    fig.add_shape(type="line", x0=_AX, x1=_BX, y0=_CY, y1=_CY,
                  line=dict(color="#444", width=2, dash="dot"))
    fig.add_annotation(x=(_AX + _BX) / 2, y=_CY - 0.14, showarrow=False,
                       text="Public channel (two-way, reconciliation)",
                       font=dict(color="#bbb", size=17))
    for x0, x1 in ((lx, lx + 0.10), (rx, rx - 0.10)):
        fig.add_annotation(x=x1, y=_CY, ax=x0, ay=_CY,
                           xref="x", yref="y", axref="x", ayref="y",
                           showarrow=True, arrowhead=2, arrowsize=1,
                           arrowwidth=1.5, arrowcolor="#888", text="")

    # --- Eve tap on the quantum channel ---
    if eve:
        tap = (lx + rx) / 2.0
        fig.add_trace(go.Scatter(
            x=[tap], y=[_QY], mode="markers+text",
            marker=dict(size=24, color="rgba(214,39,40,0.9)",
                        symbol="x-thin", line=dict(width=3, color="#d62728")),
            text=["Eve"], textposition="top center",
            textfont=dict(color="#d62728", size=13),
            hoverinfo="skip", showlegend=False,
        ))
        fig.add_annotation(
            x=tap, y=_QY - 0.10, showarrow=False,
            text=f"intercept-resend disturbs photons → QBER {qber:.1%}",
            font=dict(color="#d62728", size=11))

    # --- Alice / Bob endpoints (span both channels) ---
    cy_mid = (_QY + _CY) / 2          # disc centre
    disc_half = 0.085                 # half-height of the disc in y units
    for x, name, pool in ((_AX, "Alice", a_pool), (_BX, "Bob", b_pool)):
        # Vertical connector split in two so it never runs under the disc.
        fig.add_shape(type="line", x0=x, x1=x, y0=cy_mid + disc_half, y1=_QY,
                      line=dict(color="#555", width=2))
        fig.add_shape(type="line", x0=x, x1=x, y0=_CY, y1=cy_mid - disc_half,
                      line=dict(color="#555", width=2))
        fig.add_trace(go.Scatter(
            x=[x], y=[cy_mid], mode="markers+text",
            marker=dict(size=64, color="#1f3b66",
                        line=dict(width=2, color="#7fb3ff")),
            text=[f"{name}<br>{pool} keys"],
            textposition="middle center",
            textfont=dict(color="white", size=12),
            hoverinfo="skip", showlegend=False,
        ))

    # --- Centre statement: the key is derived, not transmitted ---
    derived = "key derived at both ends" if active else "idle (no photons)"
    fig.add_annotation(
        x=(_AX + _BX) / 2, y=(_QY + _CY) / 2, showarrow=False,
        text=f"\U0001f511 {derived}",
        font=dict(color="#2ca02c" if active else "#777", size=12),
        bgcolor="rgba(14,17,23,0.85)")

    fig.update_layout(
        xaxis=dict(visible=False, range=[0, 1]),
        yaxis=dict(visible=False, range=[0.05, 0.95]),
        margin=dict(l=10, r=10, t=10, b=10),
        height=height,
        plot_bgcolor="#0e1117",
        paper_bgcolor="#0e1117",
    )
    return fig
