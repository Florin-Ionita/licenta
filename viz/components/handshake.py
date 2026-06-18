"""Panel C: QTLS handshake sequence diagram.

Two vertical lifelines (Client, Server). Each handshake event from the bus
highlights one arrow. We render the *most recent* handshake -- once Finished
arrives, the diagram shows the full successful sequence; in flight, partial.
"""

from __future__ import annotations

import time

import plotly.graph_objects as go

from viz.bus import EventBus

# Seconds each step stays highlighted in the demo loop. The loop is purely
# illustrative -- a real QTLS handshake finishes in milliseconds, far faster
# than the dashboard refreshes, so we choreograph the steps at a readable pace
# while the *metrics* (count, latency) stay real and come from the bus.
_STEP_DWELL = 1.0

# Four lifelines: KME-A -- Client -- Server -- KME-B. Each SAE talks to its own
# local KME (the two-ended QKD topology), not to a shared one in the middle.
_AX, _CX, _SX, _BX = 0.10, 0.38, 0.62, 0.90

# Canonical choreography, top to bottom. Each tuple is (label, src_x, dst_x).
# The KME steps make explicit that the shared key comes from the local key
# store (ETSI GS QKD 014 get_key / get_key_with_key_IDs), not the handshake.
_FLOW = [
    ("client asks KME-A for a key", _CX, _AX),
    ("KME-A returns key + key_ID", _AX, _CX),
    ("ClientHello (carries key_ID)", _CX, _SX),
    ("server asks KME-B for same key_ID", _SX, _BX),
    ("KME-B returns the same key", _BX, _SX),
    ("ServerHello + Finished", _SX, _CX),
    ("Finished", _CX, _SX),
]


def build(bus: EventBus, height: int = 260) -> go.Figure:
    events = bus.snapshot("handshake", limit=200)

    # Real metrics from the bus (kept honest, not part of the demo loop).
    n_done = sum(1 for ev in events if ev.data["step"] == "client_finished")
    last_ms = None
    for ev in reversed(events):
        if ev.data["step"] == "client_finished" and "elapsed_ms" in ev.data:
            last_ms = ev.data["elapsed_ms"]
            break

    # Is the stack live? Animate the loop only when handshakes happen recently.
    active = bool(events) and (time.time() - events[-1].ts) < 5.0

    # Phase of the illustrative loop, derived from wall time so it advances
    # across refreshes. -1 means "idle, nothing lit".
    n = len(_FLOW)
    cur = int((time.time() / _STEP_DWELL) % n) if active else -1

    fig = go.Figure()

    # --- Four lifelines: KME-A | Client | Server | KME-B ---
    for x, name, col in ((_AX, "KME-A", "#1f77b4"),
                         (_CX, "Client (SAE)", "#1a1a1a"),
                         (_SX, "Server (SAE)", "#1a1a1a"),
                         (_BX, "KME-B", "#1f77b4")):
        fig.add_shape(type="line", x0=x, x1=x, y0=0, y1=0.95,
                      line=dict(color="#888", width=2))
        fig.add_annotation(x=x, y=1.0, text=name, showarrow=False,
                           font=dict(color=col, size=15))

    # --- Real metric readout (top) ---
    readout = f"completed handshakes: {n_done}"
    if last_ms is not None:
        readout += f"   last: {last_ms:.1f} ms"
    fig.add_annotation(x=0.5, y=1.10, text=readout, showarrow=False,
                       font=dict(color="#1a1a1a", size=16))

    # --- The choreographed message flow ---
    for idx, (label, src, dst) in enumerate(_FLOW):
        y = 0.88 - (idx + 1) * (0.82 / (n + 1))
        if idx == cur:
            colour, width, lblsize = "#1f77b4", 4, 15    # happening now
        elif idx < cur:
            colour, width, lblsize = "#2e7d32", 2, 13     # already passed
        else:
            colour, width, lblsize = "#ccc", 2, 13        # upcoming
        fig.add_annotation(x=dst, y=y, ax=src, ay=y,
                           xref="x", yref="y", axref="x", ayref="y",
                           showarrow=True, arrowhead=3, arrowsize=1.3,
                           arrowwidth=width, arrowcolor=colour, text="")
        fig.add_annotation(x=(src + dst) / 2, y=y + 0.03, text=label,
                           showarrow=False, font=dict(color=colour, size=lblsize))

    fig.update_layout(
        xaxis=dict(visible=False, range=[0, 1]),
        yaxis=dict(visible=False, range=[0, 1.15]),
        height=height, margin=dict(l=10, r=10, t=30, b=10),
        plot_bgcolor="white", paper_bgcolor="white",
        showlegend=False,
    )
    return fig
