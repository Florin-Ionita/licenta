"""Streamlit entry point: ``streamlit run viz/main.py``.

The page is intentionally a single file so the defence demo is one command:
``streamlit run viz/main.py`` -> open the browser -> click Start.

State model under Streamlit's rerun semantics:
  * Heavy objects (:class:`EventBus`, :class:`Runtime`) live in
    ``st.session_state``. They are created lazily on first Start.
  * ``streamlit-autorefresh`` triggers a rerun every 500 ms while the runtime
    is active, so the panels read fresh data without us managing any threads
    on Streamlit's side.
  * All asyncio work happens in the Runtime's background thread; no asyncio
    calls run on the main Streamlit thread.
"""

from __future__ import annotations

# `streamlit run viz/main.py` executes this file as a script, so the project
# root is *not* on sys.path -- inject it before importing sibling packages.
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st
from streamlit_autorefresh import st_autorefresh

from viz.bus import EventBus
from viz.components import handshake, metrics, photons, topology
from viz.runtime import Runtime


st.set_page_config(page_title="QTLS over QKD -- live demo",
                   layout="wide", page_icon="🔐")


def _ensure_state() -> None:
    if "bus" not in st.session_state:
        st.session_state.bus = EventBus()
    if "runtime" not in st.session_state:
        st.session_state.runtime = None
    if "running" not in st.session_state:
        st.session_state.running = False
    if "eve" not in st.session_state:
        st.session_state.eve = False
    if "paused" not in st.session_state:
        st.session_state.paused = False
    if "refresh_ms" not in st.session_state:
        st.session_state.refresh_ms = 1500
    if "bb84_delay_s" not in st.session_state:
        st.session_state.bb84_delay_s = 0.8


def _start_runtime() -> None:
    bus: EventBus = st.session_state.bus
    rt = Runtime(bus)
    rt.start()
    rt.set_bb84_delay(st.session_state.bb84_delay_s)
    st.session_state.runtime = rt
    st.session_state.running = True
    bus.publish("log", level="info", msg="Runtime started from dashboard")


def _sidebar() -> None:
    with st.sidebar:
        st.markdown("### Display")
        st.session_state.refresh_ms = st.slider(
            "Refresh interval (ms)", 250, 5000,
            value=st.session_state.refresh_ms, step=250,
            help="How often the dashboard re-reads bus state. Higher = calmer.",
        )
        st.session_state.paused = st.toggle(
            "⏸ Pause snapshot", value=st.session_state.paused,
            help="Freeze the panels on the current frame -- useful during a defence "
                 "to point at a specific BB84 round. Background producers keep running.",
        )

        st.markdown("### BB84 pacing")
        new_delay = st.slider(
            "Per-round delay (s)", 0.0, 3.0,
            value=float(st.session_state.bb84_delay_s), step=0.1,
            help="Slows the quantum producer so the photon panel is readable. "
                 "Has no effect on the abstract bulk producer (which already ticks at 1 Hz).",
        )
        if abs(new_delay - st.session_state.bb84_delay_s) > 1e-6:
            st.session_state.bb84_delay_s = new_delay
            if st.session_state.runtime is not None:
                st.session_state.runtime.set_bb84_delay(new_delay)


def _stop_runtime() -> None:
    rt: Runtime | None = st.session_state.runtime
    if rt is not None:
        rt.stop()
    st.session_state.runtime = None
    st.session_state.running = False


def _header() -> None:
    cols = st.columns([3, 1, 1, 1, 2])
    cols[0].markdown("### 🔐 QTLS over a simulated QKD network")
    if cols[1].button("▶ Start", disabled=st.session_state.running, width="stretch"):
        _start_runtime()
    if cols[2].button("⏹ Stop", disabled=not st.session_state.running, width="stretch"):
        _stop_runtime()
    new_eve = cols[3].toggle("Eve attack", value=st.session_state.eve,
                             disabled=not st.session_state.running)
    if new_eve != st.session_state.eve:
        st.session_state.eve = new_eve
        if st.session_state.runtime is not None:
            st.session_state.runtime.set_eve(new_eve)
    status = "● running" if st.session_state.running else "○ stopped"
    cols[4].markdown(f"**Status:** {status}")


def _render_panels() -> None:
    bus: EventBus = st.session_state.bus

    row1 = st.columns(2)
    with row1[0]:
        st.markdown("#### A) QKD network")
        st.plotly_chart(topology.build(bus), width="stretch",
                        config={"displayModeBar": False})
    with row1[1]:
        st.markdown("#### B) BB84 photon stream")
        st.plotly_chart(photons.build(bus), width="stretch",
                        config={"displayModeBar": False})

    row2 = st.columns(2)
    with row2[0]:
        st.markdown("#### C) QTLS handshake")
        st.plotly_chart(handshake.build(bus), width="stretch",
                        config={"displayModeBar": False})
    with row2[1]:
        st.markdown("#### D) Metrics")
        strip = metrics.stat_strip(bus)
        m_cols = st.columns(len(strip))
        for col, (label, value) in zip(m_cols, strip):
            col.metric(label, value)
        st.plotly_chart(metrics.build_timeseries(bus), width="stretch",
                        config={"displayModeBar": False})

    with st.expander("Event log"):
        log_events = bus.snapshot("log", limit=50)
        for ev in reversed(log_events):
            level = ev.data.get("level", "info")
            tag = {"info": "🟦", "warn": "🟧", "error": "🟥"}.get(level, "▫")
            st.text(f"{tag} {ev.data.get('msg', '')}")


def main() -> None:
    _ensure_state()
    _sidebar()
    _header()
    if st.session_state.running and not st.session_state.paused:
        st_autorefresh(interval=st.session_state.refresh_ms, key="viz-tick")
    _render_panels()


main()
