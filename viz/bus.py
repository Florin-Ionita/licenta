"""Thread-safe event bus shared between the asyncio runtime and Streamlit.

The runtime thread publishes typed events (KeyBlock produced, handshake step,
record sent, photon round, etc.). The Streamlit thread reads accumulated state
on every rerun. A single :class:`threading.Lock` is sufficient: events arrive
at ~5-50 Hz and Streamlit reads ~10 Hz, so contention is negligible.

We intentionally do *not* use ``asyncio.Queue`` here -- Streamlit's main thread
has no running event loop, and bridging one in cleanly is more code than a
plain lock-guarded deque. The deque also gives us a natural bounded buffer so
long sessions don't grow without bound.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    """One observation from somewhere in the running stack.

    ``kind`` identifies the producer ("key_block", "photon_round",
    "handshake", "record", "pool", "log"); ``data`` is a plain dict so the
    Streamlit side can read it without importing protocol types.
    """

    kind: str
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)


class EventBus:
    """A bounded, lock-guarded multi-producer/single-consumer event sink.

    The runtime thread calls :meth:`publish`; the Streamlit thread polls with
    :meth:`snapshot` to copy out the current state for rendering. We keep a
    *separate* deque per kind so panels that only need photon events don't
    have to scan through thousands of record events.
    """

    def __init__(self, per_kind_capacity: int = 500) -> None:
        self._lock = threading.Lock()
        self._cap = per_kind_capacity
        self._by_kind: dict[str, deque[Event]] = {}
        # Aggregate counters the metrics panel reads cheaply (without rescanning
        # full event lists). Updated under the same lock as publish().
        self._counters: dict[str, float] = {
            "key_bytes_produced": 0.0,
            "key_bytes_consumed": 0.0,
            "records_sent": 0.0,
            "handshakes_completed": 0.0,
            "qber_last": 0.0,
            "pool_a_fresh": 0.0,
            "pool_b_fresh": 0.0,
            "last_handshake_ms": 0.0,
        }
        self._eve_present = False

    # -- producer side -----------------------------------------------------

    def publish(self, kind: str, **data: Any) -> None:
        ev = Event(kind=kind, data=dict(data))
        with self._lock:
            buf = self._by_kind.setdefault(kind, deque(maxlen=self._cap))
            buf.append(ev)

    def update_counter(self, name: str, value: float) -> None:
        with self._lock:
            self._counters[name] = value

    def add_counter(self, name: str, delta: float) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0.0) + delta

    def set_eve(self, present: bool) -> None:
        with self._lock:
            self._eve_present = present

    # -- consumer side (Streamlit) ----------------------------------------

    def get_eve(self) -> bool:
        with self._lock:
            return self._eve_present

    def snapshot(self, kind: str, limit: int | None = None) -> list[Event]:
        with self._lock:
            buf = self._by_kind.get(kind)
            if not buf:
                return []
            if limit is None or limit >= len(buf):
                return list(buf)
            # Most-recent ``limit`` items, in chronological order.
            return list(buf)[-limit:]

    def counters(self) -> dict[str, float]:
        with self._lock:
            return dict(self._counters)
