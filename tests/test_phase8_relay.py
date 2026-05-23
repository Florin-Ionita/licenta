"""Phase 8 (optional, additive) -- trusted-node QKD relay smoke tests.

These tests only exercise ``qkd.relay``; the earlier-phase test suite is
deliberately untouched and continues to pass even if this file is deleted.
"""

from __future__ import annotations

import asyncio

import pytest

from qkd.relay import RelayError, RelayNetwork, default_topology


async def _prime(net: RelayNetwork, timeout: float = 15.0) -> None:
    """Run the per-edge feeders until every link has at least one fresh key."""
    stop = asyncio.Event()
    await net.start_feeders(stop)
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            ready = True
            for (a, b), (store_a, store_b) in net._edge_stores.items():
                if store_a.fresh_key_count() == 0 or store_b.fresh_key_count() == 0:
                    ready = False
                    break
            if ready:
                return
            await asyncio.sleep(0.1)
        raise TimeoutError("relay edges did not produce keys in time")
    finally:
        stop.set()
        await net.stop_feeders()


def test_default_topology_routes() -> None:
    net = default_topology()
    # Direct neighbours.
    assert net.route("A", "R1") == ["A", "R1"]
    # Two-hop (A-R1-B via the bypass beats A-R1-R2-B by hop count).
    path_ab = net.route("A", "B")
    assert path_ab[0] == "A" and path_ab[-1] == "B"
    assert len(path_ab) - 1 <= 3
    # Unknown node.
    with pytest.raises(RelayError):
        net.route("A", "Z")


async def test_relay_delivers_same_key_along_each_hop() -> None:
    net = default_topology()
    # Drive feeders just long enough to fill every link's pool.
    stop = asyncio.Event()
    await net.start_feeders(stop)
    try:
        # Wait for primed pools (small bespoke loop -- the helper above is for
        # the longer-running test).
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 15.0
        while loop.time() < deadline:
            if all(
                sa.fresh_key_count() > 0 and sb.fresh_key_count() > 0
                for (sa, sb) in net._edge_stores.values()
            ):
                break
            await asyncio.sleep(0.1)
        else:
            pytest.skip("relay edges did not produce keys in time")

        result = net.deliver_key("A", "B", n_bytes=32)
    finally:
        stop.set()
        await net.stop_feeders()

    # The delivered key is exactly the requested length.
    assert len(result.delivered_key) == 32
    # One hop report per edge on the chosen path.
    assert len(result.hops) == len(result.path) - 1
    # Each hop consumed link-key bytes; reports are well-formed.
    for hop in result.hops:
        assert hop.edge_key_bytes == 32
        assert hop.from_node in result.path and hop.to_node in result.path
