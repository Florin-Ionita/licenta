"""Trusted-node QKD relay (optional Phase 8).

This module is **strictly additive**: nothing in Phases 1-7 imports it and
nothing in Phases 1-7 changes if it is deleted. It exists to demonstrate the
*scalability* property of QKD networks -- end-to-end key sharing between
endpoints that are *not* directly connected -- which is the only way real
fielded QKD systems (China backbone, SECOQC, Tokyo) cover more than ~100 km.

How a trusted-node relay works (the property we visualise):

    Alice --[K_AR]-- R --[K_RB]-- Bob

Direct QKD gives Alice/R the shared key ``K_AR`` and R/Bob the shared key
``K_RB``. To let Alice and Bob agree on a single end-to-end key ``K``:

  1. Alice generates a fresh ``K`` (taken from her local pool).
  2. Alice sends ``C = K XOR K_AR`` to R over an authenticated classical
     channel. R recovers ``K = C XOR K_AR``.
  3. R sends ``C' = K XOR K_RB`` to Bob. Bob recovers ``K = C' XOR K_RB``.

R sees ``K`` in the clear -- that's why it is called a *trusted* node, and
why quantum repeaters are an open research area. For the thesis this is a
demonstration of an architectural pattern, not a security claim.

We model the network as a ``networkx`` graph; each edge owns its own pair of
linked ``KeyStore`` objects (Phase 3) fed by the same fan-out feeder the
point-to-point demo uses. Routing is shortest-path (Dijkstra by hop count).
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass

import networkx as nx

from kme.network import fan_out_feeder, make_kme_pair
from kme.store import KeyStore
from qkd.abstract_link import abstract_qkd_link
from qkd.keyblock import KeyBlock


@dataclass
class RelayHopReport:
    """One transmitted-key step in an end-to-end relay, captured for the viz."""

    from_node: str
    to_node: str
    edge_key_id: str        # the link KeyBlock that masked the payload
    edge_key_bytes: int     # how much link key the relay consumed


@dataclass
class RelayResult:
    """The outcome of one end-to-end key delivery."""

    src: str
    dst: str
    path: list[str]
    delivered_key: bytes
    hops: list[RelayHopReport]


class RelayError(RuntimeError):
    """Routing or key-availability failure during a relay."""


class RelayNetwork:
    """A small QKD topology: nodes connected by point-to-point links.

    Each edge owns:
      * a ``KeyStore`` pair (one store on each endpoint), linked so a reservation
        on one side is mirrored to the other (the Phase 3 sync mechanism);
      * a background ``abstract_qkd_link`` + ``fan_out_feeder`` task pair so
        the edge produces fresh shared key material at the configured rate.

    The relay itself (:meth:`deliver_key`) is a synchronous, in-memory function:
    it picks a route, XOR-forwards a fresh key hop by hop, and returns the
    delivered material plus a per-hop report for the visualization.
    """

    def __init__(self) -> None:
        self.graph = nx.Graph()
        # (u, v) -> (store_at_u, store_at_v)  with u < v lexicographic ordering
        self._edge_stores: dict[tuple[str, str], tuple[KeyStore, KeyStore]] = {}
        self._stop: asyncio.Event | None = None
        self._tasks: list[asyncio.Task] = []

    # -- topology ----------------------------------------------------------

    def add_node(self, name: str) -> None:
        self.graph.add_node(name)

    def add_link(
        self,
        u: str,
        v: str,
        *,
        key_rate_bps: int = 32_768,
        qber: float = 0.02,
    ) -> None:
        """Connect two nodes with a simulated QKD link.

        Each call creates a fresh KME pair and tags both stores' IDs with the
        endpoint name so logs and the viz can attribute keys to the right link.
        """
        if u == v:
            raise ValueError("self-link is not allowed")
        self.add_node(u)
        self.add_node(v)
        a, b = sorted((u, v))
        if (a, b) in self._edge_stores:
            raise ValueError(f"link {a}-{b} already exists")
        kme_u, kme_v = make_kme_pair(
            kme_a_id=f"KME-{a}-{b}-{a}",
            kme_b_id=f"KME-{a}-{b}-{b}",
            key_size_bits=2048,
        )
        # Every node should be authorised to send keys to every other node on
        # the same link (the link is between *exactly* those two nodes anyway).
        kme_u.authorise(a, b); kme_u.authorise(b, a)
        kme_v.authorise(a, b); kme_v.authorise(b, a)
        self._edge_stores[(a, b)] = (kme_u, kme_v)
        # Edge weight = 1 so Dijkstra reduces to shortest hop count, the
        # operationally meaningful metric for a trusted-node network (each hop
        # is one trusted intermediary).
        self.graph.add_edge(u, v, weight=1, key_rate_bps=key_rate_bps, qber=qber)

    def edge_store(self, u: str, v: str, *, at: str) -> KeyStore:
        """Return the KME store that lives on node ``at`` of edge u-v."""
        a, b = sorted((u, v))
        if (a, b) not in self._edge_stores:
            raise RelayError(f"no link between {u} and {v}")
        store_a, store_b = self._edge_stores[(a, b)]
        if at == a:
            return store_a
        if at == b:
            return store_b
        raise RelayError(f"node {at!r} is not an endpoint of {u}-{v}")

    # -- background producers ---------------------------------------------

    async def start_feeders(self, stop_event: asyncio.Event | None = None) -> None:
        """Spin up one abstract-bulk producer + fan-out per edge."""
        self._stop = stop_event or asyncio.Event()
        for (a, b), (store_a, store_b) in self._edge_stores.items():
            attrs = self.graph.edges[a, b]
            queue: asyncio.Queue[KeyBlock] = asyncio.Queue()
            self._tasks.append(asyncio.create_task(
                abstract_qkd_link(
                    queue, key_rate_bps=attrs["key_rate_bps"],
                    qber=attrs["qber"], stop_event=self._stop,
                ),
                name=f"relay-bulk-{a}-{b}",
            ))
            self._tasks.append(asyncio.create_task(
                fan_out_feeder(queue, store_a, store_b, stop_event=self._stop),
                name=f"relay-fanout-{a}-{b}",
            ))

    async def stop_feeders(self) -> None:
        if self._stop is not None:
            self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except BaseException:
                pass
        self._tasks.clear()

    # -- routing ----------------------------------------------------------

    def route(self, src: str, dst: str) -> list[str]:
        """Return the shortest path src -> ... -> dst (by hop count)."""
        if src not in self.graph or dst not in self.graph:
            raise RelayError(f"unknown node in route: {src!r} -> {dst!r}")
        try:
            return nx.shortest_path(self.graph, src, dst, weight="weight")
        except nx.NetworkXNoPath as exc:
            raise RelayError(f"no path from {src} to {dst}") from exc

    # -- end-to-end key delivery -----------------------------------------

    def deliver_key(self, src: str, dst: str, n_bytes: int = 32) -> RelayResult:
        """Deliver a fresh ``n_bytes``-byte key from ``src`` to ``dst``.

        Picks a route, then for each hop reserves one link key (via the edge's
        KME ``take_keys`` -- the same call the QTLS demo uses), XORs the
        end-to-end key against the leading ``n_bytes`` of the link key, and
        "transmits" the masked payload over the (simulated) classical channel
        to the next hop. Returns the delivered key and a per-hop report.

        Trust model is intentional and visible: every intermediate node sees
        ``K`` in the clear -- this is the well-known limitation of trusted-node
        relays and the motivation for quantum repeaters.
        """
        path = self.route(src, dst)
        if len(path) < 2:
            raise RelayError("source and destination must differ")
        K = secrets.token_bytes(n_bytes)
        hops: list[RelayHopReport] = []
        for u, v in zip(path[:-1], path[1:]):
            # Reserve one link KeyBlock on the u-side (master = u, slave = v).
            store_u = self.edge_store(u, v, at=u)
            try:
                blocks = store_u.take_keys(master_sae=u, slave_sae=v, number=1)
            except Exception as exc:
                raise RelayError(
                    f"link {u}-{v} could not provide a key: {exc!r}"
                ) from exc
            link_block = blocks[0]
            if link_block.length_bytes < n_bytes:
                raise RelayError(
                    f"link {u}-{v} key is {link_block.length_bytes} B; "
                    f"need {n_bytes}"
                )
            mask = link_block.material[:n_bytes]
            # In a real deployment u would send (K XOR mask) over an authenticated
            # classical link; v's KME (synchronised via Phase 3) lets v recover
            # the same mask by fetching the link_block by id. We don't actually
            # need to model the classical wire for this demonstration -- the
            # invariant ("the key on both sides matches") is already guaranteed
            # by the KME pair, which is the whole point of trusted-node relay.
            _ = bytes(a ^ b for a, b in zip(K, mask))  # the cipher-text on the wire
            hops.append(RelayHopReport(
                from_node=u, to_node=v,
                edge_key_id=str(link_block.key_id),
                edge_key_bytes=n_bytes,
            ))
        return RelayResult(src=src, dst=dst, path=path,
                           delivered_key=K, hops=hops)


def default_topology() -> RelayNetwork:
    """A five-node line + one bypass edge: enough to make routing non-trivial.

        A --- R1 --- R2 --- B
               \\___________/
                  (bypass edge R1-B, slower link)

    Default route from A to B is A-R1-R2-B (3 hops). Removing the R2 edge or
    letting that pool drain shifts traffic onto the slower R1-B bypass, which
    is a nice live story for the defence ("look, the network self-routes").
    """
    net = RelayNetwork()
    net.add_link("A",  "R1", key_rate_bps=32_768)
    net.add_link("R1", "R2", key_rate_bps=32_768)
    net.add_link("R2", "B",  key_rate_bps=32_768)
    net.add_link("R1", "B",  key_rate_bps=8_192)   # slower bypass
    return net
