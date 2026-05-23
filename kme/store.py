"""In-memory key pool for a KME, with ACLs, expiry, and reuse protection.

Two correctness properties dominate this module (both flagged as the worst
possible bugs in the project plan):

1. **key_ID synchronisation.** When a master SAE pulls a key it receives a
   ``key_ID``; the slave SAE must later receive *exactly that key_ID's
   material* from its own KME, not a different key. We guarantee this by
   having both KMEs share the *same* :class:`~qkd.keyblock.KeyBlock` objects
   (same UUID, same bytes), so a lookup by ``key_ID`` is identical on both
   sides.

2. **No key reuse.** A key, once delivered to the master, is marked consumed
   and can only afterwards be fetched by the *intended slave* (by ID). It is
   never handed out again as fresh material. This is the property that keeps
   the One-Time Pad a one-time pad.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from qkd.keyblock import KeyBlock


@dataclass
class _StoredKey:
    """A key block plus the bookkeeping the KME needs around it."""

    block: KeyBlock
    # SAE pair this key is reserved for once the master pulls it:
    master_sae: str | None = None
    slave_sae: str | None = None
    delivered_to_master: bool = False
    delivered_to_slave: bool = False
    stored_at: float = field(default_factory=time.time)


class KeyExpiredError(RuntimeError):
    """Requested key_ID exists but has passed its time-to-live."""


class KeyNotFoundError(RuntimeError):
    """Requested key_ID is unknown to this KME."""


class AccessDeniedError(RuntimeError):
    """Calling SAE is not authorised for the requested key / peer."""


class KeyPoolEmptyError(RuntimeError):
    """No fresh keys available to satisfy an enc_keys request."""


class KeyStore:
    """Thread-safe in-memory key pool for one KME.

    The store is fed :class:`KeyBlock`s from the QKD layer (Phases 1-2). It is
    accessed both from the asyncio web server thread and potentially from the
    producer thread, so every mutation is guarded by a single lock -- simple
    and sufficient for the project's scale.
    """

    def __init__(
        self,
        kme_id: str,
        key_size_bits: int = 256,
        max_key_count: int = 10_000,
        key_ttl_seconds: float = 3600.0,
    ) -> None:
        self.kme_id = kme_id
        self.key_size_bits = key_size_bits
        self.max_key_count = max_key_count
        self.key_ttl_seconds = key_ttl_seconds
        self._keys: dict[uuid.UUID, _StoredKey] = {}
        # Access control: master_sae -> set of slave_sae it may share with.
        self._acl: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        # The peer KME on the other end of the link. A reservation made here
        # is mirrored to the peer, modelling the ETSI KME-to-KME
        # synchronisation channel (real KMEs coordinate which key_ID is
        # assigned to which SAE pair over an authenticated internal link).
        self._peer: "KeyStore | None" = None

    # -- configuration -----------------------------------------------------

    def link_peer(self, peer: "KeyStore") -> None:
        """Connect this KME to its partner so reservations stay in sync."""
        self._peer = peer

    def authorise(self, master_sae: str, slave_sae: str) -> None:
        """Allow ``master_sae`` to obtain keys destined for ``slave_sae``.

        ETSI 014 leaves authorisation KME-implementation-defined; we use a
        simple explicit allow-list keyed by the SAE certificate CN.
        """
        with self._lock:
            self._acl.setdefault(master_sae, set()).add(slave_sae)

    def _is_authorised(self, master_sae: str, slave_sae: str) -> bool:
        return slave_sae in self._acl.get(master_sae, set())

    # -- feeding -----------------------------------------------------------

    def add_block(self, block: KeyBlock) -> None:
        """Insert a finished key block into the pool (called by the feeder).

        Both KMEs are given the *same* block object stream, which is what
        makes key_ID lookups consistent across the two sides.
        """
        with self._lock:
            if len(self._keys) >= self.max_key_count:
                # Pool full: drop the oldest *undelivered* key to make room,
                # modelling a bounded buffer rather than unbounded growth.
                oldest = min(
                    (k for k in self._keys.values() if not k.delivered_to_master),
                    key=lambda k: k.stored_at,
                    default=None,
                )
                if oldest is not None:
                    del self._keys[oldest.block.key_id]
            self._keys[block.key_id] = _StoredKey(block=block)

    # -- expiry ------------------------------------------------------------

    def _purge_expired_locked(self) -> None:
        now = time.time()
        expired = [
            kid
            for kid, sk in self._keys.items()
            if now - sk.stored_at > self.key_ttl_seconds
        ]
        for kid in expired:
            del self._keys[kid]

    # -- status ------------------------------------------------------------

    def fresh_key_count(self) -> int:
        with self._lock:
            self._purge_expired_locked()
            return sum(
                1 for sk in self._keys.values() if not sk.delivered_to_master
            )

    # -- enc_keys (master pulls fresh keys) --------------------------------

    def take_keys(
        self,
        master_sae: str,
        slave_sae: str,
        number: int,
    ) -> list[KeyBlock]:
        """Reserve and return ``number`` fresh keys for the master SAE.

        Each returned key is marked delivered-to-master and tagged with the
        (master, slave) pair so that only the intended slave can later fetch
        it by ID. Raises if the master is not authorised for that slave or if
        the pool cannot satisfy the request.
        """
        with self._lock:
            if not self._is_authorised(master_sae, slave_sae):
                raise AccessDeniedError(
                    f"SAE {master_sae!r} not authorised for {slave_sae!r}"
                )
            self._purge_expired_locked()
            fresh = [
                sk
                for sk in self._keys.values()
                if not sk.delivered_to_master
            ]
            fresh.sort(key=lambda sk: sk.block.created_at)
            if len(fresh) < number:
                raise KeyPoolEmptyError(
                    f"requested {number} keys, only {len(fresh)} available"
                )
            chosen = fresh[:number]
            for sk in chosen:
                sk.delivered_to_master = True
                sk.master_sae = master_sae
                sk.slave_sae = slave_sae
            reservations = [
                (sk.block.key_id, master_sae, slave_sae) for sk in chosen
            ]

        # Mirror the reservation to the peer KME *outside* our lock (the peer
        # takes its own lock). This is the simulated KME-to-KME sync channel:
        # after this returns, the slave can fetch the same key_ID from the
        # peer and get byte-identical material.
        if self._peer is not None:
            self._peer._apply_reservation(reservations)

        return [sk.block for sk in chosen]

    def _apply_reservation(
        self,
        reservations: list[tuple[uuid.UUID, str, str]],
    ) -> None:
        """Record, on this KME, reservations a master made on the peer KME.

        Called only by the peer's :meth:`take_keys`; it does not propagate
        further (no recursion). If a reserved key has not yet reached this
        KME's pool the reservation is ignored -- the shared feeder delivers
        the same blocks to both sides, so in practice the key is present.
        """
        with self._lock:
            for key_id, master_sae, slave_sae in reservations:
                sk = self._keys.get(key_id)
                if sk is None:
                    continue
                sk.delivered_to_master = True
                sk.master_sae = master_sae
                sk.slave_sae = slave_sae

    # -- dec_keys (slave fetches by ID) ------------------------------------

    def get_keys_by_id(
        self,
        slave_sae: str,
        key_ids: list[uuid.UUID],
    ) -> list[KeyBlock]:
        """Return the key material for the given IDs, for the slave SAE.

        Enforces that (a) the key exists, (b) it has not expired, (c) it was
        actually reserved for *this* slave by a prior master pull. This is the
        synchronisation guarantee: the slave gets byte-identical material to
        what the master received, because it is the same KeyBlock.
        """
        with self._lock:
            self._purge_expired_locked()
            out: list[KeyBlock] = []
            for kid in key_ids:
                sk = self._keys.get(kid)
                if sk is None:
                    raise KeyNotFoundError(f"unknown key_ID {kid}")
                if not sk.delivered_to_master:
                    # The slave is asking for a key the master never pulled.
                    raise KeyNotFoundError(
                        f"key_ID {kid} has not been activated by a master"
                    )
                if sk.slave_sae != slave_sae:
                    raise AccessDeniedError(
                        f"key_ID {kid} is not reserved for SAE {slave_sae!r}"
                    )
                sk.delivered_to_slave = True
                out.append(sk.block)
            return out
