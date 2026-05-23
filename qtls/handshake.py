"""QTLS handshake: messages and the client/server state machine.

This is the one place the protocol intentionally diverges from TLS 1.3. Real
TLS 1.3 runs an (EC)DHE exchange so both parties arrive at a shared secret.
QTLS replaces that single step with a QKD key lookup:

    1. ClientHello  -- the client has already pulled a key from its KME and
                       puts the resulting ``key_ID`` (a UUID) in this message.
    2. ServerHello  -- the server has fetched the *same* key_ID from its KME
                       (the KMEs are synchronised, Phase 3) and confirms.
    3. Both sides feed that QKD key into the identical TLS 1.3 HKDF schedule
       (Phase 5 keyschedule.py) and derive traffic keys.
    4. Finished     -- each side sends an HMAC over the handshake transcript
                       using a key derived from the QKD secret. A correct
                       Finished proves the peer holds the *same* QKD key
                       (mutual key confirmation) and that the transcript was
                       not tampered with.

Everything else -- message framing, transcript hashing, the Finished check --
follows RFC 8446's structure, which is what justifies calling the protocol
"TLS 1.3-shaped".

Messages are serialised as compact JSON. A binary TLS-exact encoding would add
no security and a lot of parsing code; JSON keeps the handshake auditable in
captures and is explicitly a presentation choice, not a security one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

PROTOCOL_VERSION = "QTLS/1.0"


@dataclass
class ClientHello:
    """First flight. ``key_id`` is the QKD key the client obtained from its
    KME's ``enc_keys``; the server will fetch the same id via ``dec_keys``."""

    version: str
    client_random: str  # 32 random bytes, hex -- transcript freshness only
    key_id: str         # UUID string of the QKD key
    sae_id: str         # the client's SAE identity (cert CN in real mTLS)

    def encode(self) -> bytes:
        return json.dumps(
            {
                "msg": "client_hello",
                "version": self.version,
                "client_random": self.client_random,
                "key_id": self.key_id,
                "sae_id": self.sae_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    @staticmethod
    def decode(raw: bytes) -> "ClientHello":
        d = json.loads(raw)
        if d.get("msg") != "client_hello":
            raise ValueError("not a ClientHello")
        return ClientHello(
            version=d["version"],
            client_random=d["client_random"],
            key_id=d["key_id"],
            sae_id=d["sae_id"],
        )


@dataclass
class ServerHello:
    """Server confirms it resolved the same ``key_id`` from its KME."""

    version: str
    server_random: str
    key_id: str  # echoed back: must equal the ClientHello key_id

    def encode(self) -> bytes:
        return json.dumps(
            {
                "msg": "server_hello",
                "version": self.version,
                "server_random": self.server_random,
                "key_id": self.key_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    @staticmethod
    def decode(raw: bytes) -> "ServerHello":
        d = json.loads(raw)
        if d.get("msg") != "server_hello":
            raise ValueError("not a ServerHello")
        return ServerHello(
            version=d["version"],
            server_random=d["server_random"],
            key_id=d["key_id"],
        )


@dataclass
class Finished:
    """Key-confirmation MAC over the handshake transcript.

    ``verify_data`` is HMAC(finished_key, transcript_hash). Because
    ``finished_key`` is derived from the QKD secret, only a peer holding the
    same QKD key can produce a value that checks out -- this is the moment the
    handshake proves both endpoints really share the QKD key.
    """

    verify_data: str  # hex

    def encode(self) -> bytes:
        return json.dumps(
            {"msg": "finished", "verify_data": self.verify_data},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    @staticmethod
    def decode(raw: bytes) -> "Finished":
        d = json.loads(raw)
        if d.get("msg") != "finished":
            raise ValueError("not a Finished")
        return Finished(verify_data=d["verify_data"])


class HandshakeError(RuntimeError):
    """The handshake failed: version mismatch, key_ID mismatch, or a Finished
    that did not verify (peer does not hold the same QKD key, or the
    transcript was tampered with). The connection must be aborted."""
