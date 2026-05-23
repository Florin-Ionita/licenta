"""QTLS connection: handshake driver + authenticated record transport.

Ties together every earlier phase:

  * Phase 3 KME (via :mod:`qtls.kme_client`) supplies the shared QKD key.
  * Phase 5 :mod:`qtls.keyschedule` turns it into traffic secrets.
  * Phase 4 OTP + Wegman-Carter (via :mod:`qtls.records`) protect each record.
  * asyncio ``StreamReader``/``StreamWriter`` carry the framed bytes over TCP.

Directional key separation (a correctness must-have): the single QKD key is
deterministically split into two *disjoint* OTP segments -- one for
client->server records, one for server->client. If both directions drew from
the same bytes they would XOR plaintext into the same key positions = OTP
reuse across directions. Splitting first makes that impossible. Each direction
additionally gets its own reusable Wegman-Carter hash key from the schedule.
"""

from __future__ import annotations

import asyncio
import hmac
import os

from qtls.crypto.otp import OTPKeyStream
from qtls.handshake import (
    ClientHello,
    Finished,
    HandshakeError,
    PROTOCOL_VERSION,
    ServerHello,
)
from qtls.keyschedule import KeySchedule
from qtls.kme_client import KMEClient
from qtls.records import (
    RecordProtector,
    RecordType,
    read_record,
)

# Bytes of the QKD key reserved for the HKDF schedule before the rest is used
# as raw OTP record material. The schedule needs >= 32 bytes (SHA-256).
_SCHEDULE_BYTES = 32


def _split_streams(otp_material: bytes) -> tuple[OTPKeyStream, OTPKeyStream]:
    """Split raw OTP material into disjoint c->s and s->c key streams.

    The two halves never overlap, so the two directions can never apply the
    same key byte (no cross-direction OTP reuse).
    """
    half = len(otp_material) // 2
    c2s = otp_material[:half]
    s2c = otp_material[half: 2 * half]
    return OTPKeyStream(c2s), OTPKeyStream(s2c)


class QTLSConnection:
    """An established QTLS connection with directional record protection.

    Created by :func:`connect` (client) or :func:`accept` (server). After the
    handshake, :meth:`send` / :meth:`recv` exchange authenticated, encrypted
    application records.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        send_protector: RecordProtector,
        recv_protector: RecordProtector,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._send = send_protector
        self._recv = recv_protector
        self._rx_buffer = b""

    # -- framed wire I/O ---------------------------------------------------

    async def _write_frame(self, data: bytes) -> None:
        """Length-prefix and write one handshake message (pre-record-layer)."""
        self._writer.write(len(data).to_bytes(4, "big") + data)
        await self._writer.drain()

    async def _read_frame(self) -> bytes:
        """Read one length-prefixed handshake message."""
        header = await self._reader.readexactly(4)
        length = int.from_bytes(header, "big")
        return await self._reader.readexactly(length)

    # -- application data --------------------------------------------------

    async def send(self, data: bytes) -> None:
        """Encrypt + authenticate ``data`` and write it as one record."""
        record = self._send.seal(RecordType.APPLICATION_DATA, data)
        self._writer.write(record)
        await self._writer.drain()

    async def recv(self) -> bytes:
        """Read, authenticate, and decrypt the next application record.

        Raises if the Wegman-Carter tag fails (forgery / corruption /
        desynchronised streams) -- an unrecoverable condition.
        """
        while True:
            framed = read_record(self._rx_buffer)
            if framed is not None:
                record, self._rx_buffer = framed
                rtype, plaintext = self._recv.open(record)
                if rtype is RecordType.APPLICATION_DATA:
                    return plaintext
                continue
            chunk = await self._reader.read(4096)
            if not chunk:
                raise ConnectionError("peer closed during recv")
            self._rx_buffer += chunk

    async def close(self) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def _build_protectors(
    qkd_key: bytes, transcript: bytes, *, is_client: bool
) -> tuple[RecordProtector, RecordProtector]:
    """Derive both directions' record protectors from the QKD key.

    Both endpoints run the *same* derivation, so the client's send protector
    and the server's receive protector wrap byte-identical key streams (and
    vice versa).
    """
    schedule = KeySchedule(qkd_key, transcript)
    otp_material = qkd_key[_SCHEDULE_BYTES:]
    if len(otp_material) < 2:
        raise HandshakeError("QKD key too short to carry record key material")

    c2s_stream, s2c_stream = _split_streams(otp_material)
    c2s_kh = KeySchedule.wc_hash_key(schedule.client_app_secret())
    s2c_kh = KeySchedule.wc_hash_key(schedule.server_app_secret())

    c2s = RecordProtector(c2s_stream, c2s_kh)
    s2c = RecordProtector(s2c_stream, s2c_kh)

    if is_client:
        return c2s, s2c  # client sends on c2s, receives on s2c
    return s2c, c2s      # server sends on s2c, receives on c2s


def _finished_value(qkd_key: bytes, transcript: bytes, label: str) -> str:
    schedule = KeySchedule(qkd_key, transcript)
    secret = (
        schedule.client_handshake_secret()
        if label == "client"
        else schedule.server_handshake_secret()
    )
    fk = KeySchedule.finished_key(secret)
    return hmac.new(fk, transcript, "sha256").hexdigest()


async def connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    kme: KMEClient,
    client_sae_id: str,
    server_sae_id: str,
) -> QTLSConnection:
    """Client side of the QTLS handshake over an open asyncio stream.

    Pulls a QKD key from the KME, sends its key_ID in the ClientHello,
    confirms the ServerHello echoes it, then both sides exchange Finished
    messages to prove they hold the same key.
    """
    key_id, qkd_key = await kme.request_key(server_sae_id)

    ch = ClientHello(
        version=PROTOCOL_VERSION,
        client_random=os.urandom(32).hex(),
        key_id=key_id,
        sae_id=client_sae_id,
    )
    conn = QTLSConnection(reader, writer, None, None)  # protectors set below
    await conn._write_frame(ch.encode())

    sh = ServerHello.decode(await conn._read_frame())
    if sh.version != PROTOCOL_VERSION:
        raise HandshakeError(f"version mismatch: {sh.version!r}")
    if sh.key_id != key_id:
        # The server resolved a different key -- the whole protocol depends on
        # this being identical, so abort loudly (Phase 3 should prevent it).
        raise HandshakeError("server echoed a different key_ID")

    transcript = ch.encode() + sh.encode()

    # Send our Finished, then verify the server's.
    await conn._write_frame(
        Finished(_finished_value(qkd_key, transcript, "client")).encode()
    )
    server_fin = Finished.decode(await conn._read_frame())
    expected = _finished_value(qkd_key, transcript, "server")
    if not hmac.compare_digest(server_fin.verify_data, expected):
        raise HandshakeError(
            "server Finished did not verify: peer does not hold the same "
            "QKD key, or the handshake was tampered with"
        )

    send_p, recv_p = _build_protectors(
        qkd_key, transcript, is_client=True
    )
    conn._send, conn._recv = send_p, recv_p
    return conn


async def accept(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    kme: KMEClient,
    server_sae_id: str,
) -> QTLSConnection:
    """Server side of the QTLS handshake.

    Reads the ClientHello, fetches the *same* key_ID from its KME, replies
    with ServerHello, then exchanges Finished messages.
    """
    conn = QTLSConnection(reader, writer, None, None)
    ch = ClientHello.decode(await conn._read_frame())
    if ch.version != PROTOCOL_VERSION:
        raise HandshakeError(f"unsupported client version {ch.version!r}")

    # Fetch the SAME key the client pulled, by its key_ID, from our KME.
    qkd_key = await kme.fetch_key(ch.sae_id, ch.key_id)

    sh = ServerHello(
        version=PROTOCOL_VERSION,
        server_random=os.urandom(32).hex(),
        key_id=ch.key_id,  # echo: proves we resolved the same id
    )
    await conn._write_frame(sh.encode())

    transcript = ch.encode() + sh.encode()

    # Verify the client's Finished, then send ours.
    client_fin = Finished.decode(await conn._read_frame())
    expected = _finished_value(qkd_key, transcript, "client")
    if not hmac.compare_digest(client_fin.verify_data, expected):
        raise HandshakeError(
            "client Finished did not verify: peer does not hold the same "
            "QKD key, or the handshake was tampered with"
        )
    await conn._write_frame(
        Finished(_finished_value(qkd_key, transcript, "server")).encode()
    )

    send_p, recv_p = _build_protectors(
        qkd_key, transcript, is_client=False
    )
    conn._send, conn._recv = send_p, recv_p
    return conn
