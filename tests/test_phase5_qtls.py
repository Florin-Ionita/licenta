"""Phase 5 acceptance tests.

'Done' criterion from the thesis plan:
  * A client sends "Hello, server" over QTLS, the server decrypts it
    correctly and verifies the Wegman-Carter tag; the wire carries
    ciphertext only.

We exercise the *full* stack in-process: real FastAPI KMEs (Phase 3) reached
over httpx's ASGI transport, the HKDF schedule (Phase 5), and the OTP +
Wegman-Carter record layer (Phase 4), connected by a real asyncio TCP socket
on loopback so the "wire" is genuine bytes we can inspect.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from kme.api import create_kme_app
from kme.network import make_kme_pair
from qkd.keyblock import KeyBlock
from qtls.connection import accept, connect
from qtls.handshake import HandshakeError
from qtls.kme_client import KMEClient
from qtls.records import RecordAuthenticationError

CLIENT_SAE = "SAE-CLIENT"
SERVER_SAE = "SAE-SERVER"
# A few KB of key: 32 B for the HKDF schedule, the rest is OTP record budget.
QKD_KEY = bytes((i * 7 + 13) % 256 for i in range(4096))


def _kme_pair_with_key():
    """Two synchronised KMEs preloaded with one shared QKD key block."""
    a, b = make_kme_pair(key_size_bits=len(QKD_KEY) * 8)
    a.authorise(CLIENT_SAE, SERVER_SAE)
    b.authorise(CLIENT_SAE, SERVER_SAE)
    block = KeyBlock(material=QKD_KEY, source="bb84-visual", qber=0.0)
    a.add_block(block)
    b.add_block(block)
    return a, b


def _kme_client(store, sae_id: str) -> KMEClient:
    """A KMEClient wired to a KME app over httpx's in-process ASGI transport
    (no real socket for the KME -- the QTLS link itself uses a real socket)."""
    app = create_kme_app(store, peer_kme_id="peer")
    transport = httpx.ASGITransport(app=app)
    http = httpx.AsyncClient(transport=transport, base_url="http://kme.local")
    return KMEClient(http, sae_id)


async def _run_pair(server_logic, client_logic):
    """Start a loopback TCP server, run server_logic per connection and
    client_logic once connected; return the client_logic result."""
    a, b = _kme_pair_with_key()
    server_kme = _kme_client(b, SERVER_SAE)
    client_kme = _kme_client(a, CLIENT_SAE)

    result_box: dict = {}

    async def handle(reader, writer):
        try:
            conn = await accept(reader, writer, server_kme, SERVER_SAE)
            await server_logic(conn)
        except Exception as e:  # surface server-side failures to the test
            result_box["server_error"] = e
        finally:
            writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    async with srv:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            conn = await connect(
                reader, writer, client_kme, CLIENT_SAE, SERVER_SAE
            )
            result_box["client"] = await client_logic(conn)
        finally:
            writer.close()
            await asyncio.sleep(0.05)  # let the server task finish
    return result_box


# --------------------------------------------------------------------------
# THE core criterion
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_client_message_decrypts_and_authenticates_server_side():
    received: dict = {}

    async def server_logic(conn):
        received["msg"] = await conn.recv()
        await conn.send(b"ack")

    async def client_logic(conn):
        await conn.send(b"Hello, server")
        return await conn.recv()

    box = await _run_pair(server_logic, client_logic)
    assert "server_error" not in box, box.get("server_error")
    assert received["msg"] == b"Hello, server"  # decrypted correctly
    assert box["client"] == b"ack"              # bidirectional works


@pytest.mark.asyncio
async def test_wire_carries_ciphertext_only():
    """Tap the real socket: the plaintext must never appear on the wire."""
    captured = bytearray()
    secret = b"TOP-SECRET-PLAINTEXT-MARKER"

    a, b = _kme_pair_with_key()
    server_kme = _kme_client(b, SERVER_SAE)
    client_kme = _kme_client(a, CLIENT_SAE)

    async def handle(reader, writer):
        conn = await accept(reader, writer, server_kme, SERVER_SAE)
        await conn.recv()
        writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    async with srv:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Wrap the writer so we see every byte actually sent on the socket.
        orig_write = writer.write

        def tap(data):
            captured.extend(data)
            return orig_write(data)

        writer.write = tap

        conn = await connect(
            reader, writer, client_kme, CLIENT_SAE, SERVER_SAE
        )
        await conn.send(secret)
        await asyncio.sleep(0.05)
        writer.close()

    assert secret not in bytes(captured), "plaintext leaked onto the wire!"
    assert len(captured) > 0


# --------------------------------------------------------------------------
# Security / robustness
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tampered_record_is_rejected():
    """Flipping a ciphertext byte must make the WC tag fail on receipt."""
    a, b = _kme_pair_with_key()
    server_kme = _kme_client(b, SERVER_SAE)
    client_kme = _kme_client(a, CLIENT_SAE)
    server_err: dict = {}

    async def handle(reader, writer):
        try:
            conn = await accept(reader, writer, server_kme, SERVER_SAE)
            await conn.recv()
        except RecordAuthenticationError as e:
            server_err["e"] = e
        finally:
            writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    async with srv:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        orig_write = writer.write
        tamper_armed = {"on": False, "done": False}

        def tamper(data):
            # Only corrupt the first APPLICATION record. The tamper is armed
            # *after* the handshake completes, so handshake frames pass
            # through intact and we are genuinely testing record-layer tag
            # rejection (not a broken handshake).
            if tamper_armed["on"] and not tamper_armed["done"]:
                data = bytearray(data)
                data[-1] ^= 0xFF  # flip a ciphertext/tag byte
                tamper_armed["done"] = True
                data = bytes(data)
            return orig_write(data)

        writer.write = tamper
        conn = await connect(
            reader, writer, client_kme, CLIENT_SAE, SERVER_SAE
        )
        tamper_armed["on"] = True  # handshake done; corrupt the next record
        await conn.send(b"this will be corrupted in flight")
        await asyncio.sleep(0.1)
        writer.close()

    assert "e" in server_err
    assert isinstance(server_err["e"], RecordAuthenticationError)


@pytest.mark.asyncio
async def test_handshake_fails_when_server_kme_lacks_key():
    """If the server's KME cannot resolve the key_ID, the handshake aborts
    rather than proceeding with mismatched keys."""
    a, _ = _kme_pair_with_key()
    # Server KME is a *fresh* unrelated store with no shared key/authorisation.
    from kme.store import KeyStore

    empty = KeyStore(kme_id="KME-EMPTY")
    server_kme = _kme_client(empty, SERVER_SAE)
    client_kme = _kme_client(a, CLIENT_SAE)
    server_err: dict = {}

    async def handle(reader, writer):
        try:
            await accept(reader, writer, server_kme, SERVER_SAE)
        except Exception as e:
            server_err["e"] = e
        finally:
            writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    async with srv:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        with pytest.raises((HandshakeError, Exception)):
            conn = await connect(
                reader, writer, client_kme, CLIENT_SAE, SERVER_SAE
            )
            await conn.recv()  # handshake won't complete
        writer.close()
    assert "e" in server_err  # server also detected the failure


@pytest.mark.asyncio
async def test_multiple_records_stay_in_lockstep():
    """Many sequential records must each decrypt -- proves the two OTP
    streams advance in perfect lockstep across records."""
    async def server_logic(conn):
        for _ in range(10):
            m = await conn.recv()
            await conn.send(m.upper())

    async def client_logic(conn):
        out = []
        for i in range(10):
            await conn.send(f"message-{i}".encode())
            out.append(await conn.recv())
        return out

    box = await _run_pair(server_logic, client_logic)
    assert "server_error" not in box, box.get("server_error")
    assert box["client"] == [f"MESSAGE-{i}".encode() for i in range(10)]
