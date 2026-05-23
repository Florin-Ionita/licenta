"""A small chat / file-transfer application that runs over QTLS.

Two roles:

  * **server** -- listens on a TCP port, completes the QTLS handshake for each
    connection, then prints whatever the peer sends and echoes an
    acknowledgement.
  * **client** -- connects, completes the handshake, and either relays lines
    typed on stdin (interactive chat) or, in ``--file`` mode, streams a 1 MB
    payload to deliberately stress the QKD key pool.

The file-transfer mode is the visible demonstration of QKD's defining
constraint: One-Time Pad consumes one key bit per message bit, so a 1 MB
transfer drains ~1 MB of key from the KME pool. Watching the pool empty (and
the connection hit back-pressure when it does) is exactly the thesis point
about maximum security at the cost of key bandwidth.

The networking/handshake reuses Phase 5 unchanged; this file only adds the
application-level send/receive loops, so the demo runs the same validated
code path as the tests.
"""

from __future__ import annotations

import argparse
import asyncio

from qtls.connection import accept, connect
from qtls.crypto.otp import OTPKeyExhaustedError
from qtls.kme_client import KMEClient
from qtls.records import RecordAuthenticationError

# Application framing: each chat message is one QTLS application record. The
# chunk is kept well below one connection's OTP budget so a transfer is sent
# as *many* records -- which makes the key pool drain gradually and
# observably (the visual point) instead of failing on the first oversized
# record. A 1 MB transfer over QKD-rate key will hit back-pressure long
# before completion; that is the demonstration, not a bug.
CHUNK = 1024
ONE_MB = 1024 * 1024


async def run_server_connection(reader, writer, kme: KMEClient, server_sae: str,
                                on_message=None) -> None:
    """Handle one inbound QTLS connection: receive messages until the peer
    closes, optionally invoking ``on_message(bytes)`` for each (used by tests
    and the visualization)."""
    conn = await accept(reader, writer, kme, server_sae)
    total = 0
    try:
        while True:
            try:
                data = await conn.recv()
            except (ConnectionError, RecordAuthenticationError):
                break
            total += len(data)
            if on_message is not None:
                on_message(data)
            # Acknowledge with the running byte count so the client (and the
            # demo viewer) can see progress.
            try:
                await conn.send(f"ack:{total}".encode())
            except OTPKeyExhaustedError:
                # Pool drained mid-transfer: this is the demonstrable QKD
                # back-pressure, not a crash. Stop gracefully.
                break
    finally:
        await conn.close()


async def send_message(conn, text: bytes) -> bytes:
    """Send one message and return the server's acknowledgement."""
    await conn.send(text)
    return await conn.recv()


async def run_chat_client(reader, writer, kme: KMEClient,
                          client_sae: str, server_sae: str,
                          lines: list[bytes]) -> list[bytes]:
    """Send each item in ``lines`` as a message; collect the acks.

    A real interactive CLI would read stdin in a loop; ``lines`` makes the
    same logic deterministic and testable. The CLI wrapper below feeds stdin
    into this function.
    """
    conn = await connect(reader, writer, kme, client_sae, server_sae)
    acks: list[bytes] = []
    try:
        for line in lines:
            acks.append(await send_message(conn, line))
    finally:
        await conn.close()
    return acks


async def run_file_client(reader, writer, kme: KMEClient,
                          client_sae: str, server_sae: str,
                          total_bytes: int = ONE_MB) -> dict:
    """Stream ``total_bytes`` to the server in CHUNK-sized records.

    Returns a small report: bytes sent before completion or before the key
    pool was exhausted. Hitting :class:`OTPKeyExhaustedError` is a *success*
    of the demonstration -- it is the QKD constraint made visible -- so it is
    reported, not raised.
    """
    conn = await connect(reader, writer, kme, client_sae, server_sae)
    sent = 0
    exhausted = False
    payload = b"Q" * CHUNK
    try:
        while sent < total_bytes:
            try:
                await conn.send(payload)
                await conn.recv()  # wait for ack (flow control)
            except OTPKeyExhaustedError:
                exhausted = True
                break
            sent += len(payload)
    finally:
        await conn.close()
    return {"bytes_sent": sent, "key_pool_exhausted": exhausted}


# --------------------------------------------------------------------------
# CLI wrapper (interactive use; the demo runtime wires the KME for you)
# --------------------------------------------------------------------------

async def _cli_server(host: str, port: int) -> None:
    from app.demo_runtime import DemoStack

    async with DemoStack() as stack:
        server_kme = stack.server_kme()

        async def handle(r, w):
            await run_server_connection(
                r, w, server_kme, stack.server_sae,
                on_message=lambda d: print(f"[server] recv {len(d)} bytes"),
            )

        srv = await asyncio.start_server(handle, host, port)
        print(f"[server] QTLS listening on {host}:{port}")
        async with srv:
            await srv.serve_forever()


async def _cli_client(host: str, port: int, file_mode: bool) -> None:
    from app.demo_runtime import DemoStack

    async with DemoStack() as stack:
        client_kme = stack.client_kme()
        reader, writer = await asyncio.open_connection(host, port)
        if file_mode:
            report = await run_file_client(
                reader, writer, client_kme,
                stack.client_sae, stack.server_sae,
            )
            print(f"[client] file transfer report: {report}")
        else:
            print("[client] type messages, empty line to quit")
            lines = []
            loop = asyncio.get_running_loop()
            while True:
                line = await loop.run_in_executor(None, input, "> ")
                if not line:
                    break
                lines.append(line.encode())
            acks = await run_chat_client(
                reader, writer, client_kme,
                stack.client_sae, stack.server_sae, lines,
            )
            for a in acks:
                print(f"[client] server said: {a.decode()}")


def main() -> None:
    p = argparse.ArgumentParser(description="QTLS demo chat / file transfer")
    p.add_argument("role", choices=["server", "client"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument(
        "--file",
        action="store_true",
        help="client: stream 1 MB to stress the QKD key pool",
    )
    args = p.parse_args()
    if args.role == "server":
        asyncio.run(_cli_server(args.host, args.port))
    else:
        asyncio.run(_cli_client(args.host, args.port, args.file))


if __name__ == "__main__":
    main()
