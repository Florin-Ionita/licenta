"""Throughput benchmark: bulk data over QTLS (OTP+WC) vs TLS 1.3 (AES-GCM).

For each payload size in ``cfg.throughput_bytes`` we transfer that many bytes
client->server through a sequence of QTLS sessions (one fresh session per OTP
budget) and report MB/s. The re-handshake cost is included on purpose -- it
is exactly the constraint a real OTP-over-QKD deployment would face, and the
thesis's evaluation chapter is honest about it.

Critical correctness points (each previously caused a hang):
  * Server-side per-connection task must FULLY exit before we call
    ``server.wait_closed()`` -- otherwise wait_closed() blocks forever.
  * The OTP-exhaust signal from the record layer is treated as end-of-session,
    not as an error. We catch by class name so we don't have to import the
    private exception type.
  * The receiver must keep draining while the sender pushes; on loopback
    Python's pipe buffer is tiny and a non-draining peer deadlocks the
    sender within a few records.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import tempfile
import time
from pathlib import Path

from benchmarks.common import (
    BenchConfig, _BenchStack, write_csv,
)
from benchmarks.handshake import _make_self_signed
from kme.store import KeyStore
from qtls.connection import accept, connect
from qtls.kme_client import KMEClient


CHUNK = 4 * 1024               # 4 KiB application records
# KME block size used for the bench. Larger blocks mean more OTP per session
# (and therefore fewer re-handshakes per MB). 64 KiB is realistic for a real
# QKD deployment that batches keys before exposing them via ETSI.
KEY_SIZE_BITS = 64 * 1024 * 8  # 64 KiB
HANDSHAKE_TIMEOUT = 10.0
DRAIN_TIMEOUT = 5.0


# -- QTLS path -------------------------------------------------------------


async def _one_qtls_session(stack: _BenchStack, payload_bytes: bytes,
                            remaining: int) -> int:
    """Open one QTLS session, push as much as the OTP budget allows.

    Returns the number of bytes successfully *sent and acknowledged by the
    receiver* (we measure recv-side counters to be honest about end-to-end
    throughput, not just send-side queue accept).
    """
    received = 0
    received_done = asyncio.Event()

    async def server_handler(reader, writer):
        nonlocal received
        try:
            conn = await asyncio.wait_for(
                accept(reader, writer,
                       stack.kme_client(stack.kme_b, stack.server_sae),
                       stack.server_sae),
                timeout=HANDSHAKE_TIMEOUT,
            )
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()
            received_done.set()
            return
        try:
            while True:
                try:
                    data = await asyncio.wait_for(conn.recv(), timeout=DRAIN_TIMEOUT)
                except (asyncio.TimeoutError, ConnectionError):
                    break
                except Exception as exc:
                    # OTP exhausted on the recv side: clean end of session.
                    if type(exc).__name__ == "OTPKeyExhaustedError":
                        break
                    raise
                received += len(data)
        finally:
            with contextlib.suppress(Exception):
                await conn.close()
            received_done.set()

    server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    sent = 0
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client_conn = await asyncio.wait_for(
            connect(reader, writer,
                    stack.kme_client(stack.kme_a, stack.client_sae),
                    stack.client_sae, stack.server_sae),
            timeout=HANDSHAKE_TIMEOUT,
        )
        try:
            while sent < remaining:
                n = min(CHUNK, remaining - sent)
                try:
                    await client_conn.send(payload_bytes[:n])
                except Exception as exc:
                    if type(exc).__name__ == "OTPKeyExhaustedError":
                        break
                    raise
                sent += n
        finally:
            with contextlib.suppress(Exception):
                await client_conn.close()
    finally:
        # Give the server a brief window to drain remaining records, then
        # force-close. wait() guarantees the handler exited so server close is
        # safe and won't hang.
        try:
            await asyncio.wait_for(received_done.wait(), timeout=DRAIN_TIMEOUT)
        except asyncio.TimeoutError:
            pass
        server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), timeout=DRAIN_TIMEOUT)
    return min(received, sent)   # report ack'd bytes


async def _qtls_transfer(total: int) -> tuple[float, int]:
    """Transfer ``total`` bytes over QTLS, opening fresh sessions as needed."""
    # Each session uses about half the KME key block bytes per direction after
    # the schedule reserve. With 8 KiB blocks that's ~4 KiB OTP per direction,
    # minus 16 B per record overhead. Estimate generously.
    # Per session we can ship ~ (KEY_SIZE_BITS/8 - 32) / 2 OTP bytes per
    # direction, minus 16 B per record. With 64 KiB blocks that's ~32 KiB/sess.
    blocks_est = max(8, total // (24 * 1024) + 8)
    transferred = 0
    payload = b"x" * CHUNK
    start = time.perf_counter()
    async with _BenchStack(prefill_blocks=blocks_est,
                            key_size_bits=KEY_SIZE_BITS) as stack:
        while transferred < total:
            got = await _one_qtls_session(stack, payload, total - transferred)
            if got <= 0:
                # Defensive: never make zero forward progress, otherwise we'd
                # spin forever. Surface as a stop condition with a clear error.
                raise RuntimeError(
                    f"QTLS session made no progress at {transferred}/{total}; "
                    f"KME pool exhausted?"
                )
            transferred += got
    elapsed = time.perf_counter() - start
    return elapsed, transferred


# -- TLS 1.3 baseline ------------------------------------------------------


async def _tls13_transfer(total: int) -> tuple[float, int]:
    cert_pem, key_pem = _make_self_signed()
    cf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cf.write(cert_pem); cf.close()
    kf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    kf.write(key_pem); kf.close()

    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(cf.name, kf.name)
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE

    received = 0
    received_done = asyncio.Event()

    async def handler(reader, writer):
        nonlocal received
        try:
            while True:
                chunk = await reader.read(CHUNK)
                if not chunk:
                    break
                received += len(chunk)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            received_done.set()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=sctx)
    port = server.sockets[0].getsockname()[1]

    payload = b"x" * CHUNK
    sent = 0
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=cctx, server_hostname="localhost",
        )
        try:
            while sent < total:
                n = min(CHUNK, total - sent)
                writer.write(payload[:n])
                await writer.drain()
                sent += n
        finally:
            # ssl transports raise NotImplementedError on write_eof, so we
            # just close: the receiver sees EOF when read returns b"".
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        try:
            await asyncio.wait_for(received_done.wait(), timeout=DRAIN_TIMEOUT)
        except asyncio.TimeoutError:
            pass
        server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), timeout=DRAIN_TIMEOUT)
        Path(cf.name).unlink(missing_ok=True)
        Path(kf.name).unlink(missing_ok=True)
    elapsed = time.perf_counter() - start
    return elapsed, min(received, sent)


# -- entry point -----------------------------------------------------------


async def run(cfg: BenchConfig) -> dict:
    rows = []
    summary: dict = {"qtls": [], "tls13": []}
    for size in cfg.throughput_bytes:
        print(f"   throughput: {size // 1024} KiB QTLS ...", flush=True)
        q_t, q_n = await _qtls_transfer(size)
        rows.append(["qtls", size, q_n, q_t, q_n / 1e6 / q_t])
        summary["qtls"].append({"bytes": size, "seconds": q_t,
                                "mbps": q_n / 1e6 / q_t})
        print(f"   throughput: {size // 1024} KiB TLS 1.3 ...", flush=True)
        t_t, t_n = await _tls13_transfer(size)
        rows.append(["tls13", size, t_n, t_t, t_n / 1e6 / t_t])
        summary["tls13"].append({"bytes": size, "seconds": t_t,
                                 "mbps": t_n / 1e6 / t_t})
    write_csv("throughput",
              ["protocol", "requested_bytes", "transferred_bytes",
               "seconds", "MB_per_s"], rows)
    return summary
