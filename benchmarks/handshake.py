"""Handshake-latency benchmark: QTLS vs classic TLS 1.3.

We measure ``time.perf_counter_ns`` around a complete handshake (ClientHello
through Finished, both directions). For each iteration we open a fresh TCP
connection and tear it down -- this includes socket setup costs, which mirrors
real-world reconnect cost. We deliberately do NOT use pyperf's wall-clock
budgeting because every iteration carries a non-trivial async setup; instead
we do classical warmup + many runs + report median / p95 / p99.

The TLS 1.3 baseline uses Python's stdlib ``ssl`` with X25519 key exchange
(stdlib default for TLS 1.3) and a self-signed RSA cert generated once at
startup. The single SAE-vs-cert difference is exactly the comparison the
thesis makes: QKD key delivery in place of an ECDHE.
"""

from __future__ import annotations

import asyncio
import ssl
import statistics
import time
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from benchmarks.common import (
    BenchConfig, _BenchStack, open_qtls_pair, write_csv,
)


@dataclass
class LatencyReport:
    label: str           # "qtls" / "tls13"
    samples_ns: list[int]

    def stats(self) -> dict[str, float]:
        s = sorted(self.samples_ns)
        n = len(s)
        return {
            "n": n,
            "mean_ms":   statistics.fmean(s) / 1e6,
            "stdev_ms":  (statistics.pstdev(s) / 1e6) if n > 1 else 0.0,
            "median_ms": statistics.median(s) / 1e6,
            "p95_ms":    s[min(n - 1, int(n * 0.95))] / 1e6,
            "p99_ms":    s[min(n - 1, int(n * 0.99))] / 1e6,
            "min_ms":    s[0] / 1e6,
            "max_ms":    s[-1] / 1e6,
        }


# -- QTLS path -------------------------------------------------------------


async def _bench_qtls(cfg: BenchConfig) -> LatencyReport:
    # Prefill heavily so we don't run out of keys mid-benchmark.
    # Each handshake consumes one KME key (1 KiB), so prefill = iters + warmup.
    needed = cfg.handshake_iters + cfg.handshake_warmup + 32
    samples: list[int] = []
    async with _BenchStack(prefill_blocks=needed) as stack:
        # Warmup.
        for _ in range(cfg.handshake_warmup):
            c, s, srv = await open_qtls_pair(stack)
            await c.close(); await s.close()
            srv.close(); await srv.wait_closed()
        # Measure.
        for _ in range(cfg.handshake_iters):
            t0 = time.perf_counter_ns()
            c, s, srv = await open_qtls_pair(stack)
            samples.append(time.perf_counter_ns() - t0)
            await c.close(); await s.close()
            srv.close(); await srv.wait_closed()
    return LatencyReport("qtls", samples)


# -- TLS 1.3 baseline ------------------------------------------------------


def _make_self_signed() -> tuple[bytes, bytes]:
    """Generate a fresh RSA-2048 self-signed cert for the localhost TLS server."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime.utcnow())
        .not_valid_after(__import__("datetime").datetime.utcnow()
                         + __import__("datetime").timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


async def _bench_tls13(cfg: BenchConfig) -> LatencyReport:
    cert_pem, key_pem = _make_self_signed()
    # Write to temp files because SSLContext only loads from disk.
    import tempfile, os
    cert_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_f.write(cert_pem); cert_f.flush(); cert_f.close()
    key_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_f.write(key_pem); key_f.flush(); key_f.close()

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    server_ctx.load_cert_chain(cert_f.name, key_f.name)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE  # self-signed; baseline only

    async def handler(reader, writer):
        # Idle until the client closes -- the handshake already happened.
        try:
            await reader.read(1)
        except Exception:
            pass
        writer.close()
        with __import__("contextlib").suppress(Exception):
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]

    try:
        for _ in range(cfg.handshake_warmup):
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_ctx, server_hostname="localhost",
            )
            writer.close()
            with __import__("contextlib").suppress(Exception):
                await writer.wait_closed()

        samples: list[int] = []
        for _ in range(cfg.handshake_iters):
            t0 = time.perf_counter_ns()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_ctx, server_hostname="localhost",
            )
            samples.append(time.perf_counter_ns() - t0)
            writer.close()
            with __import__("contextlib").suppress(Exception):
                await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
        import os
        os.unlink(cert_f.name); os.unlink(key_f.name)
    return LatencyReport("tls13", samples)


async def run(cfg: BenchConfig) -> dict:
    qtls = await _bench_qtls(cfg)
    tls = await _bench_tls13(cfg)

    write_csv(
        "handshake_latency",
        ["protocol", "iter", "elapsed_ns"],
        [[r.label, i, ns] for r in (qtls, tls) for i, ns in enumerate(r.samples_ns)],
    )
    return {"qtls": qtls.stats(), "tls13": tls.stats(),
            "qtls_samples_ns": qtls.samples_ns,
            "tls13_samples_ns": tls.samples_ns}
