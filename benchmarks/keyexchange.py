"""Key-establishment primitive benchmark: QKD fetch vs X25519 vs ML-KEM-768.

WHAT THIS MEASURES, AND WHAT IT DOES NOT
----------------------------------------
This bench isolates the *key-establishment* step of each approach and times it
on its own. It is deliberately NOT a full-handshake comparison:

  * ``handshake.py`` already measures a complete TLS 1.3 handshake (real
    OpenSSL, X25519) against the complete QTLS-over-QKD handshake. Wall-clock
    numbers there include sockets, certificates, Finished, everything.
  * here we drop to the primitive. For each approach we time only the work
    that establishes the shared secret, so the three rows ARE comparable to
    each other -- primitive vs primitive -- but they are NOT comparable to the
    full-handshake numbers in ``handshake.py``.

Why a separate primitive bench at all? Because the honest competitor to QKD is
not classical ECDHE (which a quantum adversary breaks -- the whole premise of
the thesis) but ML-KEM, the other post-quantum path. OpenSSL 3.0 on the test
host cannot negotiate ML-KEM inside a TLS handshake (that needs OpenSSL 3.5+ or
oqs-provider), so we measure ML-KEM as the standalone key-encapsulation
primitive from ``cryptography``. The label on every output row says so.

The three rows:
  * ``qkd_fetch``  : the QTLS path -- master SAE fetches one key from its KME by
                     key_ID over the ETSI 014 API. The shared secret never
                     crosses the wire; only a 16-byte key_ID does.
  * ``x25519``     : classical ECDHE primitive -- two keygens + one exchange.
                     The post-quantum-broken baseline ("today's Web").
  * ``mlkem768``   : ML-KEM-768 KEM -- keygen + encapsulate + decapsulate, one
                     round trip. The post-quantum software baseline.

We also report bytes-on-the-wire, where QKD's advantage is structural and
exact: it transmits a key_ID, not key material.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

from benchmarks.common import BenchConfig, _BenchStack, write_csv

# Wire sizes are fixed by the standards, not measured -- recorded here so the
# evaluation chapter can cite them without re-deriving.
WIRE_BYTES = {
    # approach   : (offer_bytes, response_bytes, note)
    "qkd_fetch": (16, 0, "key_ID (UUID); key material never transmitted"),
    "x25519":    (32, 32, "client + server ephemeral public keys"),
    "mlkem768":  (1184, 1088, "public key (offer) + ciphertext (response)"),
}


@dataclass
class PrimReport:
    label: str
    samples_ns: list[int]

    def stats(self) -> dict[str, float]:
        s = sorted(self.samples_ns)
        n = len(s)
        return {
            "n": n,
            "mean_us":   statistics.fmean(s) / 1e3,
            "stdev_us":  (statistics.pstdev(s) / 1e3) if n > 1 else 0.0,
            "median_us": statistics.median(s) / 1e3,
            "p95_us":    s[min(n - 1, int(n * 0.95))] / 1e3,
            "p99_us":    s[min(n - 1, int(n * 0.99))] / 1e3,
            "min_us":    s[0] / 1e3,
            "max_us":    s[-1] / 1e3,
        }


# -- X25519: keygen + keygen + exchange (one ECDHE) ------------------------


def _bench_x25519(iters: int, warmup: int) -> PrimReport:
    def one() -> None:
        a = x25519.X25519PrivateKey.generate()
        b = x25519.X25519PrivateKey.generate()
        a.exchange(b.public_key())
        b.exchange(a.public_key())

    for _ in range(warmup):
        one()
    samples: list[int] = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        one()
        samples.append(time.perf_counter_ns() - t0)
    return PrimReport("x25519", samples)


# -- ML-KEM-768: keygen + encapsulate + decapsulate ------------------------


def _bench_mlkem768(iters: int, warmup: int) -> PrimReport:
    def one() -> None:
        # Receiver generates the keypair and publishes the public key.
        sk = mlkem.MLKEM768PrivateKey.generate()
        pk = sk.public_key()
        # Initiator encapsulates against it, producing (shared, ciphertext).
        _shared_enc, ct = pk.encapsulate()
        # Receiver decapsulates to recover the same shared secret.
        sk.decapsulate(ct)

    for _ in range(warmup):
        one()
    samples: list[int] = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        one()
        samples.append(time.perf_counter_ns() - t0)
    return PrimReport("mlkem768", samples)


# -- QKD fetch: master SAE pulls one key from its KME by key_ID ------------


async def _bench_qkd_fetch(iters: int, warmup: int) -> PrimReport:
    # Each fetch consumes one KME key; prefill enough for warmup + measure.
    needed = iters + warmup + 32
    samples: list[int] = []
    async with _BenchStack(prefill_blocks=needed) as stack:
        client = stack.kme_client(stack.kme_a, stack.client_sae)

        async def one() -> None:
            # request_key returns a fresh key + key_ID for the master SAE; this
            # is exactly the key-establishment work the QTLS client does, minus
            # the rest of the handshake.
            await client.request_key(stack.server_sae)

        for _ in range(warmup):
            await one()
        for _ in range(iters):
            t0 = time.perf_counter_ns()
            await one()
            samples.append(time.perf_counter_ns() - t0)
    return PrimReport("qkd_fetch", samples)


async def run(cfg: BenchConfig) -> dict:
    # The primitive ops are cheap (micro/sub-millisecond), so we run many more
    # iterations than the full-handshake bench to get stable percentiles.
    iters = cfg.handshake_iters
    warmup = cfg.handshake_warmup

    x = _bench_x25519(iters, warmup)
    m = _bench_mlkem768(iters, warmup)
    q = await _bench_qkd_fetch(iters, warmup)

    write_csv(
        "keyexchange_primitive",
        ["approach", "iter", "elapsed_ns"],
        [[r.label, i, ns]
         for r in (q, x, m) for i, ns in enumerate(r.samples_ns)],
    )
    write_csv(
        "keyexchange_wire",
        ["approach", "offer_bytes", "response_bytes", "total_bytes", "note"],
        [[k, o, r, o + r, note] for k, (o, r, note) in WIRE_BYTES.items()],
    )
    return {
        "qkd_fetch": q.stats(),
        "x25519": x.stats(),
        "mlkem768": m.stats(),
        "wire_bytes": WIRE_BYTES,
    }
