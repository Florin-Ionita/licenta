# Implementation Plan — Information-Theoretic Secure Protocol over Simulated QKD Network

*Phased roadmap for a Python bachelor's thesis*

## 0. Executive summary (TL;DR)

Build a **"TLS 1.3-shaped" protocol in pure Python**, where **the session key comes exclusively from a simulated QKD network**. Messages are encrypted with **One-Time Pad (OTP)** and authenticated with **Wegman-Carter MAC** — both providing *information-theoretic* security, meaning unbreakable regardless of the attacker's computational power (including quantum computers).

You use **Qiskit Aer** for the visual BB84 simulation (the demo wow-factor for your defense), **FastAPI** to expose the KME according to ETSI GS QKD 014, the **`cryptography`** library only for utilities (HKDF, hash primitives), and **Streamlit + Plotly** for live visualization. The whole project is pure Python — no liboqs, no native compilation, no PQC libraries.

**Your thesis message**: *when QKD infrastructure is available, you can achieve security strictly stronger than any computational algorithm, including ML-KEM. This is the "ideal" case I am exploring.*

---

## 1. System architecture

### 1.1 Components

```
┌──────────────────────────────────────────────────────────┐
│  VISUALIZATION LAYER  (Streamlit + Plotly + asyncio bus) │
└────────────┬───────────────┬──────────────┬──────────────┘
             │ events        │ events       │ events
┌────────────▼──────┐ ┌──────▼────────┐ ┌───▼─────────────┐
│ QKD SIMULATOR     │ │  KME (ETSI    │ │  QTLS CLIENT /  │
│  - BB84 quantum   │◀▶│  GS QKD 014  │◀▶│   QTLS SERVER  │
│    (qiskit aer)   │ │  FastAPI)     │ │  (asyncio)      │
│  - abstract bulk  │ │  - key pool   │ │  - handshake FSM│
│    generator      │ │  - SAE ACL    │ │  - record layer │
│  - trusted-node   │ │  - GET_STATUS │ │  - OTP + WC-MAC │
│    relay          │ │  - GET_KEY    │ │                 │
└───────────────────┘ └───────────────┘ └─────────────────┘
```

### 1.2 How the components talk to each other

* **QKD Simulator → KME**: after each key block is produced (sifting + privacy amplification), the simulator pushes `(key_id: UUID, key_material: bytes, peer_kme: str)` into the KMEs of both endpoints through an `asyncio.Queue`.
* **KME ↔ KME**: simulated trusted-node relay (XOR-based key forwarding) over an internal `asyncio` channel — sufficient to demonstrate multi-hop.
* **SAE (TLS endpoint) ↔ KME**: real HTTPS REST calls per ETSI GS QKD 014, with mTLS authentication using locally-generated certificates.
* **QTLS client ↔ QTLS server**: TCP via `asyncio.open_connection` / `asyncio.start_server`, carrying "TLS 1.3-shaped" records.
* **All components → Visualization**: publish/subscribe over an in-process event bus (`asyncio.Queue`); Streamlit reads from `st.session_state` with autorefresh at 5-10 Hz.

### 1.3 File structure

```
qtls-qkd/
├── pyproject.toml
├── README.md
├── certs/                        # mTLS certificates for KME
├── qkd/
│   ├── __init__.py
│   ├── bb84.py                   # Qiskit quantum simulation (visual)
│   ├── abstract_link.py          # high-volume key generator
│   ├── reconciliation.py         # simplified cascade, privacy amplification
│   ├── node.py                   # Alice/Bob nodes, relay logic
│   └── network.py                # multi-node topology + feeders
├── kme/
│   ├── __init__.py
│   ├── api.py                    # FastAPI: /api/v1/keys/...
│   ├── store.py                  # in-memory key pool, ACL, expiry
│   └── models.py                 # pydantic schemas
├── qtls/
│   ├── __init__.py
│   ├── records.py                # TLS-shaped record layer
│   ├── handshake.py              # ClientHello, ServerHello, Finished
│   ├── crypto/
│   │   ├── otp.py                # OTP cipher
│   │   └── wc_mac.py             # Wegman-Carter MAC
│   ├── client.py
│   └── server.py
├── app/
│   ├── demo_chat.py              # chat application over QTLS
│   └── benchmarks.py
├── viz/
│   ├── main.py                   # Streamlit entry point
│   ├── components/               # panels: photons, handshake, etc.
│   └── bus.py                    # event bus subscriber
└── tests/
```

### 1.4 How "TLS-shaped" with QKD keys actually works

You don't modify OpenSSL — Python's `ssl` module is too sealed. You write your own **protocol inspired by TLS 1.3** that follows RFC 8446 (ClientHello / ServerHello / EncryptedExtensions / Finished, HKDF key schedule, authenticated record layer), but with one essential difference:

> Instead of a mathematical (EC)DHE key exchange, both parties request the same **QKD key** from their local KME using a common `key_ID`.

Concretely, the simplified handshake:
1. Client sends `ClientHello` with a `QKDKeyRequest` field (asks its KME for a key)
2. Client's KME returns `(key_ID, key_material)`
3. Client sends the `key_ID` to the server through `ClientHello`
4. Server requests the same key from its KME using `key_ID` (the KMEs are synchronized)
5. Server confirms via `ServerHello`
6. Both parties derive session keys from `key_material` using HKDF (same as real TLS 1.3)
7. From here on, all records are encrypted with OTP and authenticated with Wegman-Carter

This design is close enough to TLS 1.3 to justify the thesis title, while remaining tractable in a short timeframe.

---

## 2. Recommended libraries (pure Python)

| Component | Choice | Why |
|---|---|---|
| Quantum QKD (visual) | **Qiskit + qiskit-aer** | `AerSimulator(method="stabilizer")` backend — Clifford circuits run thousands of qubits/sec. The mainstream choice for quantum simulation in Python. |
| Bulk key generation | Write it yourself | `os.urandom(N)`, QBER as Bernoulli flip, configurable key rate. ~80 lines. |
| KME server (ETSI 014) | **FastAPI** + **uvicorn** + **pydantic v2** | Async-native, auto-generated OpenAPI (looks great in thesis appendices). Reference clients exist (`etsi-qkd-014-client` on PyPI). |
| Cryptographic primitives | **`cryptography` ≥ 43** | For HKDF, SHA-256/384, certificate generation. Production-grade, no surprises. |
| Visualization | **Streamlit ≥ 1.31** + **Plotly** + **streamlit-autorefresh** | Fastest path to a polished defense demo. |
| Networking | **`asyncio`** | Single-event-loop model lets you run KME, server, and viz in one process. |
| Benchmarking | **`pyperf`** for handshakes, `timeit` for hot loops, **Plotly/matplotlib** for graphs | `pyperf` produces statistics with automatic outlier rejection — publication-grade. |

### Imports you will use most

```python
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519   # only for mTLS cert
from cryptography import x509
from fastapi import FastAPI
import asyncio, uvicorn, streamlit as st, plotly.graph_objects as go
```

**No native installation steps, no C compiler headaches.** Everything installs cleanly with `pip install`.

---

## 3. The two security modes

### Mode A: One-Time Pad over QKD

* For each new TCP record, the client/server requests from the KME a key of exactly `len(plaintext)` bytes.
* Cipher: `ciphertext = plaintext XOR otp_key`. Plain and simple.
* **OTP alone provides confidentiality, not integrity** — that's why you mandatorily combine it with Mode B below.
* **Consumption tracking**: each SAE keeps a `KeyBudget` object with `bytes_remaining` and `bytes_per_second_consumed`. The KME tracks pool depth. When the pool drops below a threshold (e.g., 10 KB), the server:
  1. signals **back-pressure** to the application,
  2. emits a `KEY_DEPLETION_WARNING` event to the viz,
  3. on exhaustion → **refuses new records** (graceful failure). This is **the virtue, not the defect** of OTP design — you demonstrate the fundamental QKD constraint: maximum security at the price of key bandwidth.
* Key material is **never reused** — strict index tracking. Implemented as a memory pool indexed by `(sae_a, sae_b, offset)`.

### Mode B: Wegman-Carter authentication

This is your main information-theoretic contribution. The standard construction:

`tag = H_k(m) ⊕ r`

where `H_k` is a hash function from an *ε-almost-strongly-universal* family, and `r` is a fresh one-time pad (consumed from the QKD pool). Wegman & Carter (1981) and Portmann (2014) prove this is *universally composable* — the right citation for the QKD context.

**Concrete construction — polynomial hash over GF(2¹²⁸)**:

```python
def gf128_mul(a: int, b: int) -> int:    # AES-GCM reduction polynomial
    R = 0xE1 << 120
    z = 0
    for i in range(128):
        if (b >> (127 - i)) & 1: z ^= a
        a = (a >> 1) ^ (R if a & 1 else 0)
    return z

def poly_hash(key_k: int, msg: bytes) -> int:
    blocks = [int.from_bytes(msg[i:i+16].ljust(16, b'\x00'),'big')
              for i in range(0, len(msg), 16)]
    h = 0
    for b in blocks:
        h = gf128_mul(h ^ b, key_k)
    return h
```

Then `tag = poly_hash(k, m) XOR int.from_bytes(otp_r, 'big')` packed into 16 bytes.

This is *exactly* the GHASH construction inside AES-GCM, but **with a one-time-pad r instead of a PRF-AES block** — and that's what flips it from *computational* to *information-theoretic* security (forgery probability bounded by `n_blocks · 2⁻¹²⁸`, independent of the attacker's computational power).

You integrate this into the record layer by replacing the AEAD authentication tag in `qtls/records.py`. Mention explicitly in the thesis that **`k_H` can be reused across many messages, but each `r` must be fresh** — this is Portmann's "key recycling" insight that makes the QKD bandwidth budget feasible.

For hot paths, if pure-Python is too slow (~30 µs/block on CPython), port `gf128_mul` to **Cython** or **Numba** later — but for the demo it works without optimizations.

---

## 4. QKD simulation

**Recommendation: dual-layer simulation.**

### 4.1 Visual quantum BB84 (Qiskit)

For the demo, you simulate BB84 on a small batch (64–256 qubits per iteration) that is *visualized in real time*. This is what impresses the committee. Use `AerSimulator(method="stabilizer")` — Clifford circuits run thousands of qubits per second.

Simplified BB84 logic in Qiskit:

```python
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import random

def bb84_round(n_qubits: int):
    # Alice picks random bits and bases
    alice_bits  = [random.randint(0,1) for _ in range(n_qubits)]
    alice_bases = [random.randint(0,1) for _ in range(n_qubits)]  # 0=Z, 1=X
    
    qc = QuantumCircuit(n_qubits, n_qubits)
    for i in range(n_qubits):
        if alice_bits[i]:  qc.x(i)              # prepare |1⟩
        if alice_bases[i]: qc.h(i)              # rotate to X basis
    
    # Bob picks random bases and measures
    bob_bases = [random.randint(0,1) for _ in range(n_qubits)]
    for i in range(n_qubits):
        if bob_bases[i]: qc.h(i)
        qc.measure(i, i)
    
    sim = AerSimulator(method="stabilizer")
    result = sim.run(qc, shots=1).result()
    bob_bits = [int(b) for b in list(result.get_counts())[0][::-1]]
    
    # Sifting: keep only positions where bases match
    sifted = [(a, b) for a, b, ab, bb in 
              zip(alice_bits, bob_bits, alice_bases, bob_bases) if ab == bb]
    return alice_bits, alice_bases, bob_bits, bob_bases, sifted
```

Each round emits events to the visualization: photons with polarization, basis choices, measured bits, sifted pairs.

### 4.2 Abstract high-volume generator

For real OTP traffic (which consumes MB of keys), you can't run quantum BB84 — it would be too slow. You generate keys "as if" they came from QKD:

```python
async def abstract_qkd_link(key_rate_bps=100_000, qber=0.02, link):
    while True:
        await asyncio.sleep(1.0)
        raw_bits = os.urandom(key_rate_bps // 8)
        # simulate QBER errors
        errors = sum(1 for _ in range(len(raw_bits)*8) if random.random() < qber)
        if qber > 0.11:                              # Shor-Preskill threshold
            link.abort("QBER too high"); continue
        # privacy amplification (truncation to entropy bound)
        sifted_len = int(len(raw_bits) * 0.5 * (1 - 2*qber))
        amplified = hashlib.shake_128(raw_bits).digest(sifted_len)
        link.kme_a.add_key(amplified); link.kme_b.add_key(amplified)
```

Both layers feed the **same KME key pool**, tagged with `source: "bb84-visual"` or `source: "abstract-bulk"`, so the viz can display both.

### 4.3 Multi-node network

You model 3–5 trusted nodes in a graph (e.g., A–R1–R2–B). For a relay through R, the relay XORs the A↔R key with the R↔B key, transmits the XOR over an authenticated classical channel, and B recovers A's key. Implementation in `qkd/network.py` using `networkx` for topology and Dijkstra for shortest-path routing.

### 4.4 ETSI GS QKD 014 V1.1.1 endpoints (FastAPI routes)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/keys/{slave_SAE_ID}/status` | Returns `Status` JSON: `source_KME_ID`, `target_KME_ID`, `stored_key_count`, `max_key_count`, `key_size`, `max_key_per_request`. |
| `POST` | `/api/v1/keys/{slave_SAE_ID}/enc_keys` | Master SAE pulls keys. Body: `{number, size}`. Response: array of `{key_ID, key (base64)}`. |
| `POST` | `/api/v1/keys/{master_SAE_ID}/dec_keys` | Slave SAE retrieves by ID. Body: `{key_IDs:[…]}`. |

You authenticate clients with **mTLS** using your own CA (generated with `cryptography.x509`); extract the CN from the certificate and use it as the SAE ID. Python reference: `a-v-popov/etsi-qkd-rest` on GitHub. Read it, but write your own version — it's simple.

---

## 5. Visualization design — the defense centerpiece

### UI layout (single Streamlit page, 4 panels)

```
┌──────────────────────────────────────────────────────────────────┐
│  HEADER  Mode: [OTP+WC | OTP only | WC only]  ▶ Start  ⏸  ⏹   │
├───────────────────────────┬──────────────────────────────────────┤
│ A) QKD NETWORK TOPOLOGY   │ B) BB84 PHOTON STREAM                 │
│ Plotly node graph         │ Polarization glyphs flying along a   │
│ pulsing edges = keys/sec  │ horizontal "fiber", live bases &     │
│ on each link              │ bits, Eve (attacker) toggle          │
├───────────────────────────┼──────────────────────────────────────┤
│ C) QTLS HANDSHAKE         │ D) METRICS DASHBOARD                  │
│ Sequence diagram, each    │ - Key generation rate (bps)           │
│ message highlights as it  │ - QBER (%)                            │
│ traverses; payload sizes  │ - Pool depth bytes                    │
│                           │ - Keys consumed / message             │
│                           │ - Handshake latency ms                │
│                           │ - Throughput KB/s                     │
└───────────────────────────┴──────────────────────────────────────┘
```

### Animations to implement (in order of visual impact)

1. **Photons traversing a horizontal channel** with rotating polarization glyphs (Plotly `Scatter` with updated annotations, refreshed at 5–10 Hz). This is what impresses the committee most.
2. **Basis sifting**: photons without basis match fade out.
3. **Handshake diagram** with progressive highlighting as messages are generated.
4. **Topology graph** with edge thickness proportional to instantaneous key rate; node color reflects pool depth.
5. **Eve attack mode**: a toggle inserts an interceptor that raises QBER above the 11% threshold, triggering a visible red ABORT.

### Tech stack

`streamlit-autorefresh` for the 5–10 Hz tick, Plotly for all charts and the photon channel, and a small `asyncio` thread that feeds the event bus and writes into `st.session_state`. If Streamlit's rerun model becomes annoying for panel B, switch that panel to **Dash** or to **pyvis/D3 via `streamlit.components.v1.html`** — keep the rest in Streamlit.

---

## 6. Implementation phases (sequential, no fixed dates)

Move to the next phase only when the previous one's "Done" criteria are met. Each phase has a clear acceptance test, so you always know where you stand.

### Phase 1 — Quantum core

**Goal**: prove that two simulated nodes can produce the same secret key from BB84.

Tasks:
1. Project skeleton (`pyproject.toml`, lint, pytest, basic CI).
2. BB84 round in Qiskit on 64 qubits, with sifting.
3. Optional Eve interception model (intercept-and-resend) — raises QBER ~25%.
4. Simplified reconciliation (Cascade-lite or just announce error positions in the first iteration).
5. Privacy amplification via SHAKE-128 truncation to the smooth-min-entropy bound.

**Done when**: a pytest produces identical keys between Alice and Bob after BB84 + sifting + amplification, for QBER 0% and 5%, and fails (raises) at QBER above 11%.

### Phase 2 — Bulk key generator

**Goal**: a high-rate "abstract QKD" source feeding the same pool as BB84.

Tasks:
1. Async key producer with configurable `key_rate_bps`, `qber`, `distance_km`.
2. Same reconciliation/amplification path as BB84, but on `os.urandom` material.
3. Unified `KeyBlock` data class used by both sources.

**Done when**: you can run both producers concurrently for 30 seconds and the combined output is a stream of timestamped `KeyBlock`s ready for the KME.

### Phase 3 — KME with ETSI GS QKD 014

**Goal**: a working REST server that exposes QKD keys per the standard.

Tasks:
1. FastAPI app with `/status`, `/enc_keys`, `/dec_keys`.
2. In-memory key store with `key_ID` lookup, ACLs per SAE, expiry timer.
3. mTLS authentication with a self-signed CA.
4. A two-KME setup (`kme_a` and `kme_b`) that share the same Phase 1+2 key feed.

**Done when**: a curl command (or pytest) calling `enc_keys` on `kme_a` and `dec_keys` on `kme_b` with the returned `key_ID` retrieves identical key material on both sides.

### Phase 4 — Core cryptographic modes (OTP + Wegman-Carter)

**Goal**: cryptographic primitives independent of the protocol.

Tasks:
1. `OTPCipher` class with strict offset tracking; raises on reuse.
2. `WegmanCarterMAC` class with `gf128_mul` and `poly_hash`; takes `(k_H, r)`.
3. Tests: encryption round-trip, authentication round-trip, forgery rejection, key-reuse detection.

**Done when**: unit tests prove OTP correctness, WC tag verification correctness, and that any attempt to reuse OTP material throws an exception.

### Phase 5 — QTLS protocol (handshake + record layer)

**Goal**: a client and server that talk over TCP using QKD keys obtained through the KME.

Tasks:
1. Record layer in `qtls/records.py` (framing, length, type).
2. Handshake FSM: `ClientHello` (with `key_ID` request), `ServerHello`, `Finished`.
3. HKDF key schedule (`Derive-Secret`, `HKDF-Expand-Label`) — copy the RFC 8446 §7.1 structure.
4. Client and server use `httpx` to talk to their respective KMEs during the handshake.

**Done when**: a client sends "Hello, server" over QTLS, the server decrypts it correctly and verifies the WC tag; tcpdump on loopback shows ciphertext only.

### Phase 6 — Demo application

**Goal**: a small chat or file-transfer app on top of QTLS, useful for the demo.

Tasks:
1. Pick the simpler option: a CLI chat (`app/demo_chat.py`) where two terminals exchange messages over QTLS.
2. Add an explicit "send 1 MB file" mode to stress the key pool.

**Done when**: you can demonstrate live message exchange and watch the KME pool drain in real time.

### Phase 7 — Visualization

**Goal**: the four-panel Streamlit dashboard for live defense.

Tasks:
1. Event bus subscriber and `st.session_state` integration.
2. Panel A: topology graph with Plotly.
3. Panel B: photon stream animation with rotating polarization glyphs.
4. Panel C: handshake sequence diagram.
5. Panel D: live metrics (rate, QBER, pool depth, latency, throughput).
6. Eve attack toggle.

**Done when**: `streamlit run viz/main.py` opens a dashboard where you can start a session, watch BB84 generate keys, see the handshake complete, watch the chat exchange messages, and toggle Eve to see the protocol abort.

### Phase 8 — Multi-node relay (optional but valuable)

**Goal**: demonstrate that QKD networks scale beyond point-to-point.

Tasks:
1. 3–5 nodes in a `networkx` graph.
2. XOR-based key forwarding through trusted intermediate nodes.
3. Route selection (Dijkstra) integrated into the KME.
4. Topology panel shows the active route highlighted.

**Done when**: A and B are not directly connected, but the system relays keys through R and the end-to-end chat still works.

### Phase 9 — Benchmarking and analysis

**Goal**: numbers and graphs for the thesis evaluation chapter.

Tasks:
1. `pyperf` harness for handshake latency.
2. Throughput test: 1 MB and 10 MB transfers, OTP mode.
3. Pool-depth-over-time plot during sustained load.
4. Key consumption analysis (bits of key per bit of message).
5. Comparison table: classic TLS 1.3 (X25519+AES-GCM) baseline vs QTLS in each mode.

**Done when**: 5–6 publication-quality plots saved as PDF, ready to drop into the thesis.

### Phase 10 — Polish and defense prep

**Goal**: thesis-ready artifact.

Tasks:
1. README with installation and run instructions.
2. Architecture diagram (use `draw.io` or `excalidraw`, export as SVG).
3. 5-minute screen recording as a backup demo.
4. Anticipate and rehearse answers for the defense questions in §8.

### MVP triage — what to cut if you fall behind

Skip phases in this order if time runs short:
1. **First to cut**: Phase 8 (multi-node relay) — mention it as Future Work.
2. **Next**: Eve attack toggle in Phase 7 — keep the rest of the viz.
3. **Next**: visual quantum BB84 animation — keep BB84 as logic, but visualize only counters, not flying photons.
4. **Never cut**: Phases 1, 3, 4, 5, 7 (basic dashboard), 9. These are what the thesis title promises.

---

## 7. Benchmarking and evaluation

**Metrics to measure**:
* **Handshake latency (ms)**: median, p95, p99 over 1000 runs. `pyperf timeit`.
* **Throughput (KB/s)**: 100 MB transfer over loopback with OTP+WC.
* **Key consumption (key bits / message bit)**: 1.0 for OTP; ~128/n for WC-MAC.
* **Wire overhead**: `ClientHello`, `ServerHello` sizes.
* **KME memory footprint** under load (`tracemalloc`).
* **Scalability**: keys/sec generated under varying QBER (2%, 5%, 8%, 11%).
* **Pool depth over time** under sustained OTP load — this graph speaks for itself about QKD's fundamental constraint.

**Presentation in the thesis**: one figure per metric, comparison with classic TLS 1.3 (`X25519 + AES-GCM`) as baseline. Results table with mean ± standard deviation. Plot the pool depth during OTP stress test — it visibly drains, making your point about QKD's real-world limitation.

**Results to discuss honestly**:
- Your handshake will be *faster* than hybrid PQC TLS 1.3 (no heavy crypto computation for the key exchange, just HTTP REST), but *slower* than classic TLS 1.3 if you include KME latency.
- OTP consumes keys at a 1:1 ratio with plaintext — meaning a 100 kbps QKD channel sustains only 100 kbps of useful traffic. Critical point to discuss.
- WC-MAC in pure Python is the bottleneck — mention that real deployments use hardware acceleration (the GHASH AES-NI path). This is an honest limitation, not a mistake.

---

## 8. Common pitfalls and risk management

* **OTP reuse**: the worst possible bug — it destroys your thesis if discovered at review. Write a **strict** pytest asserting every offset is consumed exactly once; track with a hash set in tests.
* **`key_ID` synchronization between KMEs**: if client and server request different keys, everything falls apart. Implement carefully — the slave KME must return *exactly* the requested `key_ID`, not a random one.
* **CPython slowness for Wegman-Carter**: pure-Python `gf128_mul` ≈ 30 µs/block. Don't optimize prematurely — if needed, port the loop to Cython or Numba late in the project. PyPy works but breaks `cryptography`'s C extensions, so don't switch interpreters globally.
* **Streamlit reruns**: every interaction reruns the script. Cache the KME and protocol state in `st.session_state`; never instantiate heavy objects in top-level script body.
* **`asyncio` + Streamlit**: Streamlit doesn't natively run in `asyncio`. Solution: start the event loop in a separate thread and communicate through a thread-safe `queue.Queue` to `st.session_state`.
* **Scope creep**: tempting things **NOT** to do — ML-DSA signatures, other QKD protocols (E91, B92), decoy states, finite-key analysis, OpenSSL fork. Push them all to "Future Work".

### Typical defense questions and prepared answers

1. *"Why OTP and not AES-GCM?"* — OTP provides information-theoretic security, mathematically proven by Shannon's theorem (1949). AES-GCM is only computationally secure — dependent on assumptions about the difficulty of certain mathematical problems. With QKD you have the keys to afford OTP.
2. *"Is your OTP truly information-theoretic secure?"* — yes, **if** the key is uniformly random, never reused, and the same length as the plaintext. Your KME enforces all three conditions; the **authentication** with WC closes the loop (without MAC, OTP is malleable).
3. *"Why Wegman-Carter and not HMAC?"* — HMAC's security is computational; WC's is information-theoretic, matching the OTP. End-to-end security thus survives any cryptanalytic progress, not just quantum.
4. *"What's the QBER threshold and why 11%?"* — Shor-Preskill bound; above it, no positive secret-key rate can be extracted by privacy amplification.
5. *"How does your simulator compare to real QKD?"* — be honest: no decoy states, no realistic detector models, no finite-key analysis. Cite Tomamichel et al. for what rigorous analysis would require.
6. *"Why didn't you include post-quantum algorithms (ML-KEM)?"* — ML-KEM is necessary **when you don't have QKD infrastructure**; my thesis explores exactly the case when you *do* have QKD, where OTP+WC provide strictly stronger security than any computational algorithm, including ML-KEM. This is a scope decision, not an omission.
7. *"How scalable is the project?"* — limited by the QKD key rate. For low-volume applications (diplomatic messaging, bank signatures) it's perfectly applicable; for video streaming, obviously not. This matches the state of every real QKD deployment (China, ID Quantique, Toshiba).

---

## 9. Completion checklist

| Specification item | Covered |
|---|---|
| Architecture design (components, communication, modules, TLS-QKD approach) | ✅ §1 |
| Library recommendations with reasoning | ✅ §2 |
| Two security modes implementation | ✅ §3 |
| QKD simulation approach (quantum BB84, network, ETSI endpoints) | ✅ §4 |
| Visualization design (layout, stack, animations, metrics) | ✅ §5 |
| Phased plan + MVP triage | ✅ §6 |
| Benchmarking and evaluation | ✅ §7 |
| Pitfalls, risks, defense Q&A | ✅ §8 |
| Code-level hints throughout | ✅ |

**Now: open `pyproject.toml` and start with the Phase 1 test that proves quantum BB84 produces identical keys at Alice and Bob after sifting. Everything else builds on that one working primitive.**
