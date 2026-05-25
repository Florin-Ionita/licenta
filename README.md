# qtls-qkd

Information-theoretic-secure TLS 1.3-shaped protocol over a simulated QKD
network. Bachelor's thesis implementation (Python 3.12, pure-Python stack,
no native crypto libraries).

The session key never comes from (EC)DHE -- it comes from a simulated QKD
link via an ETSI GS QKD 014 KME. Application records are encrypted with a
One-Time Pad and authenticated with a Wegman-Carter MAC over GF(2¹²⁸), so
security is information-theoretic end-to-end -- with one acknowledged
caveat: the privacy-amplification extractor is SHAKE-128 rather than a
2-universal hash family, which keeps that single step under a random-oracle
(computational) assumption. Replacing it with Toeplitz hashing would restore
unconditional security throughout; see Future Work and the defense quick-fire
below.

See [`thesis_plan.md`](thesis_plan.md) for the full phased roadmap and
[`docs/design_notes.md`](docs/design_notes.md) for the decision record.

## Setup

Python **3.12+** is required.

```bash
python3.12 -m venv .venv-linux
source .venv-linux/bin/activate
pip install -e ".[dev,viz,bench]"
```

On Windows (PowerShell):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev,viz,bench]"
```

### Optional extras

- `.[dev]` -- pytest, pytest-asyncio (run the test suite)
- `.[viz]` -- streamlit, plotly, networkx, streamlit-autorefresh (Phase 7 dashboard)
- `.[bench]` -- pyperf, kaleido (Phase 9 evaluation suite)

### Native C Cascade (required)

The full Cascade reconciliation (with back-propagation) is implemented in C
in [`qkd/_cascade.c`](qkd/_cascade.c). On first import the ctypes loader in
[`qkd/_cascade.py`](qkd/_cascade.py) compiles it to a shared library using
the system C compiler (``cc`` / ``clang`` / ``gcc`` on POSIX, ``cl`` /
``gcc`` on Windows) and loads it. **If no C compiler is available the
import raises ``ImportError``** -- there is no Python fallback. The
benchmarks and Phase 6/8 tests rely on the C speed to stay inside their
timeouts, and using a single backend across the whole project keeps
results reproducible.

To force a rebuild, delete ``qkd/libcascade.so`` (or ``.dll``) and re-run
any Python command that imports ``qkd.reconciliation``.

## Running the test suite

```bash
pytest                                  # all phases
pytest tests/test_phase5_qtls.py -v     # one phase
```

All 52+ tests run in ~15 s on a laptop.

## Quantum-circuit figures

Two BB84 circuit illustrations live under `docs/figures/`:

- `bb84_circuit_demo.{pdf,png}` -- a hand-picked 4-qubit circuit covering all
  four `(prep_basis, meas_basis)` combinations. Regenerate with
  `python scripts/draw_bb84_circuit.py`.
- `bb84_circuit_round.{pdf,png}` -- a real (random) 8-qubit BB84 round
  rebuilt and drawn by `test_render_bb84_circuit_figure` in
  `tests/test_phase1_bb84.py`. Regenerated on every test run (silently
  skipped if `matplotlib` / `pylatexenc` are not installed).

## Running the live demo (Phase 7)

```bash
streamlit run viz/main.py
```

Opens a four-panel dashboard at <http://localhost:8501>:

| Panel | What it shows |
|-------|---------------|
| A     | QKD network topology with pool depth and key-rate-per-link |
| B     | BB84 photon stream with polarisation glyphs and sifting |
| C     | QTLS handshake sequence (ClientHello → ServerHello → Finished) |
| D     | Live metrics: handshake latency, key throughput, pool depth |

Sidebar controls:

- **Mode** -- switch between point-to-point and multi-hop relay (Phase 8)
- **Refresh interval** -- 250 ms (live) to 5 s (calm)
- **Pause snapshot** -- freeze the dashboard on the current frame
- **BB84 per-round delay** -- slow the quantum producer to a readable cadence

Header: Start/Stop the runtime, toggle the **Eve attack** to drive QBER
above the 11% Shor-Preskill threshold (BB84 aborts visibly).

## Running the chat demo (Phase 6, CLI)

```bash
python -m app.demo_chat
```

Two terminals exchange messages over a real QTLS connection; the second pane
streams handshake-latency and pool-depth telemetry.

## Running the benchmark suite (Phase 9)

```bash
python -m benchmarks.runner --profile lite      # ~1-2 min
python -m benchmarks.runner --profile full      # ~15-25 min (thesis figures)
python -m benchmarks.runner --profile extreme   # ~45-60 min (paper-grade)

python -m benchmarks.runner --only handshake throughput   # subset
python -m benchmarks.replot                               # rerun plots only
```

Outputs:

- Raw CSVs → `docs/benchmarks/raw/`
- PDF plots → `docs/benchmarks/plots/`

What each plot shows:

1. **Handshake latency** -- distributions of QTLS vs TLS 1.3 (X25519+AES-GCM)
2. **Latency summary table** -- mean / median / p95 / p99 / min / max
3. **Throughput bars** -- MB/s per payload size, split-panel (independent y-axes)
4. **Pool drain** -- key-pool depth under sustained chat load
5. **Key consumption ratio** -- key-bits-per-plaintext-byte vs record size
6. **QBER vs key rate** -- Shor-Preskill theoretical curve with measured points

## Repository layout

```
qkd/        BB84 quantum simulation, abstract bulk producer, reconciliation,
            privacy amplification, relay network (Phase 8)
kme/        ETSI GS QKD 014 KME server (FastAPI), key store, mTLS certs,
            two-KME synchronisation
qtls/       QTLS handshake state machine, key schedule (RFC 8446-shaped),
            record layer, OTP + Wegman-Carter primitives, KME client
app/        Single-process demo orchestrator and CLI chat app
viz/        Streamlit dashboard, event bus, asyncio runtime, panel builders
benchmarks/ Phase 9 evaluation: per-bench module + shared harness + plotters
tests/      One pytest file per phase (1-9, phase-numbered)
docs/       Design notes (prose, thesis-ready), benchmark CSVs and PDFs
```

## Thesis defence quick-fire

- *Is the whole stack really information-theoretic?* Almost. Every step --
  BB84 sifting, Cascade reconciliation (with exact leak counting), OTP
  encryption, Wegman-Carter MAC -- is unconditionally secure. The one
  exception is **privacy amplification**: the BBCM 1995 proof requires a
  uniformly chosen function from a 2-universal hash family (Toeplitz hashing
  or modular multiplication in GF(2^n)), and this implementation uses
  SHAKE-128 instead -- a single deterministic hash, not a randomly drawn
  family member. SHAKE-128 is *conjectured* to behave as a random oracle,
  under which it is effectively a perfect extractor; that conjecture is a
  computational assumption, not an information-theoretic one. Operationally
  the gap is small (SHAKE has no known attack faster than brute force, and
  post-extraction keys are large enough that brute force is infeasible). The
  drop-in fix is Toeplitz hashing with a per-session public random seed;
  listed under Future Work, and would not change the KME or QTLS layers.
- *Why OTP and not AES-GCM?* Shannon-secure given uniform, fresh, equal-length
  key -- our KME enforces all three. AES-GCM is only computationally secure.
- *Why Wegman-Carter and not HMAC?* WC's security is information-theoretic
  (matches OTP); HMAC's is computational.
- *Why 11% QBER abort?* Shor-Preskill asymptotic bound; above it no privacy
  amplification can extract a positive secret-key rate.
- *Why no ML-KEM?* PQC is the answer when QKD infrastructure is absent. This
  thesis explores the case when you *have* QKD: OTP+WC is strictly stronger.
- *Implementation gap to theoretical rate?* The reconciliation step uses full
  Cascade with back-propagation and exact leak counting (C-accelerated), so
  we track the realistic Cascade curve within ~10-15% at every QBER. The
  remaining gap to the Shor-Preskill physics ceiling is the well-known
  structural overhead of Cascade vs LDPC reconciliation (~10-15 pp) plus the
  byte-rounding step in privacy amplification. Real high-end deployments use
  LDPC and tighter extractors; listed under Future Work.
- *Why BB84 and not Ekert91 / MDI-QKD / twin-field / CV-QKD?* BB84 (in its
  decoy-state form) is what every deployed commercial QKD system actually
  ships -- ID Quantique, Toshiba, the Micius satellite ground links. It has
  the cleanest published security proof (Shor-Preskill 2000) and the minimal
  quantum substrate (single-photon source + basis-choice detectors). The
  thesis contribution is the integration layer above the QKD substrate -- the
  KME, OTP+WC record layer, and TLS-1.3-shaped handshake -- which is
  orthogonal to the choice of underlying QKD protocol. Swapping in MDI-QKD
  (detector-attack hardening), twin-field (long-distance), or CV-QKD (telecom
  homodyne integration) would not change the KME interface or QTLS layers
  above it; listed under Future Work.
- *How does the protocol detect Eve?* Through the QBER, not a Bell test.
  Eve cannot copy a qubit (no-cloning), so to read each bit she must measure
  it -- which requires guessing a basis. She guesses wrong ~50% of the time,
  and wrong-basis intercept-and-resend re-randomises Bob's outcome on those
  sifted positions. The result is a characteristic ~25% QBER on the sifted
  key, far above the channel's baseline. Alice and Bob compare a sample,
  observe the spike, and abort. Bell-inequality-based detection (the Ekert91
  / GHZ-Mermin route) is the conceptual alternative used by
  entanglement-based protocols; it is equivalent in the asymptotic limit but
  requires entangled-pair sources.
- *Why does the simulator compute the true QBER instead of estimating it from
  a public-subset announcement?* In a deployed system, Alice and Bob estimate
  QBER by publicly comparing a random subset of sifted bits and discarding
  them. Our simulator has god-mode access to both halves of the sifted key,
  so it returns the population value directly -- a strictly better estimator
  of the same quantity. The substitution is faithful for everything
  downstream (the abort threshold, reconciliation, the security argument all
  operate on the QBER *number*, not on how it was obtained). The only thing
  not modelled is finite-sample uncertainty on the estimate, which in a real
  system motivates a safety margin below the 11% threshold; listed under
  Future Work.
