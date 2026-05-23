# Design Notes & Decision Record

This document records every significant design decision in the project, the
reasoning behind it, the alternatives that were rejected, and the points most
likely to come up during the thesis defense. It is written in prose so that
its content can be adapted more or less directly into the thesis chapters.

It is updated as each phase is completed. Phases not yet implemented are not
described here.

---

## 1. Project goal and thesis statement

The project builds a **"TLS 1.3-shaped" secure communication protocol in pure
Python**, where the session key is supplied **exclusively by a simulated
Quantum Key Distribution (QKD) network**. Messages are encrypted with a
**One-Time Pad (OTP)** and authenticated with a **Wegman–Carter MAC**. Both
primitives are *information-theoretically secure*: their security does not
depend on any assumption about the computational power of an attacker, and is
therefore unaffected by advances in cryptanalysis or by quantum computers.

The thesis statement is deliberately scoped: *when QKD infrastructure is
available, one can achieve a level of security strictly stronger than any
computational algorithm, including post-quantum schemes such as ML-KEM. This
project explores that "ideal" case.* The absence of post-quantum algorithms is
therefore a **scope decision, not an omission** — ML-KEM answers the question
"what do we do when we do *not* have QKD?", which is explicitly a different
question from the one this thesis asks.

---

## 2. Environment decisions

### 2.1 Python version: official 3.12, not the Windows Store build

**Decision.** The project uses the official python.org distribution of Python
3.12.10, installed via `winget`, with a project-local virtual environment at
`.venv`.

**Why.** The machine initially had only the *Windows Store* edition of Python
3.13. The Store edition runs in an application sandbox that redirects file
system writes and has historically caused failures with virtual environments
and with packages that ship compiled C/C++ extensions. The QKD simulator
depends on `qiskit-aer`, which is exactly such a compiled extension. For a
thesis artifact that must reliably build and run on the defense machine,
trading a small amount of setup time for a battle-tested interpreter is the
correct engineering choice.

**Why 3.12 specifically and not 3.13.** At the time of writing, the Qiskit
ecosystem's most thoroughly tested support targets Python 3.12. Choosing the
most widely validated version minimises the risk of an environment-specific
failure surfacing during the defense.

**Alternative considered.** Conda/Miniforge, which also handles Qiskit's
binary packages well. Rejected only because a plain `venv` keeps the project
dependency-free at the system level and is simpler to document for a reader
reproducing the work.

### 2.2 Dependency pinning

`pyproject.toml` requires `qiskit>=1.2` and `qiskit-aer>=0.15` because those
are the first releases that support modern Python versions cleanly. The
actually installed versions (Qiskit 2.4.1, qiskit-aer 0.17.2) are recorded
here so the environment is reproducible and citable.

---

## 3. Phase 1 — Quantum core

Phase 1 implements the part of the system that turns simulated quantum
behaviour into a shared secret key: the BB84 protocol, classical
*reconciliation*, and *privacy amplification*.

### 3.1 Real Qiskit simulation, not a hand-written shortcut

**Decision.** Each BB84 round is executed as a genuine quantum circuit on
Qiskit's `AerSimulator` using the `method="stabilizer"` backend, rather than
being emulated with a few lines of classical probability.

**Why.** A central credibility point of the thesis is that the quantum layer
is *actually simulated as a quantum system*. BB84 uses only the X gate and the
Hadamard gate, which are *Clifford* gates. Circuits built solely from Clifford
gates can be simulated exactly and in polynomial time by the *stabilizer*
formalism (the Gottesman–Knill theorem). This gives the best of both worlds:
the simulation is a real quantum-circuit execution (defensible as such), yet
it scales to hundreds of qubits per round at negligible cost, so it does not
become a performance bottleneck for the rest of the system.

**Defense note.** If asked "is this really quantum simulation or just random
numbers?": the qubits are prepared, optionally intercepted, and measured
through Qiskit circuits; the stabilizer method is an exact simulator for this
class of circuits, not an approximation, and not a classical re-derivation of
the outcome.

### 3.2 BB84 implementation details

- **Basis convention.** `0 = Z` (rectilinear, states |0⟩/|1⟩);
  `1 = X` (diagonal, states |+⟩/|−⟩). Used consistently everywhere.
- **State preparation.** For each qubit: apply `X` if the chosen bit is 1
  (|0⟩ → |1⟩), then apply `H` if the chosen basis is X (rotate into the
  diagonal basis).
- **Measurement.** Apply `H` before measuring if the measuring party chose
  the X basis (rotates the diagonal basis back so a standard Z measurement
  reads it correctly), then measure.
- **Sifting.** After measurement, Alice and Bob publicly compare *only their
  basis choices* (never the bit values) and keep the positions where the
  bases agree. On average about half the qubits survive, since the bases are
  independent and uniform.
- **Randomness source.** Bit and basis choices use Python's `secrets` module,
  not `random`. These bits stand in for quantum randomness; using a weak
  pseudo-random generator here would undermine the very
  information-theoretic argument the thesis makes. This is a small but
  principled decision worth stating explicitly.

### 3.3 The eavesdropper (Eve): intercept-and-resend

**Decision.** Eve is modelled with the classic *intercept-and-resend* attack:
she measures every qubit in a basis she picks at random, then prepares and
re-sends a fresh qubit matching what she observed.

**Why this matters.** Because Eve does not know Alice's basis, she picks the
wrong basis about half the time. When she measures in the wrong basis she gets
a random result and destroys the original state; the qubit she forwards to Bob
is then wrong half the time *even when Bob later uses the correct basis*. The
net effect is a characteristic error rate of about **25%** on the sifted key.
This is precisely the disturbance that makes QKD secure: an eavesdropper
*cannot* gain information without leaving a statistically visible trace. The
legitimate parties detect Eve by estimating this error rate (the QBER) and
aborting if it is too high.

**Defense note.** This demonstrates the *no-cloning* principle in practice:
Eve cannot copy an unknown quantum state, so any attempt to learn the key
necessarily perturbs it.

### 3.4 The channel-noise parameter (a deliberate addition beyond the plan)

**Decision.** `bb84_round` and `collect_sifted_key` accept an optional
`noise` parameter: the probability that each of Bob's measured bits is
independently flipped.

**Why this was added.** A perfect simulator with no eavesdropper produces a
**QBER of exactly 0** — there is no physical noise model in an idealised
circuit. But the Phase 1 acceptance criteria require demonstrating correct
behaviour at a *non-zero* QBER (around 5%) and demonstrating that the protocol
*aborts* above the security threshold. Without a controllable error source,
those criteria are untestable. The `noise` parameter models a **depolarising
binary-symmetric channel** — the standard textbook model for QKD channel
imperfections — and is what makes the security behaviour observable and
testable. This is presented as an honest, named modelling choice, not a hidden
hack.

**Defense note.** Real QKD QBER comes from detector dark counts, imperfect
optics, and fibre loss. We do not model those individually (that would require
finite-key analysis and realistic detector models, explicitly out of scope and
listed as Future Work); the single `noise` parameter is the agreed
abstraction of all of them.

### 3.5 Reconciliation: simplified Cascade

**Decision.** Errors remaining after sifting are corrected with a *simplified
Cascade* protocol, not with the toy alternative of "Alice simply announces
which bit positions are wrong."

**Why not the toy alternative.** Announcing error positions directly leaks an
unacceptable amount of information about the key and bears no resemblance to
how real QKD systems work — a committee would immediately note both problems.
Cascade is the historically standard QKD reconciliation protocol (Brassard &
Salvail, 1994) and is defensible as a faithful, if simplified, implementation.

**How it works (and the key defense question).** Cascade is built on
*parity*: the XOR of a block of bits — a single bit of information. Alice and
Bob compare block parities; a mismatch proves the block contains an error,
which is then located by binary search and corrected. The crucial subtlety:
**a parity check only reveals an *odd* number of errors.** A block containing
2 (or 4, …) errors passes the check undetected. Cascade overcomes this by
running **multiple passes with the bit order reshuffled between them**: two
errors hiding in the same block in one pass almost certainly fall into
*different* blocks after a reshuffle, where each becomes individually
detectable.

**Implementation specifics.**
- Initial block size ≈ `0.73 / QBER` (standard Cascade heuristic — yields on
  average roughly one error per block, so most blocks have an odd, hence
  detectable, error count).
- A fixed number of *scheduled* passes, doubling the block size and
  reshuffling each time.
- Followed by *convergence* passes with small shuffled blocks that repeat
  until Alice and Bob match — capped at a maximum number of rounds so that a
  pathologically corrupted key terminates and is treated as an abort rather
  than looping forever.

**Defense answer, in one sentence.** *"A single parity check cannot detect an
even number of errors in a block; Cascade solves this by reshuffling the bit
order between passes, so error pairs that hid together in one pass are split
into separate, individually detectable blocks in the next."*

**Honest limitation.** This is a teaching-grade Cascade: it is faithful in
structure but not optimised for minimal information leakage, and the leakage
estimate fed into privacy amplification is a simple, slightly conservative
approximation rather than an exact accounting.

### 3.6 Privacy amplification: SHAKE-128 truncation

**Decision.** The reconciled key is compressed with the SHAKE-128
extendable-output hash function down to a length below the estimated secure
entropy.

**Why it is necessary.** Reconciliation broadcasts parity bits over a public
channel, and an eavesdropper may also hold partial knowledge from the quantum
phase. The reconciled key is therefore *not yet secret enough* to use
directly. Privacy amplification compresses it so that whatever an adversary
knew about the longer string becomes negligible knowledge about the shorter
output.

**The entropy accounting.** Starting from the reconciled length `n`, two
quantities are subtracted:
1. An upper bound on the eavesdropper's information, estimated as
   `n · h₂(QBER)`, where `h₂` is the binary entropy function. This is the
   standard worst-case bound linking observed error rate to leaked
   information.
2. The number of bits leaked during reconciliation (approximated from the
   number of corrections and the binary-search depth).

The remainder is the secure length. If it is non-positive the protocol
aborts: there is simply no secret left to extract.

**Why a hash function is a valid extractor here.** A cryptographic hash like
SHAKE-128 mixes its entire input so that any residual structure or partial
adversary knowledge is spread across, and effectively destroyed in, the
shorter output. It plays the role of a randomness extractor. (A fully rigorous
treatment would use a proven two-universal hash family with finite-key
parameters; that level of rigour is explicitly Future Work.)

### 3.7 Configurable abort threshold (Shor–Preskill bound)

**Decision.** The QBER abort threshold is a parameter, defaulting to
**0.11** (11%).

**Why 11%.** This is the asymptotic **Shor–Preskill bound**: above roughly an
11% error rate, no positive secret-key rate can be extracted by privacy
amplification — the eavesdropper's potential information exceeds what is left
after error correction. Aborting above it is not a failure of the
implementation; it is the *correct* security behaviour and one of the central
points the thesis demonstrates.

**Why configurable rather than hard-coded.** A parameter allows the defense
demo to show the threshold's effect directly (e.g. a 5% channel that passes
the default gate but is correctly rejected by a deliberately strict 3% gate),
which makes the security argument tangible to the committee. It also keeps the
later Eve-attack visualisation flexible.

### 3.8 Phase 1 acceptance tests

Nine automated tests encode the Phase 1 "Done" criteria:

- Structural BB84 invariants (sifted positions really do have matching bases;
  roughly half the qubits survive sifting).
- A clean channel with no Eve yields an error-free sifted key (QBER = 0).
- Eve's intercept-and-resend pushes the QBER into the ~25% band.
- The full pipeline (BB84 → reconciliation → amplification) yields a
  **bit-identical** key for Alice and Bob at QBER 0% and at ~5%.
- Both parties, applying the deterministic extractor to their now-identical
  reconciled bits, obtain byte-identical secret keys.
- The pipeline **aborts** under an Eve attack and under 20% channel noise.
- The abort threshold is genuinely configurable (a 5% channel passes the
  default 11% gate but is rejected by a strict 3% gate).

The suite passes completely and was confirmed stable across repeated runs,
which matters because BB84 and Cascade both consume real randomness — a single
green run would not be sufficient evidence of correctness.

---

## 4. Phase 2 — Bulk key generator

Phase 2 adds a second, high-throughput key source so the system can later
sustain the megabytes of key a One-Time Pad consumes, without running slow
quantum circuits for every byte.

### 4.1 Why a second, "abstract" source at all

**Decision.** Keep the faithful BB84 simulation for demonstration, and add a
separate *abstract* generator that does **not** simulate qubits but produces
key material at a high configurable rate.

**Why.** Running real Qiskit circuits to produce OTP-scale key (megabytes)
would take impractically long. This is not a shortcut unique to this project:
real QKD research codebases use exactly this dual-layer strategy — a detailed
physical model for what is being demonstrated, and an abstract high-rate model
for throughput and load experiments. The thesis presents both honestly: the
quantum layer proves the *principle*, the abstract layer enables the
*evaluation*.

### 4.2 Deviation from the thesis-plan pseudocode (important, declared)

**Decision.** The abstract generator routes its material through the **same**
reconciliation + privacy-amplification pipeline as BB84
(`reconcile_and_amplify`), rather than the plan's sketch which hashed raw
random bits directly.

**Why this deviation was necessary.** The plan's §4.2 pseudocode generated one
`os.urandom` buffer, called it the key, and "amplified" by hashing it. It
never modelled Bob holding an *errored* copy that must be reconciled. Two
problems: (1) it would produce keys that are *not* processed the same way as
BB84's, so the two sources would not be interchangeable; (2) it skips
reconciliation entirely, which is conceptually wrong for something claiming to
be a QKD source. Our version generates Alice's raw bits, derives Bob's noisy
copy with a binary-symmetric channel at the configured QBER, then reconciles
and amplifies exactly as BB84 does. Both sources are now cryptographically
identical in form and correctness.

**Defense note.** If asked why the bulk path looks different from the plan:
the plan's sketch omitted Bob's errored copy and the reconciliation step;
implementing it literally would have made the two key sources incomparable and
the "abstract QKD" label inaccurate. The deviation makes the abstraction
*more* faithful, not less, and is recorded here for transparency.

### 4.3 The unified `KeyBlock` type

**Decision.** Both sources emit a single frozen dataclass,
:class:`qkd.keyblock.KeyBlock`, carrying the final secret bytes, a unique
`key_id` (UUID), a provenance `source` tag, the QBER it was distilled at, and
a creation timestamp.

**Why.** Downstream components (the KME in Phase 3, the visualization later)
must not care which source produced a key. A single validated container
enforces that uniformity. The `source` tag exists purely so the visualization
can colour the two streams differently — it carries **no cryptographic
meaning**, which is stated explicitly so a reader does not mistake it for a
security-relevant field. The `key_id` UUID is what will let the two protocol
endpoints later request *the same* key from their respective KMEs.

### 4.4 Concurrency model

**Decision.** Both producers are `asyncio` coroutines feeding one shared
`asyncio.Queue`. The BB84 producer, being CPU-bound (Qiskit circuits), runs
its distillation in a worker thread via `asyncio.to_thread` so it does not
stall the event loop the bulk producer shares.

**Why.** The whole system is designed to run in a single process on one event
loop (KME, protocol, visualization). Proving in Phase 2 that two independent
key sources can run concurrently and merge into one ordered, timestamped
stream is exactly the integration property the later phases depend on.

### 4.5 The `distance_km` parameter

**Decision.** `distance_km` is accepted and used only to *attenuate* the
effective key rate (~3% loss per km, floored), not to model fibre physics.

**Why.** A physically accurate distance model (loss coefficients, detector
efficiency, dark counts) would require the finite-key analysis that is
explicitly out of scope. The parameter is kept as a deliberately simple
abstraction so distance-versus-rate plots in the evaluation chapter have
something meaningful to show, and it is documented as such rather than
presented as a physical model.

### 4.6 Robustness: skip-and-continue on abort

**Decision.** If a single second's material trips the Shor–Preskill abort
gate, the producer discards that block and continues rather than crashing.

**Why.** This mirrors a real deployment, which discards an unusable frame and
keeps running. It also means an Eve attack *degrades* the key stream (fewer
blocks) instead of killing the producer outright, which is the correct and
demonstrable behaviour for the later visualization.

### 4.7 Phase 2 acceptance tests

Tests cover: `KeyBlock` field validation and UUID uniqueness; the bulk
generator using the shared pipeline and aborting above threshold identically
to BB84; parameter validation; and the core criterion — both producers running
**concurrently into one queue** and yielding a unified, timestamped block
stream. The literal "30 seconds" run from the plan is implemented as a
`slow`-marked test (passes in ~31 s) and deselected from the default run; a
fast short-window test proves the same concurrency property for routine runs.

---

## 5. Phase 3 — KME with ETSI GS QKD 014

Phase 3 puts a standards-compliant REST server in front of the key pool: the
Key Management Entity (KME). Secure Application Entities (SAEs — the QTLS
endpoints in later phases) obtain keys from their local KME over the ETSI
GS QKD 014 V1.1.1 interface.

### 5.1 Verbatim conformance to ETSI GS QKD 014 V1.1.1

**Decision.** The pydantic models reproduce the standard's JSON data formats
*exactly*, including its field names (`key_ID`, `key_size`,
`stored_key_count`, `max_key_per_request`, …), and the three endpoints use the
standard's exact paths and methods.

**Why.** A central claim of the thesis is genuine standards compliance, not a
"REST-ish" approximation. Conforming to the published schema verbatim lets the
auto-generated OpenAPI document (FastAPI produces it for free) be shown in the
appendix as concrete evidence. Renaming fields to be more "Pythonic" would
have quietly broken that claim.

**Endpoints implemented.**
- `GET  /api/v1/keys/{slave_SAE_ID}/status` → `Status`
- `POST /api/v1/keys/{slave_SAE_ID}/enc_keys` → `KeyContainer` (master pull)
- `POST /api/v1/keys/{master_SAE_ID}/dec_keys` → `KeyContainer` (slave fetch
  by `key_ID`)

Key material is base64-encoded on the wire because the transport is JSON,
which cannot carry raw bytes — this is mandated by the standard, not a project
choice.

### 5.2 The key_ID synchronisation problem (the central correctness risk)

**The problem.** The thesis plan explicitly flags this as one of the two worst
possible bugs: if the master SAE pulls a key from KME-A and receives a
`key_ID`, the slave SAE *must* receive the byte-identical key when it later
asks KME-B for that same `key_ID`. If the two KMEs ever disagree about which
bytes a `key_ID` maps to, the entire protocol silently fails.

**First design and why it was wrong (a real bug the tests caught).** The
initial store marked a key "delivered to master" on KME-A's *own* per-key
bookkeeping record. But KME-B holds a *separate* bookkeeping record around the
same key. When the slave asked KME-B for the key, KME-B had no idea a master
had activated it on KME-A, and refused it. The Phase 3 acceptance test failed
exactly here — which is precisely what that test exists to catch.

**The fix: a simulated KME-to-KME synchronisation channel.** Real ETSI 014
KMEs coordinate key↔SAE assignments over an authenticated internal link
between the KMEs. We model that directly: the two stores are *linked*, and
when a master reserves keys on one KME, that reservation
`(key_ID, master_SAE, slave_SAE)` is mirrored to the peer KME. After
`enc_keys` returns, the slave can fetch the same `key_ID` from the peer and
receive identical bytes. Two further safeguards make the byte-identity
guarantee airtight: both KMEs are fed the *same* `KeyBlock` objects by the
fan-out feeder (same UUID, same bytes), and the mirrored reservation only
records intent — it never copies key material across the channel.

**Defense note.** If asked "how do the two KMEs agree on the key?": they share
the same physically-distilled key blocks (in reality, from the same quantum
channel), and they coordinate *which* `key_ID` is assigned to *which* SAE pair
over an authenticated KME-to-KME channel — exactly the architecture ETSI 014
describes. The implementation models that channel as a direct linked-peer call
rather than a network hop, which is a faithful simplification (documented, not
hidden).

### 5.3 No key reuse

**Decision.** Once a master pulls a key it is marked delivered and tagged with
the `(master, slave)` pair; afterwards only the intended slave may fetch it,
by ID. It is never handed out again as fresh material.

**Why.** This is the property that keeps the One-Time Pad a *one-time* pad —
the single most security-critical invariant in the whole thesis. It is
enforced in the store, not left to callers, and is covered by tests that
assert a wrong slave is rejected (403) and that an un-activated key cannot be
fetched (400).

### 5.4 Pool exhaustion returns 503, deliberately

**Decision.** When the pool cannot satisfy an `enc_keys` request the KME
responds **503**, not 500.

**Why.** Running out of key is *not a server fault* — it is the fundamental,
expected QKD constraint the thesis sets out to demonstrate (maximum security
at the cost of key bandwidth). A 503 ("service temporarily unavailable")
correctly frames it as back-pressure the application must handle, and gives
the later visualization a clean signal to show the pool draining.

### 5.5 SAE identity: a single authentication seam

**Decision.** SAE identity is resolved by one injectable dependency. Under
mTLS it would come from the verified client-certificate CN; for tests and
local runs it falls back to an `X-SAE-ID` header. A request with no identity
is rejected with 401.

**Why.** uvicorn does not surface the peer certificate to the route handler
conveniently. Concentrating identity resolution in a single seam keeps every
endpoint's logic identical regardless of how the SAE was authenticated, and
keeps the security-relevant code in one auditable place. This is documented as
a deliberate simplification, **not** presented as a hardened authentication
implementation.

### 5.6 Pure-Python mTLS certificate machinery

**Decision.** A self-signed demo CA, KME server certificates, and per-SAE
client certificates (with CN = SAE ID) are generated entirely via the
`cryptography` library — no OpenSSL CLI, no native build step.

**Why.** It preserves the project's "pure Python, pip-installable, no C
compiler" property. The Phase 3 test proves the chain is real: a client cert
issued by the demo CA verifies cryptographically against that CA and its CN
equals the SAE ID — the exact identity mechanism ETSI 014 relies on. It is
explicitly stated to be a *demo* CA (unencrypted keys, not a real trust
anchor) so no stronger claim is implied.

### 5.7 Phase 3 acceptance tests

Eleven tests cover: the ETSI-shaped `Status`; rejection of unidentified
callers; **the core criterion — `enc_keys` on KME-A then `dec_keys` on KME-B
returning byte-identical material**; ACL enforcement; the no-reuse /
wrong-slave / un-activated-key rejections; 503 back-pressure on exhaustion;
malformed input handling; key expiry; the fan-out feeder synchronising both
KMEs; and a real mTLS CA→client-cert→verify round-trip. Full suite across
Phases 1–3: 26 passing, the 30 s concurrency test deselected by default.

---

## 6. Phase 4 — Core cryptographic modes (OTP + Wegman-Carter)

Phase 4 implements the two *information-theoretically secure* primitives, in
isolation from the protocol that will use them in Phase 5.

### 6.1 OTP reuse made structurally impossible, not merely forbidden

**Decision.** One-Time Pad key material lives in an `OTPKeyStream` that hands
out each byte at most once and raises if asked for more than remains. The
cipher *cannot* encrypt without consuming fresh stream — there is no API path
that re-applies a byte.

**Why this design and not "just be careful".** The plan calls OTP reuse "the
worst possible bug — it destroys your thesis if discovered at review." Reuse
collapses Shannon secrecy completely: the XOR of two same-key ciphertexts
equals the XOR of the two plaintexts. Making reuse a matter of caller
discipline would mean a single mistake anywhere in Phase 5+ silently destroys
the security claim. Instead the offset only ever advances and consumed bytes
are unreachable, so reuse is *structurally* impossible. A dedicated test
asserts two identical plaintexts from one stream produce *different*
ciphertexts — direct evidence the second message used fresh key.

**Defense note.** "How do you guarantee the pad is never reused?" — the key
stream has a monotonic consumed-offset with no rewind/re-read method;
encryption consumes before it emits, so exhaustion raises *instead of*
producing an insecure ciphertext. It is enforced by the type, not by
convention.

**Confidentiality only — deliberately.** This module never authenticates. A
flipped OTP ciphertext bit flips the plaintext bit undetectably, so OTP is
*always* paired with the Wegman-Carter MAC. Keeping them separate modules
makes that separation of guarantees explicit for the reader.

**Exhaustion is normal, not an error.** `OTPKeyExhaustedError` represents the
fundamental finite-key-budget constraint of QKD; it is meant to be handled as
back-pressure (Phase 5+), consistent with the KME's 503 behaviour.

### 6.2 Wegman-Carter: the main information-theoretic contribution

**Construction.** `tag = poly_hash(k_H, message) XOR r`, where `poly_hash` is
a polynomial evaluation hash over GF(2^128) and `r` is a *fresh one-time pad*
consumed from the QKD pool. This is the Wegman-Carter (1981) construction;
Portmann (2014) proves it universally composable — the correct security notion
for QKD, and the right citation for the defense.

**Why GF(2^128) / GHASH specifically.** The hash uses the *same field and
reduction polynomial as GHASH inside AES-GCM*. This is a strong, defensible
framing: the construction is structurally identical to GCM's authenticator,
with exactly one change — GCM masks with `E_K(nonce)` (a block-cipher output,
hence only *computationally* secure), whereas we mask with a true one-time pad
`r`. That single substitution is precisely what turns a computational MAC into
an information-theoretically secure one. Forgery probability is bounded by
`(n_blocks + 1) / 2^128` **independent of the attacker's computing power**.

**Defense note ("why not HMAC?").** HMAC's security is computational (rests on
the hash's PRF assumption). Wegman-Carter's is unconditional, matching the
OTP, so end-to-end security survives *any* cryptanalytic or quantum progress —
not just the key exchange.

### 6.3 Key recycling: why authentication is affordable

**Decision.** The API takes `k_H` once (reusable across many messages) but
forces the caller to pass a fresh `r` on every `tag`/`verify` call.

**Why.** Portmann's key-recycling result: the hash key `k_H` may be safely
reused; only the mask `r` must be fresh per message. This is what makes the
QKD budget for authentication practical — 128 fresh bits per message instead
of a full-length pad. Forcing `r` to be an explicit per-call argument (rather
than hiding it inside the object) makes accidental `r` reuse visible at every
call site, mirroring the OTP "structural safety" philosophy.

### 6.4 Length binding

**Decision.** `poly_hash` folds in a final block encoding the message
bit-length.

**Why.** Without binding the length, a pure block-by-block polynomial hash
admits trivial truncation/zero-extension forgeries. Appending the length block
(exactly as GCM appends its `len(A)||len(C)` trailer) closes this. A test
asserts that appending zero bytes changes the tag.

### 6.5 Implementation honesty

`gf128_mul` is pure Python and intentionally **not** micro-optimised. The
thesis states plainly that this is the known performance hot path and that
real deployments use the hardware GHASH/AES-NI instruction path; this is an
honest limitation to discuss in the evaluation chapter, not a defect. Two
guard rails are also worth noting for the defense: a **zero hash key is
rejected** (it would make every tag equal to `r`, trivially forgeable), and
tag comparison is **constant-time** (it must not leak where a forgery first
differs).

### 6.6 Phase 4 acceptance tests

Sixteen tests cover: OTP round-trip and the literal `ct = pt XOR key`
identity; strictly-forward stream consumption; **reuse being structurally
impossible** (identical plaintexts → different ciphertexts); exhaustion
raising *before* emitting ciphertext; GF(2^128) field-law correctness
(identity, commutativity, distributivity over XOR, zero); WC tag verification;
forgery rejection for modified message, modified tag, and wrong mask; length
binding; rejection of bad key/mask sizes and the zero key; and an explicit
check of the defining WC structure `tag XOR r == poly_hash(k_H, m)`. Full
suite across Phases 1–4: 42 passing.

---

## 7. Phase 5 — QTLS protocol (handshake + record layer)

Phase 5 is the integration phase: it ties the QKD layer, the KME, and the
crypto primitives into an actual "TLS 1.3-shaped" protocol that two peers
speak over a real TCP socket.

### 7.1 What is kept from TLS 1.3 and what is replaced

**Decision.** Keep RFC 8446's *structure* — ClientHello / ServerHello /
Finished flights, the HKDF-Extract / Derive-Secret / HKDF-Expand-Label key
schedule, transcript hashing, the Finished key-confirmation MAC — and replace
*exactly one thing*: the (EC)DHE key agreement becomes a QKD key lookup by
`key_ID` through the KME.

**Why.** This is the precise sense in which the thesis title is justified. The
protocol is not "inspired by" TLS in a vague way; it follows the same key
schedule and message flow, with the single, well-isolated substitution that is
the entire point of the work. A reviewer can line the handshake up against
RFC 8446 section 7.1 and see the correspondence.

**Defense note.** "Is this really TLS-shaped or just a custom protocol?" — the
key schedule labels (`c hs traffic`, `s ap traffic`, `derived`, `finished`)
and the HkdfLabel structure are RFC 8446 verbatim; only the secret fed into
HKDF-Extract differs (QKD key instead of ECDHE). Everything downstream of that
secret is standard TLS 1.3 mechanics.

### 7.2 The handshake flow and mutual key confirmation

1. Client pulls a QKD key from its KME (`enc_keys`), receives `key_ID`.
2. ClientHello carries that `key_ID` (plus randoms and the client's SAE ID).
3. Server fetches the *same* `key_ID` from its KME (`dec_keys`) — Phase 3's
   synchronisation guarantees byte-identical material.
4. ServerHello echoes the `key_ID`.
5. Both sides run the identical HKDF schedule over the QKD key + transcript.
6. Each sends a **Finished** = HMAC(finished_key, transcript). Because
   `finished_key` derives from the QKD key, a correct Finished proves the
   peer holds the *same* QKD key **and** that the transcript was not
   tampered with. A mismatch aborts the connection.

The Finished exchange is the moment the protocol gains assurance that both
endpoints truly share the key — the QKD analogue of TLS authenticating the
key agreement.

### 7.3 Record layer: OTP + Wegman-Carter instead of an AEAD

**Decision.** A record is `header(type,length) || OTP-ciphertext || WC-tag`.
The tag covers the header *and* ciphertext.

**Why tag the header too.** OTP alone is malleable; authenticating only the
payload would still let an attacker tamper with the record type or length.
Covering the header closes that, exactly as a TLS AEAD authenticates its
associated data.

**Key sourcing decision (chosen deliberately).** The handshake obtains *one*
sizeable QKD key; both sides derive an `OTPKeyStream` from it, and each record
consumes `len(payload)` bytes for the OTP plus 16 bytes for a fresh
Wegman-Carter mask `r`, **from the same stream**. The alternative — a separate
KME HTTP round-trip per record — was rejected as needlessly chatty and as
tightly coupling the record layer to HTTP; the chosen design keeps the 1:1
key:plaintext ratio and the no-reuse guarantee while staying clean. Crucially,
`r` comes from real QKD stream bytes, never a PRF — that is what keeps the MAC
information-theoretic rather than merely computational.

### 7.4 Directional key separation (a correctness must-have)

**Decision.** The raw OTP material is split into two *disjoint* halves: one
for client→server records, one for server→client. Each direction also gets
its own (reusable) Wegman-Carter hash key from the schedule.

**Why.** If both directions drew OTP bytes from the same region, the two
streams would eventually XOR plaintext into identical key positions — OTP
reuse across directions, which is just as fatal as reuse within a direction.
Splitting *before* any record is sent makes that structurally impossible. The
two endpoints run the identical deterministic split, so the client's send
stream is byte-identical to the server's receive stream and vice versa; TCP's
in-order delivery keeps them advancing in lockstep (a test sends 10
sequential records to prove this).

### 7.5 KME transport: real HTTP via httpx

**Decision.** The client and server reach their KMEs over real HTTP using
`httpx` (the ETSI REST interface from Phase 3). Tests inject httpx's
in-process ASGI transport so they hit the same FastAPI app without a real
socket, while the QTLS link *itself* uses a genuine loopback TCP socket.

**Why.** Using the real REST path exercises and validates the standards
compliance built in Phase 3 rather than bypassing it. The ASGI transport in
tests is a speed optimisation that does not change the code path through the
KME, so the standards-compliance claim still holds.

### 7.6 Handshake messages as JSON

**Decision.** ClientHello/ServerHello/Finished are compact JSON, not a
byte-exact TLS encoding.

**Why.** A binary TLS-exact wire format would add substantial parsing code and
*no* security (the security comes from the QKD key and the record layer, not
the handshake byte layout). JSON keeps the handshake auditable in packet
captures for the defense demo. This is explicitly a presentation choice, not a
security one, and is documented as such.

### 7.7 A real bug the tests caught (worth recounting at the defense)

The first key-schedule implementation passed the *raw* handshake transcript as
the `context` argument of HKDF-Expand-Label. RFC 8446's `Derive-Secret`
actually takes `Transcript-Hash(Messages)` — a fixed 32-byte digest — not the
raw messages. The raw transcript exceeded the 1-byte HkdfLabel context-length
field and the schedule crashed. The fix (hash the transcript once in the
schedule constructor) is also what makes the implementation *correctly* match
the RFC, not just "not crash." This is a good example to cite of the
acceptance tests enforcing spec-faithfulness, not just functionality.

### 7.8 Phase 5 acceptance tests

Five tests, all exercising the full stack (real FastAPI KMEs over httpx, HKDF
schedule, OTP+WC record layer, real loopback TCP): **the core criterion** —
client sends "Hello, server", server decrypts and the WC tag verifies, plus a
bidirectional ack; **wire carries ciphertext only** — a socket tap proves the
plaintext marker never appears on the wire; a tampered record is rejected with
a WC authentication error; the handshake aborts when the server's KME cannot
resolve the `key_ID` (no proceeding with mismatched keys); and ten sequential
records all decrypt (directional streams stay in lockstep). Full suite across
Phases 1–5: 47 passing.

---

## 8. Phase 6 — Demo application

Phase 6 puts a small application on top of QTLS so the protocol can be shown
working live, and so the QKD key-budget constraint becomes visible.

### 8.1 Assembly only, no new protocol logic

**Decision.** `app/demo_runtime.py` (a `DemoStack` context manager) wires the
existing components — Phase 2 bulk producer, Phase 3 linked KME pair + fan-out
feeder, Phase 5 QTLS connection — into one process and one event loop.
`app/demo_chat.py` adds only the application-level send/receive loops and a
CLI.

**Why.** The demo must run *exactly* the code the earlier phases' tests
validate; if the demo had its own protocol shortcuts, a successful demo would
not prove the tested system works. Keeping Phase 6 to pure assembly preserves
that chain of evidence and is a point worth stating at the defense.

### 8.2 Chat vs. file transfer

**Decision.** Implement the simpler of the plan's two options — a CLI chat —
plus an explicit file-transfer stress mode.

**Why.** Chat demonstrates correctness and interactivity; the file transfer
demonstrates the *thesis's central trade-off*: OTP consumes one key bit per
message bit, so a sustained transfer drains the key faster than QKD can
replenish it and the connection hits back-pressure. Both modes share the same
validated send/receive code; the file mode just loops it.

### 8.3 The honest sizing decision (important for the defense)

**Problem discovered during implementation.** The first demo used a multi-
megabit per-second key rate so the pool would hold large blocks. But the
bulk generator's cost is dominated by Cascade reconciliation, which is
~O(n · passes); a half-megabit bit-list takes tens of seconds per block, so
the pool never filled and the demo hung. The Phase 6 tests caught this as a
timeout.

**Decision.** The demo feeds the bulk link at a *tractable* 131 072 raw
bits per tick (~8 KB of final key in ~1 s) rather than faking a huge
instantaneous key rate.

**Why this is the honest choice, not a workaround.** Real QKD key rates are
*low* (tens to hundreds of kbps in deployed systems). Pretending the
simulator can mint megabytes of key per second to make a file transfer
"succeed" would actively misrepresent the technology and undermine the
thesis. The tractable rate keeps the simulation honest and makes the
file-transfer demo do the *right* thing: visibly hit back-pressure, which is
the entire point. This trade-off is also flagged for the evaluation chapter
(Phase 9) and is a defensible, deliberate decision rather than a performance
defect.

### 8.4 Where the "pool drain" actually happens (a conceptual clarification)

**Clarification worth making explicit.** One QTLS connection consumes exactly
*one* KME key block at handshake time; the record layer then draws OTP from
that block's stream. So during a single transfer the KME pool's *block count*
barely moves — what actually drains is the **per-connection OTP stream**,
surfacing as `OTPKeyExhaustedError` → graceful back-pressure. The KME pool
depth is the coarser, longer-timescale signal (it drops one block per new
connection). The demo and tests therefore treat *bytes successfully sent
before exhaustion* as the primary drain evidence, with pool depth as the
secondary view. This distinction is stated plainly so the defense narrative
("watch the pool drain") is technically accurate rather than hand-wavy.

### 8.5 Graceful exhaustion, never a crash

**Decision.** When either side's OTP stream exhausts mid-transfer, the client
reports `{bytes_sent, key_pool_exhausted}` and the server breaks its loop
cleanly; the connection closes without an exception escaping.

**Why.** Exhaustion is the *expected demonstration*, not a fault — consistent
with the KME's 503 (Phase 3 §5.4) and the OTP module's design (Phase 4 §6.1).
A crash here would muddle the very point the demo exists to make.

### 8.6 Phase 6 acceptance tests

Three tests over the fully assembled stack: a live multi-message chat
exchange where the server decrypts each message and the client receives
running-total acks; a file transfer that drains key and ends in graceful
back-pressure (pool depth does not increase, bytes were sent); and a small
transfer that fits one connection's budget completing cleanly (the
non-degraded path). Full suite across Phases 1–6: 50 passing.

---

## 9. Cross-cutting decisions

### 4.1 Phase-by-phase delivery with review gates

The project is delivered one phase at a time, each gated by an explicit
acceptance test, and reviewed before the next phase begins. This is a
deliberate process decision for an academic artifact: it keeps every part
understandable and individually defensible, and prevents an
"all-at-once" delivery whose bugs would be hard to attribute and explain.

### 4.2 No scope cutting

The original plan included an "MVP triage" list of features to drop under time
pressure. This project does **not** follow that triage; planned scope is
implemented in full unless a strong, explicitly justified reason to cut
emerges. Any such cut would be recorded here with its justification.

### 4.3 Code style

Code is written as clean, idiomatic Python with explanatory comments
concentrated on the non-obvious cryptographic and QKD logic, using the same
terminology as the thesis (sifting, reconciliation, privacy amplification,
QBER, Shor–Preskill bound). The goal is code that can be walked through
line-by-line in front of a committee.

---

## 10. Glossary (for the thesis reader)

- **BB84** — the first QKD protocol (Bennett & Brassard, 1984); encodes bits
  in randomly chosen conjugate bases.
- **Sifting** — discarding the positions where Alice's and Bob's basis choices
  differed.
- **QBER** — Quantum Bit Error Rate; the fraction of sifted bits where Alice
  and Bob disagree.
- **Reconciliation** — classical error correction that makes the two sifted
  strings identical (here: simplified Cascade).
- **Privacy amplification** — compressing the reconciled key to remove any
  partial knowledge an eavesdropper might hold (here: SHAKE-128 truncation).
- **Shor–Preskill bound** — the ~11% QBER above which no secret key can be
  distilled.
- **Intercept-and-resend** — a basic eavesdropping attack that, due to
  no-cloning, injects a detectable ~25% error rate.
- **Information-theoretic security** — security that holds regardless of the
  attacker's computational power, as opposed to *computational* security
  which relies on unproven hardness assumptions.
- **KeyBlock** — the project's unified container for one finished block of
  shared secret key, emitted identically by both QKD sources.
- **Abstract bulk source** — the high-rate Phase 2 generator that produces key
  material without simulating qubits, used for throughput experiments.
- **Binary-symmetric channel** — the error model used by both the BB84
  `noise` parameter and the bulk generator: each bit independently flipped
  with probability equal to the QBER.
- **KME (Key Management Entity)** — the server that stores QKD keys and serves
  them to local SAEs over the ETSI GS QKD 014 REST interface.
- **SAE (Secure Application Entity)** — an application that consumes keys from
  a KME; here, the QTLS client and server.
- **ETSI GS QKD 014** — the standardised REST API (status / enc_keys /
  dec_keys) by which an SAE obtains keys from a KME.
- **key_ID** — the UUID a master SAE receives with a key; the slave SAE uses
  the same key_ID to fetch the byte-identical key from its own KME.
- **mTLS** — mutual TLS; both client and server present certificates. The
  SAE's identity is the Common Name of its client certificate.
- **One-Time Pad (OTP)** — `ciphertext = plaintext XOR key` with a uniformly
  random, never-reused key at least as long as the plaintext; perfectly
  secret (Shannon, 1949).
- **Wegman-Carter MAC** — `tag = H_{k_H}(m) XOR r` with a universal hash and a
  fresh one-time mask `r`; information-theoretically secure authentication.
- **GHASH / GF(2^128)** — the finite field and polynomial hash used inside
  AES-GCM; reused here structurally, but masked with a true OTP instead of a
  block-cipher output.
- **Key recycling** — Portmann's result that the WC hash key `k_H` may be
  reused across messages while only the mask `r` must be fresh.
- **Universal composability** — the strong security notion (Portmann, 2014)
  under which the WC MAC remains secure when composed with the rest of QKD.
- **HKDF key schedule** — the RFC 8446 §7.1 Extract/Derive-Secret/Expand-Label
  chain that turns one secret into all traffic keys; here seeded by the QKD
  key instead of an ECDHE output.
- **Transcript hash** — SHA-256 over the concatenated handshake messages;
  binds the derived keys to the exact handshake so tampering is detected.
- **Finished message** — an HMAC over the transcript using a QKD-derived key;
  proves both peers hold the same QKD key (mutual key confirmation).
- **Record** — the on-the-wire unit: `header || OTP-ciphertext || WC-tag`.
- **Directional key separation** — splitting the OTP material into disjoint
  client→server and server→client streams so the two directions never reuse
  key bytes.
- **Back-pressure** — the system refusing further records once the key budget
  is exhausted, instead of reusing key or crashing; the visible form of the
  QKD bandwidth constraint.
- **DemoStack** — the Phase 6 single-process assembly of the whole stack
  (QKD feed → KMEs → QTLS) used by the demo and the integration tests.
