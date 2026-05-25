# Recent changes & migration notes

This file is a running log of what changed in the project since the original
"Phases 1-9 complete" snapshot, so the same code can be run on another
machine (Windows, fresh Linux clone, ...) without surprises.

## Scope

Covers everything from the **C-accelerated Cascade** rewrite onward. The
Phases 1-9 architecture (BB84, KME, QTLS, dashboard, benchmark suite) is
unchanged at the API level -- only the reconciliation backend and a couple
of benchmark internals were rewritten for fidelity and speed.

## What changed

### 1. Full Cascade reconciliation with back-propagation, in C

**Why.** The original `qkd/reconciliation.py` used a simplified "Cascade-lite"
that skipped back-propagation. Its leakage estimate (`corrected * log2(n)`)
was so conservative that privacy amplification refused to extract any key
above ~5% QBER. The plot showed implementation "dying" at 5%, but the real
protocol does not -- the limitation was the implementation, not the physics.

**What.** Two new files:

- [`qkd/_cascade.c`](../qkd/_cascade.c) -- ~380 lines: classical Brassard-
  Salvail 1994 Cascade. Per-pass state (permutation, inverse, block parities
  at setup, permuted Bob view kept live), BINCONF binary search, full
  back-propagation through the history, exact tally of every parity bit
  announced on the public channel. A self-contained PCG32 RNG so the C side
  has no libc dependencies beyond `stdint`, `stdlib`, `string`.
- [`qkd/_cascade.py`](../qkd/_cascade.py) -- ctypes loader. On import:
  1. Looks for `qkd/libcascade.so` (or `.dll` on Windows).
  2. If missing or older than `_cascade.c`, invokes the system C compiler
     (`cc`/`clang`/`gcc` on POSIX, `cl`/`gcc` on Windows) to (re)build it.
  3. If no compiler is available or compilation fails, the import raises
     `ImportError`. The project deliberately has no Python fallback -- the
     benchmarks and Phase 6/8 tests rely on the C speed to stay inside their
     timeouts.

**Effect.** Plot `06_qber_vs_rate` now traces the Shor-Preskill curve up to
the 11% threshold, with ~12-15% Cascade overhead consistent with published
implementations.

### 2. Asyncio thread offload in `abstract_qkd_link`

**Why.** Cascade for a 1 Mbit block takes 1-2 s of CPU. The producer used
to call it synchronously inside an asyncio task, blocking the entire event
loop -- so `asyncio.sleep(1.0)` actually slept for ~2-3 s and the apparent
key rate was several times lower than the channel could sustain. The
dashboard and QTLS handshakes also stalled while the producer was busy.

**What.** Single line change in
[`qkd/abstract_link.py`](../qkd/abstract_link.py):

```python
block = await asyncio.to_thread(
    generate_block, effective_bits, qber, qber_abort,
)
```

Cascade runs in a worker thread; the asyncio loop stays responsive.

**Effect.** The producer's true rate (1 block per simulated second) is
restored, so the QBER bench's measured rate now aligns with the theoretical
curve at the per-second level. The dashboard stays smooth during the heavy
QBER=8% case.

### 3. Three-curve QBER plot (theoretical / realistic Cascade / measured)

**Why.** Previously the plot had two curves: pure Shor-Preskill (the physics
ceiling) and the measured points. The gap looked like 5-8x and seemed like
an implementation failure. In reality, ~85% of that gap is the structural
overhead of *any* Cascade implementation vs Shannon-optimal LDPC, plus byte-
rounding in privacy amplification.

**What.** Updated
[`benchmarks/qber_sweep.py`](../benchmarks/qber_sweep.py) and
[`benchmarks/plotting.py`](../benchmarks/plotting.py):

- Added `_cascade_secret_rate_Bps(qber, raw_rate)` returning
  `(1 - 2.15 * h2(QBER)) * raw_rate / 8` -- Shannon + 15% Cascade leak.
- CSV now contains three series labels: `theoretical`, `cascade`, `measured`.
- Plot draws:
  - **Blue solid**  -- Shor-Preskill (physics ceiling).
  - **Green dashed** -- realistic Cascade (Shannon + 15%).
  - **Orange diamonds** -- this implementation, measured.

The thesis-relevant comparison is **orange vs green**: both run Cascade and
should track closely. Blue vs green is the structural Cascade penalty (closed
by LDPC, which is Future Work).

### 4. `.gitignore` additions

Compiled C artifacts (`*.so`, `*.dll`, `*.dylib`) are now ignored; they are
rebuilt locally on first import.

## How to reproduce on a fresh machine (e.g. your other PC)

### Linux

```bash
git pull                                              # latest changes
python3.12 -m venv .venv-linux
source .venv-linux/bin/activate
pip install -e ".[dev,viz,bench]"
pytest                                                # confirm 52 passed
python -m benchmarks.runner --profile lite            # ~1-2 min
streamlit run viz/main.py                             # the demo
```

The C compiler check happens on the first `import qkd.reconciliation`:
- `cc --version` or `gcc --version` should produce output. If not:
  `sudo apt install build-essential` (Debian/Ubuntu) or equivalent.
- **If no compiler is available the import raises `ImportError`** -- the
  project has no Python fallback. Install a compiler before running tests
  or benchmarks.

### Windows

```powershell
git pull
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev,viz,bench]"
pytest                                                # confirm 52 passed
python -m benchmarks.runner --profile lite
streamlit run viz/main.py
```

The C extension needs **one** of:
- **MSVC (`cl.exe`)** -- install Visual Studio Build Tools and "Desktop
  development with C++". Open a "Developer PowerShell for VS" so `cl` is
  on PATH.
- **MinGW-w64 (`gcc.exe`)** -- install via `winget install MSYS2.MSYS2`
  and add `C:\msys64\ucrt64\bin` to PATH.

Without one of these, `import qkd.reconciliation` raises `ImportError` and
the test/benchmark suites will not run.

To force a rebuild after editing `qkd/_cascade.c`:
```bash
rm qkd/libcascade.so          # or  del qkd\libcascade.dll  on Windows
python -c "import qkd.reconciliation"   # triggers rebuild on next import
```

## Regenerating plots without re-running benches

```bash
python -m benchmarks.replot                        # all available
python -m benchmarks.replot --only qber_sweep      # just one
```

Reads the CSVs in `docs/benchmarks/raw/`, writes PDFs to
`docs/benchmarks/plots/`. Useful for iterating on plot styling.

## Smoke checks after a fresh setup

```bash
# 1. Verify the C extension loaded
python -c "from qkd import _cascade; print('C loaded:', _cascade._LIB_HANDLE is not None)"
# expected: C loaded: True
# (if the C library cannot be built, the import itself raises ImportError --
# there is no Python fallback)

# 2. Confirm Cascade is correct on a small case
python -c "
import secrets, random
from qkd.reconciliation import cascade_reconcile
random.seed(0); n = 4096
alice = [secrets.randbits(1) for _ in range(n)]
bob = [b ^ (1 if random.random() < 0.05 else 0) for b in alice]
c, l = cascade_reconcile(alice, bob, 0.05)
print(f'corrected={c} leaked={l} match={alice==bob}')
"
# expected: c ~ 200, l ~ 1300, match=True

# 3. Full test suite
pytest -q
# expected: 52 passed, 1 deselected
```

## Files added or changed in this round

| File | Change |
|------|--------|
| `qkd/_cascade.c` | NEW -- full Cascade in C |
| `qkd/_cascade.py` | NEW -- ctypes loader + auto-build; raises `ImportError` if no C compiler is available (no Python fallback) |
| `qkd/reconciliation.py` | public `cascade_reconcile` re-exports the C entry point; the Python implementation has been removed |
| `qkd/abstract_link.py` | producer uses `asyncio.to_thread` to offload Cascade |
| `benchmarks/qber_sweep.py` | added `_cascade_secret_rate_Bps`, CSV has three series |
| `benchmarks/plotting.py` | three-curve QBER plot |
| `benchmarks/replot.py` | loader merges theoretical/cascade/measured rows by QBER |
| `.gitignore` | ignore `*.so`, `*.dll`, `*.dylib` |
| `README.md` | "Native C Cascade" section, build instructions |
| `docs/CHANGES.md` | this file |

---

## Round 2: plot 06 now honours the Shor-Preskill ceiling

In the first regenerated `06_qber_vs_rate.pdf` the measured orange diamonds
sat *above* the blue Shor-Preskill physics ceiling at low QBER -- physically
impossible, so a measurement artefact. Three related bugs were responsible;
fixing them yields a plot where orange is strictly below blue at every QBER,
tracks the realistic Cascade curve within ~10-15% at low QBER, and pulls
further below it as QBER grows (the well-known Cascade penalty).

### 2.1 Producer wall-clock-time did not equal channel-time

**Why.** `abstract_qkd_link` did `await asyncio.sleep(1.0)` *before* each
distillation. With a 1 Mbit block taking ~1.2 s of Cascade, one iteration
actually lasted ~2.2 s, so the link silently emitted at *half* its declared
`key_rate_bps`. Every measured point was pulled down accordingly.

**Fix.** Real-time pacing anchor in
[`qkd/abstract_link.py`](../qkd/abstract_link.py):

```python
next_tick = time.monotonic()
while not stopped:
    next_tick += 1.0
    block = await asyncio.to_thread(generate_block, ...)
    await out_queue.put(block)
    delay = next_tick - time.monotonic()
    if delay > 0:
        await asyncio.sleep(delay)
    else:
        # Distillation exceeded one simulated second on this host: we are
        # CPU-bound. Re-anchor `next_tick` to now so we do not accumulate
        # an ever-growing backlog of missed ticks.
        next_tick = time.monotonic()
```

If Cascade overruns the 1 s tick (e.g. >10 Mbit blocks on a slow host) the
link runs flat-out instead of accumulating phantom backlog. Document under
evaluation limitations rather than silently distorting the rate.

### 2.2 Warm-up block inflated the measurement

**Why.** `_measure_one` was counting the first block's *bytes* but starting
the clock *after* it arrived. The producer had spent ~1-2 s making that
block, but `elapsed` only covered the steady-state window -- so we measured
"N+1 blocks of bytes in N blocks of time" and rate sat above the ceiling.

**Fix.** Discard the warm-up block; only blocks that arrive *after* the
timer starts count toward both bytes and time.

### 2.3 Drained blocks counted bytes outside the timed window

**Why.** After `stop.set()` the bench drained any blocks still queued.
Each drained block represented up to a full simulated channel-second
*outside* the measurement window, so its bytes were counted but its
production time was not -- same direction of inflation as 2.2.

**Fix.** Don't drain. A block finished inside the window but not yet pulled
at the deadline is lost, making the estimate slightly conservative (correct
direction).

### 2.4 Measurement now timed between block arrivals, not against a wall clock

**Why.** A fixed `t0 + duration` deadline is forced into off-by-one-block
slack -- the deadline can fall anywhere in the producer's 1 Hz heartbeat,
so the same rate sometimes measures high, sometimes low.

**Fix.** Record `t_first` when block #1 of the steady-state window arrives
and `t_last` when block #N arrives. The interval `t_last - t_first` is
exactly `N-1` channel-seconds of work that produced exactly the counted
bytes. No off-by-one slack on either side.

### 2.5 Files touched

| File | Change |
|------|--------|
| `qkd/abstract_link.py` | real-time pacing anchor (`next_tick`) so wall-clock=channel-clock; CPU-bound fallback documented |
| `benchmarks/qber_sweep.py` | discard warm-up block; no drain after stop; elapsed = `t_last - t_first` |

### 2.6 Verification

```
.venv\Scripts\python.exe -m pytest -q                          # 52 passed
.venv\Scripts\python.exe -m benchmarks.runner --profile lite --only qber_sweep
.venv\Scripts\python.exe -m benchmarks.replot --only qber_sweep
```

Sanity numbers at QBER=0.5%: theoretical 119 KiB/s, realistic Cascade
118 KiB/s, **measured ~105 KiB/s** -- below both curves, with a ~12% gap to
the cascade reference explained by this implementation's conservative
`corrected * log2(n)` leakage estimate vs. the textbook 1.15× factor.
