# qtls-qkd

Information-theoretic secure protocol (TLS 1.3-shaped) over a simulated QKD
network. Bachelor's thesis implementation.

See `thesis_plan.md` for the full phased roadmap, and
`docs/design_notes.md` for the decision record and rationale behind every
significant design choice (written as thesis-ready prose).

## Setup

```powershell
# Python 3.12, virtual environment already created at .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Phase 1 — Quantum core

BB84 quantum key distribution (real Qiskit circuit on the stabilizer
simulator), Cascade-lite reconciliation, and SHAKE-128 privacy amplification.

Run the Phase 1 acceptance tests:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_phase1_bb84.py -v
```
