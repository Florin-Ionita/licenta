r"""Draw a small, hand-picked BB84 circuit for the thesis figure.

Run from the repo root:

    .venv\Scripts\python.exe scripts\draw_bb84_circuit.py

Produces ``docs/figures/bb84_circuit_demo.pdf`` (and ``.png``). The bases below
are chosen so the picture covers all four (prep_basis, meas_basis)
combinations -- it is the canonical "what BB84 looks like as a circuit"
illustration, not a real protocol round.
"""

from __future__ import annotations

from pathlib import Path

from qiskit import QuantumCircuit


def build_demo_circuit() -> QuantumCircuit:
    # Hand-picked so every (prep_basis, meas_basis) combination appears:
    #   q0: prep Z, meas Z  -> sifted, bit stays 0
    #   q1: prep Z, meas X  -> mismatched basis, random outcome
    #   q2: prep X, meas X  -> sifted, bit stays 1
    #   q3: prep X, meas Z  -> mismatched basis, random outcome
    prep_bits  = [0, 1, 1, 0]
    prep_bases = [0, 0, 1, 1]   # 0 = Z, 1 = X
    meas_bases = [0, 1, 1, 0]

    n = len(prep_bits)
    qc = QuantumCircuit(n, n)

    for i in range(n):
        if prep_bits[i]:
            qc.x(i)
        if prep_bases[i]:
            qc.h(i)
    qc.barrier()
    for i in range(n):
        if meas_bases[i]:
            qc.h(i)
        qc.measure(i, i)

    return qc


def main() -> None:
    out_dir = Path(__file__).resolve().parent.parent / "docs" / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)

    qc = build_demo_circuit()

    fig = qc.draw(output="mpl", style="iqp")
    fig.savefig(out_dir / "bb84_circuit_demo.pdf", bbox_inches="tight")
    fig.savefig(out_dir / "bb84_circuit_demo.png", bbox_inches="tight", dpi=200)

    print("Wrote:")
    print(f"  {out_dir / 'bb84_circuit_demo.pdf'}")
    print(f"  {out_dir / 'bb84_circuit_demo.png'}")


if __name__ == "__main__":
    main()
