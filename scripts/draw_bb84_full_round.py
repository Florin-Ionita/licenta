r"""Draw the *real* default BB84 round (n_qubits=64) for reference.

This is the circuit ``bb84_round()`` actually executes with its default
parameters. The image is tall and dense -- not a thesis figure, but a
truthful illustration of one production round.

Run from the repo root:

    .venv\Scripts\python.exe scripts\draw_bb84_full_round.py
"""

from __future__ import annotations

from pathlib import Path

from qiskit import QuantumCircuit

from qkd.bb84 import bb84_round


def main() -> None:
    r = bb84_round(n_qubits=64)

    n = r.n_qubits
    qc = QuantumCircuit(n, n)
    for i in range(n):
        if r.alice_bits[i]:
            qc.x(i)
        if r.alice_bases[i]:
            qc.h(i)
    qc.barrier()
    for i in range(n):
        if r.bob_bases[i]:
            qc.h(i)
        qc.measure(i, i)

    out_dir = Path(__file__).resolve().parent.parent / "docs" / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)

    fig = qc.draw(output="mpl", style="iqp", fold=-1)  # fold=-1 = no wrap
    fig.savefig(out_dir / "bb84_circuit_full_round.pdf", bbox_inches="tight")
    fig.savefig(
        out_dir / "bb84_circuit_full_round.png",
        bbox_inches="tight",
        dpi=150,
    )

    print(f"Wrote {out_dir / 'bb84_circuit_full_round.pdf'}")
    print(f"Wrote {out_dir / 'bb84_circuit_full_round.png'}")
    print(f"Sifted positions: {r.sifted_length}/64")


if __name__ == "__main__":
    main()
