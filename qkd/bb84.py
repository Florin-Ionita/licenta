"""BB84 quantum key distribution, simulated with a real Qiskit circuit.

This module implements one *round* of the BB84 protocol (Bennett & Brassard,
1984). A round prepares ``n`` qubits at Alice, optionally lets an eavesdropper
"Eve" intercept-and-resend them, has Bob measure them, and then performs the
classical *sifting* step where the two parties keep only the bits for which
their random basis choices happened to agree.

The quantum part runs on Qiskit's ``AerSimulator`` using the *stabilizer*
method: BB84 only ever uses Clifford gates (X and H), so the stabilizer
simulator can handle hundreds of qubits per round almost instantly while still
being a genuine quantum-circuit simulation (not a hand-written shortcut).

Basis convention used throughout:
    0 = Z basis (rectilinear, states |0> / |1>)
    1 = X basis (diagonal,    states |+> / |->)
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

# A single shared stabilizer simulator instance. Clifford-only circuits make
# this exact and very fast even for large qubit counts.
_SIMULATOR = AerSimulator(method="stabilizer")


def _random_bits(n: int) -> list[int]:
    """Return ``n`` cryptographically-strong random bits (0/1).

    We use ``secrets`` rather than ``random`` because these bits stand in for
    real quantum randomness; using a weak PRNG here would undermine the whole
    information-theoretic argument of the thesis.
    """
    return [secrets.randbits(1) for _ in range(n)]


@dataclass
class BB84Round:
    """The full record of one BB84 round, kept for tests and visualization.

    Every list is indexed by qubit position, so e.g. ``alice_bits[i]`` and
    ``bob_bases[i]`` describe the same photon. ``sifted_indices`` lists the
    positions that survived sifting; ``alice_sifted``/``bob_sifted`` are the
    corresponding bit values, which should be equal wherever Eve / channel
    noise did not disturb the qubit.
    """

    n_qubits: int
    alice_bits: list[int]
    alice_bases: list[int]
    bob_bases: list[int]
    bob_bits: list[int]
    sifted_indices: list[int]
    alice_sifted: list[int]
    bob_sifted: list[int]
    eve_present: bool = False
    eve_bases: list[int] = field(default_factory=list)

    @property
    def sifted_length(self) -> int:
        return len(self.sifted_indices)

    def observed_qber(self) -> float:
        """Fraction of sifted positions where Alice and Bob disagree.

        In a real protocol this is *estimated* by publicly comparing a random
        subset of the sifted key. Here we can compute it exactly because the
        simulator knows both sides; this is purely for tests/metrics, not used
        as secret material.
        """
        if not self.sifted_indices:
            return 0.0
        mismatches = sum(
            1 for a, b in zip(self.alice_sifted, self.bob_sifted) if a != b
        )
        return mismatches / len(self.sifted_indices)


def _measure_in_bases(
    prep_bits: list[int],
    prep_bases: list[int],
    meas_bases: list[int],
) -> list[int]:
    """Build and run one Qiskit circuit: prepare qubits, then measure them.

    ``prep_bits``/``prep_bases`` describe how each qubit is prepared (by Alice,
    or by Eve when she resends). ``meas_bases`` are the bases the measuring
    party (Bob, or Eve) chooses. Returns the measured classical bits.

    Qiskit returns the measured bitstring with qubit 0 as the *rightmost*
    character, so we reverse it to get an index-aligned list.
    """
    n = len(prep_bits)
    qc = QuantumCircuit(n, n)

    # --- State preparation -------------------------------------------------
    for i in range(n):
        if prep_bits[i]:
            qc.x(i)  # |0> -> |1>
        if prep_bases[i]:
            qc.h(i)  # rotate Z-basis state into the X basis

    qc.barrier()

    # --- Measurement -------------------------------------------------------
    for i in range(n):
        if meas_bases[i]:
            qc.h(i)  # rotate X-basis measurement back into the Z basis
        qc.measure(i, i)

    result = _SIMULATOR.run(qc, shots=1).result()
    bitstring = next(iter(result.get_counts()))
    # Reverse so that bit[i] corresponds to qubit i.
    return [int(c) for c in bitstring[::-1]]


def bb84_round(
    n_qubits: int = 64,
    eve_present: bool = False,
    noise: float = 0.0,
) -> BB84Round:
    """Run a single BB84 round and return its full :class:`BB84Round` record.

    Steps:
      1. Alice picks random bits and random preparation bases.
      2. (Optional) Eve performs an intercept-and-resend attack: she measures
         in her own random bases, then re-prepares qubits from what she saw.
         Because she guesses the basis wrong ~50% of the time, this injects a
         characteristic ~25% error rate on the sifted key -- the signature the
         legitimate parties use to detect eavesdropping.
      3. Bob measures in his own random bases.
      4. Optional depolarizing channel noise: each of Bob's measured bits is
         independently flipped with probability ``noise``. A perfect simulator
         is otherwise noiseless, so this parameter is what lets us model a
         realistic non-zero QBER (e.g. 5%) and exercise the abort threshold.
      5. Sifting: keep only positions where Alice's and Bob's bases match.
    """
    if n_qubits <= 0:
        raise ValueError("n_qubits must be positive")
    if not 0.0 <= noise <= 1.0:
        raise ValueError("noise must be a probability in [0, 1]")

    alice_bits = _random_bits(n_qubits)
    alice_bases = _random_bits(n_qubits)
    bob_bases = _random_bits(n_qubits)

    eve_bases: list[int] = []
    if eve_present:
        # Eve intercepts: she measures Alice's qubits in random bases ...
        eve_bases = _random_bits(n_qubits)
        eve_bits = _measure_in_bases(alice_bits, alice_bases, eve_bases)
        # ... then resends qubits prepared from what she measured, in her
        # (wrong half the time) bases. Bob then measures Eve's qubits.
        bob_bits = _measure_in_bases(eve_bits, eve_bases, bob_bases)
    else:
        # No eavesdropper: Bob measures Alice's original qubits directly.
        bob_bits = _measure_in_bases(alice_bits, alice_bases, bob_bases)

    # --- Channel noise -----------------------------------------------------
    if noise > 0.0:
        bob_bits = [
            b ^ 1 if secrets.SystemRandom().random() < noise else b
            for b in bob_bits
        ]

    # --- Sifting -----------------------------------------------------------
    sifted_indices: list[int] = []
    alice_sifted: list[int] = []
    bob_sifted: list[int] = []
    for i in range(n_qubits):
        if alice_bases[i] == bob_bases[i]:
            sifted_indices.append(i)
            alice_sifted.append(alice_bits[i])
            bob_sifted.append(bob_bits[i])

    return BB84Round(
        n_qubits=n_qubits,
        alice_bits=alice_bits,
        alice_bases=alice_bases,
        bob_bases=bob_bases,
        bob_bits=bob_bits,
        sifted_indices=sifted_indices,
        alice_sifted=alice_sifted,
        bob_sifted=bob_sifted,
        eve_present=eve_present,
        eve_bases=eve_bases,
    )


def collect_sifted_key(
    target_bits: int,
    n_qubits: int = 64,
    eve_present: bool = False,
    noise: float = 0.0,
) -> tuple[list[int], list[int], float]:
    """Run BB84 rounds until at least ``target_bits`` sifted bits are gathered.

    Returns ``(alice_key, bob_key, qber)`` where the two key lists are the
    concatenated sifted bits (still containing errors at this stage) and
    ``qber`` is the overall observed mismatch rate across all rounds. This is
    the entry point used by reconciliation and by the Phase 1 tests.
    """
    alice_key: list[int] = []
    bob_key: list[int] = []
    total = 0
    mismatches = 0

    while len(alice_key) < target_bits:
        r = bb84_round(n_qubits=n_qubits, eve_present=eve_present, noise=noise)
        alice_key.extend(r.alice_sifted)
        bob_key.extend(r.bob_sifted)
        total += r.sifted_length
        mismatches += sum(
            1 for a, b in zip(r.alice_sifted, r.bob_sifted) if a != b
        )

    qber = (mismatches / total) if total else 0.0
    return alice_key, bob_key, qber
