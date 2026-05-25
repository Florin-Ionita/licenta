"""ctypes loader for the C Cascade implementation.

On import this module ensures a compiled shared library ``_cascade.so``
(or ``.dll`` on Windows) sits next to ``_cascade.c`` and is at least as
recent as the source. If the library is missing or stale we invoke the
system C compiler to (re)build it; if that fails we fall back to the pure-
Python ``_cascade_python`` implementation so the rest of the project keeps
working (with a one-time warning printed to stderr).

The wrapper exposes a single function::

    cascade_reconcile(alice: list[int], bob: list[int], qber: float,
                      passes: int = 4) -> tuple[int, int]

with the same semantics as the pure-Python version: Bob's list is mutated
in place, the return tuple is ``(errors_corrected, parity_bits_leaked)``.
"""

from __future__ import annotations

import ctypes
import os
import secrets
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

import numpy as np

_HERE = Path(__file__).resolve().parent
_SRC = _HERE / "_cascade.c"
_LIB_NAME = "libcascade.dll" if os.name == "nt" else "libcascade.so"
_LIB = _HERE / _LIB_NAME


class CCascadeUnavailable(RuntimeError):
    """Raised internally when the C library cannot be loaded or built."""


def _find_compiler() -> list[str] | None:
    """Return the argv prefix for the system C compiler, or None.

    On POSIX we try ``cc`` then ``clang`` then ``gcc``. On Windows we look
    for ``cl`` (MSVC) and fall back to ``gcc`` (MinGW); MSVC needs different
    flags so we record the flavour in the returned list to let the caller
    branch.
    """
    if os.name != "nt":
        for cand in ("cc", "clang", "gcc"):
            path = shutil.which(cand)
            if path:
                return [path]
        return None
    # Windows: MSVC's `cl` first (preferred), then MinGW `gcc`.
    for cand in ("cl", "gcc", "clang"):
        path = shutil.which(cand)
        if path:
            return [path]
    return None


def _build() -> None:
    """Compile _cascade.c to a shared library.

    We pick conservative, broadly-supported flags: ``-O3`` for speed,
    ``-fPIC`` for a relocatable shared object, ``-shared`` to emit one.
    No C99 features beyond ``stdint.h`` are used so any vaguely modern
    compiler accepts the source. On MSVC the equivalent flags are emitted.
    """
    compiler = _find_compiler()
    if compiler is None:
        raise CCascadeUnavailable("no C compiler found on PATH")

    exe = compiler[0]
    if os.path.basename(exe).lower().startswith("cl"):
        # MSVC syntax.
        cmd = [exe, "/O2", "/LD", "/Fe:" + str(_LIB), str(_SRC)]
    else:
        # cc / clang / gcc / MinGW.
        cmd = [exe, "-O3", "-shared", "-fPIC", "-std=c99",
               "-o", str(_LIB), str(_SRC)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        raise CCascadeUnavailable(
            f"C compiler failed:\n{exc.stderr}"
        ) from exc


def _load() -> ctypes.CDLL:
    """Ensure _cascade.so is built and up-to-date, then load it."""
    needs_build = (
        not _LIB.exists()
        or _SRC.stat().st_mtime > _LIB.stat().st_mtime
    )
    if needs_build:
        _build()
    lib = ctypes.CDLL(str(_LIB))
    # Bind argument and return types so ctypes does correct conversions.
    lib.cascade_reconcile.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),         # alice
        ctypes.POINTER(ctypes.c_uint8),         # bob
        ctypes.c_int32,                         # n
        ctypes.c_double,                        # qber
        ctypes.c_int32,                         # passes
        ctypes.c_uint64,                        # seed
        ctypes.POINTER(ctypes.c_int32),         # out_corrected
        ctypes.POINTER(ctypes.c_uint64),        # out_leaked
    ]
    lib.cascade_reconcile.restype = ctypes.c_int
    return lib


# --- module init: try to load C; remember failure for the Python fallback ---

try:
    _LIB_HANDLE = _load()
    _C_AVAILABLE = True
except Exception as exc:  # broad on purpose -- any failure -> fallback
    _LIB_HANDLE = None
    _C_AVAILABLE = False
    warnings.warn(
        f"qkd._cascade: C extension unavailable ({exc}); falling back to "
        f"slower pure-Python Cascade.",
        RuntimeWarning,
        stacklevel=2,
    )


# --- public API -----------------------------------------------------------


def is_c_available() -> bool:
    """True if the C Cascade implementation loaded successfully."""
    return _C_AVAILABLE


def cascade_reconcile_c(alice: list[int], bob: list[int],
                         qber: float, passes: int = 4) -> tuple[int, int]:
    """Run full Cascade reconciliation in C, mutating ``bob`` in place.

    Returns ``(corrected, leaked)``. Raises :class:`RuntimeError` on a
    reconciliation failure (caller treats as a protocol abort).
    """
    if not _C_AVAILABLE:
        raise CCascadeUnavailable("C Cascade not loaded")
    if len(alice) != len(bob):
        raise ValueError("Alice and Bob keys must have equal length")
    n = len(alice)
    if n == 0:
        return 0, 0

    # Round-trip through NumPy uint8 buffers: ctypes can hand C pointers to
    # contiguous ndarrays directly. We must keep the buffers alive for the
    # duration of the C call (Python references via the local vars below).
    alice_arr = np.ascontiguousarray(alice, dtype=np.uint8)
    bob_arr = np.ascontiguousarray(bob, dtype=np.uint8).copy()

    a_ptr = alice_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
    b_ptr = bob_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
    corrected = ctypes.c_int32(0)
    leaked = ctypes.c_uint64(0)
    # Draw a 64-bit seed from a CSPRNG so passes' permutations are
    # unpredictable; reconciliation correctness doesn't depend on this, but
    # using urandom keeps the behaviour aligned with the rest of the
    # project's "no weak PRNGs in the QKD path" stance.
    seed = int.from_bytes(secrets.token_bytes(8), "little")

    rc = _LIB_HANDLE.cascade_reconcile(
        a_ptr, b_ptr, ctypes.c_int32(n),
        ctypes.c_double(qber), ctypes.c_int32(passes),
        ctypes.c_uint64(seed),
        ctypes.byref(corrected), ctypes.byref(leaked),
    )
    if rc == -1:
        raise RuntimeError("C Cascade: memory allocation failed")
    # rc == -2 means non-convergence: leave bob_arr as-is and let the
    # caller's privacy_amplification reject the result.
    # We still copy bob_arr back so the residual mismatches are visible to
    # the public-facing checks in reconcile_and_amplify().

    bob[:] = bob_arr.tolist()
    return int(corrected.value), int(leaked.value)
