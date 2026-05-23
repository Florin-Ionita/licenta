"""Phase 9 evaluation harness.

Each module here measures one property of the system and writes (a) raw CSV
samples to ``docs/benchmarks/raw/`` and (b) a publication-quality PDF plot to
``docs/benchmarks/plots/``. The :mod:`benchmarks.runner` module is the entry
point: ``python -m benchmarks.runner --full`` produces every artefact in one
shot.

Design notes:
  * The runner imports each bench module on demand so a failure in one bench
    doesn't tank the rest of the suite.
  * No bench mutates global state; each spins up its own ``DemoStack`` (or
    classic-TLS pair) and tears it down.
  * Plots use Plotly + Kaleido for PDF export. They follow a consistent dark
    style so the thesis chapter looks uniform.
"""
