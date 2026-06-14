# QTLS-over-QKD: common tasks.
# Usage: `make <target>`. Run `make setup` once, then `make demo` / `make dash` / `make test`.

VENV    := .venv-linux
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
STREAMLIT := $(VENV)/bin/streamlit

.PHONY: help setup demo dash test bench bench-full clean

help:
	@echo "make setup       create the virtualenv and install everything"
	@echo "make demo        run the command-line chat demo"
	@echo "make dash        launch the live Streamlit dashboard"
	@echo "make test        run the test suite"
	@echo "make bench       run the quick benchmark profile"
	@echo "make bench-full  run the full benchmark profile (thesis figures)"
	@echo "make clean       remove the virtualenv"

setup:
	python3.12 -m venv $(VENV)
	$(PIP) install -e ".[dev,viz,bench]"

demo:
	$(PYTHON) -m app.demo_chat

dash:
	$(STREAMLIT) run viz/main.py

test:
	$(VENV)/bin/pytest

bench:
	$(PYTHON) -m benchmarks.runner --profile lite

bench-full:
	$(PYTHON) -m benchmarks.runner --profile full

clean:
	rm -rf $(VENV)
