# Development targets. The research scripts are left as they ran for the paper;
# these targets wrap the commands documented in README.md and CONTRIBUTING.md.
#
#   make venv         create .venv with uv and install the pinned requirements
#   make test         offline unit tests for the released matcher (no model, no network)
#   make lint         ruff, configuration in pyproject.toml
#   make replay       model-free replay of one suite through the released matcher, both
#                     attacks, checked against results/replay/preflight_v22.json
#   make replay-full  the whole replay: four suites, both attacks, four policy variants
#                     (writes runs_replay/preflight_v22.json; about 13 minutes)

VENV ?= .venv
PY   := $(abspath $(VENV))/bin/python
SUITE ?= slack
CFGS  ?= prov,full

.PHONY: venv test lint replay replay-full clean

venv:
	uv venv $(VENV)
	uv pip install --python $(PY) -r requirements.txt

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

replay:
	PYTHONPATH=pep:experiments $(PY) experiments/replay_quick.py $(SUITE) $(CFGS)

replay-full:
	mkdir -p runs_replay
	cd runs_replay && PYTHONPATH=../pep:../experiments $(PY) ../experiments/preflight_v22.py
	@echo "Wrote runs_replay/preflight_v22.json; the released numbers are in results/replay/preflight_v22.json"

clean:
	rm -rf runs_replay .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
