# Contributing

This repository is the artifact of a paper: the policy enforcement point (PEP), the scripts that
produced every number in the manuscript, the decision logs and the incident dataset. Contributions are
welcome wherever they do not silently change what the paper reports.

## Set up

```bash
uv venv && uv pip install -r requirements.txt   # or: make venv
make test      # same as: .venv/bin/python -m pytest -q
make lint      # same as: .venv/bin/python -m ruff check .
make replay    # same as: PYTHONPATH=pep:experiments .venv/bin/python experiments/replay_quick.py
```

The matcher imports AgentDojo, so the tests run inside the virtual environment. `python3 -m pytest -q`
with a system interpreter fails at import unless `agentdojo==0.1.35` is installed there. `make replay`
replays one suite through the released matcher without any model and checks the counts against
`results/replay/preflight_v22.json`; `make replay-full` does all four suites, both attacks and all four
policy variants (about 13 minutes on a laptop-class machine; the output is byte-identical to the released file).

## What is welcome

* **Matcher bugs**: an action the released rules (`pep/pep22.py`, `pep/pep_b22.py`) admit or deny
  wrongly. Include a replay (suite, user task, injection task) or a unit test in
  `tests/test_matcher.py` in the style of the existing ones. If it is exploitable, read SECURITY.md first.
* **Dataset corrections**: a wrong date, a better primary source, a mis-coded field. Open an issue with
  the event id and the source. `data/incidents.csv` is the authoritative file; the coder files are blind
  codings and are not edited by hand.
* **Adapters and attacks**: further OpenAI-compatible endpoints in `pep/local_llm.py` or
  `pep/providers.py`, further attacks registered the way `pep/attacks_ext.py` does.
* Documentation, tests and tooling.

## What is frozen

* `results/`, `figures/`: generated from the runs the paper reports. Do not edit by hand.
  Regenerate with the scripts in `experiments/` and say so in the pull request.
* `pep/pep_v2_frozen.py` and `pep/pep.py` (v2.1) are the versions that produced the pilot and the
  Track B numbers. Fixes go to `pep/pep22.py`, with a note in the Versions section of README.md and in
  CHANGELOG.md.
* No model on the decision path. A change that consults a model inside `PEPExecutor.query` changes the
  paper's claim and will not be merged into the released matcher; it can live as a separate variant.

## Style

* Python 3.11. `make lint` must pass. The research scripts are exempt from style rules (see
  `pyproject.toml`) so that they stay byte-for-byte the code that ran; new code and tests are not exempt.
* Keep secrets out of the tree: keys are read from files or environment variables.

## Pull requests

1. Branch from `main`, keep the change focused, add or update a test.
2. Run `make lint` and `make test`.
3. Say what changed and, for anything touching the matcher, which replay or run you used to check it.

By contributing you agree that your code is released under the Apache License 2.0 and any dataset
additions under CC BY 4.0 (see LICENSE and data/LICENSE).
