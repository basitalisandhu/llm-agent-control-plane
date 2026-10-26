# Changelog

Notable changes to the artifact. The matcher versions are the ones the paper names; the repository is
not versioned separately. All runs and codings were made in October 2026.

## Unreleased

### Added
- `LICENSE` (Apache-2.0), `data/LICENSE` (CC BY 4.0) and `NOTICE`.
- Offline unit tests for the released matcher in `tests/test_matcher.py`, run with pytest inside the
  virtual environment (`make test`).
- `requirements.txt` with pinned versions, `pyproject.toml` (ruff configuration only), `Makefile`,
  `conftest.py`, and `experiments/replay_quick.py` (one-suite model-free replay checked against the
  released counts, `make replay`).
- Continuous integration (ruff and pytest on Python 3.11), CodeQL, Dependabot, issue templates,
  `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`.

### Changed
- README restructured: key results with the file each number comes from, the architecture figure, how
  the two rules work, repository layout, the incident dataset and citation.
  Every reproduction command is unchanged.
- Public release: the manuscript sources are no longer included; the README and `CITATION.cff` cite
  the ARCAI 2026 paper.

## Matcher v2.3 (optional write-side labelling)
- `PEP_WRITE_LABELS=1` or `write_labels=True`: a value the agent writes while it is tainted is never
  promoted to the trusted pool when a later tool result returns it. Off by default so that every
  released number is reproducible. Changes no admitted-goal count on the 949 cases of either attack and
  costs one benign task under the policies without approval. Demonstration: `pep/laundering_demo.py`,
  `pep/preflight_v23.py`, `pep/test_write_labels.py`, `results/replay/preflight_v23.json`.

## Matcher v2.2 (released)
- Calendar and event `participants` are designator arguments.
- An escalated approval must match every argument that failed provenance against a binding ground-truth
  value (no wildcards).
- The strict variant's own check runs even when another argument has already failed.
- Found by the obfuscated-attack replay (`results/replay/preflight_v22.json`). For the default attack
  v2.1 and v2.2 admit the same 29 / 5 goals (provenance / provenance + approval) and keep the same
  88 / 97 benign tasks; under the obfuscated attack v2.1 admitted 11 goals with approval, v2.2 admits 8
  (base rule) and 5 (strict variant).
- The local obfuscated-attack runs (`results/local_obf/`) use this version.

## Matcher v2.1
- Four fixes found in review of the pilot logs: the token-boundary match ignored a trailing period; bare
  domains were not extracted; account numbers were canonicalised in a different case from the corpus;
  the provenance check now evaluates every argument before deciding escalability.
- Ran all of Track B (API models, `results/trackb_summaries/`, `results/results_b.json`) and the v2.1
  model-free replay (`results/replay/preflight_all.json`, `experiments/preflight_full.json`).

## Matcher v2 (frozen)
- `pep/pep_v2_frozen.py`: the code that produced the pilot results on the open-weight model
  (`results/pilot_qwen14b/`).
- Initial artifact: PEP, adapters, experiment scripts, incident dataset (80 events), blind second
  coding, Progent head-to-head harness.
