# Security policy

This repository is a research artifact: a policy enforcement point (PEP) for LLM agents, the scripts
that evaluated it, decision logs and an incident dataset. It is not a hardened product. The guarantee
the PEP offers holds only under the four assumptions stated in the paper (Sect. 4 and supplement S1),
and the paper itself documents attacks on the policy (the obfuscating attacker in `pep/attacks_ext.py`,
the laundering sequence in `pep/laundering_demo.py`).

## Reporting a vulnerability

Please report privately if you find:

* a way to make the released matcher (`pep/pep22.py`, `pep/pep_b22.py`) admit a consequential action
  whose designators come only from untrusted content while the stated assumptions hold;
* a problem in the scripts that could harm the person running them, for example a path by which an
  API key or AWS credential could leave the machine, or an unsafe default.

How:

1. GitHub: the repository's Security tab, "Report a vulnerability" (private vulnerability reporting), or
2. e-mail: muhammadbasitali0@gmail.com (the address on the paper).

Please include a minimal replay: the suite, the user task, the injection task or injected text and the
tool-call sequence. The harness in `experiments/harness4.py` replays a trajectory through the PEP
without any model, so a report can usually be reduced to a unit test in the style of
`tests/test_matcher.py`.

What to expect: an acknowledgement within seven days, then either a fix in `pep/pep22.py` with a note in
the Versions section of README.md and in CHANGELOG.md, or a documented limitation. Credit is given in
CHANGELOG.md unless you prefer otherwise.

## Out of scope

* Bypasses that rely on breaking one of the stated assumptions (A1 to A4) are limitations of the design,
  not vulnerabilities in the implementation. They are still valuable: please open an ordinary issue.
* The numbers in `results/` and the manuscript are frozen; a matcher fix does not rewrite them.

## Handling secrets when running the experiments

* API keys are read from a file (`OPENAI_API_KEY_FILE`) or from the usual AWS profile, never from the
  command line, and `key*` and `.env` are ignored by git. Do not commit key material.
* The incident dataset links only to public sources.
