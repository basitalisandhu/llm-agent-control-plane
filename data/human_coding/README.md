# Human-coded subsample (inter-rater check)

Purpose: both codings of the dataset in the paper were model-produced (author-adjudicated). A reviewer asked for a
genuine inter-rater figure. `sample_blind.csv` holds 20 events drawn at random (seed 20261003) from `data/incidents.csv`
with the labels removed. A human coder who has NOT seen `incidents.csv` fills the three `YOUR_*` columns using only the
codebook (full version of the paper, supplement S3), then `score.py` reports percent agreement and Cohen's kappa against
the author's labels, per field.

Codebook in brief (the supplement has the full definitions and every value):
- Lens: `weapon` = AI is a capability in the adversary's hands (phishing, deepfakes, agents attacking others);
  `target` = the model, its data or its serving stack is what is attacked (extraction, poisoning, jailbreak, serving bugs);
  `surface` = a model wired to tools, private data or untrusted content is turned against its owner (indirect injection,
  over-scoped agents, agents that destroy data).
- Type: `incident` = happened to a real victim; `disclosure` = a vulnerability reported by a researcher or vendor;
  `threat report` = a vendor's report on attacker activity.
- Vector: one of the values listed in the supplement's codebook (e.g. indirect-injection, direct-injection, extraction,
  poisoning, jailbreak, supply-chain, social-engineering, excessive-agency, exposure/misconfig, nhi-secrets, ...).

Run: `python3 score.py sample_blind.csv` after filling it in (keep the `id` column unchanged).
