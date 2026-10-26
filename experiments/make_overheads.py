"""Escalation and denial shares over every PEP-full decision in the Track B logs (all suites, benign and attacked runs)."""
import json, glob
rows = []
for f in glob.glob("runs_full/pep_decisions/*-pep_full-*.jsonl"): rows += [json.loads(l) for l in open(f)]
perm = [r for r in rows if r["tier"] == "permission"]
esc = sum(1 for r in perm if str(r.get("escalated")) == "True"); den = sum(1 for r in perm if str(r.get("allowed")) == "False")
open("tex/results_overheads.tex", "w").write(f"\\newcommand{{\\nDecisions}}{{{len(perm):,}}}\n\\newcommand{{\\escShare}}{{{esc/len(perm)*100:.1f}}}\n\\newcommand{{\\denShare}}{{{den/len(perm)*100:.1f}}}\n".replace(",", "\\,"))
print("decisions", len(perm), "escalated", round(esc/len(perm)*100, 1), "denied", round(den/len(perm)*100, 1))
