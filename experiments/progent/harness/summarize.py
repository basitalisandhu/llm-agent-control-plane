#!/usr/bin/env python
"""Utility / ASR / cost summary for runs written by progent_agentdojo.py (or any AgentDojo logdir).

  benign utility        = mean `utility` of  <suite>/user_task_*/none/none.json
  utility under attack  = mean `utility` of  <suite>/user_task_*/<attack>/injection_task_*.json
  ASR                   = mean `security` of the same attack files   (security == True means the injection succeeded)
Overall = pooled over every run (AgentDojo's convention) and, separately, the unweighted mean over suites.
Slack injection_task_5 is already scored by effect at run time (denied calls never count as executed).
Cost = tokens in usage-*.jsonl x gpt-5-mini list prices (input $0.25/M, cached input $0.025/M, output $2/M incl. reasoning).
"""
import argparse, json, re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRICE_IN, PRICE_CACHED, PRICE_OUT = 0.25e-6, 0.025e-6, 2.0e-6
SENTINEL = "Please try other tools or arguments and continue to finish the user task"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logdir", type=Path, default=ROOT / "runs" / "agentdojo")
    ap.add_argument("--auxdir", type=Path, default=ROOT / "runs" / "aux")
    ap.add_argument("--pipeline", default="gpt-5-mini-progent")
    ap.add_argument("--attack", default="important_instructions")
    a = ap.parse_args()

    base = a.logdir / a.pipeline
    benign, attack = defaultdict(list), defaultdict(list)
    denials = defaultdict(int)
    errors = 0
    incomplete = 0
    for f in sorted(base.glob("*/user_task_*/none/none.json")):
        d = json.loads(f.read_text())
        if d.get("utility") is None:  # crashed mid-task: AgentDojo re-runs it on resume
            incomplete += 1
            continue
        benign[f.parts[-4]].append(bool(d["utility"]))
    for f in sorted(base.glob(f"*/user_task_*/{a.attack}/injection_task_*.json")):
        d = json.loads(f.read_text())
        if d.get("utility") is None or d.get("security") is None:
            incomplete += 1
            continue
        attack[f.parts[-4]].append((bool(d["utility"]), bool(d["security"])))
        errors += bool(d.get("error"))
        if any(m["role"] == "tool" and SENTINEL in (m.get("error") or "") for m in d["messages"]):
            denials[f.parts[-4]] += 1

    def pct(x, n):
        return f"{100 * x / n:5.1f}" if n else "  n/a"

    print(f"pipeline={a.pipeline} attack={a.attack}   (logs: {base})")
    print(f"{'suite':10} {'benign U':>9} {'n':>4}   {'U|attack':>9} {'ASR':>6} {'n':>5}   {'runs w/ denial':>14}")
    tot_b = tot_bn = tot_u = tot_s = tot_n = 0
    per_suite = []
    for s in ["banking", "slack", "travel", "workspace"]:
        b, at = benign.get(s, []), attack.get(s, [])
        bu, ua, asr = (sum(b), sum(u for u, _ in at), sum(x for _, x in at))
        print(f"{s:10} {pct(bu, len(b)):>9} {len(b):>4}   {pct(ua, len(at)):>9} {pct(asr, len(at)):>6} {len(at):>5}   {denials.get(s, 0):>14}")
        tot_b += bu; tot_bn += len(b); tot_u += ua; tot_s += asr; tot_n += len(at)
        if b and at:
            per_suite.append((bu / len(b), ua / len(at), asr / len(at)))
    print(f"{'POOLED':10} {pct(tot_b, tot_bn):>9} {tot_bn:>4}   {pct(tot_u, tot_n):>9} {pct(tot_s, tot_n):>6} {tot_n:>5}")
    if per_suite:
        m = [100 * sum(x[i] for x in per_suite) / len(per_suite) for i in range(3)]
        print(f"{'SUITE-MEAN':10} {m[0]:9.1f} {'':>4}   {m[1]:9.1f} {m[2]:6.1f}   (unweighted mean over {len(per_suite)} suites)")
    if incomplete:
        print(f"note: {incomplete} log files are incomplete (crashed tasks) and were skipped; re-running resumes them")
    if errors:
        print(f"note: {errors} attack runs carry an `error` field (API-level skips; AgentDojo scores those utility=False, security=True)")

    kinds = defaultdict(lambda: defaultdict(int))
    for f in a.auxdir.glob("usage-*.jsonl"):
        for line in f.read_text().splitlines():
            r = json.loads(line)
            k = kinds[r["kind"]]
            k["calls"] += 1
            for key in ("prompt_tokens", "completion_tokens", "reasoning_tokens", "cached_tokens"):
                k[key] += r.get(key, 0)
    if kinds:
        print("\ntokens / cost so far (gpt-5-mini list prices)")
        grand = 0.0
        for kind, k in sorted(kinds.items()):
            cost = (k["prompt_tokens"] - k["cached_tokens"]) * PRICE_IN + k["cached_tokens"] * PRICE_CACHED + k["completion_tokens"] * PRICE_OUT
            grand += cost
            print(f"  {kind:24} calls={k['calls']:7d} in={k['prompt_tokens']:12,d} (cached {k['cached_tokens']:,d}) out={k['completion_tokens']:11,d} (reasoning {k['reasoning_tokens']:,d})  ${cost:8.2f}")
        print(f"  {'TOTAL':24} ${grand:.2f}")


if __name__ == "__main__":
    main()
