"""Head-to-head macros for Progent (Shi et al., 2025) on GPT-5 mini, from the run in ../progent/runs (harness/progent_agentdojo.py,
AgentDojo v1.2.2, attack important_instructions). Writes tex/results_progent.tex. Estimators as in make_results_b.py: rates pooled over
runs; 95% intervals by a bootstrap clustered on user task (2000 resamples, seed 0); an observed zero gets the exact one-sided 97.5% bound."""
import collections, glob, json, os, random
HERE = os.path.dirname(os.path.abspath(__file__))
import sys
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "progent", "runs")
SUFFIX = sys.argv[2] if len(sys.argv) > 2 else ""   # macro suffix for a second model (e.g. "Fm" for GPT-4o mini)
if len(sys.argv) > 5: PRICE_IN_ARG, PRICE_CACHED_ARG, PRICE_OUT_ARG = (float(v) for v in sys.argv[3:6])
else: PRICE_IN_ARG = PRICE_CACHED_ARG = PRICE_OUT_ARG = None
PROGENT_ROOT = ROOT
PIPE, ATTACK = ("gpt-4o-mini-progent" if SUFFIX else "gpt-5-mini-progent"), "important_instructions"
SENTINEL = "Please try other tools or arguments and continue to finish the user task"   # the harness's denial message
PRICE_IN, PRICE_CACHED, PRICE_OUT = 0.25e-6, 0.025e-6, 2.0e-6                        # gpt-5-mini list prices, Oct 2026
if PRICE_IN_ARG is not None: PRICE_IN, PRICE_CACHED, PRICE_OUT = PRICE_IN_ARG, PRICE_CACHED_ARG, PRICE_OUT_ARG   # e.g. gpt-4o-mini: 0.15e-6 0.075e-6 0.6e-6

def boot(cl, iters=2000, seed=0):
    vals = list(cl.values())
    if not vals: return float("nan"), float("nan")
    rng = random.Random(seed); means = []
    for _ in range(iters):
        flat = [x for c in (rng.choice(vals) for _ in vals) for x in c]; means.append(sum(flat) / len(flat) * 100)
    means.sort(); return means[int(0.025 * iters)], means[int(0.975 * iters) - 1]
def exact_upper(n): return 100 * (1 - 0.025 ** (1 / n)) if n else float("nan")
def cell(cl, zero_bound=False):
    flat = [x for c in cl.values() for x in c]; n, k = len(flat), sum(flat)
    if n == 0: return "--", float("nan"), 0, 0
    p = k / n * 100
    if zero_bound and k == 0: return f"0.0 [$\\leq${exact_upper(n):.1f}]", p, n, k
    lo, hi = boot(cl); return f"{p:.1f} [{lo:.0f}, {hi:.0f}]", p, n, k
def denied(d): return any(m.get("role") == "tool" and SENTINEL in (m.get("error") or "") for m in d.get("messages", []))

ben, atk_u, atk_s = (collections.defaultdict(list) for _ in range(3))
n_ben = n_atk = den_ben = den_atk = incomplete = errors = 0
for f in glob.glob(f"{ROOT}/agentdojo/{PIPE}/*/user_task_*/none/none.json"):
    d = json.load(open(f)); suite, task = f.split(os.sep)[-4], f.split(os.sep)[-3]
    if d.get("utility") is None: incomplete += 1; continue
    ben[(suite, task)].append(1 if d["utility"] else 0); n_ben += 1; den_ben += denied(d)
for f in glob.glob(f"{ROOT}/agentdojo/{PIPE}/*/user_task_*/{ATTACK}/injection_task_*.json"):
    d = json.load(open(f)); suite, task = f.split(os.sep)[-5], f.split(os.sep)[-4]
    if d.get("utility") is None or d.get("security") is None: incomplete += 1; continue
    atk_u[(suite, task)].append(1 if d["utility"] else 0); atk_s[(suite, task)].append(1 if d["security"] else 0)
    n_atk += 1; den_atk += denied(d); errors += bool(d.get("error"))

usage = collections.defaultdict(lambda: collections.Counter())
for f in glob.glob(f"{ROOT}/aux/usage-*.jsonl"):
    for line in open(f):
        r = json.loads(line); k = usage[r["kind"]]; k["calls"] += 1
        for key in ("prompt_tokens", "completion_tokens", "cached_tokens"): k[key] += r.get(key, 0)
def usd(c): return (c["prompt_tokens"] - c["cached_tokens"]) * PRICE_IN + c["cached_tokens"] * PRICE_CACHED + c["completion_tokens"] * PRICE_OUT
agent_usd = usd(usage["agent"]); policy_kinds = [k for k in usage if k != "agent"]
policy_calls = sum(usage[k]["calls"] for k in policy_kinds); policy_usd = sum(usd(usage[k]) for k in policy_kinds)
runs = n_ben + n_atk + incomplete   # every run started so far consumed policy calls

u_txt, u_pct, _, _ = cell(ben); ua_txt, ua_pct, _, _ = cell(atk_u); a_txt, a_pct, _, _ = cell(atk_s, zero_bound=True)
def f1(x): return "--" if x != x else f"{x:.1f}"
M = {"uciProg": u_txt, "uProg": f1(u_pct), "uaProg": f1(ua_pct), "aciProg": a_txt, "aProg": f1(a_pct),
     "nProgB": str(n_ben), "nProgA": str(n_atk), "nProgTasksB": str(len(ben)), "nProgTasksA": str(len(atk_u)),
     "progDenAtk": f1(100 * den_atk / n_atk) if n_atk else "--", "progDenBen": f1(100 * den_ben / n_ben) if n_ben else "--",
     "progDenAtkRuns": str(den_atk), "progDenBenRuns": str(den_ben),
     "progPolicyCalls": f"{policy_calls:,}".replace(",", "\\,"), "progAgentCalls": f"{usage['agent']['calls']:,}".replace(",", "\\,"),
     "progCallsPerRun": f"{policy_calls / runs:.1f}" if runs else "--",
     "progAgentCallsPerRun": f"{usage['agent']['calls'] / runs:.1f}" if runs else "--",
     "progPolicyUsd": f"{policy_usd:.2f}", "progAgentUsd": f"{agent_usd:.2f}", "progTotalUsd": f"{policy_usd + agent_usd:.2f}",
     "progPolicyShare": f"{100 * policy_usd / (policy_usd + agent_usd):.0f}" if policy_usd + agent_usd else "--",
     "progUsdPerRun": f"{policy_usd / runs:.3f}" if runs else "--",
     "progComplete": "complete" if (n_ben == 97 and n_atk == 949) else "partial"}
with open(os.path.join(HERE, "tex", "results_progent" + (("_" + SUFFIX.lower()) if SUFFIX else "") + ".tex"), "w") as f:
    f.write("% auto-generated by make_results_progent.py from ../progent/runs\n")
    for k, v in M.items(): f.write(f"\\newcommand{{\\{k}{SUFFIX}}}{{{v}}}\n")
print({k: M[k] for k in ("uciProg", "uaProg", "aciProg", "nProgB", "nProgA", "progDenAtk", "progCallsPerRun", "progPolicyShare", "progUsdPerRun", "progComplete")},
      f"incomplete={incomplete} errors={errors}")

# compact per-case record and usage totals for the repository (no transcripts)
import csv
REPO = os.path.join(os.environ.get("PEP_REPO", os.path.join(HERE, "..")), "results", "progent_" + ("gpt4omini" if SUFFIX else "gpt5mini"))
os.makedirs(REPO, exist_ok=True)
with open(os.path.join(REPO, "cases.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["suite", "user_task", "attack", "injection_task", "utility", "injection_succeeded", "denied_call", "duration_s"])
    for f2 in sorted(glob.glob(f"{ROOT}/agentdojo/{PIPE}/*/user_task_*/*/*.json")):
        d = json.load(open(f2)); parts = f2.split(os.sep)
        if d.get("utility") is None: continue
        w.writerow([parts[-4], parts[-3], parts[-2], parts[-1][:-5], int(bool(d["utility"])), int(bool(d.get("security"))) if parts[-2] != "none" else "", int(denied(d)), round(d.get("duration", 0), 1)])
json.dump({"runs_scored": {"benign": n_ben, "attack": n_atk, "incomplete": incomplete}, "usage": {k: dict(v) for k, v in usage.items()},
           "usd": {"agent": round(agent_usd, 2), "policy": round(policy_usd, 2)}, "prices_per_token": {"input": PRICE_IN, "cached_input": PRICE_CACHED, "output": PRICE_OUT},
           "macros": M}, open(os.path.join(REPO, "summary.json"), "w"), indent=1)
