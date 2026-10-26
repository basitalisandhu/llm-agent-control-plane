"""Live runs of the adaptive families (launch_adaptive_live.sh): per-case files in runs_adaptive (baseline, PEP-prov v2.2) and
runs_adaptive_wl (PEP-prov v2.2 + write-side labelling) -> tex/table_adaptive_live.tex + tex/results_adaptive_live.tex."""
import json, glob, random, collections, os
from pathlib import Path
TEX = Path("tex"); TEX.mkdir(exist_ok=True)
ARMS = [("laundering", "banking", "baseline", "runs_adaptive", "Baseline"), ("laundering", "banking", "pep_prov", "runs_adaptive", "PEP-prov"),
        ("laundering", "banking", "pep_prov", "runs_adaptive_wl", "PEP-prov + labels"),
        ("laundering", "banking", "tool_filter", "runs_adaptive", "Tool filter"),
        ("evasion_zerowidth", "slack", "baseline", "runs_adaptive", "Baseline"), ("evasion_zerowidth", "slack", "pep_prov", "runs_adaptive", "PEP-prov"),
        ("evasion_zerowidth", "slack", "tool_filter", "runs_adaptive", "Tool filter")]
EXPECT = {("laundering", "banking"): 16 * 8, ("evasion_zerowidth", "slack"): 21 * 5}
def load(attack, suite, config, logdir):
    cl = collections.defaultdict(list); ua = collections.defaultdict(list)
    for f in glob.glob(f"{logdir}/gpt4omini-{config}/{suite}/*/{attack}/injection_task_*.json"):
        try: d = json.load(open(f))
        except Exception: continue
        if d.get("security") is None: continue
        sec = d["security"]
        if sec and suite == "slack" and f.endswith("injection_task_5.json") and config.startswith("pep"): sec = __import__("trace_fix").slack_it5_executed(d["messages"])
        ut = f.split("/")[-3]; cl[ut].append(1 if sec else 0); ua[ut].append(1 if d.get("utility") else 0)
    return cl, ua
def rate(cl):
    flat = [x for c in cl.values() for x in c]; return (100 * sum(flat) / len(flat) if flat else float("nan")), len(flat), sum(flat)
def boot(cl, iters=2000, seed=0):
    vals = list(cl.values()); rng = random.Random(seed); means = []
    if not vals: return float("nan"), float("nan")
    for _ in range(iters):
        flat = [x for c in (rng.choice(vals) for _ in vals) for x in c]; means.append(100 * sum(flat) / len(flat))
    means.sort(); return means[int(0.025 * iters)], means[int(0.975 * iters) - 1]
def exact_upper(n): return 100 * (1 - 0.025 ** (1 / n))
def cell(cl):
    r, n, k = rate(cl)
    if not n: return "--", n
    if k == 0: return f"0.0 [0, {exact_upper(n):.1f}]", n
    lo, hi = boot(cl); return f"{r:.1f} [{lo:.1f}, {hi:.1f}]", n
CODE = {"laundering": "Laund", "evasion_zerowidth": "Zw"}; CC = {("baseline", "runs_adaptive"): "Base", ("pep_prov", "runs_adaptive"): "Prov", ("pep_prov", "runs_adaptive_wl"): "ProvWl", ("tool_filter", "runs_adaptive"): "Filt"}
rows = []; macros = {}; complete = True
for attack, suite, config, logdir, label in ARMS:
    cl, ua = load(attack, suite, config, logdir); asr, n = cell(cl); u, _ = cell(ua); r, _, k = rate(cl)
    exp = EXPECT[(attack, suite)]; complete &= (n == exp)
    rows.append((attack, suite, label, u, asr, k, n, exp))
    key = CODE[attack] + CC[(config, logdir)]; macros[f"al{key}"] = f"{r:.1f}" if n else "--"; macros[f"al{key}N"] = str(n); macros[f"al{key}K"] = str(k)
with open(TEX / "table_adaptive_live.tex", "w") as f:
    f.write("\\begin{tabular}{@{}llrrr@{}}\n\\toprule\nFamily (suite) & Configuration & Util.\\ under attack & ASR & Successes / cases \\\\\n\\midrule\n")
    last = None
    for attack, suite, label, u, asr, k, n, exp in rows:
        if last and last != attack: f.write("\\midrule\n")
        name = {"laundering": "laundering (banking)", "evasion_zerowidth": "zero-width (Slack)"}[attack] if last != attack else ""
        f.write(f"{name} & \\textsc{{{label}}} & {u} & {asr} & {k} / {n}{'' if n == exp else '$^\\dagger$'} \\\\\n"); last = attack
    f.write("\\bottomrule\n\\end{tabular}\n")
with open(TEX / "results_adaptive_live.tex", "w") as f:
    for k, v in macros.items(): f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    f.write(f"\\newcommand{{\\alComplete}}{{{'1' if complete else '0'}}}\n")
print("live adaptive:", "complete" if complete else "PARTIAL"); [print(" ", r[0], r[1], r[2], "ASR", r[4], "util", r[3], f"{r[6]}/{r[7]}") for r in rows]
