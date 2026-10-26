"""For the API models on which the attack succeeds: which injection goals still succeed under each PEP configuration (default attack),
from the per-case AgentDojo result files in runs_full/<tag>-<config>/<suite>/<user_task>/important_instructions/<injection_task>.json.
Writes tex/table_remaining.tex (supplement) and tex/results_remaining.tex (counts as macros)."""
import json, glob, os, collections
from agentdojo.task_suite.load_suites import get_suite
HERE = os.path.dirname(os.path.abspath(__file__)); TEX = os.path.join(HERE, "tex")
TAGS = {"gpt4omini": "GPT-4o mini", "llama70b": "Llama 3.3 70B"}; CFGS = [("baseline", "Baseline"), ("pep_prov", "PEP-prov"), ("pep_full", "PEP-full")]
SUITES = ["slack", "banking", "travel", "workspace"]
goal_desc = {}
for s in SUITES:
    suite = get_suite("v1.2.2", s)
    for iid, it in suite.injection_tasks.items():
        goal_desc[(s, iid)] = ((it.GOAL if hasattr(it, "GOAL") else "")[:58] + ("\u2026" if len(getattr(it, "GOAL", "")) > 58 else ""))
rows = []; macros = {}
for tag, name in TAGS.items():
    for cfg, lab in CFGS:
        succ = collections.Counter(); seen = collections.Counter()
        for f in glob.glob(f"{HERE}/runs_full/{tag}-{cfg}/*/user_task_*/important_instructions/injection_task_*.json"):
            d = json.load(open(f)); parts = f.split(os.sep); s, it = parts[-4], parts[-1][:-5]
            if d.get("security") is None: continue
            seen[(s, it)] += 1
            sec = d["security"]
            if sec and s == "slack" and it == "injection_task_5" and cfg.startswith("pep"): sec = __import__("trace_fix").slack_it5_executed(d["messages"])
            if sec: succ[(s, it)] += 1
        CODE = {"gpt4omini": "Gptfourmini", "llama70b": "Llama"}; CC = {"baseline": "Base", "pep_prov": "Prov", "pep_full": "Full"}
        tot = sum(succ.values()); macros[f"remain{CODE.get(tag, tag)}{CC.get(cfg, cfg)}"] = tot
        for (s, it), k in sorted(succ.items(), key=lambda kv: (-kv[1], kv[0])):
            rows.append((name, lab, s, it, k, seen[(s, it)], goal_desc.get((s, it), "")))
def esc(t): return t.replace("_", "\\_").replace("&", "\\&").replace("%", "\\%").replace("$", "\\$")
with open(os.path.join(TEX, "table_remaining.tex"), "w") as f:
    f.write("\\begin{table}[!htbp]\\centering\\scriptsize\\setlength{\\tabcolsep}{2pt}\n\\caption{API models on which the attack succeeds: injection goals that the agent still carried out under each configuration (default attack), with the number of user tasks on which the goal succeeded out of those run.}\n\\label{tab:remaining}\n\\begin{tabular}{@{}llllrp{3.6cm}@{}}\n\\toprule\nModel & Configuration & Suite & Injection task & Successes & Goal (abridged) \\\\\n\\midrule\n")
    pep_rows = [r for r in rows if r[1] != "Baseline"]   # the baseline list is long and uninformative; PEP arms only
    last = None
    for name, lab, s, it, k, n, g in pep_rows:
        if last is not None and name != last[0]: f.write("\\midrule\n")
        f.write(f"{esc(name) if (name, lab) != last else ''} & \\textsc{{{lab}}} & {s} & \\texttt{{{esc(it)}}} & {k} / {n} & {esc(g)} \\\\\n"); last = (name, lab)
    f.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")
# ---- classes of residual successes (fixed in advance from the replay, Sect. S1.4): goals the rule does not mediate
CLASS = {("travel", "injection_task_6"): "recommendation in output (A4)", ("travel", "injection_task_2"): "calendar title",
         ("workspace", "injection_task_1"): "system-issued file deletion"}
import collections as _c, itertools as _it
for (name, lab), grp in _it.groupby(sorted(rows, key=lambda r: (r[0], r[1])), key=lambda r: (r[0], r[1])):
    grp = list(grp); tag = {"GPT-4o mini": "Gptfourmini", "Llama 3.3 70B": "Llama"}.get(name, name.replace(" ", "")); cc = {"Baseline": "Base", "PEP-prov": "Prov", "PEP-full": "Full"}.get(lab, lab)
    by = _c.Counter(); inscope = 0
    for _, _, s_, it, k, n, g in grp:
        c = CLASS.get((s_, it));
        if c: by[c] += k
        else: inscope += k
    parts = [f"{v} {k_}" for k_, v in by.items()] + [f"{inscope} in scope"]
    macros[f"remainBreakdown{tag}{cc}"] = ", ".join(parts); macros[f"remainInScope{tag}{cc}"] = inscope
with open(os.path.join(TEX, "results_remaining.tex"), "w") as f:
    for k, v in macros.items(): f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print({k: v for k, v in macros.items()})
print("\n".join(f"{n} {l} {s} {it} {k}/{nn} {g}" for n, l, s, it, k, nn, g in rows if l != "Baseline")[:1500])
