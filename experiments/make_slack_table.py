"""Appendix table: the Slack user tasks, their requests, and how each PEP configuration fares on them per model."""
import json
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite
digest = json.load(open("results_b.json")); losses = json.load(open("losses.json"))
MODELS = [("gpt5mini", "GPT-5 mini"), ("gpt51", "GPT-5.1"), ("sonnet45", "Sonnet 4.5"), ("haiku45", "Haiku 4.5")]
CAT = {"delegated": "D", "relay": "R", "identifier": "I", "approval": "A", "no-denial": "M", "missing": "?"}
def esc(s): return s.replace("&", "\\&").replace("%", "\\%").replace("_", "\\_").replace("#", "\\#").replace("'", "'")
suite = get_suite("v1.2.2", "slack")
def status(tag, cfg, task):
    d = digest.get(tag); 
    if not d: return "--"
    r = next((r for r in d["rows"] if r["config"] == cfg), None)
    if not r: return "--"
    ut = r["suites"]["slack"]["util_tasks"]
    if task not in ut: return "--"
    if ut[task]: return "ok"
    k = f"{tag}|{cfg}|slack|{task}"
    return CAT.get(losses[k]["category"], "?") if k in losses else "b"   # b = also failed at baseline
with open("tex/table_slack_tasks.tex", "w") as f:
    f.write("\\footnotesize Outcome of every Slack task under the provenance rule (P) and the full configuration (F) per model: ok = completed; D = lost, delegated designator; R = lost, relayed designator in content; A = lost, oracle approval mismatch; M = lost without any denial (model or marking); b = failed at baseline too; -- = not run.\\par\\medskip\n")
    f.write("\\setlength{\\tabcolsep}{3pt}\\begin{tabular}{@{}l>{\\raggedright\\arraybackslash}p{5.3cm}" + "cc" * len(MODELS) + "@{}}\n\\toprule\nTask & Request (abridged) & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{n}}}" for _, n in MODELS) + " \\\\\n & & " + " & ".join("P & F" for _ in MODELS) + " \\\\\n\\midrule\n")
    for tid, t in suite.user_tasks.items():
        req = t.PROMPT.replace("\n", " "); req = req if len(req) <= 110 else req[:107] + "..."
        cells = " & ".join(f"{status(tag, 'pep_prov', tid)} & {status(tag, 'pep_full', tid)}" for tag, _ in MODELS)
        f.write(f"{tid.replace('user_task_', '')} & {esc(req)} & {cells} \\\\\n")
    f.write("\\bottomrule\n\\end{tabular}\n")
print("wrote tex/table_slack_tasks.tex")
