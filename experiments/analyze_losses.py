"""Where utility goes: classify every benign task a PEP configuration loses relative to the baseline, per model,
from the per-run transcripts (denial messages) and the ground-truth structure. Writes tex/table_losses.tex + losses.json."""
import json, glob, re, sys, collections
from pathlib import Path
LOGDIR = Path(sys.argv[1] if len(sys.argv) > 1 else "runs_full"); TEX = Path("tex")
MODELS = {"gpt5mini": "GPT-5 mini", "gpt51": "GPT-5.1", "sonnet45": "Sonnet 4.5", "haiku45": "Haiku 4.5", "gpt4omini": "GPT-4o mini", "llama70b": "Llama 3.3 70B"}
PEPCFG = ["pep_prov", "pep_prov_strict", "pep_full", "pep_full_nomark"]
LABELS = {"pep_prov": "PEP-prov", "pep_prov_strict": "PEP-prov (strict)", "pep_full": "PEP-full", "pep_full_nomark": "PEP-full, no marking"}
SUITES = ["slack", "banking", "travel", "workspace"]
digest = json.load(open("results_b.json"))

def transcript(tag, cfg, suite, task):
    f = LOGDIR / f"{tag}-{cfg}" / suite / task / "none" / "none.json"
    return json.load(open(f)) if f.exists() else None

def classify(d):
    """Return (category, denials) for one benign transcript."""
    denials = []
    for m in d["messages"]:
        if m["role"] == "tool" and (m.get("error") or "").startswith("Action denied"):
            r = m["error"]
            if "approval:" in r: kind = "approval"
            elif re.search(r"in argument '\w+' originates only", r): kind = "relay"       # designator inside free-text argument
            elif "identifier" in r: kind = "identifier"
            elif "originates only from untrusted content" in r or "is not sourced from the request" in r: kind = "delegated"  # designator/key arg from untrusted content
            else: kind = "other"
            denials.append((m["tool_call"]["function"] if m.get("tool_call") else "?", kind))
    if not denials: return "no-denial", denials
    kinds = [k for _, k in denials]
    if "relay" in kinds: return "relay", denials
    if "delegated" in kinds: return "delegated", denials
    if "identifier" in kinds: return "identifier", denials
    if "approval" in kinds: return "approval", denials
    return "other", denials

out = {}; table = collections.defaultdict(lambda: collections.Counter())
for tag, dd in digest.items():
    for r in dd["rows"]:
        if r["config"] not in PEPCFG or not r.get("lost_vs_baseline"): continue
        for item in r["lost_vs_baseline"]:
            suite, task = item.split(":")
            d = transcript(tag, r["config"], suite, task)
            if d is None: cat, den = "other", []   # no transcript (a run that ended before any check)
            else: cat, den = classify(d)
            out[f"{tag}|{r['config']}|{suite}|{task}"] = {"category": cat, "denials": den, "n_calls": sum(len(m.get("tool_calls") or []) for m in d["messages"] if m["role"] == "assistant") if d else None}
            table[(tag, r["config"])][cat] += 1
            table[(tag, r["config"])]["total"] += 1
json.dump(out, open("losses.json", "w"), indent=1)
CATS = ["delegated", "relay", "identifier", "approval", "no-denial", "other"]
with open(TEX / "table_losses.tex", "w") as f:
    f.write("\\begin{tabular}{@{}llr" + "r" * len(CATS) + "@{}}\n\\toprule\nModel & Configuration & Lost & Delegated & Relayed & Identifier & Approval & No denial & Other \\\\\n\\midrule\n")
    order = lambda kv: (list(MODELS).index(kv[0][0]) if kv[0][0] in MODELS else 99, PEPCFG.index(kv[0][1]) if kv[0][1] in PEPCFG else 99)
    for (tag, cfg), c in sorted(table.items(), key=order):
        f.write(f"{MODELS.get(tag, tag)} & \\textsc{{{LABELS[cfg]}}} & {c['total']} & " + " & ".join(str(c[k]) for k in CATS) + " \\\\\n")
    f.write("\\bottomrule\n\\end{tabular}\n")
for (tag, cfg), c in sorted(table.items()):
    print(f"{tag:9s} {cfg:16s} lost={c['total']:2d} " + " ".join(f"{k}={c[k]}" for k in CATS))
# per-task view across models for slack
print("--- slack tasks lost, by model/config:")
rows = collections.defaultdict(dict)
for k, v in out.items():
    tag, cfg, suite, task = k.split("|")
    if suite == "slack": rows[task][f"{tag}/{cfg}"] = v["category"][:4]
for t in sorted(rows, key=lambda s: int(s.split("_")[-1])): print(f"  {t:13s}", rows[t])

# ---- macros: gross losses under the provenance rule across models and the share that are delegated or relayed
prov = [v for k, v in out.items() if k.split("|")[1] == "pep_prov"]
with open(TEX / "results_losses.tex", "w") as f:
    f.write(f"\\newcommand{{\\grossProv}}{{{len(prov)}}}\n\\newcommand{{\\grossProvDesig}}{{{sum(1 for v in prov if v['category'] in ('delegated', 'relay'))}}}\n")
