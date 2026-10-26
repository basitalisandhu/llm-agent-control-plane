"""Pairwise comparison of the provenance rule with every other arm on the same model and the same cases (Change A of the
round-4 area chair): successes split by goal class (in scope vs the three classes Corollary 1 excludes), exact McNemar tests
on the paired cases and tasks, a two-way cluster bootstrap (user tasks and injection goals resampled independently across the
four suites, 2,000 resamples) of each ASR difference, and the in-scope denominators. Reads per-case files only."""
import json, glob, os, math
import numpy as np
from pathlib import Path
import trace_fix
HERE = os.path.dirname(os.path.abspath(__file__)); TEX = Path(HERE) / "tex"; RUNS = os.path.join(HERE, "runs_full")
PROG = os.path.join(HERE, "..", "progent", "runs_gpt4omini", "agentdojo", "gpt-4o-mini-progent")
OUT = {("travel", "injection_task_6"): "a4", ("travel", "injection_task_2"): "title", ("workspace", "injection_task_1"): "file"}
SUITES = {"slack": (21, 5), "banking": (16, 9), "travel": (20, 7), "workspace": (40, 14)}
N_ALL = sum(u * i for u, i in SUITES.values()); N_OUT = 20 + 20 + 40; N_IN = N_ALL - N_OUT; G_IN = sum(i for _, i in SUITES.values()) - 3
MODELS = [("gpt4omini", "GPT-4o mini", "Gptfourmini", [("baseline", "Base", "Baseline"), ("spotlight", "Spot", "Spotlight"), ("tool_filter", "Filt", "Tool filter"), ("progent", "Progent", "Progent"),
                                                        ("pep_prov", "Prov", "PEP-prov"), ("pep_prov_strict", "Strict", "PEP-prov (strict)"), ("pep_full", "Full", "PEP-full (oracle)")]),
          ("llama70b", "Llama 3.3 70B", "Llama", [("baseline", "Base", "Baseline"), ("pep_prov", "Prov", "PEP-prov")])]
def root(tag, cfg): return PROG if cfg == "progent" else f"{RUNS}/{tag}-{cfg}"
def load_sec(tag, cfg):
    d = {}; it5 = 0
    for f in glob.glob(f"{root(tag, cfg)}/*/user_task_*/important_instructions/injection_task_*.json"):
        j = json.load(open(f)); parts = f.split(os.sep); suite, ut, it = parts[-4], parts[-3], parts[-1][:-5]
        if j.get("security") is None: continue
        sec = bool(j["security"])
        if sec and suite == "slack" and it == "injection_task_5":
            it5 += 1
            if cfg.startswith("pep"): sec = trace_fix.slack_it5_executed(j["messages"])
        d[(suite, ut, it)] = sec
    return d, it5
def load_util(tag, cfg):
    d = {}
    for f in glob.glob(f"{root(tag, cfg)}/*/user_task_*/none/none.json"):
        j = json.load(open(f)); parts = f.split(os.sep)
        if j.get("utility") is None: continue
        d[(parts[-4], parts[-3])] = bool(j["utility"])
    return d
def mcnemar(b, c):
    n = b + c
    if n == 0: return 1.0
    k = min(b, c); return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)
def ptxt(p): return "\\ensuremath{<}0.001" if p < 0.001 else (f"{p:.3f}" if p < 0.1 else f"{p:.2f}")
def twoway(A, B, keys, iters=2000, seed=0):
    rng = np.random.default_rng(seed); uts = sorted({(s, u) for s, u, i in keys}); its = sorted({(s, i) for s, u, i in keys})
    ui = {k: n for n, k in enumerate(uts)}; ii = {k: n for n, k in enumerate(its)}
    a = np.array([1 if A[k] else 0 for k in keys]); b = np.array([1 if B[k] else 0 for k in keys])
    U = np.array([ui[(s, u)] for s, u, i in keys]); I = np.array([ii[(s, i)] for s, u, i in keys]); out = []
    for _ in range(iters):
        wu = np.bincount(rng.integers(0, len(uts), len(uts)), minlength=len(uts)); wi = np.bincount(rng.integers(0, len(its), len(its)), minlength=len(its))
        w = wu[U] * wi[I]; t = w.sum()
        if t: out.append(100 * (w @ a - w @ b) / t)
    out.sort(); m = len(out); return out[int(0.025 * m)], out[int(0.975 * m) - 1]
def bound(n): return 100 * (1 - 0.025 ** (1 / n))
mac = {"inScopeGoals": G_IN, "inScopeCases": N_IN, "zeroBoundInScopeGoals": f"{bound(G_IN):.1f}", "zeroBoundInScopeCases": f"{bound(N_IN):.2f}"}
rows = []
for tag, model, T, arms in MODELS:
    data = {cfg: load_sec(tag, cfg) for cfg, _, _ in arms}; util = {cfg: load_util(tag, cfg) for cfg, _, _ in arms}
    ref = data["pep_prov"][0]; refu = util["pep_prov"]
    for cfg, C, label in arms:
        sec, it5 = data[cfg]; u = util[cfg]; n = len(sec)
        if not n: continue
        k = sum(sec.values()); cls = {"in": 0, "a4": 0, "title": 0, "file": 0}
        for (s, ut, it), v in sec.items():
            if v: cls[OUT.get((s, it), "in")] += 1
        common = sorted(set(sec) & set(ref)); b = sum(1 for key in common if sec[key] and not ref[key]); c = sum(1 for key in common if ref[key] and not sec[key])
        p_asr = mcnemar(b, c); lo, hi = twoway(sec, ref, common) if cfg != "pep_prov" and common else (float("nan"), float("nan"))
        diff = 100 * (sum(sec[key] for key in common) - sum(ref[key] for key in common)) / len(common) if common else float("nan")
        cu = sorted(set(u) & set(refu)); bu = sum(1 for key in cu if u[key] and not refu[key]); cu_ = sum(1 for key in cu if refu[key] and not u[key]); p_u = mcnemar(bu, cu_)
        ku = sum(u.values()); udiff = bu - cu_
        rows.append(dict(model=model, label=label, k=k, n=n, cls=cls, p_asr=p_asr, lo=lo, hi=hi, diff=diff, ku=ku, nu=len(u), udiff=udiff, p_u=p_u, it5=it5, cfg=cfg))
        key = T + C
        mac.update({f"pw{key}K": k, f"pw{key}N": n, f"pw{key}In": cls["in"], f"pw{key}Afour": cls["a4"], f"pw{key}Title": cls["title"], f"pw{key}File": cls["file"],
                    f"pw{key}AsrP": ptxt(p_asr), f"pw{key}AsrDiff": f"{diff:+.1f}" if diff == diff else "--", f"pw{key}AsrCI": (f"[{lo:+.1f}, {hi:+.1f}]" if lo == lo else "--"),
                    f"pw{key}UtilK": ku, f"pw{key}UtilDiff": abs(udiff), f"pw{key}UtilWord": ("more" if udiff > 0 else "fewer"), f"pw{key}UtilP": ptxt(p_u), f"pw{key}ItFive": it5,
                    f"pw{key}InBound": f"{bound(sum(1 for (s, ut, it) in sec if (s, it) not in OUT)):.2f}"})
with open(TEX / "results_pairwise.tex", "w") as f:
    for k_, v in mac.items(): f.write(f"\\newcommand{{\\{k_}}}{{{v}}}\n")
with open(TEX / "table_classes.tex", "w") as f:
    f.write("\\begin{tabular}{@{}lrrrrrrrr@{}}\n\\toprule\n & \\multicolumn{5}{c}{Attack successes (of 949)} & & \\multicolumn{2}{c}{Benign utility (of 97)} \\\\\n\\cmidrule(lr){2-6}\\cmidrule(lr){8-9}\n")
    f.write("Arm & all & in scope & title & output & file & $p$ vs rule & tasks & $p$ vs rule \\\\\n\\midrule\n")
    last = None
    for r in rows:
        if last and last != r["model"]: f.write("\\midrule\n")
        dag = "" if r["n"] >= N_ALL - 5 else "$^\\dagger$"; pa = "--" if r["cfg"] == "pep_prov" else ptxt(r["p_asr"]); pu = "--" if r["cfg"] == "pep_prov" else ptxt(r["p_u"])
        if last != r["model"]: f.write(f"\\multicolumn{{9}}{{@{{}}l}}{{\\emph{{{r['model']}}}}} \\\\\n")
        f.write(f"\\textsc{{{r['label']}}} & {r['k']}{dag} & {r['cls']['in']} & {r['cls']['title']} & {r['cls']['a4']} & {r['cls']['file']} & {pa} & {r['ku']} & {pu} \\\\\n"); last = r["model"]
    f.write("\\bottomrule\n\\end{tabular}\n")
for r in rows: print(f"{r['model']:14s} {r['label']:18s} k={r['k']:3d}/{r['n']} in={r['cls']['in']} title={r['cls']['title']} a4={r['cls']['a4']} file={r['cls']['file']} p_asr={ptxt(r['p_asr'])} diff={r['diff']:+.1f} CI=[{r['lo']:+.1f},{r['hi']:+.1f}] util={r['ku']}/{r['nu']} udiff={r['udiff']:+d} p_u={ptxt(r['p_u'])} it5={r['it5']}")
print("in-scope: goals", G_IN, "cases", N_IN, "bounds", mac["zeroBoundInScopeGoals"], mac["zeroBoundInScopeCases"])
