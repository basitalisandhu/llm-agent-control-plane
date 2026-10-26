"""Aggregates Track B summaries (runs_full/summaries) into LaTeX tables + results_b.json.
Usage: python make_results_b.py [logdir]"""
import json, glob, sys, collections, random
from pathlib import Path
LOGDIR = Path(sys.argv[1] if len(sys.argv) > 1 else "runs_full"); TEX = Path("tex"); TEX.mkdir(exist_ok=True)
CONFIGS = ["baseline", "spotlight", "tool_filter", "pi_detector", "repeat_user", "pep_prov", "pep_prov_strict", "pep_full", "pep_full_nomark"]
LABELS = {"baseline": "Baseline", "spotlight": "Spotlight", "tool_filter": "Tool filter", "pi_detector": "PI detector",
          "repeat_user": "Repeat prompt", "pep_prov": "PEP-prov", "pep_prov_strict": "PEP-prov (strict)", "pep_full": "PEP-full (oracle)", "pep_full_nomark": "PEP-full, no marking"}
MODELS = {"gpt5mini": "GPT-5 mini", "gpt51": "GPT-5.1", "sonnet45": "Claude Sonnet 4.5", "haiku45": "Claude Haiku 4.5", "gpt4omini": "GPT-4o mini", "llama70b": "Llama 3.3 70B"}
RESISTANT = ["gpt5mini", "gpt51", "sonnet45", "haiku45"]        # the attack almost never succeeds undefended: these measure cost
SUSCEPTIBLE = ["gpt4omini", "llama70b"]                          # the attack succeeds undefended: these measure what the rule prevents
ATTACKS = ["important_instructions", "important_instructions_obfuscated"]; AL = {"important_instructions": "ii", "important_instructions_obfuscated": "obf"}
SUITES = ["slack", "banking", "travel", "workspace"]
S = {}
for f in glob.glob(str(LOGDIR / "summaries" / "*.json")):
    d = json.load(open(f)); d = __import__("trace_fix").correct_summary(d, LOGDIR); S[(d["tag"], d["config"], d["suite"], d["mode"], d["attack"] or "none")] = d
TRACE_FIX_CELLS = sum(int(d.get("trace_fix", 0)) for d in S.values())
TRACE_FIX_BY_TAG = {t: sum(int(d.get("trace_fix", 0)) for d in S.values() if d["tag"] == t) for t in {d["tag"] for d in S.values()}}
# attack cases a model ended at its context limit (bedrock_llm.py writes a marker message and no tool call; the case is scored on the state reached)
import os
_MARK = "model context limit exceeded"
CTX_LIMIT = {}
for tag in ("llama70b", "gpt4omini"):
    n = 0
    for root, _, files in os.walk(LOGDIR):
        if f"{tag}-" not in root or "important_instructions" not in root: continue
        for fn in files:
            if fn.startswith("injection_task_") and fn.endswith(".json") and _MARK in open(os.path.join(root, fn), errors="ignore").read(): n += 1
    CTX_LIMIT[tag] = n

def clusters(tag, config, mode, attack, key):
    cl = collections.defaultdict(list); n_suites = 0
    for suite in SUITES:
        d = S.get((tag, config, suite, mode, attack))
        if not d: continue
        n_suites += 1
        for k, v in d[key].items(): cl[(suite, k.split("|")[0])].append(1 if v else 0)
    return cl, n_suites

def rate(cl):
    flat = [x for c in cl.values() for x in c]
    return (sum(flat) / len(flat) * 100 if flat else float("nan")), len(flat), sum(flat)

def boot(cl, iters=2000, seed=0):
    vals = list(cl.values())
    if not vals: return float("nan"), float("nan")
    rng = random.Random(seed); means = []
    for _ in range(iters):
        flat = [x for c in (rng.choice(vals) for _ in vals) for x in c]; means.append(sum(flat) / len(flat) * 100)
    means.sort(); return means[int(0.025 * iters)], means[int(0.975 * iters) - 1]

def exact_upper(n): return 100 * (1 - 0.025 ** (1 / n)) if n else float("nan")
def fmt(x): return "--" if x != x else f"{x:.1f}"
def cell(cl, zero_bound=False):
    p, n, k = rate(cl)
    if n == 0: return "--", p, n, k, (float("nan"), float("nan"))
    if zero_bound and k == 0: return f"0.0 [$\\leq${exact_upper(n):.1f}]", p, n, k, (0.0, exact_upper(n))
    lo, hi = boot(cl); txt = f"{p:.1f} [{lo:.1f}, {hi:.1f}]" if 0 < p < 1 else f"{p:.1f} [{lo:.0f}, {hi:.0f}]"
    return txt, p, n, k, (lo, hi)

digest = {}
for tag, mname in MODELS.items():
    rows = []
    for c in CONFIGS:
        u_cl, nsu = clusters(tag, c, "utility", "none", "utility_results")
        if not u_cl and not any((tag, c, s, "security", a) in S for s in SUITES for a in ATTACKS): continue
        r = {"config": c, "n_suites_utility": nsu}
        r["util"], r["util_pct"], r["util_n"], r["util_k"], r["util_ci"] = cell(u_cl)
        for a in ATTACKS:
            s_cl, nss = clusters(tag, c, "security", a, "security_results"); ua_cl, _ = clusters(tag, c, "security", a, "utility_results")
            r[f"asr_{AL[a]}"], r[f"asr_{AL[a]}_pct"], r[f"asr_{AL[a]}_n"], r[f"asr_{AL[a]}_k"], r[f"asr_{AL[a]}_ci"] = cell(s_cl, zero_bound=True)
            r[f"ua_{AL[a]}"], r[f"ua_{AL[a]}_pct"], r[f"ua_{AL[a]}_n"], _, _ = cell(ua_cl); r[f"n_suites_{AL[a]}"] = nss
        # per-suite
        r["suites"] = {}
        for s in SUITES:
            du = S.get((tag, c, s, "utility", "none")); r["suites"][s] = {"util": du["utility"] * 100 if du else None,
                "util_tasks": {k.split("|")[0]: bool(v) for k, v in du["utility_results"].items()} if du else {}}
            for a in ATTACKS:
                ds = S.get((tag, c, s, "security", a)); r["suites"][s][f"asr_{AL[a]}"] = ds["security"] * 100 if ds else None
                r["suites"][s][f"asr_{AL[a]}_cases"] = [k for k, v in ds["security_results"].items() if v] if ds else []
        rows.append(r)
    if not rows: continue
    digest[tag] = {"model": mname, "rows": rows}
    base = next((r for r in rows if r["config"] == "baseline"), None)
    for r in rows:  # tasks lost/gained vs baseline (benign)
        if base and r["config"] != "baseline":
            lost, gained = [], []
            for s in SUITES:
                bt, rt = base["suites"][s]["util_tasks"], r["suites"][s]["util_tasks"]
                lost += [f"{s}:{t}" for t in bt if bt[t] and t in rt and not rt[t]]; gained += [f"{s}:{t}" for t in bt if not bt[t] and rt.get(t)]
            r["lost_vs_baseline"], r["gained_vs_baseline"] = lost, gained
    complete = all(r["n_suites_utility"] == 4 and r["n_suites_ii"] == 4 for r in rows)
    with open(TEX / f"table_b_{tag}.tex", "w") as f:
        f.write("\\begin{tabular}{@{}lrrrr@{}}\n\\toprule\nConfiguration & Utility [95\\% CI] & ASR, default [95\\% CI] & ASR, obfuscated [95\\% CI] & Util.\\ under attack \\\\\n\\midrule\n")
        for r in rows:
            f.write(f"\\textsc{{{LABELS[r['config']]}}} & {r['util']} & {r['asr_ii']} & {r['asr_obf']} & {fmt(r['ua_ii_pct'])} \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n")
    with open(TEX / f"table_b_suites_{tag}.tex", "w") as f:
        f.write("\\begin{tabular}{@{}l" + "rr" * len(SUITES) + "@{}}\n\\toprule\nConfiguration & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{s.capitalize()}}}" for s in SUITES) + " \\\\\n & " + " & ".join("Util & ASR" for _ in SUITES) + " \\\\\n\\midrule\n")
        for r in rows:
            def asr_of(s):
                v = r['suites'][s]; a = v['asr_ii'] if v['asr_ii'] is not None else v['asr_obf']
                return fmt(a if a is not None else float('nan'))
            f.write(f"\\textsc{{{LABELS[r['config']]}}} & " + " & ".join(f"{fmt(r['suites'][s]['util'] if r['suites'][s]['util'] is not None else float('nan'))} & {asr_of(s)}" for s in SUITES) + " \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n")
    print(f"=== {mname} ({'complete' if complete else 'PARTIAL'})")
    for r in rows:
        print(f"  {LABELS[r['config']]:18s} util {r['util']:>18s} (n={r['util_n']})  ASR-ii {r['asr_ii']:>16s} (n={r['asr_ii_n']})  ASR-obf {r['asr_obf']:>16s} (n={r['asr_obf_n']})  UA-ii {fmt(r['ua_ii_pct'])}" + (f"  lost {r['lost_vs_baseline']}" if r.get('lost_vs_baseline') else ""))
# combined table: model x config -> util / asr_ii / asr_obf / cases run
with open(TEX / "table_b_all.tex", "w") as f:
    f.write("\\begin{tabular}{@{}llrrrr@{}}\n\\toprule\nModel & Configuration & Utility & ASR, default & ASR, obfuscated & Cases run \\\\\n\\midrule\n")
    for tag, d in digest.items():
        for i, r in enumerate(d["rows"]):
            n_att = r["asr_ii_n"] or r["asr_obf_n"]
            cases = f"{r['util_n']} / {n_att}" + (" $^\\dagger$" if (r["util_n"] and r["util_n"] < 97) or (n_att and n_att < 949) else "")
            f.write(f"{d['model'] if i == 0 else ''} & \\textsc{{{LABELS[r['config']]}}} & {r['util']} & {r['asr_ii']} & {r['asr_obf']} & {cases} \\\\\n")
        f.write("\\midrule\n")
    f.write("\\bottomrule\n\\end{tabular}\n")
json.dump(digest, open("results_b.json", "w"), indent=1, default=str)
print("wrote tex/table_b_*.tex, results_b.json")

# ---- macros for prose: \u<Tag><Cfg> (utility %), \uci.., \a.. (ASR default), \aci.., \o.. (ASR obfuscated), \oci.., \ua.. (utility under attack, default)
TAGCODE = {"gpt5mini": "Gptmini", "gpt51": "Gptfo", "sonnet45": "Sonnet", "haiku45": "Haiku", "gpt4omini": "Gptfourmini", "llama70b": "Llama"}
CFGCODE = {"baseline": "Base", "spotlight": "Spot", "tool_filter": "Filt", "pi_detector": "Pid", "repeat_user": "Rep", "pep_prov": "Prov", "pep_prov_strict": "Strict", "pep_full": "Full", "pep_full_nomark": "Fullnm"}
def strip_ci(s): return s.split(" [")[0] if s != "--" else "--"
with open(TEX / "results_b.tex", "w") as f:
    f.write("% auto-generated by make_results_b.py\n")
    for tag, d in digest.items():
        for r in d["rows"]:
            T, C = TAGCODE[tag], CFGCODE[r["config"]]
            f.write(f"\\newcommand{{\\u{T}{C}}}{{{strip_ci(r['util'])}}}\n\\newcommand{{\\uci{T}{C}}}{{{r['util']}}}\n")
            f.write(f"\\newcommand{{\\a{T}{C}}}{{{strip_ci(r['asr_ii'])}}}\n\\newcommand{{\\aci{T}{C}}}{{{r['asr_ii']}}}\n\\newcommand{{\\ak{T}{C}}}{{{r['asr_ii_k']}}}\n")
            f.write(f"\\newcommand{{\\o{T}{C}}}{{{strip_ci(r['asr_obf'])}}}\n\\newcommand{{\\oci{T}{C}}}{{{r['asr_obf']}}}\n\\newcommand{{\\ok{T}{C}}}{{{r['asr_obf_k']}}}\n")
            base = next((b for b in d["rows"] if b["config"] == "baseline"), None)
            net = round((base["util_pct"] - r["util_pct"]) * r["util_n"] / 100) if base and r["util_n"] and base["util_n"] == r["util_n"] else "--"
            f.write(f"\\newcommand{{\\ua{T}{C}}}{{{fmt(r['ua_ii_pct'])}}}\n\\newcommand{{\\lost{T}{C}}}{{{len(r.get('lost_vs_baseline', []))}}}\n\\newcommand{{\\gained{T}{C}}}{{{len(r.get('gained_vs_baseline', []))}}}\n\\newcommand{{\\net{T}{C}}}{{{net}}}\n")
    present = {(tag, r["config"]) for tag, d in digest.items() for r in d["rows"]}
    for tag, T in TAGCODE.items():
        for cfg, C in CFGCODE.items():
            if (tag, cfg) in present: continue
            for m in ("u", "uci", "a", "aci", "ak", "o", "oci", "ok", "ua", "lost", "gained", "net"): f.write(f"\\newcommand{{\\{m}{T}{C}}}{{--}}\n")
    # model-free replay macros
    import os
    AC = {"important_instructions": "Ii", "important_instructions_obfuscated": "Obf"}; CC = {"none": "None", "prov": "Prov", "strict": "Strict", "full": "Full", "fullstrict": "Fullstrict"}
    P_all = json.load(open("preflight_all.json")) if os.path.exists("preflight_all.json") else {}
    P_22 = json.load(open("preflight_v22.json")) if os.path.exists("preflight_v22.json") else {}
    tot = btot = 0
    for a, ac in AC.items():
        for c, cc in CC.items():
            src = P_22 if (c != "none" and a in P_22 and any(k.startswith(c + "|") for k in P_22[a])) else P_all
            if a not in src or not any(k.startswith(c + "|") for k in src[a]):
                f.write(f"\\newcommand{{\\rp{ac}{cc}}}{{--}}\n\\newcommand{{\\rpp{ac}{cc}}}{{--}}\n\\newcommand{{\\rb{ac}{cc}}}{{--}}\n"); continue
            att = sum(v[0] for k, v in src[a].items() if k.startswith(c + "|")); tot = sum(v[1] for k, v in src[a].items() if k.startswith(c + "|"))
            ben = sum(v[2] for k, v in src[a].items() if k.startswith(c + "|")); btot = sum(v[3] for k, v in src[a].items() if k.startswith(c + "|"))
            f.write(f"\\newcommand{{\\rp{ac}{cc}}}{{{att}}}\n\\newcommand{{\\rpp{ac}{cc}}}{{{att/tot*100:.1f}}}\n\\newcommand{{\\rb{ac}{cc}}}{{{ben}}}\n")
    # v2.1 figures for the text (what the live Track B runs used)
    for a, ac in AC.items():
        for c, cc in CC.items():
            if a in P_all and any(k.startswith(c + "|") for k in P_all[a]):
                att = sum(v[0] for k, v in P_all[a].items() if k.startswith(c + "|")); ben = sum(v[2] for k, v in P_all[a].items() if k.startswith(c + "|"))
                f.write(f"\\newcommand{{\\rpold{ac}{cc}}}{{{att}}}\n\\newcommand{{\\rbold{ac}{cc}}}{{{ben}}}\n")
    f.write(f"\\newcommand{{\\nCases}}{{{tot or 949}}}\n\\newcommand{{\\nBenign}}{{{btot or 97}}}\n")
print("wrote tex/results_b.tex")

# ---- compact table for the 12-page version: one row per model
with open(TEX / "table_b_compact.tex", "w") as f:
    f.write("\\begin{tabular}{@{}lrrrrrr@{}}\n\\toprule\n & \\multicolumn{3}{c}{Utility (\\%)} & \\multicolumn{3}{c}{ASR (\\%)} \\\\\nModel & \\textsc{Base} & \\textsc{Prov} & \\textsc{Full} & \\textsc{Base} & \\textsc{Prov} & \\textsc{Full} \\\\\n\\midrule\n")
    for tag, d in digest.items():
        if tag not in RESISTANT: continue   # Track A API models have their own table
        R = {r["config"]: r for r in d["rows"]}
        def g(c, k):
            r = R.get(c); 
            if not r: return "--"
            v = r[k + "_pct"] if k != "asr" else (r["asr_ii_pct"] if r["asr_ii_n"] else r["asr_obf_pct"])
            return fmt(v)
        def partial(c, k):
            r = R.get(c)
            if not r: return False
            return (r["util_n"] and r["util_n"] < 97) if k == "util" else ((r["asr_ii_n"] or r["asr_obf_n"] or 0) < 949)
        def gd(c, k): return g(c, k) + ("$^\\dagger$" if partial(c, k) and g(c, k) != "--" else "")
        f.write(f"{d['model']} & {gd('baseline','util')} & {gd('pep_prov','util')} & {gd('pep_full','util')} & {gd('baseline','asr')} & {gd('pep_prov','asr')} & {gd('pep_full','asr')} \\\\\n")
    f.write("\\bottomrule\n\\end{tabular}\n")
print("wrote tex/table_b_compact.tex")

# ---- core Track B table with intervals (main text) and the net-loss range for the abstract
with open(TEX / "table_b_core.tex", "w") as f:
    f.write("\\begin{tabular}{@{}llrrr@{}}\n\\toprule\nModel & Configuration & Utility [95\\% CI] & ASR [95\\% CI] & Cases run \\\\\n\\midrule\n")
    for tag, d in digest.items():
        if tag not in RESISTANT: continue
        rows_c = [r for r in d["rows"] if r["config"] in ("baseline", "pep_prov", "pep_full")]
        for i, r in enumerate(rows_c):
            asr = r["asr_ii"] if r["asr_ii_n"] else r["asr_obf"]; n_att = r["asr_ii_n"] or r["asr_obf_n"]
            cases = f"{r['util_n']} / {n_att}"
            uf = r["util"] + ("$^\\dagger$" if r["util_n"] and r["util_n"] < 97 else ""); af = asr + ("$^\\dagger$" if n_att and n_att < 949 else "")
            f.write(f"{d['model'] if i == 0 else ''} & \\textsc{{{LABELS[r['config']]}}} & {uf} & {af} & {cases} \\\\\n")
        f.write("\\midrule\n")
    f.write("\\bottomrule\n\\end{tabular}\n")
nets = []
for tag, d in digest.items():
    if tag not in RESISTANT: continue
    base = next((b for b in d["rows"] if b["config"] == "baseline"), None); r = next((b for b in d["rows"] if b["config"] == "pep_prov"), None)
    if base and r and r["util_n"] and base["util_n"] == r["util_n"]: nets.append(round((base["util_pct"] - r["util_pct"]) * r["util_n"] / 100))
with open(TEX / "results_b.tex", "a") as f:
    for t, c in {"gpt4omini": "Gptfourmini", "llama70b": "Llama", "gpt5mini": "Gptmini", "gpt51": "Gptfo", "sonnet45": "Sonnet", "haiku45": "Haiku"}.items(): f.write(f"\\newcommand{{\\traceFix{c}}}{{{TRACE_FIX_BY_TAG.get(t, 0)}}}\n")
    f.write(f"\\newcommand{{\\traceFixCells}}{{{TRACE_FIX_CELLS}}}\n\\newcommand{{\\ctxLimitLlama}}{{{CTX_LIMIT.get('llama70b', 0)}}}\n\\newcommand{{\\ctxLimitGptfourmini}}{{{CTX_LIMIT.get('gpt4omini', 0)}}}\n")
    f.write(f"\\newcommand{{\\netProvMin}}{{{min(nets) if nets else '--'}}}\n\\newcommand{{\\netProvMax}}{{{max(nets) if nets else '--'}}}\n")
print("wrote tex/table_b_core.tex; net range", nets)

# ---- API models on which the attack succeeds undefended: security table (utility, utility under attack, ASR), all 949 cases
with open(TEX / "table_b_susceptible.tex", "w") as f:
    f.write("\\begin{tabular}{@{}llrrrr@{}}\n\\toprule\nModel & Configuration & Utility [95\\% CI] & Util.\\ under attack & ASR [95\\% CI] & Cases run \\\\\n\\midrule\n")
    for tag in SUSCEPTIBLE:
        d = digest.get(tag)
        if not d: continue
        ORDER = ["baseline", "spotlight", "tool_filter", "pep_prov", "pep_prov_strict", "pep_full"]
        rows_c = sorted([r for r in d["rows"] if r["config"] in ORDER and r["asr_ii_n"]], key=lambda r: ORDER.index(r["config"]))
        prog_row = tag == "gpt4omini" and (TEX / "results_progent_fm.tex").exists()
        for i, r in enumerate(rows_c):
            if prog_row and r["config"] == "pep_prov":   # Progent (Shi et al.) on the same model and cases, scored by make_results_progent.py
                f.write(" & Progent & \\uciProgFm & \\uaProgFm & \\aciProgFm & \\nProgBFm{} / \\nProgAFm \\\\\n")
            n_att = r["asr_ii_n"]; cases = f"{r['util_n']} / {n_att}"
            uf = r["util"] + ("$^\\dagger$" if r["util_n"] and r["util_n"] < 97 else ""); af = r["asr_ii"] + ("$^\\dagger$" if n_att and n_att < 949 else "")
            f.write(f"{d['model'] if i == 0 else ''} & \\textsc{{{LABELS[r['config']]}}} & {uf} & {r['ua_ii_pct'] if r['ua_ii_pct'] == r['ua_ii_pct'] else float('nan'):.1f} & {af} & {cases} \\\\\n".replace("nan", "--"))
        f.write("\\midrule\n")
    f.write("\\bottomrule\n\\end{tabular}\n")
txt = (TEX / "table_b_susceptible.tex").read_text()
(TEX / "table_b_susceptible_conf.tex").write_text("\n".join(l for l in txt.splitlines() if "PEP-prov (strict)" not in l and "\\textsc{Spotlight}" not in l) + "\n")
print("wrote tex/table_b_susceptible.tex (+ _conf without the strict row)")
