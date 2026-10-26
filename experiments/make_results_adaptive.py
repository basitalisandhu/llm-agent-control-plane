"""Macros and the supplement section for the adaptive attack families (reads preflight_adaptive.json, which
preflight_adaptive.py writes; the table itself, tex/table_adaptive.tex, is written by preflight_adaptive.py)."""
import json
from pathlib import Path
import attacks_adaptive as A
d = json.load(open("preflight_adaptive.json")); T = d["totals"]; TEX = Path("tex")
def n(fam, wl, pol): return T[fam][wl][pol]["admitted"]
code = {"evasion_ip": "Ip", "evasion_idn": "Idn", "evasion_zerowidth": "Zw", "evasion_spelled": "Sp", "laundering": "Laund", "sender_field": "Sender",
        "important_instructions": "Ii", "important_instructions_obfuscated": "Obf"}
pc = {"prov": "Prov", "strict": "Strict", "full": "Full", "fullstrict": "Fullstrict"}
with open(TEX / "results_adaptive.tex", "w") as f:
    for fam, c in code.items():
        for pol, p in pc.items():
            f.write(f"\\newcommand{{\\ad{c}{p}Off}}{{{n(fam,'off',pol)}}}\n\\newcommand{{\\ad{c}{p}On}}{{{n(fam,'on',pol)}}}\n")
    b = T["important_instructions"]
    f.write(f"\\newcommand{{\\adBenignProvOff}}{{{b['off']['prov']['benign_ok']}}}\n\\newcommand{{\\adBenignProvOn}}{{{b['on']['prov']['benign_ok']}}}\n")
    f.write(f"\\newcommand{{\\adBenignFullOff}}{{{b['off']['full']['benign_ok']}}}\n\\newcommand{{\\adPairsNoRef}}{{{sum(s['pairs']-s['with_reference_actions'] for s in d['meta']['pairs'].values())}}}\n")
    f.write(f"\\newcommand{{\\adReplays}}{{{d['meta']['replays']['off']['replays']:,}}}\n\\newcommand{{\\adMemo}}{{{d['meta']['replays']['off'].get('memo_hits', 0):,}}}\n\\newcommand{{\\adSkipped}}{{{d['meta']['replays']['off'].get('skipped_no_reference_actions', 0):,}}}\n")
    import re as _re, glob as _gl
    vals = {}
    for fn in _gl.glob("tex/results_*.tex"):
        for mname, v in _re.findall(r"\\newcommand\{\\(rpIiNone|rpIiProv)\}\{(\d+)\}", open(fn).read()): vals[mname] = int(v)
    if "rpIiNone" in vals and "rpIiProv" in vals: f.write(f"\\newcommand{{\\rppIiReach}}{{{100 * vals['rpIiProv'] / vals['rpIiNone']:.1f}}}\n")
# supplement section
ASSUMP = {"evasion_ip": "A3", "evasion_idn": "A3", "evasion_zerowidth": "A3", "evasion_spelled": "A3", "laundering": "A1", "sender_field": "A1 premise ($T^0$)"}
def tex(s): return s.replace("F_ii+", "(ii$^+$)").replace("F_iii", "(iii)").replace("F_ii", "(ii)").replace("F_i", "(i)").replace("S^0", "$S^0$").replace("S^t", "$S^t$").replace("_", "\\_").replace("&", "\\&").replace("%", "\\%")
rows = []
for fam in A.FAMILIES:
    doc = A.FAMILY_DOC[fam]
    rows.append(f"\\texttt{{{tex(fam)}}} & {ASSUMP[fam]} & {tex(doc['clauses'])} & {tex(doc['why'])} \\\\")
with open(TEX / "supp_adaptive.tex", "w") as f:
    f.write(r"""\section{Adaptive attack families}
\label{app:adaptive}
The six families of Table~\ref{tab:adaptive} are registered attacks of the benchmark that rewrite the text of the \emph{important instructions} attack for each goal; the goal and its security check are the benchmark's, unchanged, and where a family has nothing to rewrite it returns the default text byte for byte. They were written from the counterexamples stated with assumptions A1--A3 after matcher v2.2 was frozen, with their own pattern code rather than the extractor's, and the matching rules were not changed afterwards (v2.3 adds labelling only). The replay (\adReplays{} replays executed per labelling setting, \adMemo{} further cells served from a memo of identical trajectories and \adSkipped{} pair-policy cells skipped for want of reference actions) runs a perfectly obedient agent: for the three canonical-form evasions it restores the canonical form and executes the benchmark's reference actions; for the IP form it executes them with the IP literal; for laundering it inserts the write and read-back calls before them; for the sender-field family it addresses the reply to the typed sender. A goal is admitted when the policy executes every goal-bearing reference action; \adPairsNoRef{} pairs whose goals have no reference actions in the benchmark are never admitted. Laundering applies where a suite has a tool that writes a typed field and one that reads it back (banking, travel and workspace: 8, 3 and 12 of their goals); Slack has none and the family falls back to the obfuscated text there. The sender-field family applies where the injected content is carried by a record with a typed sender field (five e-mail carriers in workspace, 108 pairs). Table~\ref{tab:adaptivefam} gives the construction of each family. None is optimisation-based; an attacker who searches the matcher's code for forms it misses is the next step named in the conclusion. Three artefacts of the benchmark bear on the counts. First, the benchmark's security check looks for the original host or address, so for \texttt{evasion\_ip} and \texttt{sender\_field} it cannot register the obedient agent's action; measured by that check alone the two rows read as the obfuscated attack (32/29/8/5) and the default attack (29/29/5/5) respectively, and Table~\ref{tab:adaptive} therefore reports the policy's decision for them. Second, workspace goal~0 can never register success for the nine user tasks whose injection sits in an e-mail, because the check matches the injected e-mail by subject; this undercounts every attack on that goal, live runs included. Third, in live runs the benchmark serialises structured tool results as YAML, which escapes non-ASCII characters, so a model sees the zero-width and homoglyph forms in e-mails and calendar entries as escape sequences rather than as invisible characters; the Slack suite used for the live zero-width run carries its injections in plain text fields.
\begin{table}[!htbp]\centering\scriptsize\setlength{\tabcolsep}{3pt}
\caption{The adaptive families: the assumption each targets, the clause of the rule it aims at, and why it would pass.}
\label{tab:adaptivefam}
\begin{tabular}{@{}p{2.3cm}p{0.9cm}p{2.0cm}p{5.6cm}@{}}
\toprule
Family & Targets & Clause & Construction and intended effect \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}\end{table}
\IfFileExists{table_adaptive_live.tex}{\begin{table}[!htbp]\centering\scriptsize\setlength{\tabcolsep}{3pt}\caption{Live runs of two families on GPT-4o mini with matcher v2.2 (laundering on the eight banking goals that have a write/read-back pair, all 16 user tasks; zero-width evasion on every Slack pair): utility under attack and attack success, percent with 95\% intervals clustered by user task (exact upper bound for an observed zero); $\dagger$ marks an arm not yet complete.}\label{tab:adaptivelive}\input{table_adaptive_live.tex}\end{table}}{}
""")

# ---- table bodies (full: every family on its own row; conference: the three canonical-form evasions on one row)
ROWS = [("important_instructions", "default attack"), ("important_instructions_obfuscated", "obfuscated attack (existing)"),
        ("evasion_ip", "\\texttt{evasion\\_ip}"), ("evasion_idn", "\\texttt{evasion\\_idn}"), ("evasion_zerowidth", "\\texttt{evasion\\_zerowidth}"),
        ("evasion_spelled", "\\texttt{evasion\\_spelled}"), ("laundering", "\\texttt{laundering}"), ("sender_field", "\\texttt{sender\\_field}")]
def ent(fam, pol):
    a, b = n(fam, "off", pol), n(fam, "on", pol)
    return f"{a}" if a == b else f"{a}\\,/\\,{b}"
HEAD = "\\begin{tabular}{@{}lrrrr@{}}\n\\toprule\nAttack family & Base rule & Strict & Approval & Strict\\,+\\,approval \\\\\n\\midrule\n"
def row(fam, label): return f"{label} & " + " & ".join(ent(fam, pol) for pol in ("prov", "strict", "full", "fullstrict")) + " \\\\\n"
full = HEAD + "".join(row(f, l) + ("\\midrule\n" if f == "important_instructions_obfuscated" else "") for f, l in ROWS) + "\\bottomrule\n\\end{tabular}\n"
conf_rows = []
for f, l in ROWS:
    if f == "important_instructions": continue   # conference build: the default attack's counts (29/29/5/5) are given in the text
    if f == "evasion_idn": conf_rows.append(row(f, "\\texttt{evasion\\_idn} / \\texttt{\\_zerowidth} / \\texttt{\\_spelled}"))
    elif f in ("evasion_zerowidth", "evasion_spelled"): continue
    else: conf_rows.append(row(f, l) + ("\\midrule\n" if f == "important_instructions_obfuscated" else ""))
assert all(ent("evasion_idn", p_) == ent("evasion_zerowidth", p_) == ent("evasion_spelled", p_) for p_ in ("prov", "strict", "full", "fullstrict"))
(TEX / "table_adaptive_body.tex").write_text(full); (TEX / "table_adaptive_body_conf.tex").write_text(HEAD + "".join(conf_rows) + "\\bottomrule\n\\end{tabular}\n")
print("wrote table_adaptive_body(.tex, _conf.tex)")

print("wrote tex/results_adaptive.tex, tex/supp_adaptive.tex")
