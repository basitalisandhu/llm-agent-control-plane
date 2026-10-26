"""Appendix tables: incident dataset (from incidents.csv) and tiering tables (from pep.py)."""
import csv, re
from pathlib import Path
import pep
TEX = Path("tex")
def esc(s):
    s = str(s).replace("\\", "\\textbackslash{}")
    for a, b in [("&", "\\&"), ("%", "\\%"), ("$", "\\$"), ("#", "\\#"), ("_", "\\_"), ("{", "\\{"), ("}", "\\}"), ("~", "\\textasciitilde{}"), ("^", "\\textasciicircum{}")]:
        s = s.replace(a, b)
    return s
rows = list(csv.DictReader(open("incidents.csv")))
TYPE = {"incident": "I", "disclosure": "D", "vulnerability-disclosure": "D", "report": "R", "threat report": "R", "threat-report": "R"}
with open(TEX / "table_incidents.tex", "w") as f:
    f.write("\\begin{longtable}{@{}>{\\raggedright\\arraybackslash}p{0.95cm}>{\\raggedright\\arraybackslash}p{1.15cm}>{\\raggedright\\arraybackslash}p{5.1cm}>{\\raggedright\\arraybackslash}p{0.75cm}>{\\raggedright\\arraybackslash}p{1.05cm}>{\\raggedright\\arraybackslash}p{2.7cm}@{}}\n")
    f.write("\\caption{The incident dataset (I = real-world incident, D = vendor-acknowledged vulnerability disclosure, R = vendor threat report). Lens and vector as coded with the codebook; sources in the released dataset.}\\label{tab:incidents}\\\\\n\\toprule\nID & Date & Event & Type & Lens & Vector \\\\\n\\midrule\n\\endfirsthead\n\\toprule\nID & Date & Event & Type & Lens & Vector \\\\\n\\midrule\n\\endhead\n")
    for r in rows:
        name = r["name"]; name = name if len(name) <= 95 else name[:92] + "..."
        f.write(f"\\mbox{{D-{r['id']}}} & {esc(r['date'])} & {esc(name)} & {TYPE.get(r['type'].strip().lower(), esc(r['type']))} & {esc(r['lens'])} & {esc(r['vector'])} \\\\\n")
    f.write("\\bottomrule\n\\end{longtable}\n")
import collections
print("incidents:", len(rows), collections.Counter(r["lens"] for r in rows), collections.Counter(r["type"] for r in rows))
with open(TEX / "table_tiering.tex", "w") as f:
    f.write("\\begin{tabular}{@{}l>{\\raggedright\\arraybackslash}p{4.6cm}>{\\raggedright\\arraybackslash}p{5.0cm}@{}}\n\\toprule\nSuite & Consequential tool & Key arguments \\\\\n\\midrule\n")
    for suite, tools in pep.PERMISSION_TOOLS.items():
        for i, t in enumerate(sorted(tools)):
            ka = ", ".join(pep.KEY_ARGS.get(t, [])) or "(none)"
            f.write(f"{suite.capitalize() if i == 0 else ''} & \\texttt{{{esc(t)}}} & \\texttt{{{esc(ka)}}} \\\\\n")
    f.write("\\bottomrule\n\\end{tabular}\n")
print("consequential tools:", sum(len(v) for v in pep.PERMISSION_TOOLS.values()), "distinct", len(set().union(*pep.PERMISSION_TOOLS.values())))
print("identity args:", sorted(pep.IDENTITY_ARGS), "id args:", sorted(pep.ID_ARGS), "free-text tools:", sorted(pep.FREE_TEXT_TOOLS), "free-text fields:", sorted(pep.FREE_TEXT_FIELDS))
