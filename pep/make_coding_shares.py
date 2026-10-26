#!/usr/bin/env python3
"""
make_coding_shares.py -- how the dataset's lens shares depend on who coded it, and how far the
three codings agree with each other.

Inputs
  incidents.csv (next to this script)  author's coding: id, type, lens, vector, ... (80 events)
  <repo>/data/incidents_coder2.csv     second coding, an independent run of the same model family,
                                       made without the author's labels: id, lens, vector
  <repo>/data/incidents_coder3.csv     third coding by GPT-5 mini, made without the author's labels:
                                       id, type, lens, vector
Outputs
  tex/results_coding.tex   \\newcommand macros for the text
  tex/table_coding.tex     table tab:coding
  stdout                   every number behind them, the lens confusion matrices, the disagreeing ids

Definitions
  share         events in a lens / 80, as a percentage rounded half up to an integer.
  incident set  the events with type = incident.  The author's own 25 define it for the author and for
                coder 2 (coder 2 coded no type); coder 3's own type defines it for coder 3 (29 events,
                not 25).  Coder 3's lens on the author's 25 is printed as a sensitivity check.
  agreement     events given the same label by both codings / 80.
  kappa         Cohen's kappa, unweighted: (po - pe) / (1 - pe), pe = sum over labels of
                p1(label) * p2(label) from the two codings' marginals, as in make_dataset_tables.py.
  type          coded by the author and by coder 3 only, so only that pair has a type agreement.
  spellings     lower-cased; spaces and underscores become hyphens; "disclosure" is read as
                "vulnerability-disclosure" (so "threat report" = "threat-report").
All rounding is half up on exact fractions, so a tie such as 54/80 = 67.5% is printed as 68.

Run:  .venv/bin/python make_coding_shares.py [--repo REPO]
"""
import argparse
import csv
import re
import sys
from collections import Counter
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_REPO = HERE.parent

LENSES = ["weapon", "target", "surface"]
TYPES = ["incident", "vulnerability-disclosure", "threat-report"]
CODINGS = ["author", "coder2", "coder3"]
PAIRS = [("author", "coder2"), ("author", "coder3"), ("coder2", "coder3")]
FIELDS_OF = {"author": ["type", "lens", "vector"], "coder2": ["lens", "vector"], "coder3": ["type", "lens", "vector"]}
ROW_LABEL = {"author": "Author", "coder2": r"Coder 2 (Claude)", "coder3": r"Coder 3 (GPT-5 mini)"}
PAIR_LABEL = {("author", "coder2"): "Author--coder 2", ("author", "coder3"): "Author--coder 3",
              ("coder2", "coder3"): "Coder 2--coder 3"}
MACRO_NAME = {"author": "Author", "coder2": "CoderTwo", "coder3": "CoderThree"}
N_EVENTS, N_INCIDENTS = 80, 25            # the figures the paper states for the author's coding

# ---------------------------------------------------------------- spelling
SYNONYMS = {"disclosure": "vulnerability-disclosure"}


def norm(value):
    """Case, whitespace and the 'disclosure' / 'threat report' spellings."""
    v = re.sub(r"[\s_]+", "-", value.strip().lower())
    return SYNONYMS.get(v, v)


assert norm("Vulnerability-Disclosure") == norm("disclosure") == norm("vulnerability disclosure") == "vulnerability-disclosure"
assert norm("threat report") == norm("Threat-Report") == "threat-report"


# ---------------------------------------------------------------- loading
def load(path, fields):
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            i = r["id"].strip()
            if i in out:
                sys.exit("%s: duplicate id %s" % (path, i))
            out[i] = {k: norm(r[k]) for k in fields}
            for k, v in out[i].items():
                if not v:
                    sys.exit("%s: empty %s for id %s" % (path, k, i))
    return out


def load_all(repo):
    c = {"author": load(HERE / "incidents.csv", FIELDS_OF["author"]),
         "coder2": load(repo / "data" / "incidents_coder2.csv", FIELDS_OF["coder2"]),
         "coder3": load(repo / "data" / "incidents_coder3.csv", FIELDS_OF["coder3"])}
    ids = sorted(c["author"])
    for name in CODINGS:
        if sorted(c[name]) != ids:
            sys.exit("%s does not cover exactly the author's event ids" % name)
    if len(ids) != N_EVENTS:
        sys.exit("expected %d events, found %d" % (N_EVENTS, len(ids)))
    vectors = {c["author"][i]["vector"] for i in ids}
    for name in CODINGS:
        for field, allowed in (("lens", LENSES), ("type", TYPES), ("vector", vectors)):
            if field in FIELDS_OF[name]:
                bad = sorted({c[name][i][field] for i in ids} - set(allowed))
                if bad:
                    sys.exit("%s: unknown %s value(s) after normalising: %s" % (name, field, bad))
    return c, ids


# ---------------------------------------------------------------- statistics (exact fractions)
def fmt(x, nd=0):
    """Fraction -> text, rounded half away from zero to nd decimals (no float rounding)."""
    scale = 10 ** nd
    q = int(abs(x) * scale + Fraction(1, 2))
    s = str(q).rjust(nd + 1, "0")
    if nd:
        s = s[:-nd] + "." + s[-nd:]
    return ("-" if x < 0 and q else "") + s


def pct(n, d):
    return fmt(Fraction(100 * n, d))


def kappa_stats(a, b):
    n = len(a)
    agree = sum(x == y for x, y in zip(a, b))
    ca, cb = Counter(a), Counter(b)
    po = Fraction(agree, n)
    pe = Fraction(sum(ca[k] * cb[k] for k in ca.keys() | cb.keys()), n * n)
    kappa = (po - pe) / (1 - pe) if pe != 1 else None
    return dict(n=n, agree=agree, po=po, pe=pe, kappa=kappa, k=len(ca.keys() | cb.keys()))


def compute(c, ids):
    R = {}
    R["lens_n"] = {k: Counter(c[k][i]["lens"] for i in ids) for k in CODINGS}
    inc_author = [i for i in ids if c["author"][i]["type"] == "incident"]
    if len(inc_author) != N_INCIDENTS:
        sys.exit("expected %d real-world incidents under the author's type, found %d" % (N_INCIDENTS, len(inc_author)))
    inc_set = {"author": inc_author, "coder2": inc_author,
               "coder3": [i for i in ids if c["coder3"][i]["type"] == "incident"]}
    R["inc_set"] = inc_set
    R["inc_surface"] = {k: sum(c[k][i]["lens"] == "surface" for i in inc_set[k]) for k in CODINGS}
    R["inc_surface_coder3_author_type"] = sum(c["coder3"][i]["lens"] == "surface" for i in inc_author)
    R["pair"] = {}
    for p, q in PAIRS:
        for f in ("lens", "vector", "type"):
            if f in FIELDS_OF[p] and f in FIELDS_OF[q]:
                a = [c[p][i][f] for i in ids]
                b = [c[q][i][f] for i in ids]
                R["pair"][(p, q, f)] = kappa_stats(a, b)
                R["pair"][(p, q, f)]["diff"] = [(i, x, y) for i, x, y in zip(ids, a, b) if x != y]
    return R


# ---------------------------------------------------------------- console report
def report(c, ids, R):
    n = len(ids)
    print("%d events; incident set: author %d, coder 3 %d\n" % (n, len(R["inc_set"]["author"]), len(R["inc_set"]["coder3"])))
    print("Lens shares of the %d events" % n)
    for k in CODINGS:
        print("  %-7s " % k + "  ".join("%s %d (%s%%)" % (l, R["lens_n"][k][l], fmt(Fraction(100 * R["lens_n"][k][l], n), 1))
                                         for l in LENSES))
    print("\nSurface events among the real-world incidents")
    basis = {"author": "author's type", "coder2": "author's type (coder 2 coded no type)", "coder3": "coder 3's own type"}
    for k in CODINGS:
        s, d = R["inc_surface"][k], len(R["inc_set"][k])
        print("  %-7s %d/%d = %s%%  [incident set: %s]" % (k, s, d, fmt(Fraction(100 * s, d), 1), basis[k]))
    s, d = R["inc_surface_coder3_author_type"], len(R["inc_set"]["author"])
    print("  coder3  %d/%d = %s%%  [sensitivity: coder 3's lens on the author's 25]" % (s, d, fmt(Fraction(100 * s, d), 1)))
    print("\nPairwise agreement (events of %d) and Cohen's kappa" % n)
    for (p, q, f), S in R["pair"].items():
        print("  %-6s-%-6s %-6s agree %2d/%d = %s%%  po %.4f  pe %.4f  kappa %s (%s)  [%d labels]" % (
            p, q, f, S["agree"], S["n"], fmt(S["po"] * 100, 2), float(S["po"]), float(S["pe"]),
            fmt(S["kappa"], 4), fmt(S["kappa"], 2), S["k"]))
    print("  type for any pair with coder 2: not coded.  (Imputing the author's type to coder 2 would make"
          " coder2-coder3 equal to author-coder3 and author-coder2 trivially 80/80.)")
    print("\nLens confusion matrices (rows = first coding, columns = second coding; weapon, target, surface)")
    for p, q in PAIRS:
        print("  %s (rows) x %s (columns)" % (p, q))
        for l1 in LENSES:
            print("    %-8s" % l1 + " ".join("%3d" % sum(1 for i in ids if c[p][i]["lens"] == l1 and c[q][i]["lens"] == l2)
                                             for l2 in LENSES))
    print("\nDisagreements (event id: first coding / second coding)")
    for (p, q, f), S in R["pair"].items():
        if f != "vector":
            print("  %s-%s %s (%d): " % (p, q, f, len(S["diff"])) + ", ".join("D-%d %s/%s" % (int(i), x, y) for i, x, y in S["diff"]))
        else:
            print("  %s-%s vector (%d): " % (p, q, len(S["diff"])) + ", ".join("D-%d" % int(i) for i, _, _ in S["diff"]))


# ---------------------------------------------------------------- macros
def macros(c, ids, R):
    n = len(ids)
    surf = {k: int(pct(R["lens_n"][k]["surface"], n)) for k in CODINGS}
    inc = {k: int(pct(R["inc_surface"][k], len(R["inc_set"][k]))) for k in CODINGS}
    L23, V23 = R["pair"][("coder2", "coder3", "lens")], R["pair"][("coder2", "coder3", "vector")]
    out = ["% Generated by make_coding_shares.py from incidents.csv (author), data/incidents_coder2.csv and",
           "% data/incidents_coder3.csv; edit the script, not this file.  Percentages are integers, rounded half up;",
           "% use as \\pctSurfaceAuthor\\%.  Shares of the 80 events:"]
    for k in CODINGS:
        out.append("\\newcommand{\\pctSurface%s}{%d}" % (MACRO_NAME[k], surf[k]))
    out += ["\\newcommand{\\pctSurfaceMin}{%d}" % min(surf.values()), "\\newcommand{\\pctSurfaceMax}{%d}" % max(surf.values()),
            "% Agreement of coder 2 with coder 3 (percent of the 80 events; kappa to two decimals):",
            "\\newcommand{\\kappaLensTwoThree}{%s}" % fmt(L23["kappa"], 2),
            "\\newcommand{\\kappaVectorTwoThree}{%s}" % fmt(V23["kappa"], 2),
            "\\newcommand{\\agreeLensTwoThree}{%s}" % pct(L23["agree"], n),
            "\\newcommand{\\agreeVectorTwoThree}{%s}" % pct(V23["agree"], n),
            "% Surface-lens share among the real-world incidents (author's type for the author and coder 2,",
            "% coder 3's own type for coder 3; the last one is coder 3's lens on the author's incidents):"]
    for k in CODINGS:
        out.append("\\newcommand{\\pctSurfaceInc%s}{%d}" % (MACRO_NAME[k], inc[k]))
    out += ["\\newcommand{\\pctSurfaceIncMin}{%d}" % min(inc.values()), "\\newcommand{\\pctSurfaceIncMax}{%d}" % max(inc.values()),
            "\\newcommand{\\nIncCoderThree}{%d}" % len(R["inc_set"]["coder3"]),
            "\\newcommand{\\pctSurfaceIncCoderThreeAuthorType}{%s}" % pct(R["inc_surface_coder3_author_type"], len(R["inc_set"]["author"]))]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- table
def table(c, ids, R):
    n = len(ids)
    rows_a, sums = [], []
    for k in CODINGS:
        cells = ["%d (%s)" % (R["lens_n"][k][l], pct(R["lens_n"][k][l], n)) for l in LENSES]
        sums.append(sum(int(pct(R["lens_n"][k][l], n)) for l in LENSES))
        s, d = R["inc_surface"][k], len(R["inc_set"][k])
        rows_a.append("%s & %s & %d/%d (%s) \\\\" % (ROW_LABEL[k], " & ".join(cells), s, d, pct(s, d)))
    rows_b = []
    for p, q in PAIRS:
        cells = []
        for f in ("lens", "vector", "type"):
            S = R["pair"].get((p, q, f))
            cells.append("%s (%d)" % (fmt(S["kappa"], 2), S["agree"]) if S else "n/a")
        rows_b.append("%s & %s \\\\" % (PAIR_LABEL[(p, q)], " & ".join(cells)))
    s3a, d3a = R["inc_surface_coder3_author_type"], len(R["inc_set"]["author"])
    d3 = len(R["inc_set"]["coder3"])
    rounding = " Percentages are rounded and need not sum to 100." if any(s != 100 for s in sums) else ""
    caption = (
        "Lens shares under three codings of the %d events, and agreement between the codings. "
        "The first coding is the author's, made with a language-model assistant. Coder~2 is an independent run of "
        "the same model family and coded lens and vector only; coder~3 is GPT-5~mini and coded type, lens and "
        "vector; neither saw the author's labels. "
        "(a)~Events in each lens (\\%% of %d) and the surface-lens share of the real-world incidents (type = incident): "
        "the author's %d incidents for the author and for coder~2, which coded no type, and coder~3's own type "
        "for coder~3, which gives %d incidents (on the author's %d its surface share is %d/%d, %s\\%%).%s "
        "(b)~Cohen's $\\kappa$ for each pair of codings and field, with the number of the %d events on which the "
        "two codings give the same label in parentheses; $\\kappa=(p_o-p_e)/(1-p_e)$, with $p_e$ the agreement expected "
        "from the two codings' marginals. Type was coded by the author and coder~3 only, so n/a elsewhere."
    ) % (n, n, len(R["inc_set"]["author"]), d3, d3a, s3a, d3a, pct(s3a, d3a), rounding, n)
    out = [
        "% Generated by make_coding_shares.py from incidents.csv (author), data/incidents_coder2.csv and",
        "% data/incidents_coder3.csv; edit the script, not this file.  Needs booktabs.",
        "\\begin{table}[!htbp]",
        "\\centering\\footnotesize",
        "\\setlength{\\tabcolsep}{5pt}",
        "\\caption{%s}" % caption,
        "\\label{tab:coding}",
        "\\textit{(a) Lens shares}\\par\\smallskip",
        "\\begin{tabular}{@{}lrrrr@{}}",
        "\\toprule",
        " & \\multicolumn{3}{c}{All %d events, $n$ (\\%%)} & Real-world incidents \\\\" % n,
        "\\cmidrule(lr){2-4}\\cmidrule(l){5-5}",
        "Coding & Weapon & Target & Surface & Surface, $n/N$ (\\%) \\\\",
        "\\midrule"] + rows_a + [
        "\\bottomrule",
        "\\end{tabular}",
        "\\par\\medskip",
        "\\textit{(b) Pairwise agreement: Cohen's $\\kappa$ (events agreed)}\\par\\smallskip",
        "\\begin{tabular}{@{}lccc@{}}",
        "\\toprule",
        "Pair & Lens & Vector & Type \\\\",
        "\\midrule"] + rows_b + [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}"]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", type=Path, default=DEFAULT_REPO, help="repository holding data/incidents_coder{2,3}.csv")
    args = ap.parse_args()
    c, ids = load_all(args.repo)
    R = compute(c, ids)
    report(c, ids, R)
    (HERE / "tex").mkdir(exist_ok=True)
    (HERE / "tex" / "results_coding.tex").write_text(macros(c, ids, R), encoding="utf-8")
    (HERE / "tex" / "table_coding.tex").write_text(table(c, ids, R), encoding="utf-8")
    print("\nwrote tex/results_coding.tex and tex/table_coding.tex")


if __name__ == "__main__":
    main()
