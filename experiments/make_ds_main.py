"""Compact dataset table for the main text: lens x type (+ adversary), and the surface events against the two rules."""
import csv, collections
rows = list(csv.DictReader(open("incidents.csv")))
L = [("surface", "Attack surface"), ("target", "Target"), ("weapon", "Weapon")]
T = [("incident", "Incidents"), ("vulnerability-disclosure", "Disclosures"), ("threat-report", "Threat reports")]
lines = ["\\begin{tabular}{@{}lrrrrr@{}}", "\\toprule", "Lens & " + " & ".join(n for _, n in T) + " & Total & With adversary \\\\", "\\midrule"]
for lk, ln in L:
    r = [x for x in rows if x["lens"] == lk]
    lines.append(f"{ln} & " + " & ".join(str(sum(1 for x in r if x['type'] == tk)) for tk, _ in T) + f" & {len(r)} & {sum(1 for x in r if x['adversarial'] == 'yes')} \\\\")
lines.append("\\midrule")
lines.append("Total & " + " & ".join(str(sum(1 for x in rows if x['type'] == tk)) for tk, _ in T) + f" & {len(rows)} & {sum(1 for x in rows if x['adversarial'] == 'yes')} \\\\")
lines += ["\\bottomrule", "\\end{tabular}", "\\par\\medskip", "\\begin{tabular}{@{}lr@{}}", "\\toprule", "Surface-lens events with an adversary (41), by impact channel & Events \\\\", "\\midrule"]
adv = [x for x in rows if x["lens"] == "surface" and x["adversarial"] == "yes"]
cls = [("Tool call to an attacker-chosen destination (provenance rule)", ("tool-call send", "file publish", "financial transfer")),
       ("Rendered link or image (provenance rule only with client egress mediation)", ("image/link fetch",)),
       ("Code execution or destruction, no attacker designator (approval rule)", ("code exec", "data destruction")),
       ("Disclosure only (out of scope)", ("disclosure-only",))]
for name, keys in cls: lines.append(f"{name} & {sum(1 for x in adv if x['channel_out'] in keys)} \\\\")
na = [x for x in rows if x["lens"] == "surface" and x["adversarial"] == "no"]
lines.append(f"\\midrule Surface-lens events without an adversary (agent acting on its own; approval rule) & {len(na)} \\\\")
lines += ["\\bottomrule", "\\end{tabular}"]
open("tex/table_ds_main.tex", "w").write("\n".join(lines) + "\n"); print("wrote tex/table_ds_main.tex")
