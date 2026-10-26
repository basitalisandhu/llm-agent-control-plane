"""Parses incidents.psv (pipe-separated rows from the dataset agent) into macros + fig_incidents.pdf + a CSV."""
import csv, re, collections, sys
from pathlib import Path
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

src = Path("incidents.psv").read_text().splitlines()
rows = []
for line in src:
    if "|" not in line or line.lower().startswith("id |") or line.strip().startswith("EXCLUDED"):
        continue
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 13 or not re.match(r"^\d+$", parts[0]):
        continue
    rows.append(dict(id=parts[0], date=parts[1], name=parts[2], type=parts[3], lens=parts[4].lower(), vector=parts[5].lower(),
                     channel_in=parts[6].lower(), authority=parts[7].lower(), channel_out=parts[8].lower(), adversarial=parts[9].lower(),
                     outcome=parts[10].lower(), cve=parts[11], url=parts[12], notes=parts[13] if len(parts) > 13 else ""))
n = len(rows)
lens = collections.Counter(r["lens"] for r in rows)
years = sorted({r["date"][:4] for r in rows})
by_year_lens = {y: collections.Counter(r["lens"] for r in rows if r["date"].startswith(y)) for y in years}
surf = [r for r in rows if r["lens"] == "surface"]
chan = collections.Counter(r["channel_in"] for r in surf)
with open("tex/results_incidents.tex", "w") as f:
    f.write(f"\\newcommand{{\\nIncidents}}{{{n}}}\n")
    for k, key in [("pctSurface", "surface"), ("pctWeapon", "weapon"), ("pctTarget", "target")]:
        f.write(f"\\newcommand{{\\{k}}}{{{lens[key] / n * 100:.0f}}}\n")
    f.write(f"\\newcommand{{\\nSurface}}{{{lens['surface']}}}\n")
    types = collections.Counter(r["type"] for r in rows)
    f.write(f"\\newcommand{{\\nDisclosures}}{{{types['vulnerability-disclosure']}}}\\newcommand{{\\nRealIncidents}}{{{types['incident']}}}\\newcommand{{\\nThreatReports}}{{{types['threat-report']}}}\n")
    ind = sum(1 for r in surf if r["vector"] == "indirect-injection")
    cons = sum(1 for r in surf if r["channel_out"] in ("tool-call send", "image/link fetch", "code exec", "data destruction", "file publish", "financial transfer"))
    nonadv = sum(1 for r in surf if r["adversarial"] == "no")
    f.write(f"\\newcommand{{\\pctIndirect}}{{{ind / len(surf) * 100:.0f}}}\\newcommand{{\\pctConsequential}}{{{cons / len(surf) * 100:.0f}}}\\newcommand{{\\nNonAdversarial}}{{{nonadv}}}\n")
with open("incidents.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.0), gridspec_kw={"width_ratios": [1.1, 1]})
bottom = [0] * len(years)
for key, col in [("surface", "#0b3d91"), ("weapon", "#6f6f6f"), ("target", "#bdbdbd")]:
    vals = [by_year_lens[y][key] for y in years]
    axes[0].bar(years, vals, bottom=bottom, color=col, label=key.capitalize()); bottom = [b + v for b, v in zip(bottom, vals)]
axes[0].set_title(f"Events by lens and year (n={n})", fontsize=9); axes[0].legend(fontsize=7, frameon=False)
top = chan.most_common(8)
axes[1].barh([k for k, _ in top][::-1], [v for _, v in top][::-1], color="#0b3d91")
axes[1].set_title(f"Entry channel, surface lens (n={len(surf)})", fontsize=9)
for ax in axes: ax.tick_params(labelsize=8); ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout(); fig.savefig("tex/fig_incidents.pdf")
print("n", n, dict(lens), "surface channels", top)
print("years", {y: dict(c) for y, c in by_year_lens.items()})
