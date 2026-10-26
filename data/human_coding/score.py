"""Percent agreement and Cohen's kappa between a human-coded sheet and data/incidents.csv, per field."""
import csv, sys, collections, os
HERE = os.path.dirname(os.path.abspath(__file__))
sheet = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "sample_blind.csv")
truth = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "..", "incidents.csv")))}
FIELDS = [("YOUR_LENS (weapon/target/surface)", "lens"), ("YOUR_VECTOR", "vector"), ("YOUR_TYPE (incident/disclosure/threat report)", "type")]
def kappa(pairs):
    n = len(pairs); po = sum(a == b for a, b in pairs) / n
    ca, cb = collections.Counter(a for a, _ in pairs), collections.Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return po, (po - pe) / (1 - pe) if pe < 1 else float("nan")
for col, field in FIELDS:
    pairs = [(r[col].strip().lower(), truth[r["id"]][field].strip().lower()) for r in csv.DictReader(open(sheet)) if r[col].strip()]
    if not pairs: print(f"{field}: no answers filled in"); continue
    po, k = kappa(pairs); print(f"{field}: n={len(pairs)} agreement={100*po:.0f}% kappa={k:.2f}")
