"""Agreement between a blind tool-tiering sheet and the author's tables (data/tier_annotation/author_tables.json).
Reports, per suite and overall: Cohen's kappa on the consequential/regular split, and for the tools both sides call
consequential, the share of key-argument sets that match exactly, with the disagreeing tools listed.
Run: python3 score.py tools_blind.csv   (after the YOUR_* columns are filled; keep suite and tool unchanged)."""
import csv, json, os, sys, collections
HERE = os.path.dirname(os.path.abspath(__file__))
sheet = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "tools_blind.csv")
A = json.load(open(os.path.join(HERE, "author_tables.json")))
cons = {(s, t) for s, ts in A["consequential"].items() for t in ts}
def norm(v): return sorted(x.strip() for x in v.replace(";", ",").split(",") if x.strip() and x.strip() != "-")
pairs, keyhits, keymiss = [], 0, []
for r in csv.DictReader(open(sheet)):
    yours = r["YOUR_CONSEQUENTIAL (yes/no)"].strip().lower()
    if yours not in ("yes", "no"): continue
    mine = "yes" if (r["suite"], r["tool"]) in cons else "no"
    pairs.append((yours, mine, r["suite"]))
    if yours == "yes" and mine == "yes":
        ya = norm(r["YOUR_KEY_ARGS (comma-separated parameter names, or -)"]); ma = sorted(A["key_args"].get(r["tool"], []))
        if ya == ma: keyhits += 1
        else: keymiss.append((r["suite"], r["tool"], ya, ma))
def kappa(p):
    n = len(p); po = sum(a == b for a, b, _ in p) / n
    ca, cb = collections.Counter(a for a, _, _ in p), collections.Counter(b for _, b, _ in p)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return po, (po - pe) / (1 - pe) if pe < 1 else float("nan")
if not pairs: sys.exit("no YOUR_CONSEQUENTIAL answers filled in")
for s in ["slack", "banking", "travel", "workspace", "all"]:
    p = [x for x in pairs if s == "all" or x[2] == s]
    if p: po, k = kappa(p); print(f"{s:10s} consequential/regular: n={len(p)} agreement={100*po:.0f}% kappa={k:.2f}")
both = keyhits + len(keymiss)
print(f"key arguments: {keyhits} of {both} consequential tools match exactly" if both else "key arguments: no tool called consequential by both")
for s, t, ya, ma in keymiss: print(f"  {s}/{t}: yours={ya} author={ma}")
