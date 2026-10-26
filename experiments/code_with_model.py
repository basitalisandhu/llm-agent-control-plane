"""Blind third coding of the incident dataset by a different model family (OpenAI GPT-5 mini): the model sees the codebook and each
event's id, date, name, notes and source URL, never the labels, and returns type, lens and vector. Writes
data/incidents_coder3.csv into the repository and prints percent agreement and Cohen's kappa against the author's coding.
The API key is read from the file named by OPENAI_API_KEY_FILE into the process only; it is never printed."""
import ast, csv, json, os, re, sys, time, collections
HERE = os.path.dirname(os.path.abspath(__file__)); REPO = os.path.dirname(HERE)
MODEL = os.environ.get("CODER_MODEL", "gpt-5-mini")
keyfile = os.environ.get("OPENAI_API_KEY_FILE") or sys.exit("set OPENAI_API_KEY_FILE to a file containing the key")
m = re.search(r"sk-[A-Za-z0-9_\-]{20,}", open(keyfile).read()); assert m, "no key found in key file"
os.environ["OPENAI_API_KEY"] = m.group(0)
import openai
client = openai.OpenAI()
tree = ast.parse(open(os.path.join(HERE, "make_dataset_tables.py")).read())
CODEBOOK = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "CODEBOOK")
def detex(t): return re.sub(r"\\(?:cbval|cbn|emph|texttt)\{([^}]*)\}", r"\1", t).replace("~", " ")
lines = []
for field, desc, values in CODEBOOK:
    if field not in ("type", "lens", "vector"): continue
    lines.append(f"\n## {field}: {detex(desc)}\nAllowed values (use exactly one, verbatim):")
    for v, d in values: lines.append(f"- {v}: {detex(d)}")
codebook_text = "\n".join(lines)
rows = list(csv.DictReader(open(os.path.join(HERE, "incidents.csv"))))
out, raw = [], {}
for r in rows:
    prompt = (f"You are coding one event of a dataset of AI-security events under the codebook below. Decide the three fields from the event "
              f"description alone; if a field is uncertain, pick the single best value. Reply with a JSON object with keys type, lens, vector.\n{codebook_text}\n\n"
              f"## Event\nid: D-{int(r['id'])}\ndate: {r['date']}\nname: {r['name']}\nnotes: {r['notes']}\nsource: {r['url']}\n")
    for attempt in range(3):
        try:
            resp = client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": prompt}], response_format={"type": "json_object"})
            ans = json.loads(resp.choices[0].message.content); break
        except Exception as e:
            ans = None; time.sleep(3 * (attempt + 1))
    if ans is None: print("no answer for", r["id"], file=sys.stderr); ans = {}
    out.append({"id": r["id"], "type": str(ans.get("type", "")).strip(), "lens": str(ans.get("lens", "")).strip(), "vector": str(ans.get("vector", "")).strip()})
os.makedirs(os.path.join(REPO, "data"), exist_ok=True)
with open(os.path.join(REPO, "data", "incidents_coder3.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["id", "type", "lens", "vector"]); w.writeheader(); w.writerows(out)
norm = {"disclosure": "vulnerability-disclosure", "threat report": "threat-report"}
def kappa(pairs):
    n = len(pairs); po = sum(a == b for a, b in pairs) / n
    ca, cb = collections.Counter(a for a, _ in pairs), collections.Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n); return po, (po - pe) / (1 - pe)
truth = {r["id"]: r for r in rows}; res = {}
for field in ("lens", "vector", "type"):
    pairs = [(norm.get(o[field].lower(), o[field].lower()), norm.get(truth[o["id"]][field].strip().lower(), truth[o["id"]][field].strip().lower())) for o in out if o[field]]
    po, k = kappa(pairs); res[field] = (len(pairs), round(100 * po), round(k, 2))
    print(f"{field}: n={len(pairs)} agreement={100*po:.0f}% kappa={k:.2f}; disagreements: {[o['id'] for o, pr in zip([o for o in out if o[field]], pairs) if pr[0] != pr[1]]}")
json.dump({"model": MODEL, "results": res}, open(os.path.join(REPO, "data", "incidents_coder3_agreement.json"), "w"), indent=1)
with open(os.path.join(HERE, "tex", "results_coder3.tex"), "w") as f:
    for field, (n, po, k) in res.items(): f.write(f"\\newcommand{{\\agreeC{field.capitalize()}}}{{{po}}}\n\\newcommand{{\\kappaC{field.capitalize()}}}{{{k:.2f}}}\n")
    f.write(f"\\newcommand{{\\coderThreeModel}}{{{MODEL}}}\n")
print("wrote data/incidents_coder3.csv, tex/results_coder3.tex")
