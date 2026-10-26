#!/usr/bin/env python3
"""make_stats.py -- paired and two-way-clustered statistics for the Track B results.

README (methods)
================
Why.  Reviewers asked for (1) a paired test of the utility differences, (2) uncertainty that respects BOTH sources of
dependence in an AgentDojo attack run -- the same user task is attacked with many injection goals and the same goal is tried
on many user tasks -- and (3) a table that shows them.  Everything is computed from the per-case booleans already stored in the
run summaries; no run is repeated and no model or network call is made.

Inputs (read-only).  <logdir>/summaries/*.json, one file per (tag, config, suite, mode, attack), each holding
"utility_results" and "security_results" keyed "user_task_N" (benign) or "user_task_N|injection_task_M" (attack); True = task
solved / attack succeeded.  runs_full = API models on the full benchmark (97 benign tasks; 949 attack cases = every user task
x every injection goal of its suite; 35 goals).  runs_v2 = open-weight subset, tag qwen14b (39 tasks, 78 cases, 8 goals).
Clusters are identified WITHIN a suite: user task = (suite, user_task_N), injection goal = (suite, injection_task_M), because
injection_task_3 of banking and of slack are different goals.  Macro code names (tags, configs) and display names are read
from make_results_b.py by parsing its source with ast; it is never imported (it executes and rewrites its outputs on import).

Outputs.  tex/results_stats.tex (macros) and tex/table_stats.tex (two tables).  Nothing else is written.

1. Paired utility test -- exact McNemar.  A configuration's benign run is compared with the same model's baseline on the same
   tasks.  A task is LOST if the baseline solved it and the configuration did not, GAINED in the opposite case, concordant
   otherwise.  If the configuration did not change any task's pass probability, a discordant task is lost or gained with
   probability 1/2, so lost ~ Binomial(lost + gained, 1/2) and the exact two-sided p-value is min(1, 2 P[X <= min(lost, gained)])
   (McNemar 1947, exact conditional form).  No discordant task: p = 1.  The exact test is conservative for small counts, and
   each arm is a single run, so run-to-run model noise is part of what makes a task discordant.
   Macros: \\mcnLost<Tag><Cfg>, \\mcnGained<Tag><Cfg>, \\mcnP<Tag><Cfg>; open-weight subset (39 tasks): \\mcnLostA<Cfg> etc.

2. Two-way cluster bootstrap for attack success (and utility under attack).  A case (user task u, goal g) belongs to two
   clusters, so cases sharing u or g are not independent: a case-level interval is too narrow, and the one-way interval over user
   tasks in make_results_b.py ignores the dependence through g.  Following the multiway-clustering idea of Cameron, Gelbach and
   Miller (2011, J. Bus. Econ. Stat. 29:238-249) both dimensions are clustered at once: in each of B = 2000 resamples draw the
   n_u user tasks with replacement and, independently, the n_g goals with replacement (numpy PCG64, seed 0); case (u, g) is
   kept with multiplicity m_u * m_g (0 if u or g was not drawn) and the resampled rate is sum(m_u m_g y_ug) / sum(m_u m_g).
   This is the pigeonhole bootstrap of Owen (2007, Ann. Appl. Stat. 1:386-411).  McCullagh (2000, Bernoulli 6:285-301) shows
   that none of the simple row/column resampling schemes is exact for a crossed layout, so --selftest checks calibration by
   simulation (97 x 35 layout, goal effect SD 1.5 on the logit scale, 95% nominal): resampling user tasks only, as the one-way
   interval does, covers the true rate about half of the time; the two-way interval covers it about 0.91-0.94 (rare events
   undercover a little, as percentile intervals tend to).  The 95% interval is the percentile interval: ordered resamples 51 and 1950 of 2000, the
   convention of the one-way intervals in make_results_b.py.  Draws are pooled over suites (not stratified), like that
   one-way bootstrap, so arms with the same clusters share the same resamples.
   Macros: \\asrTwoWay<Tag><Cfg> and \\uaTwoWay<Tag><Cfg> ("rate [lo, hi]", percent); open-weight subset: \\asrTwoWayA<Cfg>.

3. Zero bounds.  With no successful attack the bootstrap interval collapses to [0, 0], so the exact (Clopper-Pearson) one-sided
   97.5% upper bound for zero successes in n units, 1 - 0.025^(1/n), is also given, in percent, with units = cases
   (n = 949), user tasks (n = 97) or injection goals (n = 35).  With clusters as units a unit counts as one trial that
   "succeeds" if any attack in it succeeded, so the bound limits the probability that a random user task or goal is ever
   successfully attacked; the goal bound is the conservative one when the goals are the clusters that matter.  The case bound
   treats cases as independent.  Macros: \\zeroBoundGoals, \\zeroBoundTasks, \\zeroBoundCases (+ A for the subset); "--" if the
   observed rate is not zero.

Completeness policy.  A (tag, config) statistic is emitted only if its arm covers the whole reference grid (all four suites, the
same task/case keys as the union over the arms of that directory); partial or absent arms give "--" macros and
are listed at the foot of results_stats.tex and on stdout; a table row needs both its paired test and its ASR.  Partial arms
are never mixed into full-sample statistics.

Self-check.  After writing, lost/gained lists, utilities and ASR counts are compared with results_b.json and losses.json
(informational: a mismatch means those files are stale relative to the summaries).

Reproducibility.  No clock; seed 0; input digest in the macro header; one process, integer arithmetic only.
Run:  .venv/bin/python make_stats.py [full_logdir [subset_logdir]]   (defaults runs_full, runs_v2)
      .venv/bin/python make_stats.py --selftest    (statistical unit checks; reads and writes no data; a few seconds)
"""
import ast, hashlib, json, math, sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
FULL_DIR = HERE / (ARGS[0] if len(ARGS) > 0 else "runs_full")
SUB_DIR = HERE / (ARGS[1] if len(ARGS) > 1 else "runs_v2")
TEX = HERE / "tex"
SUITES = ["slack", "banking", "travel", "workspace"]
ATTACK = "important_instructions"                       # the default attack
B, SEED = 2000, 0
SUB_TAG, SUB_NAME = "qwen14b", "Qwen2.5-14B"
SUBSET_CFGS = ["baseline", "spotlight", "pep_prov", "pep_full"]
TABLE_CFGS = ["pep_prov", "pep_full"]
EXTRA_TAGCODE = {"gpt4omini": "Gptfourmini", "llama70b": "Llama"}      # tags missing from make_results_b.py's TAGCODE (letters only)
EXTRA_MODELS = {"gpt4omini": "GPT-4o mini", "llama70b": "Llama 3.3 70B"}
SHORT_MODELS = {"Claude Sonnet 4.5": "Sonnet 4.5", "Claude Haiku 4.5": "Haiku 4.5"}   # as table_losses.tex does; keeps Table 1 inside the llncs text width


# ---------------------------------------------------------------- names shared with make_results_b.py
def read_maps(path):
    wanted, out = {"TAGCODE", "CFGCODE", "LABELS", "MODELS"}, {}
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted:
            out[node.targets[0].id] = ast.literal_eval(node.value)
    if wanted - set(out):
        sys.exit(f"cannot read {sorted(wanted - set(out))} from make_results_b.py (needed so the macro names match the existing ones)")
    return out

MAPS = read_maps(HERE / "make_results_b.py")
TAGCODE, CFGCODE, LABELS, MODELS = MAPS["TAGCODE"], MAPS["CFGCODE"], MAPS["LABELS"], MAPS["MODELS"]
DIGITS = dict(zip("0123456789", "zero one two three four five six seven eight nine".split()))

def code_of(tag):
    if tag in TAGCODE: return TAGCODE[tag]
    if tag in EXTRA_TAGCODE: return EXTRA_TAGCODE[tag]
    return "".join(DIGITS.get(ch, ch) for ch in tag if ch.isalnum()).capitalize()

def name_of(tag, S):
    n = MODELS.get(tag) or EXTRA_MODELS.get(tag) or next((d["model"] for k, d in S.items() if k[0] == tag), tag)
    return SHORT_MODELS.get(n, n)


# ---------------------------------------------------------------- loading (one snapshot: other runs are still writing)
def load_summaries(logdir):
    S, h, problems = {}, hashlib.sha256(), []
    for f in sorted((logdir / "summaries").glob("*.json")):
        raw = f.read_bytes()
        try:
            d = json.loads(raw); key = (d["tag"], d["config"], d["suite"], d["mode"], d["attack"] or "none")
        except (ValueError, KeyError) as e:
            problems.append(f"{f.name}: unreadable ({type(e).__name__}); skipped"); continue
        parts = tuple(f.stem.split("__"))
        if parts != key[:len(parts)]: problems.append(f"{f.name}: file name disagrees with its fields {key}")
        if key in S: problems.append(f"{f.name}: duplicate arm {key}; the later file is used")
        S[key] = d; h.update(f.name.encode() + b"\0" + raw)
    return S, {"n": len(S), "sha": h.hexdigest()[:12], "problems": problems}

def reference(S):
    """Union over arms of the task keys / case keys per suite: what a complete arm must cover."""
    ru, rs = defaultdict(set), defaultdict(set)
    for (tag, cfg, suite, mode, att), d in S.items():
        if mode == "utility": ru[suite] |= {k.split("|")[0] for k in d["utility_results"]}
        elif att == ATTACK: rs[suite] |= set(d["security_results"])
    return ru, rs

def sort_key(x):
    suite, task = x
    try: n = int(task.rsplit("_", 1)[1])
    except (IndexError, ValueError): n = 10 ** 9
    return (SUITES.index(suite), n, task)

class Data:
    def __init__(self, logdir):
        self.S, self.info = load_summaries(logdir); self.dir = logdir
        self.ru, self.rs = reference(self.S)
        ok = all(self.ru.get(s) for s in SUITES) and all(self.rs.get(s) for s in SUITES)
        self.ref_u = {(s, t) for s in SUITES for t in self.ru.get(s, ())}
        self.ref_s = {(s, *k.split("|")) for s in SUITES for k in self.rs.get(s, ())}
        self.ref_ok = ok
        self.n_tasks, self.n_cases = len(self.ref_u), len(self.ref_s)
        self.n_goals = len({(s, g) for (s, u, g) in self.ref_s})
        self.tags = sorted({k[0] for k in self.S})

    def util(self, tag, cfg):
        """Benign arm: {'res': {(suite, task): bool}, 'have': suites present, 'complete': bool} or None."""
        res, have = {}, []
        for s in SUITES:
            d = self.S.get((tag, cfg, s, "utility", "none"))
            if d is None: continue
            have.append(s); res.update({(s, k.split("|")[0]): bool(v) for k, v in d["utility_results"].items()})
        return {"res": res, "have": have, "complete": self.ref_ok and set(res) == self.ref_u} if have else None

    def sec(self, tag, cfg):
        """Default-attack arm: {'cases': {(suite, user, goal): (attack_succeeded, user_task_solved)}, ...} or None."""
        cases, have = {}, []
        for s in SUITES:
            d = self.S.get((tag, cfg, s, "security", ATTACK))
            if d is None: continue
            have.append(s)
            for k, v in d["security_results"].items():
                if k not in d["utility_results"]: sys.exit(f"{tag}/{cfg}/{s}: case {k} has no utility_results entry (corrupt summary)")
                u, g = k.split("|"); cases[(s, u, g)] = (bool(v), bool(d["utility_results"][k]))
        return {"cases": cases, "have": have, "complete": self.ref_ok and set(cases) == self.ref_s} if have else None


# ---------------------------------------------------------------- statistics
def mcnemar_exact(lost, gained):
    """Exact two-sided McNemar p as a Fraction: min(1, 2 P[Binomial(n, 1/2) <= min]) on the n = lost + gained discordant tasks."""
    n = lost + gained
    if n == 0: return Fraction(1)
    tail = sum(math.comb(n, i) for i in range(min(lost, gained) + 1))
    return min(Fraction(1), Fraction(tail, 2 ** (n - 1)))

def fmt_p(p, tex=True):
    """'<0.001'; three decimals below 0.1 (resolves values near 0.05); else two.  Exact rounding, half up (no float artefacts)."""
    if p < Fraction(1, 1000): return r"\ensuremath{<}0.001" if tex else "<0.001"   # \ensuremath: "<" in any font encoding, text or math mode
    q = math.floor(p * 1000 + Fraction(1, 2))
    if q < 100: return f"0.{q:03d}"
    q = math.floor(p * 100 + Fraction(1, 2)); return f"{q // 100}.{q % 100:02d}"

def exact_upper(n):
    """Exact one-sided 97.5% upper limit (percent) for zero successes in n units."""
    return 100 * (1 - 0.025 ** (1 / n)) if n else float("nan")

def grid(cases):
    users = sorted({(s, u) for (s, u, g) in cases}, key=sort_key); goals = sorted({(s, g) for (s, u, g) in cases}, key=sort_key)
    ui, gi = {x: i for i, x in enumerate(users)}, {x: i for i, x in enumerate(goals)}
    M = np.zeros((len(users), len(goals)), dtype=np.int64); Ys, Yu = M.copy(), M.copy()
    for (s, u, g), (sec, ua) in cases.items():
        r, c = ui[(s, u)], gi[(s, g)]; M[r, c] = 1; Ys[r, c] = sec; Yu[r, c] = ua
    return len(users), len(goals), M, Ys, Yu

def draw_counts(rng, n, b):
    """b resamples of n clusters drawn with replacement, returned as a (b, n) matrix of multiplicities."""
    idx = rng.integers(0, n, size=(b, n))
    return np.bincount((idx + np.arange(b)[:, None] * n).ravel(), minlength=b * n).reshape(b, n)

def two_way(M, outcomes, b=B, seed=SEED):
    """Pigeonhole (two-way cluster) bootstrap.  Rows of M/outcomes = user tasks, columns = goals; M marks the cases that exist.
    Returns one percentile interval (percent) per outcome matrix, and the number of degenerate resamples that were skipped."""
    rng = np.random.default_rng(seed)
    ru, rg = draw_counts(rng, M.shape[0], b), draw_counts(rng, M.shape[1], b)      # user and goal multiplicities, independent
    den = ((ru @ M) * rg).sum(axis=1); keep = den > 0                              # sum over cases of m_u * m_g
    out = []
    for Y in outcomes:
        r = np.sort(100.0 * ((ru @ Y) * rg).sum(axis=1)[keep] / den[keep]); m = len(r)
        out.append((float(r[int(0.025 * m)]), float(r[int(0.975 * m) - 1])))
    return out, int((~keep).sum())

def asr_stats(arm):
    nu, ng, M, Ys, Yu = grid(arm["cases"])
    n, k, ka = int(M.sum()), int(Ys.sum()), int(Yu.sum())
    ((lo, hi), (ulo, uhi)), skipped = two_way(M, [Ys, Yu])
    r = {"n": n, "k": k, "pct": 100 * k / n, "lo": lo, "hi": hi, "ua_pct": 100 * ka / n, "ua_lo": ulo, "ua_hi": uhi,
         "n_users": nu, "n_goals": ng, "skipped": skipped, "zero": None}
    if k == 0: r["zero"] = {"cases": exact_upper(n), "tasks": exact_upper(nu), "goals": exact_upper(ng)}
    return r

def selftest():
    """Statistical unit checks: exact McNemar vs an independent definition; vectorised vs literal bootstrap; interval calibration."""
    for n in range(41):                                  # (1) p = sum of all outcomes no more likely than the observed one (exact rationals)
        pmf = [Fraction(math.comb(n, k), 2 ** n) for k in range(n + 1)]
        for b in range(n + 1): assert mcnemar_exact(b, n - b) == (sum(q for q in pmf if q <= pmf[b]) if n else 1), (b, n - b)
    print("selftest 1: exact McNemar equals the 'no more likely than observed' definition for all (lost, gained) with n <= 40")
    rng = np.random.default_rng(5); nu, ng, nb = 14, 5, 200                       # (2) keep case (u, g) once per draw of u and per draw of g
    M = (rng.random((nu, ng)) < 0.8).astype(np.int64); Y = M * (rng.random((nu, ng)) < 0.3).astype(np.int64)
    r2 = np.random.default_rng(SEED); iu = r2.integers(0, nu, size=(nb, nu)); ig = r2.integers(0, ng, size=(nb, ng))
    lit = sorted(100.0 * sum(int(Y[u, g]) for u in iu[b] for g in ig[b]) / d for b in range(nb) if (d := sum(int(M[u, g]) for u in iu[b] for g in ig[b])))
    (fast,), skipped = two_way(M, [Y], b=nb); m = len(lit)
    assert not skipped and np.allclose(fast, (lit[int(0.025 * m)], lit[int(0.975 * m) - 1])), (fast, lit[:3])
    print("selftest 2: vectorised two-way bootstrap equals the literal loop over drawn users x drawn goals")
    rng = np.random.default_rng(1); nu, ng, mu0, su, sg, reps, nb = 97, 35, -2.0, 0.8, 1.5, 200, 300       # (3) calibration on a crossed layout
    a, g = rng.normal(0, su, 2_000_000), rng.normal(0, sg, 2_000_000); truth = 100 * float(np.mean(1 / (1 + np.exp(-(mu0 + a + g)))))
    hit, one = 0, 0
    for _ in range(reps):
        P = 1 / (1 + np.exp(-(mu0 + rng.normal(0, su, nu)[:, None] + rng.normal(0, sg, ng)[None, :]))); Yb = (rng.random((nu, ng)) < P).astype(np.int64)
        Mb = np.ones_like(Yb); (lo, hi), = two_way(Mb, [Yb], b=nb)[0]; hit += lo <= truth <= hi
        ru = draw_counts(rng, nu, nb); r1 = np.sort(100.0 * (ru @ Yb).sum(1) / (ru @ Mb).sum(1)); one += r1[int(0.025 * nb)] <= truth <= r1[int(0.975 * nb) - 1]
    print(f"selftest 3: true rate {truth:.1f}%, 95% intervals cover it: user tasks only {one / reps:.2f}, two-way {hit / reps:.2f} ({reps} simulated layouts, {nb} resamples)")
    assert hit / reps >= 0.85 and one / reps <= 0.75

def paired(base, arm):
    lost = sorted(f"{s}:{t}" for (s, t), v in base["res"].items() if v and not arm["res"][(s, t)])
    gained = sorted(f"{s}:{t}" for (s, t), v in base["res"].items() if not v and arm["res"][(s, t)])
    return {"lost": lost, "gained": gained, "p": mcnemar_exact(len(lost), len(gained))}

def util_pct(arm): return 100 * sum(arm["res"].values()) / len(arm["res"])
def f1(x): return f"{x:.1f}"
def ci_text(pct, lo, hi): return f"{pct:.1f} [{lo:.1f}, {hi:.1f}]"


# ---------------------------------------------------------------- analysis of one data directory
def analyse(D, tag, cfgs):
    """Per config: benign utility, paired comparison with the baseline, and attack statistics; None where incomplete."""
    base = D.util(tag, "baseline"); base = base if base and base["complete"] else None
    out = {}
    for cfg in cfgs:
        u, s = D.util(tag, cfg), D.sec(tag, cfg)
        u = u if u and u["complete"] else None; s = s if s and s["complete"] else None
        r = {"util": util_pct(u) if u else None, "util_base": util_pct(base) if base else None, "pair": None, "asr": None}
        if cfg != "baseline" and u and base: r["pair"] = paired(base, u)
        if s: r["asr"] = asr_stats(s)
        out[cfg] = r
    return out

def availability(D, tags, label):
    """Human-readable list of arms that are absent or partial for what the analysis needs."""
    notes = []
    for tag in tags:
        cfgs = sorted({k[1] for k in D.S if k[0] == tag}, key=lambda c: (c != "baseline", c))
        for cfg in cfgs:
            u, s = D.util(tag, cfg), D.sec(tag, cfg)
            un, sn = len(u["have"]) if u else 0, len(s["have"]) if s else 0
            bits = []
            if not (u and u["complete"]): bits.append(f"benign {un}/4 suites" + (" (partial)" if un else " (absent)"))
            if not (s and s["complete"]): bits.append(f"default attack {sn}/4 suites" + (" (partial)" if sn else " (absent)"))
            if bits: notes.append(f"{label} {tag}/{cfg}: " + "; ".join(bits))
        if (tag, "baseline", SUITES[0], "utility", "none") not in D.S and cfgs:
            notes.append(f"{label} {tag}: no baseline benign run, so no paired test for any of its configs")
    return notes


# ---------------------------------------------------------------- main
if "--selftest" in sys.argv: selftest(); sys.exit(0)
FULL, SUB = Data(FULL_DIR), Data(SUB_DIR)
for D, nm in ((FULL, FULL_DIR.name), (SUB, SUB_DIR.name)):
    if not D.ref_ok: sys.exit(f"{nm}: summaries do not cover all four suites; cannot define the reference grid")
tags_all = list(dict.fromkeys(list(TAGCODE) + list(EXTRA_TAGCODE) + FULL.tags))
preferred = ["pep_prov", "pep_full", "pep_prov_strict", "pep_full_nomark", "spotlight", "tool_filter", "repeat_user", "pi_detector", "baseline"]
CFG_ORDER = [c for c in preferred if c in CFGCODE] + [c for c in CFGCODE if c not in preferred]
RES = {tag: analyse(FULL, tag, CFG_ORDER) for tag in tags_all}
SUBRES = analyse(SUB, SUB_TAG, SUBSET_CFGS)

# ---- macros
macros = {}
def put(name, value):
    assert name not in macros, name
    macros[name] = value

def put_mcn(suffix, r):
    pr = r["pair"]
    put(f"mcnLost{suffix}", len(pr["lost"]) if pr else "--"); put(f"mcnGained{suffix}", len(pr["gained"]) if pr else "--"); put(f"mcnP{suffix}", fmt_p(pr["p"]) if pr else "--")

def put_asr(suffix, r):
    a = r["asr"]
    put(f"asrTwoWay{suffix}", ci_text(a["pct"], a["lo"], a["hi"]) if a else "--")
    for unit, key in (("Goals", "goals"), ("Tasks", "tasks"), ("Cases", "cases")):
        put(f"zeroBound{unit}{suffix}", f1(a["zero"][key]) if a and a["zero"] else "--")
    put(f"uaTwoWay{suffix}", ci_text(a["ua_pct"], a["ua_lo"], a["ua_hi"]) if a else "--")

put("statsNBoot", B); put("statsNTasks", FULL.n_tasks); put("statsNCases", FULL.n_cases); put("statsNGoals", FULL.n_goals)
put("statsNTasksA", SUB.n_tasks); put("statsNCasesA", SUB.n_cases); put("statsNGoalsA", SUB.n_goals)
for tag in tags_all:                                                                       # 1. paired utility tests
    for cfg in CFG_ORDER:
        if cfg != "baseline": put_mcn(code_of(tag) + CFGCODE[cfg], RES[tag][cfg])
for tag in tags_all:                                                                       # 2. two-way intervals and zero bounds
    for cfg in CFG_ORDER: put_asr(code_of(tag) + CFGCODE[cfg], RES[tag][cfg])
for cfg in SUBSET_CFGS:                                                                    # open-weight subset ("A")
    if cfg != "baseline": put_mcn("A" + CFGCODE[cfg], SUBRES[cfg])
    put_asr("A" + CFGCODE[cfg], SUBRES[cfg])

notes = availability(FULL, FULL.tags, "full:") + availability(SUB, [SUB_TAG], "subset:")
for tag in ("gpt5mini", "gpt51", "sonnet45", "haiku45"):                                    # configs that were simply never run
    never = [c for c in ("spotlight", "pep_prov_strict", "pep_full_nomark") if not any(k[0] == tag and k[1] == c for k in FULL.S)]
    if never: notes.append(f"full: {tag}: never run: {', '.join(never)}")
for D, nm in ((FULL, FULL_DIR.name), (SUB, SUB_DIR.name)):
    notes += [f"{nm}: {p}" for p in D.info["problems"]]

header = [
    "% auto-generated by make_stats.py -- do not edit.  Methods: README at the top of make_stats.py.",
    f"% inputs: {FULL_DIR.name}/summaries {FULL.info['n']} files sha256:{FULL.info['sha']}; {SUB_DIR.name}/summaries {SUB.info['n']} files sha256:{SUB.info['sha']}",
    f"% two-way cluster bootstrap: {B} resamples, seed {SEED}, numpy {np.__version__}; 95% percentile interval = ordered resamples 51 and 1950",
    f"% full benchmark: {FULL.n_tasks} tasks, {FULL.n_cases} cases, {FULL.n_goals} injection goals (a goal = suite + injection task); open-weight subset: {SUB.n_tasks}, {SUB.n_cases}, {SUB.n_goals}",
    "% code names as in make_results_b.py (TAGCODE, CFGCODE); extra tags: " + ", ".join(f"{t}={c}" for t, c in EXTRA_TAGCODE.items()) + "; subset macros carry an A before the config code",
    "% \\mcnLost/\\mcnGained/\\mcnP: lost = baseline solved and config failed, gained = the reverse, p = exact two-sided McNemar (write $p$ \\mcnP.. in text mode: small p is \\ensuremath{<}0.001); benign tasks, same-model baseline",
    "% \\asrTwoWay: ASR (percent) [95% two-way cluster-bootstrap interval], default attack; \\uaTwoWay: utility under attack, same interval",
    "% \\zeroBoundGoals/Tasks/Cases: exact one-sided 97.5% upper bound (percent) if the observed ASR is zero (units: goals/user tasks/cases), else --",
    "% '--' = arm absent or incomplete (listed at the end of this file); partial arms are never reported",
]
TEX.mkdir(exist_ok=True)
with open(TEX / "results_stats.tex", "w") as f:
    f.write("\n".join(header) + "\n")
    for k, v in macros.items(): f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    f.write("% ---- data availability at generation time\n")
    for n in notes: f.write(f"% {n}\n")

# ---- tables
CAP1 = (r"Paired and clustered statistics for the API models (PEP-full: provenance rule with oracle approval). \emph{Utility}: benign tasks solved (\%) by the model's own baseline and by "
        r"the configuration, over the same @T@ tasks; \emph{lost} and \emph{gained}: tasks solved only by the baseline and only by the "
        r"configuration; $p$: exact two-sided McNemar test on these discordant tasks. \emph{ASR}: attack success (\%) under the default "
        r"attack over @C@ cases, with the 95\% percentile interval (CI) of a two-way cluster bootstrap (user tasks and injection goals "
        r"resampled independently, @B@ resamples). \emph{Bound}: for an observed ASR of zero, where that interval is degenerate, the exact "
        r"one-sided 97.5\% upper limit with the @G@ injection goals as the units.")
CAP2 = (r"The same statistics for the open-weight subset (@M@; @T@ benign tasks, @C@ attack cases, @G@ injection goals). Utility, lost, "
        r"gained and $p$ are relative to the subset baseline; \emph{Bound} uses the @G@ injection goals as units.")
def fill(s, T, C, G, **kw):
    for k, v in {"@T@": T, "@C@": C, "@G@": G, "@B@": B, **{f"@{a}@": b for a, b in kw.items()}}.items(): s = s.replace(k, str(v))
    return s
def bound_cell(a): return r"$\leq$" + f1(a["zero"]["goals"]) if a and a["zero"] else "--"
def asr_cell(a): return ci_text(a["pct"], a["lo"], a["hi"]) if a else "--"
def cells(r):
    pr = r["pair"]; a = r["asr"]
    return [f1(r["util_base"]) if r["util_base"] is not None else "--", f1(r["util"]) if r["util"] is not None else "--",
            str(len(pr["lost"])) if pr else "--", str(len(pr["gained"])) if pr else "--", fmt_p(pr["p"]) if pr else "--", asr_cell(a), bound_cell(a)]

rows1, groups = [], []
for tag in tags_all:
    rr = [(cfg, RES[tag][cfg]) for cfg in TABLE_CFGS if RES[tag][cfg]["pair"] and RES[tag][cfg]["asr"]]   # a row needs the paired test AND the ASR
    if rr: groups.append((tag, rr))
t1 = [r"\begin{table}[t]", r"\centering\footnotesize\setlength{\tabcolsep}{2.5pt}",
      r"\caption{" + fill(CAP1, FULL.n_tasks, FULL.n_cases, FULL.n_goals) + "}", r"\label{tab:stats}",
      r"\begin{tabular}{@{}llccccccc@{}}", r"\toprule",
      r" & & \multicolumn{2}{c}{Utility (\%)} & \multicolumn{3}{c}{Paired vs.\ baseline} & \multicolumn{2}{c}{ASR (\%)} \\",
      r"\cmidrule(lr){3-4}\cmidrule(lr){5-7}\cmidrule(l){8-9}",
      r"Model & Configuration & Base & Config & Lost & Gained & $p$ & 95\% CI & Bound \\", r"\midrule"]
for gi, (tag, rr) in enumerate(groups):
    for i, (cfg, r) in enumerate(rr):
        t1.append((name_of(tag, FULL.S) if i == 0 else "") + " & " + r"\textsc{" + LABELS[cfg].replace(" (oracle)", "") + "} & " + " & ".join(cells(r)) + r" \\")
    if gi < len(groups) - 1: t1.append(r"\midrule")
t1 += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
t2 = [r"\begin{table}[t]", r"\centering\footnotesize\setlength{\tabcolsep}{2.5pt}",
      r"\caption{" + fill(CAP2, SUB.n_tasks, SUB.n_cases, SUB.n_goals, M=SUB_NAME) + "}", r"\label{tab:statsA}",
      r"\begin{tabular}{@{}lcccccc@{}}", r"\toprule",
      r"Configuration & Utility (\%) & Lost & Gained & $p$ & ASR (\%) [95\% CI] & Bound \\", r"\midrule"]
for cfg in SUBSET_CFGS:
    c = cells(SUBRES[cfg]); t2.append(r"\textsc{" + LABELS[cfg].replace(" (oracle)", "") + "} & " + " & ".join(c[1:]) + r" \\")
t2 += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
(TEX / "table_stats.tex").write_text("\n".join(t1) + "\n\n" + "\n".join(t2) + "\n")

# ---- stdout report
print(f"inputs: {FULL_DIR.name} {FULL.info['n']} summaries (sha256 {FULL.info['sha']}): {FULL.n_tasks} tasks / {FULL.n_cases} cases / {FULL.n_goals} goals; "
      f"{SUB_DIR.name} {SUB.info['n']} summaries (sha256 {SUB.info['sha']}): {SUB.n_tasks} / {SUB.n_cases} / {SUB.n_goals}")
def report(label, res, cfgs):
    for cfg in cfgs:
        r = res[cfg]; pr, a = r["pair"], r["asr"]
        if r["util"] is None and not a: continue
        s = f"  {label:9s} {cfg:16s} util {f1(r['util_base']) if r['util_base'] is not None else '--':>5s}->{f1(r['util']) if r['util'] is not None else '--':>5s}"
        s += f"  lost {len(pr['lost']):2d} gained {len(pr['gained']):2d} p={fmt_p(pr['p'], tex=False):>6s}" if pr else " " * 37
        if a: s += f"  ASR {ci_text(a['pct'], a['lo'], a['hi']):18s} k={a['k']:3d}/{a['n']}" + (f"  zero-bound cases/tasks/goals {a['zero']['cases']:.2f}/{a['zero']['tasks']:.1f}/{a['zero']['goals']:.1f}" if a["zero"] else "") + f"  UA {ci_text(a['ua_pct'], a['ua_lo'], a['ua_hi'])}"
        if a and a["skipped"]: s += f"  [{a['skipped']} degenerate resamples skipped]"
        print(s)
for tag in tags_all: report(tag, RES[tag], CFG_ORDER)
report("subset", SUBRES, SUBSET_CFGS)
print("availability notes:"); [print("  " + n) for n in notes]

# ---- self-check against the existing outputs (informational)
mism, compared = [], 0
rb = HERE / "results_b.json"
if rb.exists():
    for tag, dd in json.load(open(rb)).items():
        for row in dd["rows"]:
            mine = RES.get(tag, {}).get(row["config"])
            if not mine: continue
            if mine["pair"] and "lost_vs_baseline" in row:
                compared += 1
                if sorted(row["lost_vs_baseline"]) != mine["pair"]["lost"] or sorted(row["gained_vs_baseline"]) != mine["pair"]["gained"]:
                    mism.append(f"{tag}/{row['config']}: lost/gained differ from results_b.json")
            if mine["util"] is not None and abs(row["util_pct"] - mine["util"]) > 1e-9: mism.append(f"{tag}/{row['config']}: utility {row['util_pct']:.3f} vs {mine['util']:.3f}")
            a = mine["asr"]
            if a and row.get("asr_ii_n"):
                compared += 1
                if (row["asr_ii_k"], row["asr_ii_n"]) != (a["k"], a["n"]) or abs(row["ua_ii_pct"] - a["ua_pct"]) > 1e-9: mism.append(f"{tag}/{row['config']}: ASR counts or utility-under-attack differ from results_b.json")
lj = HERE / "losses.json"
if lj.exists():
    cnt = defaultdict(int)
    for k in json.load(open(lj)): cnt[tuple(k.split("|")[:2])] += 1
    for (tag, cfg), n in sorted(cnt.items()):
        pr = RES.get(tag, {}).get(cfg, {}).get("pair") if tag in RES and cfg in RES[tag] else None
        if pr:
            compared += 1
            if len(pr["lost"]) != n: mism.append(f"{tag}/{cfg}: {len(pr['lost'])} lost here vs {n} in losses.json")
print(f"self-check against results_b.json / losses.json: {compared} comparisons, {len(mism)} mismatches" + ("" if not mism else ":"))
for m in mism: print("  " + m)
print(f"wrote {TEX / 'results_stats.tex'} ({len(macros)} macros) and {TEX / 'table_stats.tex'}")
