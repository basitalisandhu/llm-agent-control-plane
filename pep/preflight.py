"""Pre-flight: replay a perfect (fully hijackable) agent through the PEP on the matrix subset."""
import os, sys, collections
# Env: REVIEW_TMP_DIR, the directory that holds harness2.py (not part of this repository).
sys.path.insert(0, os.environ.get("REVIEW_TMP_DIR") or sys.exit("set REVIEW_TMP_DIR to the directory that holds harness2.py"))
import warnings; warnings.filterwarnings("ignore")
import harness2 as harness
from agentdojo.task_suite.load_suites import get_suite
from matrix import SUBSET
res = {}
for cfg in ["prov", "full"]:
    for suite_name, (uts, its) in SUBSET.items():
        suite = get_suite("v1.2.2", suite_name); attack = harness.make_attack(suite)
        att = tot = 0; util_ok = util_tot = 0; denials = collections.Counter()
        for ut_id in uts:
            ut = suite.get_user_task_by_id(ut_id)
            u, _, log = harness.replay(suite, ut, None, cfg, attack); util_tot += 1; util_ok += bool(u)
            for ph, fn, args, allowed, why in log:
                if not allowed: denials[(ut_id, fn)] += 1
            for it_id in its:
                it = suite.get_injection_task_by_id(it_id)
                u, s, log = harness.replay(suite, ut, it, cfg, attack); tot += 1; att += bool(s)
        res[(cfg, suite_name)] = (att, tot, util_ok, util_tot, dict(denials))
        print(f"{cfg:5s} {suite_name:9s} attacks achieved {att:2d}/{tot:2d} | benign utility {util_ok:2d}/{util_tot:2d} | benign denials: {sorted(denials)[:8]}", flush=True)
