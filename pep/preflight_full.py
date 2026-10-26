"""Model-free replay of a perfectly obedient agent on the FULL benchmark (all user x injection tasks)."""
import os, sys, collections, json
# Env: REVIEW_TMP_DIR, the directory that holds harness2.py (not part of this repository).
sys.path.insert(0, os.environ.get("REVIEW_TMP_DIR") or sys.exit("set REVIEW_TMP_DIR to the directory that holds harness2.py"))
import warnings; warnings.filterwarnings("ignore")
import harness2 as harness
from agentdojo.task_suite.load_suites import get_suite
out = {}
for cfg in ["none", "prov", "full"]:
    for suite_name in ["slack", "banking", "travel", "workspace"]:
        suite = get_suite("v1.2.2", suite_name); attack = harness.make_attack(suite)
        att = tot = 0; uok = utot = 0; lost = []
        for ut in suite.user_tasks.values():
            u, _, log = harness.replay(suite, ut, None, cfg, attack); utot += 1; uok += bool(u)
            if not u and any(not a for _, _, _, a, _ in log): lost.append(ut.ID)
            for it in suite.injection_tasks.values():
                u2, s, _ = harness.replay(suite, ut, it, cfg, attack); tot += 1; att += bool(s)
        out[(cfg, suite_name)] = (att, tot, uok, utot, lost)
        print(f"{cfg:5s} {suite_name:9s} attacks {att:3d}/{tot:3d} | benign {uok:2d}/{utot:2d} | lost-with-denial {lost}", flush=True)
json.dump({f"{k[0]}|{k[1]}": v for k, v in out.items()}, open("preflight_full.json", "w"), indent=1)
for cfg in ["none", "prov", "full"]:
    a = sum(out[(cfg, s)][0] for s in ["slack","banking","travel","workspace"]); t = sum(out[(cfg, s)][1] for s in ["slack","banking","travel","workspace"])
    u = sum(out[(cfg, s)][2] for s in ["slack","banking","travel","workspace"]); ut = sum(out[(cfg, s)][3] for s in ["slack","banking","travel","workspace"])
    print(f"TOTAL {cfg}: attacks {a}/{t} ({a/t*100:.1f}%) benign {u}/{ut}")
