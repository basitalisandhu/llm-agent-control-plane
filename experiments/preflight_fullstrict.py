import sys, json, warnings; warnings.filterwarnings("ignore")
sys.dont_write_bytecode = True
import harness3 as harness
from agentdojo.task_suite.load_suites import get_suite
out = {}
for attack_name in ["important_instructions", "important_instructions_obfuscated"]:
    out[attack_name] = {}
    for suite_name in ["slack", "banking", "travel", "workspace"]:
        suite = get_suite("v1.2.2", suite_name); attack = harness.make_attack(suite, attack_name)
        att = tot = 0; uok = utot = 0; lost = []; succ = []
        for ut in suite.user_tasks.values():
            u, _, _ = harness.replay(suite, ut, None, "fullstrict", attack); utot += 1; uok += bool(u)
            if not u: lost.append(ut.ID)
            for it in suite.injection_tasks.values():
                u2, s, _ = harness.replay(suite, ut, it, "fullstrict", attack); tot += 1; att += bool(s)
                if s: succ.append(f"{ut.ID}|{it.ID}")
        out[attack_name][f"fullstrict|{suite_name}"] = [att, tot, uok, utot, lost, succ]
        print(f"{attack_name[:22]:22s} fullstrict {suite_name:9s} attacks {att:3d}/{tot:3d} | benign {uok:2d}/{utot:2d} | lost {lost}", flush=True)
json.dump(out, open("preflight_fullstrict.json", "w"), indent=1); print("DONE")
