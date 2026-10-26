"""Replay with matcher v2.2, write-side labelling ON (A1 remedy): sets PEP_WRITE_LABELS=1 so every PEPExecutor harness4 builds enables write_labels; writes preflight_v23.json."""
import sys, json, warnings; warnings.filterwarnings("ignore")
sys.dont_write_bytecode = True
import os
os.environ["PEP_WRITE_LABELS"] = "1"  # enable optional write-side labelling for every executor harness4 constructs
import harness4 as harness
from agentdojo.task_suite.load_suites import get_suite
out = {}
for attack_name in ["important_instructions", "important_instructions_obfuscated"]:
    out[attack_name] = {}
    for cfg in ["prov", "strict", "full", "fullstrict"]:
        for suite_name in ["slack", "banking", "travel", "workspace"]:
            suite = get_suite("v1.2.2", suite_name); attack = harness.make_attack(suite, attack_name)
            att = tot = 0; uok = utot = 0; lost = []; succ = []
            for ut in suite.user_tasks.values():
                u, _, _ = harness.replay(suite, ut, None, cfg, attack); utot += 1; uok += bool(u)
                if not u: lost.append(ut.ID)
                for it in suite.injection_tasks.values():
                    u2, s, _ = harness.replay(suite, ut, it, cfg, attack); tot += 1; att += bool(s)
                    if s: succ.append(f"{ut.ID}|{it.ID}")
            out[attack_name][f"{cfg}|{suite_name}"] = [att, tot, uok, utot, lost, succ]
            print(f"{attack_name[:22]:22s} {cfg:10s} {suite_name:9s} attacks {att:3d}/{tot:3d} | benign {uok:2d}/{utot:2d} | lost {lost}", flush=True)
    for cfg in ["prov", "strict", "full", "fullstrict"]:
        a = sum(v[0] for k, v in out[attack_name].items() if k.startswith(cfg + "|")); t = sum(v[1] for k, v in out[attack_name].items() if k.startswith(cfg + "|"))
        u = sum(v[2] for k, v in out[attack_name].items() if k.startswith(cfg + "|")); ut = sum(v[3] for k, v in out[attack_name].items() if k.startswith(cfg + "|"))
        print(f"TOTAL v23 {attack_name} {cfg}: attacks {a}/{t} ({a/t*100:.1f}%) benign {u}/{ut}", flush=True)
json.dump(out, open("preflight_v23.json", "w"), indent=1); print("V23 DONE (write_labels ON)")
