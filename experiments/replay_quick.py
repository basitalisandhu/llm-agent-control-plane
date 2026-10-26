"""Quick model-free replay for `make replay`: one suite, both attacks, the released matcher (v2.2).

Replays the benchmark's reference trajectories through the PEP as if a perfectly obedient agent executed
them (the user's ground truth, then the injection's ground truth once the injection has been read), the
procedure of preflight_v22.py, restricted to one suite and two policy variants so that it finishes in well
under two minutes. Each count is checked against the released output in results/replay/preflight_v22.json;
the exit status is non-zero if any differs.

    PYTHONPATH=pep:experiments .venv/bin/python experiments/replay_quick.py [suite] [cfg,cfg,...]

Suites: slack, banking, travel, workspace. Configurations: prov, strict, full, fullstrict.
"""
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.dont_write_bytecode = True
import harness4 as harness  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

suite_name = sys.argv[1] if len(sys.argv) > 1 else "slack"
cfgs = sys.argv[2].split(",") if len(sys.argv) > 2 else ["prov", "full"]
released_path = Path(__file__).resolve().parents[1] / "results" / "replay" / "preflight_v22.json"
released = json.loads(released_path.read_text())
suite = get_suite("v1.2.2", suite_name)
status = 0
for attack_name in ["important_instructions", "important_instructions_obfuscated"]:
    attack = harness.make_attack(suite, attack_name)
    for cfg in cfgs:
        att = tot = uok = utot = 0
        for ut in suite.user_tasks.values():
            u, _, _ = harness.replay(suite, ut, None, cfg, attack)
            utot += 1
            uok += bool(u)
            for it in suite.injection_tasks.values():
                _, s, _ = harness.replay(suite, ut, it, cfg, attack)
                tot += 1
                att += bool(s)
        got = [att, tot, uok, utot]
        expected = released[attack_name][f"{cfg}|{suite_name}"][:4]
        verdict = "matches the released replay" if got == expected else f"DIFFERS from the released replay {expected}"
        status |= int(got != expected)
        print(f"{attack_name:34s} {cfg:10s} {suite_name:9s} attacks {att:3d}/{tot:3d} | benign {uok:2d}/{utot:2d} | {verdict}", flush=True)
sys.exit(status)
