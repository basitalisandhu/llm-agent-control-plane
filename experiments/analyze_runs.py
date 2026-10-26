"""Per-run analysis: denied calls, attack goals achieved per suite/config, utility failure categories."""
import json, glob, collections, sys
from pathlib import Path
LOGDIR = Path(sys.argv[1] if len(sys.argv) > 1 else "runs")
CONFIGS = ["baseline", "spotlight", "pep_prov", "pep_full"]
TAG = sys.argv[2] if len(sys.argv) > 2 else "qwen14b"
out = {}
for c in CONFIGS:
    stats = collections.Counter(); per_suite = collections.defaultdict(collections.Counter)
    for f in glob.glob(str(LOGDIR / f"{TAG}-{c}" / "*" / "*" / "*" / "*.json")):
        d = json.load(open(f)); suite = f.split("/")[-4]; attack = f.split("/")[-2]
        msgs = d["messages"]
        denied = [m for m in msgs if m["role"] == "tool" and (m.get("error") or "").startswith("Action denied")]
        calls = sum(len(m.get("tool_calls") or []) for m in msgs if m["role"] == "assistant")
        key = "security" if attack != "none" else "utility"
        stats[f"{key}_cases"] += 1; stats[f"{key}_calls"] += calls; stats[f"{key}_denied"] += len(denied)
        if denied: stats[f"{key}_cases_with_denial"] += 1
        if key == "security":
            if d["security"] is True: stats["attack_success"] += 1; per_suite[suite]["attack_success"] += 1
            per_suite[suite]["cases"] += 1
            if d["utility"]: stats["util_under_attack"] += 1
        else:
            if d["utility"]: stats["util_ok"] += 1
            elif denied: stats["util_fail_with_denial"] += 1
            else: stats["util_fail_no_denial"] += 1
    out[c] = {"stats": dict(stats), "per_suite": {s: dict(v) for s, v in per_suite.items()}}
print(json.dumps(out, indent=1))
