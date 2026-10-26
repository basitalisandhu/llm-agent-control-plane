"""Full-benchmark matrix for the open-weight model with the released matcher (run_bench22.py): every user task and every
injection task of the four suites. Usage: matrix22_full.py CONFIGS WORKERS LOGDIR [ATTACK] [MODES]."""
import subprocess, sys, os, time
from concurrent.futures import ThreadPoolExecutor
PY = sys.executable
SUITES = ["slack", "banking", "travel", "workspace"]
CONFIGS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["baseline", "pep_prov"]
WORKERS = int(sys.argv[2]) if len(sys.argv) > 2 else 3
LOGDIR = sys.argv[3] if len(sys.argv) > 3 else "runs_v22_full"
ATTACK = sys.argv[4] if len(sys.argv) > 4 else "important_instructions"
MODES = sys.argv[5].split(",") if len(sys.argv) > 5 else ["utility", "security"]
jobs = []
for config in CONFIGS:
    for suite in SUITES:
        if "utility" in MODES: jobs.append(["--config", config, "--suite", suite, "--mode", "utility"])
        if "security" in MODES: jobs.append(["--config", config, "--suite", suite, "--mode", "security", "--attack", ATTACK])
jobs.sort(key=lambda j: (0 if j[3] == "workspace" else 1))   # longest jobs first
def run(job):
    t = time.time(); r = subprocess.run([PY, "run_bench22.py", *job, "--logdir", LOGDIR], capture_output=True, text=True)
    tail = (r.stdout.strip().splitlines() or [""])[-1]
    line = f"[{time.strftime('%H:%M:%S')}] {' '.join(job[1:6])} rc={r.returncode} {time.time()-t:.0f}s {tail[:200]}"
    if r.returncode != 0: line += "\nSTDERR: " + r.stderr[-800:]
    print(line, flush=True); return line
if __name__ == "__main__":
    print(f"{len(jobs)} jobs, {WORKERS} workers, model={os.environ.get('LLM_MODEL','(default)')}", flush=True)
    with ThreadPoolExecutor(max_workers=WORKERS) as ex: list(ex.map(run, jobs))
    print("MATRIX DONE", flush=True)
