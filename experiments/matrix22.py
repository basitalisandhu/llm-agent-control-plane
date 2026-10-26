"""Builds the job list for the experiment matrix and runs it with N parallel workers."""
import subprocess, sys, os, time, json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

PY = sys.executable  # the venv interpreter running this script (resolve() would follow the symlink out of the venv)
SUBSET = {  # stratified fixed subset: even-numbered user tasks (workspace: every fourth); first two injection tasks
    "slack": ([f"user_task_{i}" for i in range(0, 21, 2)], ["injection_task_1", "injection_task_2"]),
    "banking": ([f"user_task_{i}" for i in range(0, 16, 2)], ["injection_task_0", "injection_task_1"]),
    "travel": ([f"user_task_{i}" for i in range(0, 20, 2)], ["injection_task_0", "injection_task_1"]),
    "workspace": ([f"user_task_{i}" for i in range(0, 40, 4)], ["injection_task_0", "injection_task_1"]),
}
CONFIGS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["baseline", "pep_prov", "spotlight", "pep_full"]
WORKERS = int(sys.argv[2]) if len(sys.argv) > 2 else 1
LOGDIR = sys.argv[3] if len(sys.argv) > 3 else "runs_v2"
ATTACK = sys.argv[4] if len(sys.argv) > 4 else "important_instructions"
MODES = sys.argv[5].split(",") if len(sys.argv) > 5 else ["utility", "security"]

jobs = []
if __name__ == "__main__":
  for config in CONFIGS:
    for suite, (ut, it) in SUBSET.items():
        if "utility" in MODES: jobs.append(["--config", config, "--suite", suite, "--mode", "utility", "--user-tasks", ",".join(ut)])
        if "security" in MODES: jobs.append(["--config", config, "--suite", suite, "--mode", "security", "--user-tasks", ",".join(ut), "--injection-tasks", ",".join(it), "--attack", ATTACK])

def run(job):
    t = time.time()
    cmd = [PY, "run_bench22.py", *job, "--logdir", LOGDIR]
    r = subprocess.run(cmd, capture_output=True, text=True)
    tail = (r.stdout.strip().splitlines() or [""])[-1]
    line = f"[{time.strftime('%H:%M:%S')}] {' '.join(job[1:6])} rc={r.returncode} {time.time()-t:.0f}s {tail[:200]}"
    if r.returncode != 0:
        line += "\nSTDERR: " + r.stderr[-800:]
    print(line, flush=True)
    return line

if __name__ == "__main__":
    print(f"{len(jobs)} jobs, {WORKERS} workers, model={os.environ.get('LLM_MODEL','(default)')}", flush=True)
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(run, jobs))
    print("MATRIX DONE", flush=True)
