"""Full-benchmark driver for API-served models (Track B): all user tasks, all injection tasks, several
attacks and defences, N parallel workers. Usage:
  LLM_PROVIDER=openai LLM_MODEL=gpt-4.1 LLM_TAG=gpt41 python matrix_full.py <configs> <attacks> <workers> <logdir>
Configs: baseline,spotlight,tool_filter,pi_detector,repeat_user,pep_prov,pep_prov_strict,pep_full
Attacks: important_instructions,important_instructions_obfuscated,tool_knowledge
"""
import subprocess, sys, os, time
from concurrent.futures import ThreadPoolExecutor

SUITES = ["slack", "banking", "travel", "workspace"]
CONFIGS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["baseline", "spotlight", "pep_prov", "pep_full"]
ATTACKS = sys.argv[2].split(",") if len(sys.argv) > 2 else ["important_instructions"]
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 8
LOGDIR = sys.argv[4] if len(sys.argv) > 4 else "runs_full"
PY = sys.executable

jobs = []
for config in CONFIGS:
    for suite in SUITES:
        jobs.append(["--config", config, "--suite", suite, "--mode", "utility"])
        for attack in ATTACKS:
            jobs.append(["--config", config, "--suite", suite, "--mode", "security", "--attack", attack])

def run(job):
    t = time.time()
    r = subprocess.run([PY, "run_bench_b.py", *job, "--logdir", LOGDIR], capture_output=True, text=True)
    tail = (r.stdout.strip().splitlines() or [""])[-1]
    line = f"[{time.strftime('%H:%M:%S')}] {' '.join(job[1::2])} rc={r.returncode} {time.time()-t:.0f}s {tail[:220]}"
    if r.returncode != 0:
        line += "\nSTDERR: " + r.stderr[-1200:]
    print(line, flush=True)

if __name__ == "__main__":
    print(f"{len(jobs)} jobs, {WORKERS} workers, provider={os.environ.get('LLM_PROVIDER','openai-compatible')} model={os.environ.get('LLM_MODEL')}", flush=True)
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(run, jobs))
    print("MATRIX DONE", flush=True)
