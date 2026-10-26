#!/usr/bin/env bash
# Progent (sunblaze-ucb/progent `secagent`) on pristine AgentDojo 0.1.35, benchmark v1.2.2, agent + policy model gpt-5-mini.
# Full matrix: {slack, banking, travel, workspace} x {benign utility, important_instructions security}.
#
#   OPENAI_API_KEY=sk-... ./run_progent.sh [--workers 4] [options]
#
# Options (all optional):
#   --workers N              concurrent worker processes (default 4; each process = one suite/mode/shard job)
#   --model M                agent model, OpenAI chat-completions name (default gpt-5-mini)
#   --policy-model M         Progent policy generation/update model (default: same as --model)
#   --suites "a b"           default "slack banking travel workspace"
#   --modes "benign attack"  default both
#   --attack-shards S        user-task shards per suite for the attack runs, default "workspace=4,banking=2,travel=2,slack=2"
#   --paper-protocol         drop travel injection_task_2/6 like the Progent authors (default: full v1.2.2 = 949 attack pairs)
#   --reasoning-effort E     minimal|low|medium|high for the agent (default: API default)
#   --attack-model-name N    prose model name inside the attack string (default "GPT-5"; env PROGENT_ATTACK_MODEL_NAME)
#   --logroot DIR            default <this dir>/runs   (AgentDojo logs: DIR/agentdojo, side logs: DIR/aux, job logs: DIR/logs)
#   --retries N              attempts per job before giving up (default 3; finished tasks are skipped on every retry)
#   --force-rerun            re-run tasks that already have a log
#   --smoke                  1 benign + 1 attack task on slack into DIR-smoke (a few cents) and exit
#   --skip-preflight         skip the free models.retrieve() key/model check at start
#   --dry-run                print the job list and exit (no key needed)
#
# Safe to re-run: AgentDojo skips every (user task, injection task) that already has a complete log.
# Only the API key's *presence* is checked; it is never printed or written.
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/.venv/bin/python"
HARNESS="$HERE/harness/progent_agentdojo.py"

PREFLIGHT=1; WORKERS=4; MODEL="gpt-5-mini"; POLICY_MODEL=""; SUITES="slack banking travel workspace"; MODES="benign attack"
ATTACK="important_instructions"; BENCH="v1.2.2"; LOGROOT="$HERE/runs"; RETRIES=3
SHARDS="workspace=4,banking=2,travel=2,slack=2"; EXTRA=""; SMOKE=0; DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --workers|-j) WORKERS="$2"; shift 2;;
    --model) MODEL="$2"; shift 2;;
    --policy-model) POLICY_MODEL="$2"; shift 2;;
    --suites) SUITES="$2"; shift 2;;
    --modes) MODES="$2"; shift 2;;
    --attack-shards) SHARDS="$2"; shift 2;;
    --paper-protocol) EXTRA="$EXTRA --paper-protocol"; shift;;
    --reasoning-effort) EXTRA="$EXTRA --reasoning-effort $2"; shift 2;;
    --attack-model-name) EXTRA="$EXTRA --attack-model-name $2"; shift 2;;
    --no-injection-task-utility) EXTRA="$EXTRA --no-injection-task-utility"; shift;;
    --logroot) LOGROOT="$2"; shift 2;;
    --retries) RETRIES="$2"; shift 2;;
    --force-rerun) EXTRA="$EXTRA --force-rerun"; shift;;
    --smoke) SMOKE=1; shift;;
    --skip-preflight) PREFLIGHT=0; shift;;
    --dry-run) DRY=1; shift;;
    -h|--help) sed -n '2,28p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
[ -n "$POLICY_MODEL" ] || POLICY_MODEL="$MODEL"
[ "$SMOKE" = 1 ] && LOGROOT="${LOGROOT}-smoke"

if [ "$DRY" = 0 ] && [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "OPENAI_API_KEY is not set in the environment (run: OPENAI_API_KEY=... $0)" >&2; exit 2
fi
[ -x "$PY" ] || { echo "missing venv python: $PY" >&2; exit 2; }

LOGDIR="$LOGROOT/agentdojo"; AUXDIR="$LOGROOT/aux"; JOBLOGS="$LOGROOT/logs"
export PYTHONUNBUFFERED=1 PYTHONWARNINGS=ignore::SyntaxWarning
export PY HARNESS JOBLOGS RETRIES
export COMMON="--model $MODEL --policy-model $POLICY_MODEL --benchmark-version $BENCH --attack $ATTACK --logdir $LOGDIR --auxdir $AUXDIR$EXTRA"

shards_for() {  # suite -> shard count from --attack-shards
  local kv; for kv in $(echo "$SHARDS" | tr ',' ' '); do [ "${kv%%=*}" = "$1" ] && { echo "${kv#*=}"; return; }; done; echo 1
}

run_job() {  # args: suite mode shard(i/n) [extra harness args...]
  local suite="$1" mode="$2" shard="$3"; shift 3
  local tag="${suite}-${mode}-shard${shard/\//of}" attempt rc
  for attempt in $(seq 1 "$RETRIES"); do
    echo "[$(date +%H:%M:%S)] START $tag (attempt $attempt)" | tee -a "$JOBLOGS/$tag.log"
    "$PY" "$HARNESS" --suite "$suite" --mode "$mode" --shard "$shard" $COMMON "$@" >>"$JOBLOGS/$tag.log" 2>&1; rc=$?
    if [ "$rc" = 0 ]; then echo "[$(date +%H:%M:%S)] OK    $tag"; return 0; fi
    echo "[$(date +%H:%M:%S)] FAIL  $tag rc=$rc (attempt $attempt/$RETRIES; see $JOBLOGS/$tag.log)"; sleep 30
  done
  echo "$tag" >> "$JOBLOGS/FAILED"; return 1
}
export -f run_job

tripwires() {  # Progent swallows policy-UPDATE failures (SECAGENT_IGNORE_UPDATE_ERROR=True): count them so they are not silent
  local upd json; upd=$(cat "$JOBLOGS"/*.log 2>/dev/null | grep -c "Ignore the update error"); json=$(cat "$JOBLOGS"/*.log 2>/dev/null | grep -c "Error decoding JSON")
  echo "tripwires: ignored policy-update failures=$upd, unparsable policy-LLM JSON (retried)=$json  (large numbers => inspect $JOBLOGS)"
}

# ---- job list: biggest first so the workers stay busy ----
JOBS=()
for mode in $MODES; do
  if [ "$mode" = attack ]; then
    for suite in workspace banking travel slack; do
      case " $SUITES " in *" $suite "*) n=$(shards_for "$suite"); for ((i=0; i<n; i++)); do JOBS+=("$suite attack $i/$n"); done;; esac
    done
  fi
done
for mode in $MODES; do
  if [ "$mode" = benign ]; then
    for suite in workspace travel slack banking; do
      case " $SUITES " in *" $suite "*) JOBS+=("$suite benign 0/1");; esac
    done
  fi
done

echo "agent=$MODEL policy=$POLICY_MODEL benchmark=$BENCH attack=$ATTACK workers=$WORKERS jobs=${#JOBS[@]} logs=$LOGROOT"
if [ "$DRY" = 1 ]; then printf '  %s\n' "${JOBS[@]}"; echo "per-job command: $PY $HARNESS --suite S --mode M --shard i/n $COMMON"; exit 0; fi

mkdir -p "$LOGDIR" "$AUXDIR" "$JOBLOGS"

if [ "$PREFLIGHT" = 1 ]; then  # free call (no tokens): validates the key and access to both models; prints only the error class
  PF_MODELS="$MODEL $POLICY_MODEL" "$PY" - <<'PFEOF' || { echo "preflight failed (key rejected / model not accessible); fix and re-run, or --skip-preflight" >&2; exit 3; }
import os, sys, openai
c = openai.OpenAI()
for m in dict.fromkeys(os.environ["PF_MODELS"].split()):
    try:
        c.models.retrieve(m)
    except Exception as e:
        print(f"preflight: {type(e).__name__} status={getattr(e, 'status_code', None)} model={m}", file=sys.stderr); sys.exit(1)
print("preflight ok:", os.environ["PF_MODELS"])
PFEOF
fi

if [ "$SMOKE" = 1 ]; then
  rm -f "$JOBLOGS/FAILED"
  run_job slack benign 0/1 --user-task user_task_0 && run_job slack attack 0/1 --user-task user_task_0 --injection-task injection_task_1
  "$PY" "$HERE/harness/summarize.py" --logdir "$LOGDIR" --auxdir "$AUXDIR" --pipeline "$MODEL-progent"; rc=$?
  tripwires; exit $rc
fi

rm -f "$JOBLOGS/FAILED"
printf '%s\n' "${JOBS[@]}" | xargs -P "$WORKERS" -I{} bash -c 'run_job {}'
"$PY" "$HERE/harness/summarize.py" --logdir "$LOGDIR" --auxdir "$AUXDIR" --pipeline "$MODEL-progent"
tripwires
if [ -s "$JOBLOGS/FAILED" ]; then echo "FAILED JOBS (re-run this script to resume):"; cat "$JOBLOGS/FAILED"; exit 1; fi
echo "ALL JOBS FINISHED"
