#!/bin/zsh
# usage: ./launch_rerun.sh <provider> <model> <tag> <configs> <attacks> <workers> <logname>
# Env: PAPER_DIR (working directory holding the runner scripts and .venv), OPENAI_API_KEY_FILE (file containing the key),
#      AWS_PROFILE (optional, default "default").
cd "${PAPER_DIR:?set PAPER_DIR to the working directory that holds the runner scripts}"
export LLM_PROVIDER=$1 LLM_MODEL=$2 LLM_TAG=$3 OPENAI_API_KEY_FILE="${OPENAI_API_KEY_FILE:?set OPENAI_API_KEY_FILE to a file containing the key}" AWS_PROFILE="${AWS_PROFILE:-default}" AWS_REGION=us-east-1 CAP_OPENAI=120 CAP_BEDROCK=380 COST_LEDGER="$(pwd)/runs_full/cost_ledger.jsonl"
caffeinate -s -i .venv/bin/python matrix_full.py "$4" "$5" "$6" runs_full > "$7" 2>&1
echo "MATRIX EXIT $?" >> "$7"
