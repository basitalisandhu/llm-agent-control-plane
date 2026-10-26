#!/bin/zsh
# Env: PAPER_DIR (working directory holding the runner scripts and .venv).
cd "${PAPER_DIR:?set PAPER_DIR to the working directory that holds the runner scripts}"
./launch_trackb.sh bedrock us.anthropic.claude-sonnet-4-5-20250929-v1:0 sonnet45 baseline,pep_prov,pep_full important_instructions 6
./launch_trackb.sh bedrock us.anthropic.claude-haiku-4-5-20251001-v1:0 haiku45 baseline,spotlight,pep_prov,pep_prov_strict,pep_full important_instructions_obfuscated 6
echo "BEDROCK CHAIN DONE" >> matrix_full_haiku45.log
