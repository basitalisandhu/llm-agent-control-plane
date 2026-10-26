#!/bin/zsh
# Env: PAPER_DIR (working directory holding the runner scripts and .venv).
cd "${PAPER_DIR:?set PAPER_DIR to the working directory that holds the runner scripts}"
while ! grep -q "MATRIX EXIT" matrix_full_gpt5mini.log 2>/dev/null; do sleep 120; done
./launch_trackb.sh openai gpt-5.1 gpt51 baseline,pep_prov,pep_full important_instructions 8
echo "OPENAI CHAIN DONE" >> matrix_full_gpt51.log
