#!/bin/zsh
# Env: PAPER_DIR (working directory holding the runner scripts and .venv).
cd "${PAPER_DIR:?set PAPER_DIR to the working directory that holds the runner scripts}"
caffeinate -s -i .venv/bin/python matrix22.py baseline,pep_prov,pep_prov_strict 3 runs_v2_obf important_instructions_obfuscated security > matrix_local_obf.log 2>&1
caffeinate -s -i .venv/bin/python matrix22.py pep_prov_strict 3 runs_v2_obf important_instructions utility >> matrix_local_obf.log 2>&1
echo "LOCAL OBF DONE" >> matrix_local_obf.log
