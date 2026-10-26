#!/bin/zsh
# Live runs of the adaptive families on GPT-4o mini (the cheapest model the attack works on), matcher v2.2.
# laundering on banking (the 8 goals with a write/read-back pair), three arms: baseline, PEP-prov, PEP-prov + write labels;
# evasion_zerowidth on slack (all 105 pairs), two arms: baseline, PEP-prov.  Separate log dirs so the two PEP-prov arms do not collide.
cd "$(dirname "$0")"
export LLM_PROVIDER=openai LLM_MODEL=gpt-4o-mini LLM_TAG=gpt4omini OPENAI_API_KEY_FILE="${OPENAI_API_KEY_FILE:-$HOME/.openai_key}" CAP_OPENAI=120 CAP_BEDROCK=380 COST_LEDGER="$(pwd)/runs_full/cost_ledger.jsonl" PEP_VERSION=22
LAUND="injection_task_0,injection_task_1,injection_task_2,injection_task_3,injection_task_4,injection_task_5,injection_task_6,injection_task_8"
run() { # name config suite attack logdir extra-args...
  local name=$1; shift
  nohup .venv/bin/python run_bench_b.py --config "$1" --suite "$2" --mode security --attack "$3" --logdir "$4" "${@:5}" > "adaptive_live_${name}.log" 2>&1 &
}
run laund_base     baseline banking laundering runs_adaptive --injection-tasks "$LAUND"
run laund_prov     pep_prov banking laundering runs_adaptive --injection-tasks "$LAUND"
PEP_WRITE_LABELS=1 run laund_prov_wl pep_prov banking laundering runs_adaptive_wl --injection-tasks "$LAUND"
run zw_base        baseline slack evasion_zerowidth runs_adaptive
run zw_prov        pep_prov slack evasion_zerowidth runs_adaptive
wait
echo "ADAPTIVE LIVE DONE"
