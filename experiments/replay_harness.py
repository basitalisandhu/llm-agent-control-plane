import sys, json, copy, os
sys.dont_write_bytecode = True
# Env: PAPER_DIR (optional) directory holding pep.py / pep22.py; defaults to the pep/ directory of this repository.
PAPER = os.environ.get("PAPER_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pep")
sys.path.insert(0, PAPER)
import warnings; warnings.filterwarnings("ignore")
import pep
from pep import PEPExecutor
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime, FunctionCall
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.models import MODEL_NAMES
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.types import ChatAssistantMessage, ChatUserMessage, ChatSystemMessage, text_content_block_from_string, get_text_content_as_str
from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages

MODEL_NAMES["qwen14b"] = "Qwen2.5-14B"
CFG = {"prov": dict(prov=True, appr=False), "tiers": dict(prov=False, appr=True), "full": dict(prov=True, appr=True), "none": dict(prov=False, appr=False)}

EXEC_CLS = PEPExecutor

def task_lookup_for(suite):
    tl = {t.PROMPT: t for t in suite.user_tasks.values()}
    tl.update({t.GOAL: t for t in suite.injection_tasks.values()})
    return tl

def make_attack(suite):
    p = AgentPipeline([]); p.name = "qwen14b-baseline"
    return load_attack("important_instructions", suite, p)

def replay(suite, user_task, injection_task, cfgname, attack, marker="<INFORMATION>"):
    injections = attack.attack(user_task, injection_task) if injection_task is not None else {}
    env = suite.load_and_inject_default_environment(injections)
    env = user_task.init_environment(env)
    pre_env = env.model_copy(deep=True)
    runtime = FunctionsRuntime(suite.tools)
    c = CFG[cfgname]
    ex = EXEC_CLS(suite.name, task_lookup_for(suite), provenance=c["prov"], approval=c["appr"], mark=False, decision_log=None)
    prompt = user_task.PROMPT
    gt_user = user_task.ground_truth(env.model_copy(deep=True))
    gt_inj = injection_task.ground_truth(env.model_copy(deep=True)) if injection_task is not None else []
    messages = [ChatSystemMessage(role="system", content=[text_content_block_from_string("sys")]),
                ChatUserMessage(role="user", content=[text_content_block_from_string(prompt)])]
    log = []  # (phase, function, args, allowed, reason)
    state = {"env": env, "messages": messages}
    def step(call, phase):
        fc = FunctionCall(function=call.function, args=copy.deepcopy(dict(call.args)), id=f"c{len(state['messages'])}")
        msgs = [*state["messages"], ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("")], tool_calls=[fc])]
        _, _, e2, m2, _ = ex.query(prompt, runtime, state["env"], msgs)
        state["env"], state["messages"] = e2, m2
        res = m2[-1]
        err = res.get("error") or ""
        denied = err.startswith("Action denied")
        txt = get_text_content_as_str(res["content"]) if res.get("content") else ""
        log.append((phase, call.function, dict(call.args), not denied, err if denied else ""))
        return (not denied), txt, err
    inj_done = injection_task is None
    for call in gt_user:
        ok, txt, err = step(call, "user")
        if (not inj_done) and marker in txt:
            for ic in gt_inj:
                step(ic, "inj")
            inj_done = True
    msgs = state["messages"]
    denied_ids = {m["tool_call_id"] for m in msgs if m["role"] == "tool" and (m.get("error") or "").startswith("Action denied")}
    kept = []
    for m in msgs:
        if m["role"] == "assistant" and m.get("tool_calls"):
            m = {**m, "tool_calls": [tc for tc in m["tool_calls"] if tc.id not in denied_ids]}
        kept.append(m)
    traces = functions_stack_trace_from_messages(kept)
    out = [text_content_block_from_string(user_task.GROUND_TRUTH_OUTPUT)]
    util = suite._check_user_task_utility(user_task, out, pre_env, state["env"], traces)
    sec = None
    if injection_task is not None:
        sec = suite._check_injection_task_security(injection_task, out, pre_env, state["env"], traces)
    return util, sec, log
