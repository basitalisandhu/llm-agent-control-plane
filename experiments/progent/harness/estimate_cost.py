#!/usr/bin/env python
"""Offline cost model for the full Progent x gpt-5-mini run (no network). Uses each suite's ground-truth trajectories
(real tool outputs from the AgentDojo environments) to size the contexts, then applies per-call output-token assumptions.
Everything marked ASSUMPTION is a guess; measure with `summarize.py` after the --smoke run and rescale.
"""
import json, os, sys
os.environ.setdefault("SECAGENT_POLICY_MODEL", "gpt-5-mini")
import tiktoken
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.agent_pipeline.llms.openai_llm import _function_to_openai
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import get_text_content_as_str
import secagent.tool as st
from secagent import apply_secure_tool_wrapper

enc = tiktoken.get_encoding("o200k_base")
T = lambda s: len(enc.encode(s))
PRICE_IN, PRICE_OUT = 0.25e-6, 2.0e-6

# ASSUMPTIONS (low / central / high): output tokens per call (reasoning included) and policy-update rate.
OUT = {"low": dict(agent=200, gen=500, dec=120, upd=500, p_upd=0.25, attack_factor=1.1, cache=0.5),
       "central": dict(agent=400, gen=900, dec=250, upd=900, p_upd=0.40, attack_factor=1.25, cache=0.3),
       "high": dict(agent=900, gen=1800, dec=500, upd=1800, p_upd=0.60, attack_factor=1.5, cache=0.0)}
SYS_GEN, SYS_DEC, SYS_UPD = T(st.get_SYS_PROMPT()), T(st.SYS_PROMPT_UPDATE), T(st.get_SYS_PROMPT_2())
system_prompt_tokens = T(load_system_message(None))
print(f"policy system-prompt tokens: gen={SYS_GEN} decision={SYS_DEC} update={SYS_UPD}; agent system prompt={system_prompt_tokens}\n")

rows = {}
for name in ["slack", "banking", "travel", "workspace"]:
    suite = get_suite("v1.2.2", name)
    st.available_tools.clear()
    for f in suite.tools:
        apply_secure_tool_wrapper(f.run)
    tools_json_tokens = T("TOOLS: " + json.dumps(st.get_available_tools()))
    agent_tools_tokens = T(json.dumps([_function_to_openai(f).copy() if hasattr(_function_to_openai(f), 'copy') else _function_to_openai(f) for f in suite.tools], default=str))
    n_user, n_inj = len(suite.user_tasks), len(suite.injection_tasks)
    runtime = FunctionsRuntime(suite.tools)
    per_task = []
    for uid, ut in suite.user_tasks.items():
        env = ut.init_environment(suite.load_and_inject_default_environment({}))
        _, _, _, msgs, _ = GroundTruthPipeline(ut).query(ut.PROMPT, runtime, env)
        # sequential-tool-call assumption: one agent call per ground-truth tool call + 1 final answer
        base = system_prompt_tokens + agent_tools_tokens + T(ut.PROMPT) + 30
        hist, calls = 0, []
        for m in msgs:
            if m["role"] == "assistant" and m.get("tool_calls"):
                calls.append(("call", [(tc.function, tc.args) for tc in m["tool_calls"]]))
                hist_after_assistant = sum(T(tc.function + json.dumps(tc.args)) for tc in m["tool_calls"]) + 15
                calls[-1] += (hist_after_assistant,)
            elif m["role"] == "tool":
                calls.append(("result", T(get_text_content_as_str(m["content"]) or ""), m["tool_call"]))
        agent_in = []
        cur = base
        n_batches = 0
        res_tokens = []
        for c in calls:
            if c[0] == "call":
                agent_in.append(cur)           # an agent call that produced this tool call
                cur += c[2]
                n_batches += 1
            else:
                cur += c[1] + 10
                res_tokens.append(c[1])
        agent_in.append(cur)                    # final-answer call
        per_task.append(dict(agent_in=agent_in, batches=n_batches, res_tokens=res_tokens, query=T(ut.PROMPT)))
    rows[name] = dict(n_user=n_user, n_inj=n_inj, tools_tokens=tools_json_tokens, agent_tools=agent_tools_tokens, tasks=per_task)
    mean_calls = sum(len(t["agent_in"]) for t in per_task) / n_user
    mean_in = sum(sum(t["agent_in"]) for t in per_task) / n_user
    print(f"{name:10} user_tasks={n_user:3d} injection_tasks={n_inj:3d} tools={len(suite.tools):2d} policy-TOOLS tokens={tools_json_tokens:5d} "
          f"agent-tools tokens={agent_tools_tokens:5d} | GT agent calls/task={mean_calls:4.1f} agent input tokens/task={mean_in:8.0f}")

print()
for scen, o in OUT.items():
    tot = {"agent_in": 0, "agent_out": 0, "pol_in": 0, "pol_out": 0, "runs": 0, "agent_calls": 0, "pol_calls": 0}
    for name, r in rows.items():
        for attack in (False, True):
            n_pairs = r["n_user"] * (r["n_inj"] if attack else 1)
            if attack:
                n_pairs += r["n_inj"]            # injection tasks run once as user tasks (benchmark_suite_with_injections)
            mean = lambda f: sum(f(t) for t in r["tasks"]) / r["n_user"]
            fac = o["attack_factor"] if attack else 1.0
            a_calls = mean(lambda t: len(t["agent_in"])) * fac
            a_in = mean(lambda t: sum(t["agent_in"])) * fac * (1.12 if attack else 1.0)   # +injection text in outputs
            batches = mean(lambda t: t["batches"]) * fac
            q = mean(lambda t: t["query"])
            res = mean(lambda t: sum(t["res_tokens"]))
            gen_in = SYS_GEN + r["tools_tokens"] + q
            dec_in = batches * (SYS_DEC + r["tools_tokens"] + q + 60)
            upd_calls = batches * o["p_upd"]
            upd_in = upd_calls * (SYS_UPD + r["tools_tokens"] + q + 60 + (res / max(1, batches)) + 300)
            tot["agent_in"] += n_pairs * a_in
            tot["agent_out"] += n_pairs * a_calls * o["agent"]
            tot["pol_in"] += n_pairs * (gen_in + dec_in + upd_in)
            tot["pol_out"] += n_pairs * (o["gen"] + batches * o["dec"] + upd_calls * o["upd"])
            tot["runs"] += n_pairs
            tot["agent_calls"] += n_pairs * a_calls
            tot["pol_calls"] += n_pairs * (1 + batches + upd_calls)
    cached = o["cache"]
    cost_in = lambda x: x * (1 - cached) * PRICE_IN + x * cached * 0.025e-6
    agent_cost = cost_in(tot["agent_in"]) + tot["agent_out"] * PRICE_OUT
    pol_cost = cost_in(tot["pol_in"]) + tot["pol_out"] * PRICE_OUT
    print(f"[{scen:7}] runs={tot['runs']:.0f} agent_calls={tot['agent_calls']:.0f} policy_calls={tot['pol_calls']:.0f} | "
          f"agent in={tot['agent_in']/1e6:6.1f}M out={tot['agent_out']/1e6:5.2f}M -> ${agent_cost:6.2f} | "
          f"policy in={tot['pol_in']/1e6:6.1f}M out={tot['pol_out']/1e6:5.2f}M -> ${pol_cost:6.2f} | TOTAL ${agent_cost + pol_cost:6.2f} "
          f"(cache hit assumed {cached:.0%})")
