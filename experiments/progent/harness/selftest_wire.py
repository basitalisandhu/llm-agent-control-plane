#!/usr/bin/env python
"""Captures the REAL HTTP request bodies the openai SDK would send (httpx.MockTransport, no network) for
(a) one AgentDojo agent turn and (b) the three Progent policy calls, with gpt-5-mini. Confirms: no `temperature`,
`developer` role for the agent system prompt, `seed` only on policy calls, tools sent only on agent calls."""
import json, os, sys
os.environ["SECAGENT_POLICY_MODEL"] = "gpt-5-mini"
import httpx, openai

BODIES = []


def handler(request: httpx.Request) -> httpx.Response:
    BODIES.append((request.url.path, json.loads(request.content)))
    return httpx.Response(200, json={
        "id": "x", "object": "chat.completion", "created": 0, "model": "gpt-5-mini",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "No"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}})


real = openai.OpenAI


def mk(*a, **k):
    return real(api_key="sk-test", http_client=httpx.Client(transport=httpx.MockTransport(handler)))


openai.OpenAI = mk
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatSystemMessage, ChatUserMessage, text_content_block_from_string as tb
import secagent.tool as st

suite = get_suite("v1.2.2", "banking")
llm = OpenAILLM(mk(), "gpt-5-mini")
msgs = [ChatSystemMessage(role="system", content=[tb("sys")]), ChatUserMessage(role="user", content=[tb("hi")])]
llm.query("hi", FunctionsRuntime(suite.tools), messages=msgs)
agent_path, agent_body = BODIES[-1]

st.update_available_tools([{"name": "get_balance", "description": "d", "args": {}}])
st.init_user_query = "q"
st.api_request(st.get_SYS_PROMPT(), "TOOLS: []\nUSER_QUERY: q", 0.0)
gen_body = BODIES[-1][1]
st.api_request(st.SYS_PROMPT_UPDATE, "x", 0.2)
dec_body = BODIES[-1][1]
st.api_request(st.get_SYS_PROMPT_2(), "x", 0.4)
upd_body = BODIES[-1][1]

print("agent  :", agent_path, "keys=", sorted(agent_body), "| first role =", agent_body["messages"][0]["role"], "| n_tools =", len(agent_body["tools"]))
for name, b in (("policy-gen", gen_body), ("decision", dec_body), ("update", upd_body)):
    print(f"{name:11}: keys=", sorted(b), "| roles =", [m["role"] for m in b["messages"]], "| seed =", b.get("seed"))
assert all("temperature" not in b for b in (agent_body, gen_body, dec_body, upd_body))
assert agent_body["messages"][0]["role"] == "developer" and "tools" in agent_body and "seed" not in agent_body
assert gen_body["seed"] == 0 and "tools" not in gen_body and gen_body["model"] == "gpt-5-mini"
assert "```json" in gen_body["messages"][0]["content"] and "```json" in upd_body["messages"][0]["content"]
print("WIRE CHECK PASSED (no temperature anywhere; gpt-5 output-format suffix present)")
