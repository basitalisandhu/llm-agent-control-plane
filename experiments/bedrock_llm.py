"""Bedrock adapters: Claude via AnthropicBedrock (same Messages API as AgentDojo's AnthropicLLM) and
any Bedrock chat model via the Converse API with tool use (Llama 3.3 70B, Nova, etc.)."""
from __future__ import annotations
import cost_ledger
import json, os, time
from collections.abc import Sequence
import boto3
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, get_text_content_as_str, text_content_block_from_string


def claude_bedrock_llm(model_id: str, region: str | None = None):
    """AgentDojo's AnthropicLLM accepts any client with the Anthropic Messages interface."""
    from anthropic import AnthropicBedrock
    from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
    client = AnthropicBedrock(aws_region=region or os.environ.get("AWS_REGION", "us-east-1"))
    return AnthropicLLM(client, model_id, temperature=0.0)


class ConverseLLM(BasePipelineElement):
    """Bedrock Converse API with tool use (for Llama / Nova / Mistral on Bedrock)."""

    def __init__(self, model_id: str, region: str | None = None, max_tokens: int = 2048) -> None:
        self.model_id = model_id; self.max_tokens = max_tokens
        self.client = boto3.client("bedrock-runtime", region_name=region or os.environ.get("AWS_REGION", "us-east-1"))
        self.name = model_id

    @staticmethod
    def _tool_spec(tool):
        schema = tool.parameters.model_json_schema()
        return {"toolSpec": {"name": tool.name, "description": (tool.description or "")[:1000], "inputSchema": {"json": schema}}}

    def _to_converse(self, messages: Sequence[ChatMessage]):
        system, out = [], []
        for m in messages:
            if m["role"] == "system":
                system.append({"text": get_text_content_as_str(m["content"])})
            elif m["role"] == "user":
                out.append({"role": "user", "content": [{"text": get_text_content_as_str(m["content"])}]})
            elif m["role"] == "assistant":
                content = []
                txt = get_text_content_as_str(m["content"]) if m.get("content") else ""
                if txt: content.append({"text": txt})
                for tc in (m.get("tool_calls") or []):
                    content.append({"toolUse": {"toolUseId": tc.id, "name": tc.function, "input": dict(tc.args)}})
                out.append({"role": "assistant", "content": content or [{"text": "."}]})
            elif m["role"] == "tool":
                body = m.get("error") or get_text_content_as_str(m["content"]) or ""
                block = {"toolResult": {"toolUseId": m["tool_call_id"], "content": [{"text": body[:60000]}],
                                        "status": "error" if m.get("error") else "success"}}
                if out and out[-1]["role"] == "user":
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return system, out

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        system, conv = self._to_converse(messages)
        tools = [self._tool_spec(t) for t in runtime.functions.values()]
        kwargs = dict(modelId=self.model_id, messages=conv, inferenceConfig={"temperature": 0.0, "maxTokens": self.max_tokens})
        if system: kwargs["system"] = system
        if tools: kwargs["toolConfig"] = {"tools": tools}
        cost_ledger.check_cap("bedrock")
        last = None
        for attempt in range(5):
            try:
                resp = self.client.converse(**kwargs); break
            except Exception as e:  # noqa: BLE001
                if _is_context_overflow(e):
                    # The conversation no longer fits the model's context window: end the run here with a
                    # marker message and no tool calls (the case is scored on the state reached so far).
                    out = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(CONTEXT_LIMIT_MARKER)], tool_calls=None)
                    return query, runtime, env, [*messages, out], extra_args
                last = e; time.sleep(5 * (attempt + 1))
        else:
            raise last
        u = resp.get("usage", {})
        cost_ledger.record("bedrock", self.model_id, int(u.get("inputTokens", 0)), 0, int(u.get("outputTokens", 0)), getattr(self, "tag", ""))
        cost_ledger.check_cap("bedrock")
        content = resp["output"]["message"]["content"]
        text = "".join(b.get("text", "") for b in content if "text" in b)
        calls = [FunctionCall(function=b["toolUse"]["name"], args=dict(b["toolUse"]["input"]), id=b["toolUse"]["toolUseId"])
                 for b in content if "toolUse" in b]
        if not calls:   # Llama 3.x often writes the call as JSON text instead of a toolUse block; parse that form
            parsed = _text_tool_calls(text, set(runtime.functions))
            if parsed:
                calls = parsed; text = ""
        out = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(text)], tool_calls=calls or None)
        return query, runtime, env, [*messages, out], extra_args

CONTEXT_LIMIT_MARKER = "[run terminated: model context limit exceeded]"

def _is_context_overflow(exc) -> bool:
    s = str(exc).lower()
    return any(k in s for k in ("maximum context length", "context window", "input is too long", "too many tokens", "input length"))

def _coerce(v):
    """A JSON-looking string argument ("[\"a\"]", "{...}", "3") becomes the value it encodes."""
    if isinstance(v, str):
        t = v.strip()
        if t[:1] in "[{" or t in ("true", "false", "null") or (t.replace(".", "", 1).lstrip("-").isdigit()):
            try: return json.loads(t)
            except Exception: return v
    return v

def _text_tool_calls(text, known):
    """Tool calls written as JSON text: {"type":"function","name":..., "parameters":{...}} (one object, a list, or several lines)."""
    import re, uuid
    out = []
    cands = []
    t = text.strip()
    if not t: return out
    for chunk in ([t] + [m for m in re.findall(r"\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}", t)]):
        try: obj = json.loads(chunk)
        except Exception: continue
        cands.extend(obj if isinstance(obj, list) else [obj])
    seen = set()
    for o in cands:
        if not isinstance(o, dict): continue
        name = o.get("name") or (o.get("function") or {}).get("name") if isinstance(o.get("function"), dict) else o.get("name")
        args = o.get("parameters", o.get("arguments", (o.get("function") or {}).get("arguments") if isinstance(o.get("function"), dict) else None))
        if isinstance(args, str):
            try: args = json.loads(args)
            except Exception: args = {}
        if name in known and isinstance(args, dict) and (name, json.dumps(args, sort_keys=True)) not in seen:
            seen.add((name, json.dumps(args, sort_keys=True)))
            out.append(FunctionCall(function=name, args={k: _coerce(v) for k, v in args.items()}, id="call_" + uuid.uuid4().hex[:12]))
    return out
