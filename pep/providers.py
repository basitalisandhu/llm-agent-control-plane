"""Provider adapters for Track B with cost accounting: OpenAI (reasoning effort low) and Bedrock Claude."""
from __future__ import annotations
import os, time
from collections.abc import Sequence
import openai
from openai import NOT_GIVEN
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM, _message_to_openai, _function_to_openai, _openai_to_assistant_message
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage
import cost_ledger


class OpenAICostLLM(OpenAILLM):
    """OpenAI API with explicit temperature (non-reasoning) or low reasoning effort (GPT-5 family), cost ledger, cap."""

    def __init__(self, client: openai.OpenAI, model: str, reasoning_effort: str | None = None, tag: str = "") -> None:
        super().__init__(client, model, temperature=0.0)
        self.reasoning_effort = reasoning_effort; self.tag = tag
        self.is_reasoning = model.startswith(("gpt-5", "o1", "o3", "o4"))

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        cost_ledger.check_cap("openai")
        msgs = [_message_to_openai(m, self.model) for m in messages]
        tools = [_function_to_openai(t) for t in runtime.functions.values()]
        kw = dict(model=self.model, messages=msgs, tools=tools or NOT_GIVEN, tool_choice="auto" if tools else NOT_GIVEN)
        if self.is_reasoning:
            kw["reasoning_effort"] = self.reasoning_effort or "low"
        else:
            kw["temperature"] = 0.0; kw["seed"] = 0
        last = None
        for attempt in range(6):
            try:
                c = self.client.chat.completions.create(**kw); break
            except Exception as e:  # noqa: BLE001
                last = e; time.sleep(min(60, 4 * 2 ** attempt))
        else:
            raise last
        u = c.usage; cached = getattr(getattr(u, "prompt_tokens_details", None), "cached_tokens", 0) or 0
        cost_ledger.record("openai", self.model, u.prompt_tokens, cached, u.completion_tokens, self.tag)
        out = _openai_to_assistant_message(c.choices[0].message)
        return query, runtime, env, [*messages, out], extra_args


class BedrockClaudeLLM(OpenAILLM.__mro__[1]):  # BasePipelineElement
    """Claude on Bedrock via the synchronous Messages API, with prompt caching and a cost ledger."""

    def __init__(self, model_id: str, region: str, tag: str = "", max_tokens: int = 2048) -> None:
        from anthropic import AnthropicBedrock
        self.client = AnthropicBedrock(aws_region=region)
        self.model = model_id; self.tag = tag; self.max_tokens = max_tokens; self.name = model_id

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        from agentdojo.agent_pipeline.llms.anthropic_llm import _conversation_to_anthropic, _function_to_anthropic, _anthropic_to_assistant_message
        cost_ledger.check_cap("bedrock")
        system_prompt, anthropic_messages = _conversation_to_anthropic(messages)
        tools = [_function_to_anthropic(t) for t in runtime.functions.values()]
        if tools:
            tools = list(tools); tools[-1] = {**tools[-1], "cache_control": {"type": "ephemeral"}}
        system = [{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}] if system_prompt else NOT_GIVEN
        last = None
        for attempt in range(6):
            try:
                r = self.client.messages.create(model=self.model, messages=anthropic_messages, tools=tools or NOT_GIVEN,
                                                max_tokens=self.max_tokens, system=system, extra_body={"temperature": 0.0})
                break
            except Exception as e:  # noqa: BLE001
                last = e; time.sleep(min(60, 4 * 2 ** attempt))
        else:
            raise last
        u = r.usage
        cached = getattr(u, "cache_read_input_tokens", 0) or 0
        created = getattr(u, "cache_creation_input_tokens", 0) or 0
        cost_ledger.record("bedrock", self.model, (u.input_tokens or 0) + cached + created, cached, u.output_tokens or 0, self.tag)
        out = _anthropic_to_assistant_message(r)
        return query, runtime, env, [*messages, out], extra_args


def bedrock_claude_llm(model_id: str, region: str, tag: str = ""):
    return BedrockClaudeLLM(model_id, region, tag)
