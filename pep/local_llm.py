"""Local-model adapters: deterministic sampling, reasoning pass-back, text-only tool planner."""
from __future__ import annotations
from collections.abc import Sequence
import openai
from openai import NOT_GIVEN
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLM, _message_to_openai, _function_to_openai, _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatUserMessage, text_content_block_from_string, get_text_content_as_str


class LocalOpenAILLM(OpenAILLM):
    """OpenAI-compatible LLM element with explicit temperature/seed and reasoning pass-back."""

    def __init__(self, client: openai.OpenAI, model: str, seed: int = 0) -> None:
        super().__init__(client, model, temperature=0.0)
        self.seed = seed

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        openai_messages = []
        for m in messages:
            om = _message_to_openai(m, self.model)
            if om.get("role") == "developer":  # Ollama ignores the 'developer' role; the system prompt must be 'system'
                om = {**om, "role": "system"}
            if m["role"] == "assistant" and m.get("reasoning"):
                om = {**om, "reasoning": m["reasoning"]}
            openai_messages.append(om)
        openai_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        import os, json as _json
        dump = os.environ.get("PEP_DEBUG_DUMP")
        if dump:
            with open(dump, "a") as f:
                f.write(_json.dumps({"messages": openai_messages, "tools": openai_tools}, default=str) + "\n")
        import time as _time
        last = None
        for attempt in range(4):
            try:
                completion = self.client.chat.completions.create(
                    model=self.model, messages=openai_messages, tools=openai_tools or NOT_GIVEN,
                    tool_choice="auto" if openai_tools else NOT_GIVEN, temperature=0.0, seed=self.seed,
                )
                break
            except Exception as e:  # noqa: BLE001
                last = e; _time.sleep(3 * (attempt + 1))
        else:
            raise last
        raw = completion.choices[0].message
        output = _openai_to_assistant_message(raw)
        reasoning = getattr(raw, "reasoning", None)
        if reasoning:
            output["reasoning"] = reasoning  # type: ignore[typeddict-unknown-key]
        return query, runtime, env, [*messages, output], extra_args


class PlannerToolFilter(BasePipelineElement):
    """P2 capability scoping: a planner that sees ONLY the principal's request (no tool outputs)
    and selects the tool subset for the task before any untrusted content is read."""

    PROMPT = ("You are a planner. Given the user's request below and the list of available tools, output ONLY a "
              "comma-separated list of the tool names that are necessary to complete the request. Include every tool "
              "that could plausibly be needed; do not invent tool names.\n\nAvailable tools:\n{tools}\n\nUser request:\n{query}")

    def __init__(self, client: openai.OpenAI, model: str, min_tools: int = 1) -> None:
        self.client, self.model, self.min_tools = client, model, min_tools

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        tool_desc = "\n".join(f"- {t.name}: {(t.description or '').strip().splitlines()[0] if t.description else ''}"
                              for t in runtime.functions.values())
        prompt = self.PROMPT.format(tools=tool_desc, query=query)
        completion = self.client.chat.completions.create(
            model=self.model, messages=[{"role": "user", "content": prompt}], temperature=0.0, seed=0)
        text = (completion.choices[0].message.content or "").lower()
        selected = {name: tool for name, tool in runtime.functions.items() if name.lower() in text}
        if len(selected) >= self.min_tools:
            runtime.update_functions(selected)
        extra_args = {**extra_args, "planner_tools": sorted(selected)}
        return query, runtime, env, messages, extra_args
