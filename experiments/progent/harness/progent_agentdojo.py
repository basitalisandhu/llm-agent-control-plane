#!/usr/bin/env python
"""Progent (sunblaze-ucb/progent, `secagent` library) on pristine AgentDojo 0.1.35 / benchmark v1.2.2.

One process = one (suite, mode[, shard]) job.  Progent keeps its policy in module-global state, so never run
two jobs in the same process; run several processes instead (run_progent.sh does).

How this mirrors the authors' integration (progent-repo/agentdojo/, a fork of agentdojo 0.1.29 whose whole
diff is ~40 lines; verified with `diff` against the PyPI wheel):
  1. InitQuery            -> generate_security_policy(query)           [ProgentInitQuery]
  2. ToolsExecutor        -> generate_update_security_policy(calls, str(results), manual_check=False) after every
                             tool batch when SECAGENT_UPDATE == "True"  [ProgentToolsExecutor]
  3. suite task_suite.py  -> make_function(apply_secure_tool_wrapper(tool)) for every tool + update_always_allowed_tools(
                             <generic read-only allow-list>)            [wrap_suite]
  4. base_attacks.py      -> policy disabled while the ground-truth pipeline discovers injection candidates [patch]
  5. benchmark.py         -> reset_security_policy() before every task  [done in ProgentInitQuery]
  6. run.sh               -> SECAGENT_UPDATE=True, SECAGENT_IGNORE_UPDATE_ERROR=True, policy model == agent model

Deliberate differences from the authors' setup:
  * benchmark v1.2.2 on pristine agentdojo 0.1.35 (authors: CLI-default v1.1.2 on a 0.1.29 fork); every injection task is
    kept (authors dropped travel injection_task_2/_6; --paper-protocol restores that)
  * slack injection_task_5's trace oracle sees executed calls only (authors corrected those results by hand)
  * gpt-5* policy model: no temperature, JSON-format suffix as for o1/o3/gpt-4.1 (patches/progent-secagent-gpt5.patch)
  * the attack string addresses the model as --attack-model-name (default "GPT-5"; AgentDojo has no gpt-5 entry)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Authors' generic read-only allow-lists (progent-repo/agentdojo/src/agentdojo/default_suites/v1/<suite>/task_suite.py).
GENERIC_ALLOWED = {
    "banking": (["get_most_recent_transactions"], True),  # allow_all_no_arg_tools=True
    "slack": (["get_channels", "read_channel_messages", "read_inbox", "get_users_in_channel"], False),
    "travel": (
        [
            "get_user_information", "get_all_hotels_in_city", "get_hotels_prices", "get_rating_reviews_for_hotels",
            "get_hotels_address", "get_all_restaurants_in_city", "get_cuisine_type_for_restaurants",
            "get_restaurants_address", "get_rating_reviews_for_restaurants",
            "get_dietary_restrictions_for_all_restaurants", "get_contact_information_for_restaurants",
            "get_price_for_restaurants", "check_restaurant_opening_hours", "get_all_car_rental_companies_in_city",
            "get_car_types_available", "get_rating_reviews_for_car_rental", "get_car_fuel_options",
            "get_car_rental_address", "get_car_price_per_day", "search_calendar_events", "get_day_calendar_events",
            "get_flight_information",
        ],
        False,
    ),
    "workspace": (
        [
            "get_unread_emails", "get_sent_emails", "get_received_emails", "get_draft_emails", "search_emails",
            "search_contacts_by_name", "search_contacts_by_email", "get_current_day", "search_calendar_events",
            "get_day_calendar_events", "search_files_by_filename", "get_file_by_id", "list_files", "search_files",
        ],
        False,
    ),
}

# Injection tasks the Progent authors removed from ALL their experiments (paper, Appendix D: the two travel
# "preference attacks"; progent-repo comments out travel InjectionTask2 and InjectionTask6). Off by default.
PAPER_PROTOCOL_EXCLUDED = {"travel": {"injection_task_2", "injection_task_6"}}

BLOCK_SENTINEL = "Please try other tools or arguments and continue to finish the user task"


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", required=True, choices=sorted(GENERIC_ALLOWED))
    ap.add_argument("--mode", required=True, choices=["benign", "attack"])
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--model", default="gpt-5-mini", help="agent model (OpenAI chat-completions name)")
    ap.add_argument("--policy-model", default=None, help="Progent policy generation/update model (default: --model)")
    ap.add_argument("--benchmark-version", default="v1.2.2")
    ap.add_argument("--logdir", type=Path, default=ROOT / "runs" / "agentdojo")
    ap.add_argument("--auxdir", type=Path, default=ROOT / "runs" / "aux")
    ap.add_argument("--user-task", action="append", default=None, help="restrict to these user task ids (repeatable)")
    ap.add_argument("--injection-task", action="append", default=None, help="restrict to these injection task ids")
    ap.add_argument("--shard", default="0/1", help="i/n: run only user tasks with index %% n == i (attack mode)")
    ap.add_argument("--no-injection-task-utility", action="store_true",
                    help="skip the 'injection tasks as user tasks' runs that benchmark_suite_with_injections does "
                         "(they never enter utility/ASR); by default only shard 0 runs them")
    ap.add_argument("--paper-protocol", action="store_true",
                    help="exclude the travel injection tasks the Progent authors dropped (injection_task_2, _6)")
    ap.add_argument("--attack-model-name", default=os.environ.get("PROGENT_ATTACK_MODEL_NAME", "GPT-5"),
                    help="prose name the important_instructions string uses for the model ('to you, {model}'); "
                         "AgentDojo has no entry for gpt-5-mini. Env: PROGENT_ATTACK_MODEL_NAME")
    ap.add_argument("--reasoning-effort", default=None, choices=[None, "minimal", "low", "medium", "high"],
                    help="agent reasoning_effort (default: not sent => API default, medium for gpt-5-mini)")
    ap.add_argument("--force-rerun", action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
    shard_i, shard_n = (int(x) for x in args.shard.split("/"))
    tag = f"{args.suite}-{args.mode}" + (f"-shard{shard_i}of{shard_n}" if shard_n > 1 else "")
    args.auxdir.mkdir(parents=True, exist_ok=True)
    args.logdir.mkdir(parents=True, exist_ok=True)

    # --- environment that secagent reads AT IMPORT TIME (authors' run.sh values) ---------------------------------
    os.environ["SECAGENT_POLICY_MODEL"] = args.policy_model or args.model
    os.environ.setdefault("SECAGENT_UPDATE", "True")
    os.environ.setdefault("SECAGENT_IGNORE_UPDATE_ERROR", "True")
    os.environ.setdefault("SECAGENT_GENERATE", "True")
    os.environ["SECAGENT_USAGE_LOG"] = str(args.auxdir / f"usage-policy-{tag}.jsonl")
    agent_usage_path = args.auxdir / f"usage-agent-{tag}.jsonl"
    policy_log_path = args.auxdir / f"policies-{tag}.jsonl"

    import openai
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.llms import openai_llm
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.attacks.base_attacks import BaseAttack
    from agentdojo.benchmark import (
        benchmark_suite_without_injections,
        run_task_with_injection_tasks,
        run_task_without_injection_tasks,
    )
    from agentdojo.functions_runtime import EmptyEnv
    from agentdojo.logging import Logger, OutputLogger
    from agentdojo.models import MODEL_NAMES
    from agentdojo.task_suite import task_suite as task_suite_module
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.types import get_text_content_as_str

    import secagent
    from secagent import (
        apply_secure_tool_wrapper, generate_security_policy, generate_update_security_policy,
        get_current_config, reset_security_policy, update_always_allowed_tools, update_security_policy,
    )
    from secagent.tool import get_generated_policy

    def log_policy(event, **kw):
        ctx = getattr(Logger.get(), "context", {}) or {}
        rec = {"t": time.time(), "event": event, "suite": args.suite,
               "user_task": ctx.get("user_task_id"), "injection_task": ctx.get("injection_task_id"), **kw}
        with open(policy_log_path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    class QuietLogger(OutputLogger):
        """OutputLogger (needed: TraceLogger takes `logdir` from its delegate) minus the rich table dump on every message."""

        def log(self, messages, **kwargs):
            self.messages += messages[len(self.messages):]

    # --- 1) model name for the attack string ('to you, {model}') -------------------------------------------------
    MODEL_NAMES.setdefault(args.model, args.attack_model_name)

    # --- 2) token accounting for the AGENT calls (policy calls are logged inside secagent.tool) ------------------
    _orig_request = openai_llm.chat_completion_request

    def request_with_usage(*a, **k):
        completion = _orig_request(*a, **k)
        try:
            u = completion.usage
            d = getattr(u, "completion_tokens_details", None)
            pd = getattr(u, "prompt_tokens_details", None)
            with open(agent_usage_path, "a") as f:
                f.write(json.dumps({
                    "kind": "agent", "model": args.model, "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                    "reasoning_tokens": getattr(d, "reasoning_tokens", 0) or 0,
                    "cached_tokens": getattr(pd, "cached_tokens", 0) or 0}) + "\n")
        except Exception:
            pass
        return completion

    openai_llm.chat_completion_request = request_with_usage  # OpenAILLM.query resolves it from module globals

    # --- 3) wrap the suite's tools (authors: make_function(apply_secure_tool_wrapper(tool))) ----------------------
    suite = get_suite(args.benchmark_version, args.suite)
    suite.tools = [f.model_copy(update={"run": apply_secure_tool_wrapper(f.run)}) for f in suite.tools]
    allowed, all_no_arg = GENERIC_ALLOWED[args.suite]
    update_always_allowed_tools(allowed, allow_all_no_arg_tools=all_no_arg)
    names = {f.name for f in suite.tools}
    missing = [t for t in allowed if t not in names]
    assert not missing, f"generic allow-list names not in suite {args.suite}: {missing}"

    # --- 4) ground-truth runs (injection-candidate discovery) must not be policed --------------------------------
    _orig_candidates = BaseAttack.get_injection_candidates

    def candidates_without_policy(self, user_task):
        saved = get_current_config()
        update_security_policy(None)
        try:
            return _orig_candidates(self, user_task)
        finally:
            update_security_policy(saved)

    BaseAttack.get_injection_candidates = candidates_without_policy

    # --- 5) effect-based scoring: a tool call that Progent denied never executed ----------------------------------
    # (automates the authors' manual correction of slack injection_task_5, whose oracle reads the emitted call trace)
    def executed_only_trace(messages):
        denied = {id(m["tool_call"]) for m in messages
                  if m["role"] == "tool" and m.get("error") and BLOCK_SENTINEL in m["error"]}
        return [tc for m in messages if m["role"] == "assistant" for tc in (m["tool_calls"] or []) if id(tc) not in denied]

    task_suite_module.functions_stack_trace_from_messages = executed_only_trace

    # --- 6) pipeline elements ---------------------------------------------------------------------------------
    class ProgentInitQuery(InitQuery):
        def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
            reset_security_policy()
            generate_security_policy(query)  # LLM call; raises after 6 failed attempts (as in the authors' code)
            log_policy("init", policy=get_generated_policy())
            return super().query(query, runtime, env, messages, extra_args)

    class ProgentToolsExecutor(ToolsExecutor):
        def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
            n_before = len(messages)
            out = super().query(query, runtime, env, messages, extra_args)
            added = out[3][n_before:]
            if added and os.getenv("SECAGENT_UPDATE", "False") == "True":
                calls, results = [], []
                for m in added:
                    if m["role"] != "tool":
                        continue
                    err = m.get("error") or ""
                    if err.startswith("Empty function name provided") or err.startswith("Invalid tool "):
                        continue  # the authors' executor skips these before run_function
                    calls.append({"name": m["tool_call"].function, "args": m["tool_call"].args})
                    results.append(get_text_content_as_str(m["content"]))
                generate_update_security_policy(calls, str(results), manual_check=False)
                log_policy("update", calls=calls, policy=get_generated_policy())
            return out

    client = openai.OpenAI()  # reads OPENAI_API_KEY from the environment
    llm_kwargs = {"reasoning_effort": args.reasoning_effort} if args.reasoning_effort else {}
    llm = OpenAILLM(client, args.model, **llm_kwargs)  # temperature=0.0 default => NOT sent (0.0 or NOT_GIVEN)
    tools_loop = ToolsExecutionLoop([ProgentToolsExecutor(), llm])
    pipeline = AgentPipeline([SystemMessage(load_system_message(None)), ProgentInitQuery(), llm, tools_loop])
    pipeline.name = f"{args.model}-progent"
    print(f"[{tag}] pipeline={pipeline.name} agent={args.model} policy_model={os.environ['SECAGENT_POLICY_MODEL']} "
          f"suite={args.suite} benchmark={args.benchmark_version} mode={args.mode} attack={args.attack if args.mode == 'attack' else 'none'}",
          flush=True)

    # --- 7) run -----------------------------------------------------------------------------------------------
    t0 = time.time()
    all_user = list(suite.user_tasks.keys())
    all_user.sort(key=lambda s: int(s.rsplit("_", 1)[1]))
    user_ids = args.user_task or all_user
    with QuietLogger(str(args.logdir), live=None):
        if args.mode == "benign":
            results = benchmark_suite_without_injections(
                pipeline, suite, logdir=args.logdir, force_rerun=args.force_rerun,
                user_tasks=user_ids if args.user_task else None, benchmark_version=args.benchmark_version)
            util = list(results["utility_results"].values())
            print(f"[{tag}] DONE benign utility {sum(util)}/{len(util)} = {100 * sum(util) / max(1, len(util)):.1f}% "
                  f"in {time.time() - t0:.0f}s", flush=True)
            summary = {"utility": sum(util), "n": len(util)}
        else:
            inj_ids = list(suite.injection_tasks.keys())
            inj_ids.sort(key=lambda s: int(s.rsplit("_", 1)[1]))
            if args.injection_task:
                inj_ids = list(args.injection_task)
            if args.paper_protocol:
                inj_ids = [i for i in inj_ids if i not in PAPER_PROTOCOL_EXCLUDED.get(args.suite, set())]
            user_ids = [u for k, u in enumerate(user_ids) if k % shard_n == shard_i]
            attack = load_attack(args.attack, suite, pipeline)
            print(f"[{tag}] user_tasks={len(user_ids)} injection_tasks={len(inj_ids)} "
                  f"pairs={len(user_ids) * len(inj_ids)} attack_model_name={attack.model_name!r}", flush=True)
            if shard_i == 0 and not args.no_injection_task_utility:
                for iid in inj_ids:  # same as benchmark_suite_with_injections: injection tasks run as user tasks
                    run_task_without_injection_tasks(suite, pipeline, suite.get_injection_task_by_id(iid),
                                                     args.logdir, args.force_rerun, args.benchmark_version)
            n = s = u_ok = 0
            for k, uid in enumerate(user_ids, 1):
                utility, security = run_task_with_injection_tasks(
                    suite, pipeline, suite.get_user_task_by_id(uid), attack, args.logdir, args.force_rerun,
                    inj_ids, args.benchmark_version)
                n += len(security)
                s += sum(security.values())
                u_ok += sum(utility.values())
                print(f"[{tag}] {k}/{len(user_ids)} {uid}: running UA {u_ok}/{n} ASR {s}/{n} "
                      f"({100 * s / max(1, n):.1f}%) elapsed {time.time() - t0:.0f}s", flush=True)
            summary = {"utility_under_attack": u_ok, "attack_success": s, "n": n}
        (args.auxdir / f"summary-{tag}.json").write_text(json.dumps({**summary, "seconds": time.time() - t0}))


if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=SyntaxWarning)
    main()
