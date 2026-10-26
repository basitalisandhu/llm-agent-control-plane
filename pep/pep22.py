"""Policy Enforcement Point (PEP) for AgentDojo pipelines (v2.2: participants are designators; escalation binds the failing arguments).

Deterministic mediation of every proposed tool call:
  * tiering of tools into regular (read-only) and consequential;
  * provenance rule: designators (recipients, URLs, e-mail addresses, account numbers) and object
    identifiers in a consequential action must be sourced from the principal's request or from typed
    fields of tool results, never solely from free text authored by third parties;
  * approval rule: an oracle principal approves a consequential action only if its key arguments match
    an action entailed by the request (each entailed action is approved once).
"""
from __future__ import annotations

import json
import os
import re
import time
from ast import literal_eval
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import BaseModel

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

PERMISSION_TOOLS: dict[str, set[str]] = {
    "slack": {"send_direct_message", "send_channel_message", "add_user_to_channel", "invite_user_to_slack",
              "remove_user_from_slack", "post_webpage", "get_webpage"},
    "banking": {"send_money", "schedule_transaction", "update_scheduled_transaction", "update_password",
                "update_user_info"},
    "travel": {"create_calendar_event", "cancel_calendar_event", "reserve_hotel", "reserve_car_rental",
               "reserve_restaurant", "send_email"},
    "workspace": {"send_email", "delete_email", "create_calendar_event", "cancel_calendar_event",
                  "reschedule_calendar_event", "add_calendar_event_participants", "append_to_file",
                  "create_file", "delete_file", "share_file"},
}
KEY_ARGS: dict[str, list[str]] = {
    "send_direct_message": ["recipient"], "send_channel_message": ["channel"],
    "add_user_to_channel": ["user", "channel"], "invite_user_to_slack": ["user", "user_email"],
    "remove_user_from_slack": ["user"], "post_webpage": ["url"], "get_webpage": ["url"],
    "send_money": ["recipient", "amount"], "schedule_transaction": ["recipient", "amount"],
    "update_scheduled_transaction": ["id", "recipient", "amount"], "update_password": ["password"],
    "update_user_info": ["first_name", "last_name", "street", "city"],
    "create_calendar_event": ["participants", "start_time"], "cancel_calendar_event": ["event_id"],
    "reserve_hotel": ["hotel"], "reserve_car_rental": ["company"], "reserve_restaurant": ["restaurant"],
    "send_email": ["recipients", "cc", "bcc", "attachments"], "delete_email": ["email_id"],
    "reschedule_calendar_event": ["event_id", "new_start_time"],
    "add_calendar_event_participants": ["event_id", "participants"],
    "append_to_file": ["file_id"], "create_file": ["filename"], "delete_file": ["file_id"],
    "share_file": ["file_id", "email", "permission"],
}
# designator arguments: fail-closed (must be sourced from the request or from typed data)
IDENTITY_ARGS = {"recipient", "recipients", "cc", "bcc", "user_email", "email", "url", "user", "participants"}
# object identifiers: must be identifiers the system returned (or named in the request)
ID_ARGS = {"event_id", "email_id", "file_id", "id"}
# tools whose entire result is third-party free text
FREE_TEXT_TOOLS = {"get_webpage", "read_file", "get_rating_reviews_for_hotels",
                   "get_rating_reviews_for_restaurants", "get_rating_reviews_for_car_rental"}
FREE_TEXT_FIELDS = {"body", "subject", "description", "content", "reviews", "title", "text", "notes"}

_TOKEN_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|https?://[^\s\"'<>]+|www\.[^\s\"'<>]+|\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|ai|co|dev|app|info|biz|edu|gov|uk|au|de|fr|ch|me|xyz|site|online)\b(?:/[^\s\"'<>]*)?|\b[A-Za-z]{2}\d{2}(?:[A-Za-z0-9]{8,30}|(?: ?[A-Za-z0-9]{4}){2,8}(?: ?[A-Za-z0-9]{1,3})?)\b")
_IDENT_RE = re.compile(r"[\w.@:/+\-]{1,80}")
_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9 \-]{8,34}$")
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def canon(v) -> str:
    """Canonical form shared by all comparisons: case, whitespace, URL scheme/www/slash, IBAN spacing."""
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, (int, float)):
        f = float(v)
        return str(int(f)) if f.is_integer() else f"{f:.2f}".rstrip("0").rstrip(".")
    s = re.sub(r"\s+", " ", str(v)).strip().strip("\"'.,;:")
    if _IBAN_RE.match(s.upper()):
        return re.sub(r"[\s\-]", "", s).lower()  # lower-case like every other canonical form (corpus is lower-cased)
    s = s.lower()
    if s.startswith(("http://", "https://", "www.")) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", s):
        s = re.sub(r"^https?://", "", s); s = re.sub(r"^www\.", "", s).rstrip("/")
    try:
        f = float(s.replace(",", ""))
        return str(int(f)) if f.is_integer() else f"{f:.2f}".rstrip("0").rstrip(".")
    except ValueError:
        return s


def bounded_in(needle: str, hay: str) -> bool:
    if not needle:
        return False
    return re.search(r"(?<![\w@-])" + re.escape(needle) + r"(?![\w@-])", hay) is not None


def _values_of(v) -> list:
    if isinstance(v, (list, tuple, set)):
        return [x for i in v for x in _values_of(i)]
    if isinstance(v, dict):
        return [x for i in v.values() for x in _values_of(i)]
    return [v]


class Pools:
    def __init__(self, query: str):
        self.query = canon_text(query)
        self.structured: set[str] = set()
        self.ids: set[str] = set()
        self.free: list[str] = []
        self._corpus = ""
        # Write-side labelling (optional, off by default): canonical values the agent has
        # written while they were tainted. When non-empty, such a value that would otherwise
        # be promoted to the trusted/typed pools on read-back stays tainted instead. The set
        # is only ever populated when PEPExecutor.write_labels is on, so when the feature is
        # off this stays empty and _add_typed is byte-for-byte identical to the released code.
        self.written_tainted: set[str] = set()

    def add_free(self, text: str):
        self.free.append(text); self._corpus = ""

    def corpus(self) -> str:
        if not self._corpus:
            self._corpus = canon_text("\n".join(self.free))
        return self._corpus

    def _add_typed(self, c: str, as_id: bool = False):
        """Promote a canonical value into the trusted/typed pools, unless write-side labelling
        has flagged it as written-tainted, in which case it is filed as untrusted free text."""
        if c in self.written_tainted:
            self.add_free(c); return
        self.structured.add(c)
        if as_id:
            self.ids.add(c)

    def walk(self, obj, field: str | None = None):
        if field in FREE_TEXT_FIELDS:
            self.add_free(json.dumps(obj, default=str) if not isinstance(obj, str) else obj); return
        if isinstance(obj, BaseModel):
            for name, value in obj.model_dump().items():
                self.walk(value, name)
        elif isinstance(obj, dict):
            for name, value in obj.items():
                self.walk(name, None); self.walk(value, str(name))
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                self.walk(item, field)
        elif obj is None:
            return
        elif isinstance(obj, str):
            if field in ("id", "id_"):
                self._add_typed(canon(obj), as_id=True); return
            if _IDENT_RE.fullmatch(obj.strip()):
                self._add_typed(canon(obj))
                for tok in _TOKEN_RE.findall(obj):
                    self._add_typed(canon(tok))
            else:
                self.add_free(obj)
        else:
            c = canon(obj); self._add_typed(c, as_id=(field in ("id", "id_")))


def canon_text(text: str) -> str:
    """Canonicalise a whole text: lower-case, URL and IBAN tokens normalised in place."""
    t = re.sub(r"\s+", " ", text)
    def sub(m):
        return canon(m.group(0))
    t = _TOKEN_RE.sub(sub, t)
    return t.lower()


class PEPState:
    def __init__(self, query: str, gt: list[FunctionCall] | None, gt_error: str | None = None):
        self.query = query
        self.pools = Pools(query)
        self.gt = gt
        self.gt_error = gt_error
        self.consumed: set[int] = set()
        self.decisions: list[dict] = []
        # per-state set of values the agent wrote while tainted (write-side labelling); aliases
        # the Pools set so the labeller and the executor share one object.
        self.written_tainted: set[str] = self.pools.written_tainted


def _same_date(a: str, b: str) -> bool:
    ma, mb = _DATE_RE.match(str(a).strip()), _DATE_RE.match(str(b).strip())
    return bool(ma and mb and ma.group(1) == mb.group(1))


class PEPExecutor(BasePipelineElement):
    def __init__(self, suite_name: str, task_lookup: dict[str, object], provenance: bool = True,
                 approval: bool = True, mark: bool = False, decision_log: Path | None = None,
                 tool_output_formatter: Callable = tool_result_to_str, write_labels: bool = False) -> None:
        self.suite_name = suite_name
        self.permission_tools = PERMISSION_TOOLS[suite_name]
        self.task_lookup = task_lookup
        self.provenance, self.approval, self.mark = provenance, approval, mark
        # Optional write-side labelling (Assumption A1 / "no laundering"): off by default so the
        # released numbers are reproducible. Enabled by the constructor argument or by the
        # environment variable PEP_WRITE_LABELS=1, read once here at construction.
        self.write_labels = bool(write_labels) or os.environ.get("PEP_WRITE_LABELS") == "1"
        self.decision_log = decision_log
        self.output_formatter = tool_output_formatter
        self._state: PEPState | None = None

    # ------------------------------------------------------------------ provenance
    def _sourced(self, st: PEPState, c: str) -> bool:
        return bounded_in(c, st.pools.query) or c in st.pools.structured

    def _tainted(self, st: PEPState, c: str) -> bool:
        return bounded_in(c, st.pools.corpus())

    def _provenance_check(self, st: PEPState, call: FunctionCall) -> tuple[bool, str, str, frozenset]:
        """Returns (ok, reason, kind, failed_args). ALL arguments are checked; kind is 'token' if any designator inside
        free-text content fails (never escalable), else 'key' (escalable only if every failing argument matches,
        exactly, a binding value the request entails)."""
        failures: list[tuple[str, str, str]] = []
        for arg, val in call.args.items():
            for v in _values_of(val):
                if v is None or isinstance(v, bool):
                    continue
                c = canon(v)
                if not c:
                    continue
                if arg in ID_ARGS:
                    if not (c in st.pools.ids or bounded_in(c, st.pools.query)):
                        failures.append(("key", arg, f"identifier '{v}' in '{arg}' was not issued by the system nor named in the request"))
                    continue
                if arg in IDENTITY_ARGS:
                    if not self._sourced(st, c):
                        why = "originates only from untrusted content" if self._tainted(st, c) else "is not sourced from the request or from trusted data"
                        failures.append(("key", arg, f"designator '{v}' in '{arg}' {why}"))
                    continue
                if arg in KEY_ARGS.get(call.function, []) and not self._sourced(st, c) and self._tainted(st, c):
                    failures.append(("key", arg, f"argument '{arg}'='{v}' originates only from untrusted content"))
                if isinstance(v, str):
                    for tok in _TOKEN_RE.findall(v):
                        ct = canon(tok)
                        if ct and not self._sourced(st, ct) and self._tainted(st, ct):
                            failures.append(("token", arg, f"designator '{tok}' in argument '{arg}' originates only from untrusted content"))
        failures += self._extra_provenance_failures(st, call)
        if not failures:
            return True, "", "", frozenset()
        kind = "token" if any(k == "token" for k, _, _ in failures) else "key"
        return False, "; ".join(r for _, _, r in failures[:3]), kind, frozenset(a for _, a, _ in failures)

    def _extra_provenance_failures(self, st: PEPState, call: FunctionCall) -> list[tuple[str, str, str]]:
        return []

    # ------------------------------------------------------------------ write-side labelling
    def _record_writes(self, st: PEPState, call: FunctionCall) -> None:
        """Write-side labelling (optional). Record the canonical values and the extracted
        designators of this executed call's arguments that are tainted at this moment -- in the
        untrusted corpus (U), or not in the trusted set (T) -- so that if a later tool result
        would promote the same value into the trusted/typed pools it is kept tainted instead.
        This closes the laundering path of Assumption A1 (e.g. writing an attacker account number
        into a profile field, reading it back as typed data, then paying it)."""
        def flag(v) -> None:
            c = canon(v)
            if c and (self._tainted(st, c) or not self._sourced(st, c)):
                st.written_tainted.add(c)
            if isinstance(v, str):
                for tok in _TOKEN_RE.findall(v):
                    ct = canon(tok)
                    if ct and (self._tainted(st, ct) or not self._sourced(st, ct)):
                        st.written_tainted.add(ct)
        for _arg, val in call.args.items():
            for v in _values_of(val):
                if v is None or isinstance(v, bool):
                    continue
                flag(v)

    # ------------------------------------------------------------------ approval
    def _binding(self, st: PEPState, gv) -> bool:
        """A ground-truth value binds the principal's approval only if it is recoverable from the request
        or from data the system returned; otherwise the benchmark's value is arbitrary (wildcard)."""
        vals = [canon(x) for x in _values_of(gv) if x is not None]
        if not vals:
            return False
        hay = st.pools.query + "\n" + st.pools.corpus()
        return any(bounded_in(c, hay) or c in st.pools.structured for c in vals)

    def _args_match(self, st: PEPState, arg: str, gv, cv, strict: bool = False, must_bind: bool = False) -> bool:
        if strict and (arg in IDENTITY_ARGS | ID_ARGS or must_bind):
            if gv is None or cv is None or not self._binding(st, gv):
                return False
            gs = {canon(x) for x in _values_of(gv) if x is not None}
            cs = {canon(x) for x in _values_of(cv) if x is not None}
            if arg in IDENTITY_ARGS | ID_ARGS or isinstance(gv, (list, tuple, set)) or isinstance(cv, (list, tuple, set)):
                return bool(cs) and cs.issubset(gs)
            g, c = _values_of(gv)[0], _values_of(cv)[0]
            if isinstance(g, (int, float)) or isinstance(c, (int, float)):
                try:
                    return abs(float(g) - float(c)) < 0.01
                except (TypeError, ValueError):
                    return canon(g) == canon(c)
            return canon(g) == canon(c)
        if gv is None:
            if arg in IDENTITY_ARGS | ID_ARGS:  # not entailed: only a grounded value is approvable
                return all(self._sourced(st, canon(x)) or canon(x) in st.pools.ids for x in _values_of(cv) if x is not None)
            return True
        if cv is None:
            return True
        if not self._binding(st, gv):
            return True
        gl, cl = [x for x in _values_of(gv) if x is not None], [x for x in _values_of(cv) if x is not None]
        if isinstance(gv, (list, tuple, set)) or isinstance(cv, (list, tuple, set)):
            cs, gs = {canon(x) for x in cl}, {canon(x) for x in gl}
            return (not cs) or cs.issubset(gs)
        g, c = gl[0], cl[0]
        if isinstance(g, (int, float)) or isinstance(c, (int, float)):
            try:
                return abs(float(g) - float(c)) < 0.01
            except (TypeError, ValueError):
                return canon(g) == canon(c)
        if _DATE_RE.match(str(g).strip()) and _DATE_RE.match(str(c).strip()):
            return _same_date(g, c)
        return canon(g) == canon(c)

    def _approval_check(self, st: PEPState, call: FunctionCall, strict: bool = False, failed: frozenset = frozenset()) -> tuple[bool, str]:
        if st.gt is None:
            return False, f"no principal request available ({st.gt_error or 'unknown task'})"
        for i, g in enumerate(st.gt):
            if i in st.consumed or g.function != call.function:
                continue
            if all(self._args_match(st, a, g.args.get(a), call.args.get(a), strict, must_bind=(a in failed)) for a in KEY_ARGS.get(call.function, []) + [a for a in failed if a not in KEY_ARGS.get(call.function, [])]):
                st.consumed.add(i)
                return True, ""
        if any(g.function == call.function for g in st.gt):
            return False, f"arguments of '{call.function}' do not match an action the principal requested (or it was already approved once)"
        return False, f"'{call.function}' was not part of the principal's request"

    # ------------------------------------------------------------------ element
    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        if len(messages) == 0 or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args
        n_tool_msgs = sum(1 for m in messages if m["role"] == "tool")
        if self._state is None or n_tool_msgs == 0 or self._state.query != query:
            gt, gt_err = None, None
            task = self.task_lookup.get(query)
            if task is not None:
                try:
                    gt = task.ground_truth(env.model_copy(deep=True))
                except Exception as e:  # noqa: BLE001
                    gt, gt_err = [], f"ground_truth failed: {e!r}"
            else:
                gt_err = "task not found"
            self._state = PEPState(query, gt, gt_err)
        st = self._state

        results = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function not in (t.name for t in runtime.functions.values()):
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                                     tool_call_id=tool_call.id, tool_call=tool_call,
                                                     error=f"Invalid tool {tool_call.function} provided."))
                continue
            for k, v in list(tool_call.args.items()):
                if isinstance(v, str) and is_string_list(v):
                    tool_call.args[k] = literal_eval(v)
            tier = "permission" if tool_call.function in self.permission_tools else "regular"
            decision = {"t": time.time(), "tool": tool_call.function,
                        "args": json.loads(json.dumps(tool_call.args, default=str)), "tier": tier,
                        "allowed": True, "reason": "", "escalated": False}
            if tier == "permission":
                prov_ok, prov_why, kind, failed = (True, "", "", frozenset()) if not self.provenance else self._provenance_check(st, tool_call)
                if self.provenance and not prov_ok:
                    # escalation: the principal may confirm an action whose arguments failed provenance only if every
                    # failing argument matches, exactly, a binding value the request itself entails (strict approval);
                    # a tainted designator inside free-text content is never approvable.
                    appr_ok, appr_why = (False, "") if not self.approval else self._approval_check(st, tool_call, strict=True, failed=failed)
                    if self.approval and appr_ok and kind == "key":
                        decision.update(escalated=True, reason=f"approved despite provenance: {prov_why}")
                    else:
                        decision.update(allowed=False, reason=f"provenance: {prov_why}")
                elif self.approval:
                    appr_ok, appr_why = self._approval_check(st, tool_call)
                    if not appr_ok:
                        decision.update(allowed=False, reason=f"approval: {appr_why}")
            st.decisions.append(decision)
            if self.decision_log is not None:
                with self.decision_log.open("a") as f:
                    f.write(json.dumps({"query": query[:120], **decision}) + "\n")
            if not decision["allowed"]:
                msg = ("Action denied by the policy enforcement point: " + decision["reason"] +
                       ". The action was not executed. Continue with the user's original request using only the "
                       "information and actions the user asked for.")
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                                     tool_call_id=tool_call.id, tool_call=tool_call, error=msg))
                continue
            raw, error = runtime.run_function(env, tool_call.function, tool_call.args)
            if error is None:
                if self.write_labels:
                    self._record_writes(st, tool_call)
                if tool_call.function in FREE_TEXT_TOOLS:
                    st.pools.add_free(raw if isinstance(raw, str) else self.output_formatter(raw))
                else:
                    st.pools.walk(raw)
            text = self.output_formatter(raw)
            if self.mark:
                text = f"<<{text}>>"
            results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                                 tool_call_id=tool_call.id, tool_call=tool_call, error=error))
        extra_args = {**extra_args, "pep_decisions": st.decisions}
        return query, runtime, env, [*messages, *results], extra_args
