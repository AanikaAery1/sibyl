"""Gateway Action Gate (ACTION-GATE.md §2.2): decide every proposed tool call in an
OpenAI-compatible response before the agent sees it.

Each ``choices[].message.tool_calls[]`` entry (and the legacy ``function_call``) is evaluated
with the shared evaluator over the agent's signed policies. Arguments arrive as a JSON string;
one that does not parse strictly (duplicate members included: a lenient agent parser could
read a different value) is blocked. A choice with any non-allowed call loses *all* its tool
calls (parallel calls are atomic: no half-executed transfer pair) and becomes an assistant
message explaining the refusal with ``finish_reason: "stop"``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Final, Literal
from uuid import UUID

from sibyl_schemas.action_gate import (
    ActionDecisionRequest,
    Decision,
    Effect,
    HeldActionRequest,
    apply_counter,
    args_digest,
    evaluate_all,
)
from sibyl_schemas.canonical import parse_json_strict
from sibyl_schemas.scrub import SecretsScrubber

from ..policy.view import ActionContext, PolicyState
from .api import ActionApi

MAX_CALLS: Final = 64
MAX_HELD_ARGS_CHARS: Final = 64 * 1024
_SAFE: Final = re.compile(r"[^A-Za-z0-9._:-]")
Outcome = Literal["allowed", "blocked", "held"]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_int(value: Any, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def as_str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


@dataclass(frozen=True)
class ProposedCall:
    choice: int
    position: int
    call_id: str | None
    name: str
    arguments: Any  # the raw ``arguments`` value (usually a JSON string)


@dataclass(frozen=True)
class CallVerdict:
    call: ProposedCall
    decision: Decision
    held_action_id: str | None = None

    @property
    def outcome(self) -> Outcome:
        if self.decision.effect is Effect.ALLOW:
            return "allowed"
        return "held" if self.held_action_id else "blocked"


@dataclass
class GateResult:
    verdicts: list[CallVerdict] = field(default_factory=list)

    @property
    def refused_choices(self) -> set[int]:
        return {v.call.choice for v in self.verdicts if v.outcome != "allowed"}

    def headers(self) -> list[tuple[str, str]]:
        outcomes = {v.outcome for v in self.verdicts}
        if outcomes <= {"allowed"}:
            return []
        out = [("x-sibyl-action", "blocked" if "blocked" in outcomes else "held")]
        held = [v.held_action_id for v in self.verdicts if v.held_action_id]
        if held:
            out.append(("x-sibyl-held-action-id", ",".join(held)))
        return out

    def refusal(self, choice: int) -> str:
        lines = []
        for v in self.verdicts:
            if v.call.choice != choice or v.outcome == "allowed":
                continue
            name = v.call.name[:80] or "unknown"
            if v.outcome == "held":
                lines.append(
                    f"Sibyl is holding the tool call `{name}` for human approval "
                    f"(held action {v.held_action_id}): {v.decision.reason}"
                )
            else:
                lines.append(f"Sibyl blocked the tool call `{name}`: {v.decision.reason}")
        skipped = [
            v.call.name[:80]
            for v in self.verdicts
            if v.call.choice == choice and v.outcome == "allowed"
        ]
        if skipped:
            lines.append("Other tool calls in the same turn were withheld: " + ", ".join(skipped))
        return "\n".join(lines)


def calls_in_message(choice: int, message: Any) -> list[ProposedCall]:
    if not isinstance(message, dict):
        return []
    out: list[ProposedCall] = []
    for position, entry in enumerate(message.get("tool_calls") or []):
        if not isinstance(entry, dict):
            out.append(ProposedCall(choice, position, None, "", None))
            continue
        fn = as_dict(entry.get("function"))
        call_id = entry.get("id") if isinstance(entry.get("id"), str) else None
        name = as_str(fn.get("name"))
        out.append(ProposedCall(choice, position, call_id, name, fn.get("arguments")))
    legacy = message.get("function_call")
    if isinstance(legacy, dict):
        name = as_str(legacy.get("name"))
        out.append(ProposedCall(choice, len(out), None, name, legacy.get("arguments")))
    return out


def proposed_calls(doc: Any) -> list[ProposedCall]:
    """Every proposed call in a non-streaming chat completion, in order."""
    if not isinstance(doc, dict) or not isinstance(doc.get("choices"), list):
        return []
    out: list[ProposedCall] = []
    for position, choice in enumerate(doc["choices"]):
        if not isinstance(choice, dict):
            continue
        index = as_int(choice.get("index"), position)
        out.extend(calls_in_message(index, choice.get("message")))
    return out


def parse_arguments(raw: Any) -> tuple[bool, Any]:
    if isinstance(raw, dict | list):
        return True, raw
    if raw is None or raw == "":
        return True, {}
    if not isinstance(raw, str):
        return False, None
    try:
        return True, parse_json_strict(raw)
    except ValueError:
        return False, None


def _blocked(rule_id: str, reason: str) -> Decision:
    return Decision(effect=Effect.BLOCK, rule_id=rule_id, reason=reason)


class ToolCallGate:
    def __init__(self, api: ActionApi | None, scrubber: SecretsScrubber) -> None:
        self._api = api
        self._scrubber = scrubber

    async def decide(
        self,
        ctx: ActionContext,
        calls: list[ProposedCall],
        *,
        request_id: str,
        tenant_id: UUID,
        agent_id: str,
        policy_state: PolicyState,
        on_behalf_of: dict[str, str] | None = None,
    ) -> GateResult:
        result = GateResult()
        for call in calls[:MAX_CALLS]:
            result.verdicts.append(
                await self._one(
                    ctx, call, request_id, tenant_id, agent_id, policy_state, on_behalf_of
                )
            )
        for call in calls[MAX_CALLS:]:
            result.verdicts.append(
                CallVerdict(call, _blocked("sibyl:too_many_calls", "too many tool calls"))
            )
        return result

    async def _one(
        self,
        ctx: ActionContext,
        call: ProposedCall,
        request_id: str,
        tenant_id: UUID,
        agent_id: str,
        state: PolicyState,
        on_behalf_of: dict[str, str] | None,
    ) -> CallVerdict:
        try:
            return await self._evaluate(
                ctx, call, request_id, tenant_id, agent_id, state, on_behalf_of
            )
        except Exception:  # never release a call the gate failed to decide
            return CallVerdict(call, _blocked("sibyl:evaluator_error", "action gate failed"))

    async def _evaluate(
        self,
        ctx: ActionContext,
        call: ProposedCall,
        request_id: str,
        tenant_id: UUID,
        agent_id: str,
        state: PolicyState,
        on_behalf_of: dict[str, str] | None,
    ) -> CallVerdict:
        if ctx.missing:
            return CallVerdict(
                call, _blocked("sibyl:policy_missing", "an action policy is missing")
            )
        ok, args = parse_arguments(call.arguments)
        if not ok:
            return CallVerdict(
                call,
                _blocked("sibyl:unparseable_arguments", "tool arguments are not valid JSON"),
            )
        decision = evaluate_all(ctx.policies, call.name, args)
        if decision.sensitive and state in (PolicyState.EXPIRED, PolicyState.UNAVAILABLE):
            return CallVerdict(
                call, _blocked("sibyl:fail_closed", "sensitive tool and the policy is expired")
            )
        cid = self._call_id(request_id, call)
        if decision.needs_counter is not None:
            decision = await self._counter(decision, call, args, cid, tenant_id, agent_id)
        if decision.effect is not Effect.ESCALATE:
            return CallVerdict(call, decision)
        held = await self._hold(decision, call, args, cid, tenant_id, agent_id, on_behalf_of)
        if held is None:
            reason = f"{decision.reason} (could not be held for approval)"
            return CallVerdict(
                call, decision.model_copy(update={"effect": Effect.BLOCK, "reason": reason})
            )
        return CallVerdict(call, decision, held)

    @staticmethod
    def _call_id(request_id: str, call: ProposedCall) -> str:
        tail = _SAFE.sub("_", call.call_id or f"c{call.position}")[:60]
        return f"{request_id}:{call.choice}:{tail}"[:160]

    async def _counter(
        self,
        decision: Decision,
        call: ProposedCall,
        args: Any,
        cid: str,
        tenant: UUID,
        agent: str,
    ) -> Decision:
        need = decision.needs_counter
        unresolved = decision.model_copy(update={"needs_counter": None})
        if self._api is None or need is None or decision.policy_id is None or not _is_uuid(agent):
            return unresolved
        body = ActionDecisionRequest(
            call_id=cid,
            agent_id=agent,
            source="gateway",
            policy_id=decision.policy_id,
            policy_version=decision.policy_version or 1,
            rule_id=need.rule_id,
            tool=call.name[:256] or "unknown",
            counter_key=need.counter_key,
            increment=need.increment,
            max=need.max,
            window_s=need.window_s,
            args_sha256=args_digest(args),
        ).model_dump(mode="json", by_alias=True)
        answer = await self._api.decide(tenant, body)
        return (
            unresolved if answer is None else apply_counter(decision, within_cap=answer.within_cap)
        )

    async def _hold(
        self,
        decision: Decision,
        call: ProposedCall,
        args: Any,
        cid: str,
        tenant: UUID,
        agent: str,
        on_behalf_of: dict[str, str] | None = None,
    ) -> str | None:
        if self._api is None or not _is_uuid(agent):
            return None
        scrubbed, _ = self._scrubber.scrub_json(args, "tool_args")
        if len(json.dumps(scrubbed, default=str)) > MAX_HELD_ARGS_CHARS:
            scrubbed = {"truncated": True}
        # WAVE3 frozen request field (model owned by AG-LIVE); validated at the gateway edge
        # and again by the shared model here, so the control plane never sees another shape.
        obo: dict[str, Any] = {} if on_behalf_of is None else {"on_behalf_of": dict(on_behalf_of)}
        body = HeldActionRequest(
            call_id=cid,
            agent_id=agent,
            source="gateway",
            tool=call.name[:256] or "unknown",
            args=scrubbed,
            args_sha256=args_digest(args),
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            rule_id=decision.rule_id,
            reason=decision.reason[:500],
            hold_timeout_s=decision.hold_timeout_s or 900,
            **obo,
        ).model_dump(mode="json", by_alias=True)
        status = await self._api.hold(tenant, body)
        return None if status is None else str(status.held_action_id)


def _is_uuid(text: str) -> bool:
    try:
        UUID(text)
    except ValueError:
        return False
    return True


def rewrite_completion(doc: dict[str, Any], result: GateResult) -> dict[str, Any]:
    """A copy of the completion where each refused choice is a plain assistant refusal."""
    refused = result.refused_choices
    choices = []
    for position, choice in enumerate(doc.get("choices") or []):
        index = as_int(as_dict(choice).get("index"), position)
        if index not in refused or not isinstance(choice, dict):
            choices.append(choice)
            continue
        message = {"role": "assistant", "content": result.refusal(index)}
        choices.append({**choice, "message": message, "finish_reason": "stop"})
    return {**doc, "choices": choices}
