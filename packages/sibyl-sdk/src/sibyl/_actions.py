"""SDK Action Gate enforcement (ACTION-GATE.md §2.1): decide a tool call before it runs.

Order per call: the agent's action policies from the held signed snapshot are evaluated with
`sibyl_schemas.action_gate` (the same evaluator as the gateway); a cumulative rule asks the
control plane for the authoritative check-and-increment (`POST /api/v1/action-decisions`,
idempotent per call id); `block` raises `SibylActionBlocked`; `escalate` creates a held action
(`POST /api/v1/held-actions`) and either waits for a person (bounded by the policy's
`hold_timeout_s`; no decision in time is a deny, `SibylActionDenied`) or, with
`mode="async"`, raises `SibylActionHeld`.

Fail closed: a tool that is sensitive (declared `sensitive=True` or listed in a policy's
`sensitive_tools`) is blocked when no fresh snapshot (fresh or within grace) is held. A
control-plane failure never allows: an unanswered counter keeps the cap's `on_exceed`, an
escalation that cannot be held is denied.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final, Literal

import httpx
from sibyl_schemas.action_gate import (
    ActionDecisionRequest,
    ActionDecisionResult,
    Decision,
    Effect,
    HeldActionRequest,
    HeldActionStatus,
    apply_counter,
    args_digest,
    evaluate_all,
)

from sibyl import _obo
from sibyl._errors import SibylActionBlocked, SibylActionDenied, SibylActionHeld, SibylConfigError
from sibyl._ids import uuid7

if TYPE_CHECKING:
    from sibyl._client import Client

log = logging.getLogger("sibyl")

HOLD_PATH: Final = "/api/v1/held-actions"
DECISION_PATH: Final = "/api/v1/action-decisions"
FAIL_CLOSED_RULE: Final = "sibyl:fail_closed"
POLICY_MISSING_RULE: Final = "sibyl:policy_missing"
HOLD_FAILED_RULE: Final = "sibyl:hold_unavailable"
MAX_ARG_DEPTH: Final = 32
MAX_HELD_ARGS_CHARS: Final = 64 * 1024
Mode = Literal["wait", "async"]
_USABLE: Final = frozenset({"fresh", "stale"})
_FINAL_DENY: Final = frozenset({"denied", "expired", "cancelled"})


@dataclass(frozen=True, kw_only=True)
class ActionConfig:
    """Action Gate knobs. Holds wait at most `max_hold_wait` even if a policy allows longer."""

    enabled: bool = True
    api_timeout: timedelta = timedelta(seconds=5)
    hold_poll_interval: timedelta = timedelta(seconds=1)
    hold_poll_max_interval: timedelta = timedelta(seconds=5)
    max_hold_wait: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        if self.hold_poll_interval <= timedelta(0) or self.api_timeout <= timedelta(0):
            raise SibylConfigError("ActionConfig intervals must be positive")


def jsonable(value: Any, depth: int = 0) -> Any:
    """Tool arguments as JSON-like data for evaluation: Decimals become decimal strings (so
    amounts compare exactly), models are dumped, everything else unknown becomes its str."""
    if depth > MAX_ARG_DEPTH:
        return None
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [jsonable(v, depth + 1) for v in value]
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", "replace")
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return jsonable(dump(mode="json"), depth + 1)
        except Exception:  # a broken model dump must not break enforcement
            return str(value)
    return str(value)


@dataclass(frozen=True)
class Verdict:
    """What the gate let through: the decision and, for an approved hold, its id."""

    decision: Decision
    held_action_id: str | None = None


class ActionEnforcer:
    def __init__(
        self,
        client: Client,
        config: ActionConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client
        self._cfg = config
        self._transport = transport
        self._sleep = sleep
        self._http: httpx.Client | None = None

    # ------------------------------------------------------------------ public

    def check(
        self,
        tool: str,
        args: Any,
        *,
        sensitive: bool = False,
        mode: Mode = "wait",
        call_id: str | None = None,
        task_id: str | None = None,
    ) -> Verdict:
        decision = self.plan(tool, args, sensitive=sensitive)
        if decision is None:
            return Verdict(_ALLOW)
        return self._finish(tool, jsonable(args), decision, mode, call_id or str(uuid7()), task_id)

    async def acheck(
        self,
        tool: str,
        args: Any,
        *,
        sensitive: bool = False,
        mode: Mode = "wait",
        call_id: str | None = None,
        task_id: str | None = None,
    ) -> Verdict:
        """Async twin: evaluation is inline; control-plane I/O and waiting run in a thread so
        the event loop never blocks."""
        decision = self.plan(tool, args, sensitive=sensitive)
        if decision is None or (decision.effect is Effect.ALLOW and decision.needs_counter is None):
            return Verdict(decision or _ALLOW)
        return await asyncio.to_thread(
            self._finish, tool, jsonable(args), decision, mode, call_id or str(uuid7()), task_id
        )

    def plan(self, tool: str, args: Any, *, sensitive: bool = False) -> Decision | None:
        """The local decision, or None when there is nothing to enforce."""
        if not self._cfg.enabled:
            return None
        snap = self._client.snapshot
        freshness = snap.freshness_at(self._client.clock.time()) if snap else "unavailable"
        decision: Decision | None = None
        if snap is not None and snap.action_policy_missing:
            decision = _block(POLICY_MISSING_RULE, "an action policy is missing from the snapshot")
        elif snap is not None and snap.action_policies:
            decision = evaluate_all(snap.action_policies, tool, jsonable(args))
        is_sensitive = sensitive or (decision is not None and decision.sensitive)
        if is_sensitive and freshness not in _USABLE:
            return _block(
                FAIL_CLOSED_RULE, f"sensitive tool and no fresh policy snapshot ({freshness})"
            )
        return decision

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None

    # ------------------------------------------------------------------ enforcement

    def _finish(
        self,
        tool: str,
        args: Any,
        decision: Decision,
        mode: Mode,
        call_id: str,
        task_id: str | None,
    ) -> Verdict:
        if decision.needs_counter is not None:
            decision = self._counter(tool, args, decision, call_id)
        if decision.effect is Effect.ALLOW:
            return Verdict(decision)
        if decision.effect is Effect.BLOCK:
            self._telemetry(tool, decision, "blocked")
            raise SibylActionBlocked(tool, decision.rule_id, decision.reason)
        held = self._hold(tool, args, decision, call_id, task_id)
        if held is None:
            self._telemetry(tool, decision, "hold unavailable")
            raise SibylActionDenied(
                tool, None, "unavailable", "the action could not be held", rule_id=decision.rule_id
            )
        self._telemetry(tool, decision, f"held {held.held_action_id}")
        if mode == "async":
            raise SibylActionHeld(
                tool, held.held_action_id, decision.reason, rule_id=decision.rule_id
            )
        state = self._wait(held, decision)
        if state != "approved":
            self._telemetry(tool, decision, f"{state} {held.held_action_id}")
            raise SibylActionDenied(
                tool, held.held_action_id, state, decision.reason, rule_id=decision.rule_id
            )
        return Verdict(decision, held.held_action_id)

    def _counter(self, tool: str, args: Any, decision: Decision, call_id: str) -> Decision:
        need = decision.needs_counter
        agent = self._client.agent_id
        if need is None or agent is None or decision.policy_id is None:
            return decision
        body = ActionDecisionRequest(
            call_id=call_id,
            agent_id=str(agent),
            source="sdk",
            policy_id=decision.policy_id,
            policy_version=decision.policy_version or 1,
            rule_id=need.rule_id,
            tool=tool[:256] or "unknown",
            counter_key=need.counter_key,
            increment=need.increment,
            max=need.max,
            window_s=need.window_s,
            args_sha256=args_digest(args),
        )
        payload = self._post(DECISION_PATH, body.model_dump(mode="json", by_alias=True), call_id)
        if payload is None:
            return decision.model_copy(update={"needs_counter": None})  # stays on_exceed
        try:
            result = ActionDecisionResult.model_validate(payload)
        except ValueError:
            log.warning("sibyl: malformed action-decision response; failing closed")
            return decision.model_copy(update={"needs_counter": None})
        return apply_counter(decision, within_cap=result.within_cap)

    def _hold(
        self, tool: str, args: Any, decision: Decision, call_id: str, task_id: str | None
    ) -> HeldActionStatus | None:
        agent = self._client.agent_id
        if agent is None:
            return None
        scrubbed, _ = self._client.scrub.scrubber.scrub_json(args, "tool_args")
        if len(str(scrubbed)) > MAX_HELD_ARGS_CHARS:
            scrubbed = {"truncated": True}
        body: dict[str, Any] = HeldActionRequest(
            call_id=call_id,
            agent_id=str(agent),
            source="sdk",
            tool=tool[:256] or "unknown",
            args=scrubbed,
            args_sha256=args_digest(args),
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            rule_id=decision.rule_id,
            reason=decision.reason[:500],
            hold_timeout_s=decision.hold_timeout_s or 900,
        ).model_dump(mode="json", by_alias=True)
        if task_id:
            body["task_id"] = task_id
        obo = _obo.current()
        if obo is not None:
            body["on_behalf_of"] = obo  # WAVE3 frozen field (AG-LIVE owns the model)
        payload = self._post(HOLD_PATH, body, call_id)
        try:
            return None if payload is None else HeldActionStatus.model_validate(payload)
        except ValueError:
            log.warning("sibyl: malformed held-action response; denying")
            return None

    def _wait(self, held: HeldActionStatus, decision: Decision) -> str:
        if held.state != "pending":
            return held.state
        limit = min(float(decision.hold_timeout_s or 900), self._cfg.max_hold_wait.total_seconds())
        deadline = self._client.clock.monotonic() + limit
        interval = self._cfg.hold_poll_interval.total_seconds()
        ceiling = self._cfg.hold_poll_max_interval.total_seconds()
        while True:
            remaining = deadline - self._client.clock.monotonic()
            if remaining <= 0:
                return "timeout"
            self._sleep(min(interval, remaining))
            interval = min(ceiling, interval * 1.5)
            status = self._get(f"{HOLD_PATH}/{held.held_action_id}")
            if status is None:
                continue
            if status.state == "approved" or status.state in _FINAL_DENY:
                return status.state

    # ------------------------------------------------------------------ http

    def _http_client(self) -> httpx.Client:
        if self._http is None:
            settings = self._client.settings
            self._http = httpx.Client(
                base_url=settings.api_endpoint,
                timeout=self._cfg.api_timeout.total_seconds(),
                transport=self._transport,
                follow_redirects=False,
                headers={"Authorization": f"Bearer {settings.api_key}"},
            )
        return self._http

    def _post(self, path: str, body: dict[str, Any], call_id: str) -> Any:
        try:
            response = self._http_client().post(
                path, json=body, headers={"Idempotency-Key": call_id}
            )
        except httpx.HTTPError as exc:
            log.warning("sibyl: %s failed (%s); failing closed", path, type(exc).__name__)
            return None
        if response.status_code not in (200, 201):
            log.warning("sibyl: %s answered HTTP %s; failing closed", path, response.status_code)
            return None
        try:
            return response.json()
        except ValueError:
            return None

    def _get(self, path: str) -> HeldActionStatus | None:
        try:
            response = self._http_client().get(path)
            if response.status_code != 200:
                return None
            return HeldActionStatus.model_validate(response.json())
        except (httpx.HTTPError, ValueError):
            return None

    def _telemetry(self, tool: str, decision: Decision, outcome: str) -> None:
        snap = self._client.snapshot
        state = snap.freshness_at(self._client.clock.time()) if snap else "none"
        reason = f"{outcome}: {tool[:60]} rule={decision.rule_id}: {decision.reason}"
        try:
            self._client._emit_decision(
                {
                    "action": "tool_blocked",
                    "state": "none" if state == "unavailable" else state,
                    "fail_mode": snap.fail_mode if snap else "open",
                    "reason": reason[:200],
                }
            )
        except Exception:
            log.exception("sibyl: could not emit the action decision")


_ALLOW = Decision(effect=Effect.ALLOW, rule_id=None, reason="no action policy applies")


def _block(rule_id: str, reason: str) -> Decision:
    return Decision(effect=Effect.BLOCK, rule_id=rule_id, reason=reason, sensitive=True)
