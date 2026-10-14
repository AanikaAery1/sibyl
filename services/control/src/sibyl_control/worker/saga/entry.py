"""Opening sagas: the one entry point for detected, predicted and operator-initiated incidents.

``open_saga`` inserts the ``failover`` row (idempotent on ``idempotency_key``; at most one live
saga per agent, else ``saga_in_flight``). ``open_predicted`` is lane P's entry: it applies tier
gating (ML §4.5: D13 approval on tier 1, D39 ``degrade_then_auto`` on tier 2, the D36 release
gate, the per-agent breaker, the D21 hold) and then opens the saga, degrades, or does nothing.
Both run inside the caller's tenant transaction and never commit on their own.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID

import asyncpg

from ...core.outbox import OutboxMessage, PgOutboxWriter
from . import engine, routing
from .gating import at_least, decide_predicted
from .model import (
    DEGRADE_THEN_AUTO,
    LIVE_STATES,
    Actor,
    Env,
    SagaError,
    SagaOpen,
)

if TYPE_CHECKING:
    from ...core.settings import Settings

AUDIT_LOCK_SQL = "SELECT sibyl.audit_lock($1)"
PREDICT_WORKER_ID = "predict"
_LIVE_SQL = (
    "SELECT id FROM sibyl.failover WHERE tenant_id = $1 AND agent_id = $2"
    " AND state = ANY($3::text[]) LIMIT 1"
)
_INSERT_SQL = """
INSERT INTO sibyl.failover (tenant_id, agent_id, kind, state, step, priority, idempotency_key,
  request_idempotency_key, trigger_alert_id, rule_codes, health_snapshot_id, actor_kind,
  actor_key_id, requested_by_user_id, from_state, step_results, next_action_at, max_attempts,
  claimed_by, claim_lock_until)
VALUES ($1, $2, $3, $4, 'validate', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb,
        now() + $16::interval, $17, $18, CASE WHEN $18::text IS NULL THEN NULL ELSE now() END)
RETURNING *
"""


async def live_saga(conn: Any, tenant: UUID, agent_id: UUID) -> UUID | None:
    value: UUID | None = await conn.fetchval(_LIVE_SQL, tenant, agent_id, list(LIVE_STATES))
    return value


def _open_info(req: SagaOpen) -> dict[str, Any]:
    return {
        "trigger": req.trigger,
        "actor_rule_id": None if req.actor.rule_id is None else str(req.actor.rule_id),
        "actor_session_id": None if req.actor.session_id is None else str(req.actor.session_id),
        "target": req.target.as_json() if req.target is not None else None,
        "failure_mode": req.failure_mode,
        "reason": req.reason,
        "alert_ids": [str(a) for a in req.alert_ids],
        "batch": dict(req.batch) if req.batch else None,
        "excluded_provider_ids": [str(p) for p in req.excluded_provider_ids],
        "prediction": dict(req.prediction) if req.prediction else None,
        "degrade_then_auto": req.degrade_then_auto,
    }


async def open_saga(
    conn: Any,
    tenant: UUID,
    req: SagaOpen,
    *,
    inline: bool = False,
    extra_results: Mapping[str, Any] | None = None,
    env: Env | None = None,
) -> tuple[dict[str, Any], bool]:
    """Insert the saga row; ``(row, created)``. ``inline`` = the api runs it in this request."""
    existing = await conn.fetchrow(
        "SELECT * FROM sibyl.failover WHERE tenant_id = $1 AND idempotency_key = $2",
        tenant,
        req.idempotency_key,
    )
    if existing is not None:
        return dict(existing), False
    live = await live_saga(conn, tenant, req.agent_id)
    if live is not None:
        raise SagaError("saga_in_flight", extensions={"incident_id": str(live)})
    state = await routing.state_of(conn, tenant, req.agent_id)
    if state is None:
        raise SagaError("invalid_transition", "the agent has no routing state yet")
    results = {"open": _open_info(req), **dict(extra_results or {})}
    try:
        async with conn.transaction():
            row = await conn.fetchrow(
                _INSERT_SQL,
                tenant,
                req.agent_id,
                req.kind,
                "running" if inline else "pending",
                req.priority,
                req.idempotency_key,
                req.request_idempotency_key,
                req.trigger_alert_id,
                list(req.rule_codes),
                req.health_snapshot_id,
                req.actor.kind,
                req.actor.key_id if req.actor.kind == "api_key" else None,
                req.actor.user_id if req.actor.kind == "human" else None,
                state["state"],
                results,
                req.delay,
                req.max_attempts,
                "api" if inline else None,
            )
    except asyncpg.UniqueViolationError:
        live = await live_saga(conn, tenant, req.agent_id)
        raise SagaError(
            "saga_in_flight", extensions={"incident_id": str(live) if live else None}
        ) from None
    outbox = env.outbox if env is not None else PgOutboxWriter()
    await outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "incident.updated",
            "failover",
            row["id"],
            {
                "incident_id": str(row["id"]),
                "agent_id": str(req.agent_id),
                "state": row["state"],
                "step": row["step"],
            },
        ),
    )
    return dict(row), True


# --- lane P entry -----------------------------------------------------------------------------


@dataclass(frozen=True)
class PredictedTrigger:
    """A 15-minute prediction for one agent, as lane P hands it over (frozen ``Prediction``)."""

    agent_id: UUID
    band: str  # probability_band of the 15 m horizon
    confidence: str
    contributing_rules: Sequence[str]
    predicted_failure_mode: str | None = None
    horizon_s: int = 900
    prediction_id: UUID | None = None
    health_snapshot_id: UUID | None = None
    alert_id: UUID | None = None


@dataclass(frozen=True)
class PredictedOutcome:
    action: str  # none | watch | suppressed | degrade | degrade_then_auto | saga | approval
    reason: str
    failover_id: UUID | None = None


async def _rule_id(conn: Any, tenant: UUID, codes: Sequence[str]) -> UUID | None:
    if not codes:
        return None
    value: UUID | None = await conn.fetchval(
        "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = $2", tenant, codes[0]
    )
    return value


async def _degrade_now(
    conn: Any, env: Env, tenant: UUID, row: dict[str, Any], actor: Actor, codes: Sequence[str]
) -> dict[str, Any]:
    applied = await routing.apply(
        conn,
        tenant,
        row["agent_id"],
        expected_from="active",
        to_state="degraded",
        trigger="rule",
        actor=actor,
        idempotency_key=f"failover:{row['id']}:degrade",
        audit_action="route.changed",
        failover_id=row["id"],
        rule_codes=list(codes),
        health_snapshot_id=row.get("health_snapshot_id"),
        reason="predicted failure: degraded mode while the prediction is confirmed",
    )
    return {"transition_id": str(applied.transition_id), "routing_version": applied.routing_version}


async def open_predicted(
    conn: Any, tenant: UUID, trig: PredictedTrigger, *, env: Env
) -> PredictedOutcome:
    """Gate one 15 m prediction and act on it. The D36 gate is ``env.automation_band``
    (``Settings.predicted_automation_band``), so the caller passes its Settings-built ``Env``."""
    agent = await conn.fetchrow(
        "SELECT a.tier, p.preemptive_mode FROM sibyl.agent a LEFT JOIN sibyl.continuity_plan p"
        " ON p.tenant_id = a.tenant_id AND p.agent_id = a.id WHERE a.tenant_id = $1 AND a.id = $2",
        tenant,
        trig.agent_id,
    )
    state = await routing.state_of(conn, tenant, trig.agent_id)
    if agent is None or state is None:
        return PredictedOutcome("none", "unknown agent or no routing state")
    if await routing.hold_active(conn, tenant, trig.agent_id):
        await engine.suppress_for_hold(conn, tenant, trig.alert_id)
        return PredictedOutcome("suppressed", "operator hold (D21)")
    if state["state"] not in ("active", "degraded"):
        return PredictedOutcome("none", f"agent is {state['state']}")
    if await live_saga(conn, tenant, trig.agent_id) is not None:
        return PredictedOutcome("none", "saga_in_flight")
    decision = decide_predicted(
        tier=int(agent["tier"]),
        horizon_s=trig.horizon_s,
        band=trig.band,
        confidence=trig.confidence,
        contributing_rules=trig.contributing_rules,
        preemptive_mode=agent["preemptive_mode"],
        breaker_open=await engine.breaker_open(conn, tenant, trig.agent_id),
        automation_band=env.automation_band,
    )
    if decision.action in ("none", "watch"):
        return PredictedOutcome(decision.action, decision.reason)
    return await _execute(
        conn,
        env,
        tenant,
        trig,
        state["state"],
        action=decision.action,
        reason=decision.reason,
        mode=decision.mode,
        persist_band=env.automation_band,
    )


async def _execute(
    conn: Any,
    env: Env,
    tenant: UUID,
    trig: PredictedTrigger,
    routing_state: str,
    *,
    action: str,
    reason: str,
    mode: str | None,
    persist_band: str,
) -> PredictedOutcome:
    """Open the gated saga: ``degrade`` (done at once), ``degrade_then_auto`` (degrade now,
    failover after 20 s if the prediction persists), ``saga`` (automatic) or ``approval``."""
    if action == "degrade" and routing_state != "active":
        return PredictedOutcome("none", "already degraded")
    codes = tuple(trig.contributing_rules)
    actor = Actor("rule", rule_id=await _rule_id(conn, tenant, codes))
    key_basis = trig.prediction_id or trig.health_snapshot_id
    if key_basis is None:
        key_basis = await conn.fetchval("SELECT sibyl.uuidv7()")
    req = SagaOpen(
        agent_id=trig.agent_id,
        actor=actor,
        trigger="predicted",
        idempotency_key=f"predicted:{trig.agent_id}:{key_basis}",
        kind="degrade" if action == "degrade" else "preemptive",
        trigger_alert_id=trig.alert_id,
        rule_codes=codes,
        health_snapshot_id=trig.health_snapshot_id,
        failure_mode=trig.predicted_failure_mode,
        prediction={
            "band": trig.band,
            "confidence": trig.confidence,
            "prediction_id": None if trig.prediction_id is None else str(trig.prediction_id),
            "decision": action,
            "mode": mode,
            "persist_band": persist_band,
        },
        degrade_then_auto=action == "degrade_then_auto",
        delay=DEGRADE_THEN_AUTO if action == "degrade_then_auto" else timedelta(0),
    )
    row, created = await open_saga(conn, tenant, req, inline=action == "degrade", env=env)
    if not created:
        return PredictedOutcome(action, "already opened", row["id"])
    needs_degrade = action in ("degrade", "degrade_then_auto") and routing_state == "active"
    if needs_degrade:
        degraded = await _degrade_now(conn, env, tenant, row, actor, codes)
        changes: dict[str, Any] = {"step_results": engine.with_result(row, "degrade", degraded)}
        if action == "degrade":
            changes.update(
                state="done",
                step="done",
                to_state="degraded",
                routing_transition_id=UUID(degraded["transition_id"]),
                finished_at=await conn.fetchval("SELECT now()"),
                claim_lock_until=None,
            )
        else:
            changes["routing_transition_id"] = UUID(degraded["transition_id"])
        row = await engine.save(conn, env, tenant, row, **changes)
    return PredictedOutcome(action, reason, row["id"])


HORIZON_S = {"15m": 900, "1h": 3600, "24h": 86400}
MODE_ACTION = {"approval": "approval", "degrade_then_auto": "degrade_then_auto", "auto": "saga"}


async def request_predicted_failover(
    conn: Any,
    tenant_id: UUID,
    agent_id: UUID,
    prediction_id: UUID,
    horizon: str,
    band: str,
    confidence: str,
    *,
    mode: Literal["approval", "degrade_then_auto", "auto"],
    settings: Settings,
) -> UUID | None:
    """Lane P's entry (agreed signature): P has already applied tier gating, the D36 release
    gate and the per-agent breaker; ``mode`` is the result. Called once per rising edge of the
    15 m gate crossing inside P's tenant transaction (the prediction row is visible).

    S still owns: the D21 hold (declined, ``hold_suppressed_count`` counted), ``saga_in_flight``
    (the live saga is joined: its id is returned), viability, the D22 forced hold at approval
    timeout and the 20 s ``degrade_then_auto`` timer. Returns the failover id created or
    joined, or ``None`` when declined.

    ``settings`` is the worker's ``Settings`` (B20): the ``Env`` is built from it exactly as the
    saga loop builds its own (``runner.worker_env``), so the 20 s persistence floor is the
    deployment's D36 band, never a hard-coded one or a tenant value. It is required: the
    predict loop passes its ``ctx.settings`` (B20). The tenant's audit lock is taken here,
    before any row is locked or audit row appended (CR-P2; a no-op when the caller already
    holds it).
    """
    from .runner import worker_env  # runner -> detect -> entry: resolved at call time

    env = worker_env(settings, wid=PREDICT_WORKER_ID)
    if HORIZON_S.get(horizon) != 900 or mode not in MODE_ACTION:
        return None
    if mode != "approval" and not at_least(band, env.automation_band):
        # B20 at the saga boundary (fail closed): an automated mode below the deployment's D36
        # band is never acted on, whatever band the caller gated with.
        return None
    await conn.execute(AUDIT_LOCK_SQL, tenant_id)
    pred = await conn.fetchrow(
        "SELECT contributions, predicted_failure_mode, health_snapshot_id FROM sibyl.prediction"
        " WHERE tenant_id = $1 AND id = $2 AND agent_id = $3 LIMIT 1",
        tenant_id,
        prediction_id,
        agent_id,
    )
    rules = _contributing_rules(pred["contributions"] if pred is not None else None)
    trig = PredictedTrigger(
        agent_id=agent_id,
        band=band,
        confidence=confidence,
        contributing_rules=rules,
        predicted_failure_mode=pred["predicted_failure_mode"] if pred is not None else None,
        prediction_id=prediction_id,
        health_snapshot_id=pred["health_snapshot_id"] if pred is not None else None,
    )
    state = await routing.state_of(conn, tenant_id, agent_id)
    if state is None or state["state"] not in ("active", "degraded"):
        return None
    if await routing.hold_active(conn, tenant_id, agent_id):
        return None
    live = await live_saga(conn, tenant_id, agent_id)
    if live is not None:
        return live
    outcome = await _execute(
        conn,
        env,
        tenant_id,
        trig,
        state["state"],
        action=MODE_ACTION[mode],
        reason=f"lane P gated: {mode}",
        mode=mode,
        persist_band=env.automation_band,
    )
    return outcome.failover_id


def _contributing_rules(contributions: Any) -> tuple[str, ...]:
    """Rule codes from ``prediction.contributions`` (a list of ``{rule|rule_id|code, ...}``)."""
    out: list[str] = []
    for item in contributions or []:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            code = item.get("rule") or item.get("rule_id") or item.get("code")
            if isinstance(code, str):
                out.append(code)
    return tuple(out)
