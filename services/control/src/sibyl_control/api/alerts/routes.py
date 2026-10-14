"""Alert routes (API.md §5.9, §6.5; D24, D33, R29, R42).

* ``GET /alerts``: filters from the contract plus ``unverdicted=true``, the D33 queue (resolved
  alerts without a verdict, ``verdict_wanted`` first) with the backlog SLI in the envelope.
* ``GET /alerts/{id}``: the alert, its fire-time ``sibyl-health/1`` snapshot, the provider
  incident when collapsed, the failover (``incident_id``) and the verdict.
* ``POST /alerts/{id}/actions``: ``ack``, ``silence`` (``until``), ``close`` with a mandatory
  verdict (422 ``verdict_required``). ``close`` writes ``label(kind=alert_verdict,
  label_strength=verdict)`` and ``alert.verdict`` in one transaction; on a resolved,
  unverdicted alert it is allowed exactly once (409 ``already_resolved`` after). A verdict on a
  provider-scope alert propagates to its incident's resolved, unverdicted member alerts
  (``labeller.kind=worker``, ML.md §3.7).

Group-limited principals see only alerts of agents in their groups; provider- and
platform-scope alerts are tenant-wide resources (404 to a group-limited caller).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.etag import etag_for_row
from ...core.outbox import OutboxMessage
from ...core.problems import ProblemError
from ...worker.alerts.lifecycle import backlog_sli
from ..auth.common import parse_uuid
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..reads.agents import health_document
from ..registry._kit import (
    JSON,
    Outcome,
    PageQuery,
    audit,
    jsonable,
    keyset_page,
    run_read,
    run_write,
    services_of,
    user_id,
)
from .models import AlertAction
from .views import ALERT_SELECT, alert_view

router = APIRouter()

MAX_SILENCE = timedelta(days=30)
STATES = ("open", "acked", "resolved")
SEVERITIES = ("info", "warning", "critical")

_SNAPSHOT_SQL = (
    "SELECT h.*, coalesce((c.config #>> '{provisional,min_requests_1h}')::int, 50) AS events_needed"
    " FROM sibyl.health_snapshot h LEFT JOIN sibyl.scoring_config c ON c.tenant_id = h.tenant_id"
    " AND c.id = h.scoring_config_id WHERE h.tenant_id = $1 AND h.agent_id = $2 AND h.id = $3"
    " AND h.evaluated_at >= $4"
)
_INCIDENT_SQL = (
    "SELECT id, provider_id, state, severity, started_at, resolved_at, affected_agent_ids"
    " FROM sibyl.provider_incident WHERE tenant_id = $1 AND id = $2"
)


def _etag(row: Any) -> str:
    return etag_for_row(row["updated_at"], row["id"])


def _group_of(row: Any) -> UUID | None:
    """The resource group for the object rule; non-agent alerts have none (tenant-wide)."""
    return row["agent_group_id"] if row["scope"] == "agent" else None


async def _load(conn: Any, tenant: UUID, alert_id: UUID, *, lock: bool = False) -> Any:
    sql = ALERT_SELECT.format(where="AND a.id = $2")
    row = await conn.fetchrow(sql, tenant, alert_id)
    if row is None:
        raise ProblemError("not_found")
    if lock:
        await conn.execute(
            "SELECT 1 FROM sibyl.alert WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            tenant,
            alert_id,
        )
        row = await conn.fetchrow(sql, tenant, alert_id)
    return row


# ---------------------------------------------------------------------------- reads


@router.get(API_PREFIX + "/alerts")
async def list_alerts(
    ctx: Annotated[AuthContext, Depends(guard("listAlerts"))],
    state: Annotated[str | None, Query(max_length=20)] = None,
    severity: Annotated[str | None, Query(max_length=20)] = None,
    agent_id: UUID | None = None,
    provider_id: UUID | None = None,
    rule_code: Annotated[str | None, Query(max_length=41)] = None,
    include_suppressed: bool = False,
    since: datetime | None = None,
    unverdicted: bool = False,
    limit: int | None = None,
    cursor: str | None = None,
) -> Response:
    if state is not None and state not in STATES:
        raise ProblemError("validation_failed", "state is open, acked or resolved")
    if severity is not None and severity not in SEVERITIES:
        raise ProblemError("validation_failed", "severity is info, warning or critical")
    page = PageQuery.of(
        limit,
        cursor,
        state=state,
        severity=severity,
        agent_id=agent_id,
        provider_id=provider_id,
        rule_code=rule_code,
        include_suppressed=include_suppressed,
        since=since,
        unverdicted=unverdicted,
    )

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        where: list[str] = []

        def add(clause: str, value: Any) -> None:
            args.append(value)
            where.append(clause.format(n=len(args)))

        if state is not None:
            add("a.state = ${n}", state)
        if severity is not None:
            add("a.severity = ${n}", severity)
        if agent_id is not None:
            add("a.agent_id = ${n}", agent_id)
        if provider_id is not None:
            add("a.provider_id = ${n}", provider_id)
        if rule_code is not None:
            add("r.code = ${n}", rule_code)
        if since is not None:
            add("a.first_fired_at >= ${n}", since)
        if not include_suppressed:
            where.append("NOT a.suppressed_by_incident")
        if unverdicted:
            where.append("a.state = 'resolved' AND a.verdict IS NULL")
        groups = ctx.group_filter()
        if groups is not None:
            add("a.scope = 'agent' AND g.agent_group_id = ANY(${n}::uuid[])", list(groups))
        sql = ALERT_SELECT.format(where="".join(f" AND {w}" for w in where))
        if unverdicted:
            outcome = await keyset_page(
                conn,
                ctx,
                select=sql,
                args=args,
                page=page,
                keys=("vw", "resolved_at", "id"),
                key_types="itu",
                descending=True,
                serialize=alert_view,
            )
            sli = await backlog_sli(conn, ctx.tenant_id, ctx.now)
            outcome.body["backlog"] = sli.as_json()
            return outcome
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("first_fired_at", "id"),
            descending=True,
            serialize=alert_view,
        )

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/alerts/{alert_id}")
async def get_alert(
    alert_id: str, ctx: Annotated[AuthContext, Depends(guard("getAlert"))]
) -> Response:
    aid = parse_uuid(alert_id)

    async def work(conn: Any) -> Outcome:
        row = await _load(conn, ctx.tenant_id, aid)
        ctx.check(resource_group_id=_group_of(row))
        body = alert_view(row)
        body["health_snapshot"] = None
        if row["health_snapshot_id"] is not None and row["agent_id"] is not None:
            snap = await conn.fetchrow(
                _SNAPSHOT_SQL,
                ctx.tenant_id,
                row["agent_id"],
                row["health_snapshot_id"],
                row["first_fired_at"] - timedelta(minutes=5),
            )
            if snap is not None:
                body["health_snapshot"] = health_document(ctx.tenant_id, snap)
        body["provider_incident"] = None
        if row["provider_incident_id"] is not None:
            inc = await conn.fetchrow(_INCIDENT_SQL, ctx.tenant_id, row["provider_incident_id"])
            if inc is not None:
                body["provider_incident"] = {
                    "id": str(inc["id"]),
                    "provider_id": str(inc["provider_id"]),
                    "state": inc["state"],
                    "severity": inc["severity"],
                    "opened_at": jsonable(inc["started_at"]),
                    "affected_agent_ids": [str(a) for a in inc["affected_agent_ids"] or ()],
                }
        return Outcome(body, etag=_etag(row))

    return await run_read(ctx, work)


# ---------------------------------------------------------------------------- actions


@router.post(API_PREFIX + "/alerts/{alert_id}/actions")
async def act_on_alert(
    alert_id: str,
    body: AlertAction,
    ctx: Annotated[AuthContext, Depends(guard("actOnAlert"))],
) -> Response:
    aid = parse_uuid(alert_id)
    if body.action == "close" and body.verdict is None:
        raise ProblemError("verdict_required", "closing an alert needs a verdict: tp, fp or unsure")
    if body.action == "silence":
        if body.until is None:
            raise ProblemError("validation_failed", "silence needs `until`")
        if body.until.tzinfo is None:
            raise ProblemError("validation_failed", "`until` must carry a timezone")

    async def work(conn: Any) -> Outcome:
        row = await _load(conn, ctx.tenant_id, aid, lock=True)
        ctx.action(body.action, resource_group_id=_group_of(row))
        if body.action == "ack":
            return await _ack(conn, ctx, row, body)
        if body.action == "silence":
            return await _silence(conn, ctx, row, body)
        return await _close(conn, ctx, row, body)

    return await run_write(ctx, work, idempotent=True)


async def _emit(conn: Any, ctx: AuthContext, row: Any, event: str) -> None:
    payload: JSON = {
        "alert_id": str(row["id"]),
        "rule": row["rule_code"],
        "severity": row["severity"],
        "scope": row["scope"],
        "state": row["state"],
    }
    for key in ("agent_id", "provider_id", "provider_incident_id"):
        if row[key] is not None:
            payload[key] = str(row[key])
    if row["verdict"] is not None:
        payload["verdict"] = row["verdict"]
    message = OutboxMessage("alert", event, "alert", row["id"], payload)
    await services_of(ctx).outbox.emit(conn, ctx.tenant_id, message)


async def _respond(conn: Any, ctx: AuthContext, alert: UUID, receipt: Any, event: str) -> Outcome:
    row = await _load(conn, ctx.tenant_id, alert)
    await _emit(conn, ctx, row, event)
    return Outcome(alert_view(row), etag=_etag(row), receipt=receipt)


async def _ack(conn: Any, ctx: AuthContext, row: Any, body: AlertAction) -> Outcome:
    if row["state"] == "resolved":
        raise ProblemError("already_resolved")
    if row["state"] != "open":
        raise ProblemError(
            "invalid_transition", f"alert is {row['state']}; only open alerts are acked"
        )
    await conn.execute(
        "UPDATE sibyl.alert SET state = 'acked', acked_at = $3, acked_by_user_id = $4"
        " WHERE tenant_id = $1 AND id = $2",
        ctx.tenant_id,
        row["id"],
        ctx.now,
        user_id(ctx),
    )
    receipt = await audit(
        conn,
        ctx,
        "alert.acked",
        resource_type="alert",
        resource_id=row["id"],
        resource_ref=row["dedupe_key"],
        reason=body.reason,
        detail={"alert_id": row["id"]},
    )
    return await _respond(conn, ctx, row["id"], receipt, "alert.updated")


async def _silence(conn: Any, ctx: AuthContext, row: Any, body: AlertAction) -> Outcome:
    until = body.until
    assert until is not None
    if row["state"] == "resolved":
        raise ProblemError("already_resolved")
    if until <= ctx.now or until > ctx.now + MAX_SILENCE:
        raise ProblemError("validation_failed", "`until` is in the future and at most 30 days away")
    await conn.execute(
        "UPDATE sibyl.alert SET state = 'acked', silenced_until = $3, silenced_by_user_id = $4,"
        " acked_at = coalesce(acked_at, $5), acked_by_user_id = coalesce(acked_by_user_id, $4)"
        " WHERE tenant_id = $1 AND id = $2",
        ctx.tenant_id,
        row["id"],
        until,
        user_id(ctx),
        ctx.now,
    )
    receipt = await audit(
        conn,
        ctx,
        "alert.silenced",
        resource_type="alert",
        resource_id=row["id"],
        resource_ref=row["dedupe_key"],
        reason=body.reason,
        detail={"alert_id": row["id"], "until": until},
    )
    return await _respond(conn, ctx, row["id"], receipt, "alert.updated")


_LABEL_SQL = """
INSERT INTO sibyl.label (tenant_id, agent_id, kind, label_strength, judges_kind, judges_id,
  window_start, window_end, feature_snapshot_id, judged_as_of, labeller_kind, labeller_ref, value,
  reason)
VALUES ($1, $2, 'alert_verdict', 'verdict', 'alert', $3, $4, $5, $6, $4, $7, $8, $9::jsonb, $10)
RETURNING id
"""


async def _feature_snapshot(conn: Any, tenant: UUID, row: Any) -> UUID | None:
    if row["health_snapshot_id"] is None or row["agent_id"] is None:
        return None
    return await conn.fetchval(  # type: ignore[no-any-return]
        "SELECT feature_snapshot_id FROM sibyl.health_snapshot WHERE tenant_id = $1"
        " AND agent_id = $2 AND id = $3 AND evaluated_at >= $4",
        tenant,
        row["agent_id"],
        row["health_snapshot_id"],
        row["first_fired_at"] - timedelta(minutes=5),
    )


async def _label_agents(conn: Any, tenant: UUID, row: Any) -> list[UUID]:
    """Labels judge one agent each; a provider-scope verdict labels the incident's agents."""
    if row["agent_id"] is not None:
        return [row["agent_id"]]
    agents: list[UUID] = []
    if row["provider_incident_id"] is not None:
        affected = await conn.fetchval(
            "SELECT affected_agent_ids FROM sibyl.provider_incident WHERE tenant_id = $1 AND id ="
            " $2",
            tenant,
            row["provider_incident_id"],
        )
        members = await conn.fetch(
            "SELECT DISTINCT agent_id FROM sibyl.alert WHERE tenant_id = $1"
            " AND provider_incident_id = $2 AND agent_id IS NOT NULL",
            tenant,
            row["provider_incident_id"],
        )
        agents = sorted({*(affected or ()), *(m["agent_id"] for m in members)}, key=str)
    return agents


async def _write_labels(
    conn: Any,
    ctx: AuthContext,
    row: Any,
    agents: list[UUID],
    *,
    labeller: str,
    ref: str | None,
    note: str | None,
    verdict: str,
) -> list[UUID]:
    end = row["resolved_at"] or ctx.now
    fs = await _feature_snapshot(conn, ctx.tenant_id, row)
    ids = []
    for agent in agents:
        ids.append(
            await conn.fetchval(
                _LABEL_SQL,
                ctx.tenant_id,
                agent,
                str(row["id"]),
                row["first_fired_at"],
                max(end, row["first_fired_at"]),
                fs if agent == row["agent_id"] else None,
                labeller,
                ref,
                {"verdict": verdict, "alert_id": str(row["id"]), "rule": row["rule_code"]},
                note,
            )
        )
    return ids


async def _close(conn: Any, ctx: AuthContext, row: Any, body: AlertAction) -> Outcome:
    verdict = body.verdict
    assert verdict is not None
    if row["verdict"] is not None:
        raise ProblemError("already_resolved", "this alert already has a verdict")
    agents = await _label_agents(conn, ctx.tenant_id, row)
    if not agents:
        raise ProblemError(
            "invalid_transition", "a provider alert with no affected agents cannot be labelled yet"
        )
    actor = user_id(ctx)
    labels = await _write_labels(
        conn,
        ctx,
        row,
        agents,
        labeller="operator",
        ref=str(actor) if actor else None,
        note=body.verdict_note,
        verdict=verdict,
    )
    was_open = row["state"] != "resolved"
    await conn.execute(
        "UPDATE sibyl.alert SET verdict = $3, verdict_label_id = $4,"
        " state = 'resolved', resolved_at = coalesce(resolved_at, $5), silenced_until = NULL"
        " WHERE tenant_id = $1 AND id = $2",
        ctx.tenant_id,
        row["id"],
        verdict,
        labels[0],
        ctx.now,
    )
    propagated = await _propagate(conn, ctx, row, verdict, labels[0])
    receipt = await audit(
        conn,
        ctx,
        "alert.labelled",
        resource_type="alert",
        resource_id=row["id"],
        resource_ref=row["dedupe_key"],
        reason=body.reason,
        detail={
            "alert_id": row["id"],
            "verdict": verdict,
            "label_id": labels[0],
            "propagated_to": propagated,
        },
    )
    return await _respond(
        conn, ctx, row["id"], receipt, "alert.resolved" if was_open else "alert.updated"
    )


async def _propagate(
    conn: Any, ctx: AuthContext, row: Any, verdict: str, source_label: UUID
) -> list[UUID]:
    """A provider-scope verdict judges the incident: label its resolved, unverdicted members."""
    if row["scope"] != "provider" or row["provider_incident_id"] is None:
        return []
    members = await conn.fetch(
        ALERT_SELECT.format(
            where="AND a.provider_incident_id = $2 AND a.id <> $3 AND a.state = 'resolved'"
            " AND a.verdict IS NULL AND a.agent_id IS NOT NULL"
        ),
        ctx.tenant_id,
        row["provider_incident_id"],
        row["id"],
    )
    done: list[UUID] = []
    for member in members:
        (label,) = await _write_labels(
            conn,
            ctx,
            member,
            [member["agent_id"]],
            labeller="worker",
            ref=str(source_label),
            note=None,
            verdict=verdict,
        )
        await conn.execute(
            "UPDATE sibyl.alert SET verdict = $3, verdict_label_id = $4 WHERE tenant_id = $1 AND"
            " id = $2",
            ctx.tenant_id,
            member["id"],
            verdict,
            label,
        )
        done.append(member["id"])
    return done


__all__ = ["router"]
