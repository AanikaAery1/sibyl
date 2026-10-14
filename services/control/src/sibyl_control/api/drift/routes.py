"""``/drift`` and ``/agents/{agent_id}/drift`` (D51): read the fleet's and one agent's drift,
read one report, and reset an agent's baselines.

A reset supersedes the matching current baselines and starts new ``collecting`` ones from
``since`` (default now; a past ``since`` lets the next drift tick re-freeze on recent traffic),
resolves the open ``silent_drift`` / ``model_change`` alerts on those keys (the change was
acknowledged) and is audited ``drift.baseline_reset`` with the operator's reason. Drift never
changes routing, so no snapshot or outbox policy event follows.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sibyl_schemas.models.drift import DriftBaselineReset

from ...core.problems import ProblemError
from ...worker.drift.alerts import MODEL_CHANGE, RULES, SILENT_DRIFT, AlertWriter, dedupe_key
from ...worker.drift.config import DEFAULT_CONFIG
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    Outcome,
    PageQuery,
    audit,
    keyset_page,
    load_agent,
    run_read,
    run_write,
    services_of,
    user_id,
)
from . import views

router = APIRouter()
HISTORY = 48
HISTORY_MAX = 500
_CODES = list(RULES)
_VERDICTS = "^(none|watch|drift)$"
_STATES = "^(collecting|frozen)$"

_LATEST = """
LEFT JOIN LATERAL (
  SELECT r.id AS report_id, r.evaluated_at, r.verdict, r.identity_changed, r.max_ratio, r.features
    FROM sibyl.drift_report r
   WHERE r.tenant_id = b.tenant_id AND r.baseline_id = b.id
   ORDER BY r.evaluated_at DESC
   LIMIT 1) lr ON true
"""
# Both statements are concatenations of constant fragments (no input reaches them).
_LIST_SQL = (
    "SELECT b.id, b.agent_id, a.name AS agent_name, b.provider, b.model, b.state, b.frozen_at,"  # noqa: S608
    " b.sample_count, b.created_at, lr.report_id, lr.evaluated_at, lr.verdict,"
    " lr.identity_changed, lr.max_ratio, lr.features"
    " FROM sibyl.drift_baseline b JOIN sibyl.agent a ON a.tenant_id = b.tenant_id"
    " AND a.id = b.agent_id" + _LATEST + " WHERE b.tenant_id = $1 AND b.state <> 'superseded'"
)
_SUMMARY_SQL = (
    "SELECT count(*) AS baselines,"  # noqa: S608
    " count(*) FILTER (WHERE b.state = 'collecting') AS collecting,"
    " count(*) FILTER (WHERE b.state = 'frozen') AS frozen,"
    " count(*) FILTER (WHERE lr.verdict = 'drift') AS drift,"
    " count(*) FILTER (WHERE lr.verdict = 'watch') AS watch,"
    " count(*) FILTER (WHERE lr.identity_changed) AS identity_changed,"
    " (SELECT count(*) FROM sibyl.alert al JOIN sibyl.alert_rule ar ON ar.tenant_id = al.tenant_id"
    "   AND ar.id = al.rule_id WHERE al.tenant_id = $1 AND al.state <> 'resolved'"
    "   AND ar.code = ANY($2::text[])) AS open_alerts"
    " FROM sibyl.drift_baseline b" + _LATEST + " WHERE b.tenant_id = $1 AND b.state <> 'superseded'"
)
_CURRENT_SQL = (
    "SELECT * FROM sibyl.drift_baseline WHERE tenant_id = $1 AND agent_id = $2"
    " AND state <> 'superseded' ORDER BY provider, model"
)
_LATEST_REPORTS_SQL = (
    "SELECT DISTINCT ON (r.baseline_id) r.* FROM sibyl.drift_report r"
    " JOIN sibyl.drift_baseline b ON b.tenant_id = r.tenant_id AND b.id = r.baseline_id"
    " AND b.state <> 'superseded'"
    " WHERE r.tenant_id = $1 AND r.agent_id = $2 ORDER BY r.baseline_id, r.evaluated_at DESC"
)
_HISTORY_SQL = (
    "SELECT id, baseline_id, evaluated_at, verdict, behaviour_evaluated, identity_changed,"
    " max_ratio, sample_count FROM sibyl.drift_report WHERE tenant_id = $1 AND agent_id = $2"
    " AND ($4::timestamptz IS NULL OR evaluated_at >= $4)"
    " ORDER BY evaluated_at DESC, id DESC LIMIT $3"
)
_ALERTS_SQL = (
    "SELECT al.id, ar.code, al.severity, al.state, al.first_fired_at, al.summary, al.dedupe_key"
    " FROM sibyl.alert al JOIN sibyl.alert_rule ar ON ar.tenant_id = al.tenant_id"
    " AND ar.id = al.rule_id WHERE al.tenant_id = $1 AND al.agent_id = $2"
    " AND al.state <> 'resolved' AND ar.code = ANY($3::text[]) ORDER BY al.first_fired_at DESC"
)
_REPORT_SQL = "SELECT * FROM sibyl.drift_report WHERE tenant_id = $1 AND id = $2"
_SUPERSEDE_SQL = (
    "UPDATE sibyl.drift_baseline SET state = 'superseded', superseded_at = now()"
    " WHERE tenant_id = $1 AND id = $2 AND state <> 'superseded' RETURNING id"
)
_NEW_SQL = (
    "INSERT INTO sibyl.drift_baseline (tenant_id, agent_id, provider, model, window_start,"
    " reset_by_user_id, reset_reason, supersedes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    " RETURNING *"
)
_LINK_SQL = "UPDATE sibyl.drift_baseline SET superseded_by = $3 WHERE tenant_id = $1 AND id = $2"


@router.get(API_PREFIX + "/drift")
async def list_drift(
    ctx: Annotated[AuthContext, Depends(guard("listDrift"))],
    verdict: Annotated[str | None, Query(pattern=_VERDICTS)] = None,
    state: Annotated[str | None, Query(pattern=_STATES)] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    page = PageQuery.of(limit, cursor, verdict=verdict, state=state, agent_id=agent_id)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = _LIST_SQL
        for column, value in (
            ("lr.verdict", verdict),
            ("b.state", state),
            ("b.agent_id", agent_id),
        ):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        outcome = await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("b.created_at", "b.id"),
            descending=True,
            serialize=views.key_summary,
        )
        totals = await conn.fetchrow(_SUMMARY_SQL, ctx.tenant_id, _CODES)
        outcome.body["summary"] = views.summary(totals)
        return outcome

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/drift/reports/{report_id}")
async def get_drift_report(
    report_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getDriftReport"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(_REPORT_SQL, ctx.tenant_id, report_id)
        if row is None:
            raise ProblemError("not_found")
        return Outcome(views.report(row), etag=f'"{row["id"]}"')

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/agents/{agent_id}/drift")
async def get_agent_drift(
    agent_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getAgentDrift"))],
    since: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=HISTORY_MAX)] = HISTORY,
) -> Response:
    """``since`` and ``limit`` bound ``history`` only (newest first); baselines, the latest
    reports and open alerts are always current."""

    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        await load_agent(conn, ctx, agent_id)
        baselines = await conn.fetch(_CURRENT_SQL, tenant, agent_id)
        latest = await conn.fetch(_LATEST_REPORTS_SQL, tenant, agent_id)
        history = await conn.fetch(_HISTORY_SQL, tenant, agent_id, limit, since)
        alerts = await conn.fetch(_ALERTS_SQL, tenant, agent_id, _CODES)
        body = {
            "agent_id": str(agent_id),
            "baselines": [views.baseline(r) for r in baselines],
            "latest": [views.report(r) for r in latest],
            "history": [views.report_summary(r) for r in history],
            "open_alerts": [views.alert_ref(r) for r in alerts],
        }
        return Outcome(body)

    return await run_read(ctx, work)


def _since(ctx: AuthContext, body: DriftBaselineReset) -> Any:
    since = body.since or ctx.now
    if since > ctx.now:
        raise ProblemError("validation_failed", "since cannot be in the future")
    if ctx.now - since > DEFAULT_CONFIG.baseline_max_span:
        days = DEFAULT_CONFIG.baseline_max_span // timedelta(days=1)
        raise ProblemError("validation_failed", f"since must be within the last {days} days")
    return since


@router.post(API_PREFIX + "/agents/{agent_id}/drift/baseline", status_code=201)
async def reset_drift_baseline(
    agent_id: UUID,
    body: DriftBaselineReset,
    ctx: Annotated[AuthContext, Depends(guard("resetDriftBaseline"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        await load_agent(conn, ctx, agent_id, lock=True)
        since = _since(ctx, body)
        current = [
            r
            for r in await conn.fetch(_CURRENT_SQL + " FOR UPDATE", tenant, agent_id)
            if (body.provider is None or r["provider"] == body.provider)
            and (body.model is None or r["model"] == body.model)
        ]
        if not current:
            raise ProblemError("not_found", "no current drift baseline matches")
        writer = AlertWriter(conn, tenant, ctx.now, services_of(ctx).outbox, services_of(ctx).audit)
        live = {r["dedupe_key"]: r for r in await conn.fetch(_ALERTS_SQL, tenant, agent_id, _CODES)}
        superseded: list[UUID] = []
        created: list[dict[str, Any]] = []
        for old in current:
            await conn.fetchval(_SUPERSEDE_SQL, tenant, old["id"])
            new = await conn.fetchrow(
                _NEW_SQL,
                tenant,
                agent_id,
                old["provider"],
                old["model"],
                since,
                user_id(ctx),
                body.reason.strip(),
                old["id"],
            )
            await conn.execute(_LINK_SQL, tenant, old["id"], new["id"])
            superseded.append(old["id"])
            created.append(dict(new))
            for code in (SILENT_DRIFT, MODEL_CHANGE):
                alert = live.get(dedupe_key(code, agent_id, old["provider"], old["model"]))
                if alert is not None:
                    await writer.resolve(code, alert["id"], outcome="unknown")
        receipt = await audit(
            conn,
            ctx,
            "drift.baseline_reset",
            resource_type="agent",
            resource_id=agent_id,
            reason=body.reason.strip(),
            detail={
                "agent_id": agent_id,
                "superseded": superseded,
                "new_baselines": [r["id"] for r in created],
                "since": since,
                "alerts_resolved": writer.resolved,
            },
        )
        result = {
            "agent_id": str(agent_id),
            "superseded": [str(s) for s in superseded],
            "baselines": [views.baseline(r) for r in created],
        }
        return Outcome(result, status=201, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)
