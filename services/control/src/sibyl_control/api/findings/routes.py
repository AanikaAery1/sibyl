"""``/findings``: external monitors submit advisory findings; everyone with ``sentinel:read`` (and
monitor keys, within their watched groups) reads findings of every source; humans rate them.

``POST /findings`` (monitor key, ``findings:write``):

1. the monitor must be **active** (409 ``not_active`` while paused) and within its per-monitor
   rate (``rate_limit_per_min``, 429 with ``Retry-After``);
2. the subject must exist **within the monitor's watched groups** (404 otherwise, never 403); a
   fleet finding needs an all-groups monitor; the finding's ``agent_id`` is derived from the
   subject, never taken from the body;
3. the row, its ``finding.submitted`` audit (actor ``api_key``) and, when the finding asks for
   one, an ``alert_requested`` flag the worker turns into a watch-only ``external_finding``
   alert. A ``held_action_review`` carries its ``advice`` to the held action's reviewers.

Nothing here can allow, block, approve, fail over or change policy: the route writes only
``external_finding``.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sibyl_schemas.models.monitor import FindingFeedbackBody, FindingSubmit
from sibyl_schemas.values import ExternalSubjectKind

from ...core.authz import NOT_APPLICABLE
from ...core.problems import ProblemError
from ...core.ratelimit import RatePolicy, enforce
from ..auth.common import Outcome as Written
from ..auth.common import actor_record, principal_of, record_denials, run_mutation
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from ..registry._kit import Outcome, PageQuery, audit, keyset_page, run_read, run_write, user_id
from .views import EXTERNAL_ONE_SQL, UNION_SQL, finding_view

BASE = API_PREFIX + "/findings"
RESOURCE = "external_finding"
RUN_LOOKBACK = timedelta(days=31)
router = APIRouter()
submit_router = APIRouter(dependencies=[Depends(record_denials)])
"""``POST /findings`` writes through ``auth.common.run_mutation``, whose object-rule refusals
are audited by ``record_denials``; the reads audit their own refusals (``registry._kit``)."""

_MONITOR_SQL = (
    "SELECT id, name, state, rate_limit_per_min FROM sibyl.monitor"
    " WHERE tenant_id = $1 AND id = $2 FOR SHARE"
)
_SUBJECT_SQL: dict[str, str] = {
    "incident": (
        "SELECT f.agent_id, a.agent_group_id FROM sibyl.failover f"
        " JOIN sibyl.agent a ON a.tenant_id = f.tenant_id AND a.id = f.agent_id"
        " WHERE f.tenant_id = $1 AND f.id = $2"
    ),
    "held_action": (
        "SELECT h.agent_id, a.agent_group_id FROM sibyl.held_action h"
        " JOIN sibyl.agent a ON a.tenant_id = h.tenant_id AND a.id = h.agent_id"
        " WHERE h.tenant_id = $1 AND h.id = $2"
    ),
    "agent": (
        "SELECT id AS agent_id, agent_group_id FROM sibyl.agent WHERE tenant_id = $1 AND id = $2"
    ),
    "run": (
        "SELECT e.agent_id, a.agent_group_id FROM sibyl.events e"
        " JOIN sibyl.agent a ON a.tenant_id = e.tenant_id AND a.id = e.agent_id"
        " WHERE e.tenant_id = $1 AND e.task_id = $2 AND e.event_type = 'agent.invoke'"
        " AND e.ts >= $3 ORDER BY e.ts DESC LIMIT 1"
    ),
}
_INSERT_SQL = """
INSERT INTO sibyl.external_finding (tenant_id, monitor_id, api_key_id, kind, subject_kind,
  subject_id, agent_id, severity, summary, body, recommendation, advice, confidence, provider,
  model, alert_requested)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14, $15, $16)
RETURNING id
"""
_SENTINEL_FEEDBACK_SQL = """
UPDATE sibyl.sentinel_finding SET feedback = $3, feedback_by_user_id = $4, feedback_at = now()
 WHERE tenant_id = $1 AND id = $2
RETURNING id, kind
"""
_EXTERNAL_FEEDBACK_SQL = """
UPDATE sibyl.external_finding SET feedback = $3, feedback_by_user_id = $4, feedback_at = now()
 WHERE tenant_id = $1 AND id = $2
RETURNING id, kind, monitor_id
"""
_SOURCE = "^(sentinel|external)$"
_KIND = (
    "^(incident_explanation|held_action_review|semantic_drift|fleet_summary|anomaly|safety"
    "|quality|cost|other)$"
)
_SUBJECT = "^(incident|held_action|agent|run|fleet)$"
_SEVERITY = "^(info|warning|critical)$"


# --- submit -----------------------------------------------------------------------------------


async def _subject(conn: Any, ctx: AuthContext, body: FindingSubmit) -> UUID | None:
    """The agent the finding is about, after the watched-groups rule (404 when out of reach)."""
    kind = body.subject_kind
    if kind is ExternalSubjectKind.FLEET:
        ctx.check(resource_group_id=None)  # an all-groups monitor only
        return None
    args: list[Any] = [ctx.tenant_id, body.subject_id]
    if kind is ExternalSubjectKind.RUN:
        args.append(ctx.now - RUN_LOOKBACK)
    row = await conn.fetchrow(_SUBJECT_SQL[kind.value], *args)
    if row is None:
        ctx.check(resource_group_id=NOT_APPLICABLE)
        raise ProblemError("not_found", f"no {kind.value} {body.subject_id}")
    ctx.check(resource_group_id=row["agent_group_id"])
    agent: UUID = row["agent_id"]
    return agent


async def _rate(ctx: AuthContext, monitor: Any) -> None:
    services = get_services(ctx.request) if ctx.request is not None else None
    if services is None:  # pragma: no cover - the guard always attaches the request
        return
    policy = RatePolicy("monitor_findings", int(monitor["rate_limit_per_min"]), 60.0)
    enforce(await services.rate_limiter.hit(f"monitor:{monitor['id']}:findings", policy))


@submit_router.post(BASE)
async def submit_finding(
    request: Request,
    body: FindingSubmit,
    ctx: Annotated[AuthContext, Depends(guard("submitFinding"))],
) -> Response:
    principal = principal_of(ctx)
    services = get_services(request)
    monitor_id = principal.monitor_id
    if monitor_id is None:  # pragma: no cover - findings:write is monitor-bound (DB CHECK)
        raise ProblemError("forbidden", audit_denied=True)

    async def mutate(conn: Any) -> Written:
        tenant = principal.tenant_id
        monitor = await conn.fetchrow(_MONITOR_SQL, tenant, monitor_id)
        if monitor is None or monitor["state"] != "active":
            ctx.object_rule_checked("group")
            raise ProblemError("not_active", "the monitor is paused or revoked")
        await _rate(ctx, monitor)
        agent = await _subject(conn, ctx, body)
        wants_alert = body.wants_alert() and agent is not None
        finding_id = await conn.fetchval(
            _INSERT_SQL,
            tenant,
            monitor_id,
            principal.id,
            body.kind.value,
            body.subject_kind.value,
            body.subject_id,
            agent,
            body.severity.value,
            body.summary,
            body.body,
            body.recommendation,
            body.advice.value if body.advice else None,
            body.confidence,
            body.provider,
            body.model,
            wants_alert,
        )
        detail: dict[str, Any] = {
            "finding_id": str(finding_id),
            "monitor_id": str(monitor_id),
            "kind": body.kind.value,
            "subject_kind": body.subject_kind.value,
            "severity": body.severity.value,
            "alert_requested": wants_alert,
        }
        if body.subject_id is not None:
            detail["subject_id"] = str(body.subject_id)
        if agent is not None:
            detail["agent_id"] = str(agent)
        if body.advice is not None:
            detail["advice"] = body.advice.value
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "finding.submitted",
                resource_type=RESOURCE,
                resource_id=finding_id,
                resource_ref=monitor["name"],
                detail=detail,
            ),
        )
        row = await conn.fetchrow(EXTERNAL_ONE_SQL, tenant, finding_id)
        return Written(
            201,
            finding_view(row),
            headers={"Location": f"{BASE}/{finding_id}"},
            receipt=receipt,
        )

    return await run_mutation(request, ctx, mutate, idempotent=True)


# --- reads ------------------------------------------------------------------------------------


def _scope(ctx: AuthContext, args: list[Any]) -> str:
    """A monitor key sees findings about agents in its watched groups (and fleet findings only
    with all groups); ``sentinel:read`` holders are tenant-wide."""
    groups = ctx.group_filter()
    if groups is None:
        return ""
    args.append(list(groups))
    return f" AND x.agent_group_id = ANY(${len(args)}::uuid[])"


@router.get(BASE)
async def list_findings(
    ctx: Annotated[AuthContext, Depends(guard("listFindings"))],
    source: Annotated[str | None, Query(pattern=_SOURCE)] = None,
    monitor_id: Annotated[UUID | None, Query()] = None,
    kind: Annotated[str | None, Query(pattern=_KIND)] = None,
    subject_kind: Annotated[str | None, Query(pattern=_SUBJECT)] = None,
    subject_id: Annotated[UUID | None, Query()] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    severity: Annotated[str | None, Query(pattern=_SEVERITY)] = None,
    since: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    filters = {
        "source": source,
        "monitor_id": monitor_id,
        "kind": kind,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "agent_id": agent_id,
        "severity": severity,
        "since": since,
    }
    page = PageQuery.of(limit, cursor, **filters)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = UNION_SQL + _scope(ctx, args)
        for column, value in filters.items():
            if value is None:
                continue
            args.append(value)
            op = ">=" if column == "since" else "="
            name = "created_at" if column == "since" else column
            sql += f" AND x.{name} {op} ${len(args)}"
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("x.created_at", "x.id"),
            descending=True,
            serialize=finding_view,
        )

    return await run_read(ctx, work)


@router.get(BASE + "/{finding_id}")
async def get_finding(
    finding_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getFinding"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(UNION_SQL + " AND x.id = $2", ctx.tenant_id, finding_id)
        if row is None:
            ctx.check(resource_group_id=NOT_APPLICABLE)
            raise ProblemError("not_found")
        ctx.check(resource_group_id=row["agent_group_id"])
        return Outcome(finding_view(row))

    return await run_read(ctx, work)


@router.post(BASE + "/{finding_id}/feedback")
async def record_finding_feedback(
    finding_id: UUID,
    body: FindingFeedbackBody,
    ctx: Annotated[AuthContext, Depends(guard("recordFindingFeedback"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        who = user_id(ctx)
        value = body.feedback.value
        row = await conn.fetchrow(_SENTINEL_FEEDBACK_SQL, tenant, finding_id, value, who)
        if row is not None:
            action, resource = "sentinel.feedback_recorded", "sentinel_finding"
            detail = {"finding_id": str(row["id"]), "feedback": value, "kind": row["kind"]}
        else:
            row = await conn.fetchrow(_EXTERNAL_FEEDBACK_SQL, tenant, finding_id, value, who)
            if row is None:
                raise ProblemError("not_found")
            action, resource = "finding.feedback_recorded", RESOURCE
            detail = {
                "finding_id": str(row["id"]),
                "feedback": value,
                "kind": row["kind"],
                "monitor_id": str(row["monitor_id"]),
            }
        receipt = await audit(
            conn, ctx, action, resource_type=resource, resource_id=row["id"], detail=detail
        )
        view = await conn.fetchrow(UNION_SQL + " AND x.id = $2", tenant, finding_id)
        return Outcome(finding_view(view), receipt=receipt)

    return await run_write(ctx, work, idempotent=True)
