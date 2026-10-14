"""``/sentinel/findings`` (list, get, feedback) and ``POST /sentinel/explain`` (on demand).

``explain`` works like a scheduled analysis but in the requesting human's name: the subject (an
incident or a held action) must exist; Sentinel must be enabled; the day's budget is reserved
first (409 ``conflict`` and a ``sentinel.budget_exhausted`` audit row when it is spent); the
model is called after the Idempotency-Key claim with no transaction held; a provider failure is
503 and refunds the reservation. The finding is advisory: it never changes the held action or
the incident.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sibyl_schemas.models.sentinel import SentinelExplainBody, SentinelFeedbackBody
from sibyl_schemas.values import SentinelTask

from ...core.audit import audit_actor
from ...core.problems import ProblemError
from ...worker.sentinel import budget, engine, gather
from ...worker.sentinel.findings import Subject, finding_record, insert_finding
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    Outcome,
    PageQuery,
    audit,
    keyset_page,
    run_read,
    run_write,
    services_of,
    user_id,
)
from .runtime import content_reader, open_session, run_after_claim
from .views import finding_view

BASE = API_PREFIX + "/sentinel/findings"
EXPLAIN = API_PREFIX + "/sentinel/explain"
RESOURCE = "sentinel_finding"
router = APIRouter()
_GET_SQL = "SELECT * FROM sibyl.sentinel_finding WHERE tenant_id = $1 AND id = $2"
_FEEDBACK_SQL = """
UPDATE sibyl.sentinel_finding SET feedback = $3, feedback_by_user_id = $4, feedback_at = now()
 WHERE tenant_id = $1 AND id = $2
RETURNING *
"""
_KIND = "^(incident_explanation|held_action_review|semantic_drift|fleet_summary)$"
_SUBJECT = "^(incident|held_action|agent|fleet)$"
_SEVERITY = "^(info|warning|critical)$"
_TRIGGER = "^(scheduled|on_demand)$"


@router.get(BASE)
async def list_sentinel_findings(
    ctx: Annotated[AuthContext, Depends(guard("listSentinelFindings"))],
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    kind: Annotated[str | None, Query(pattern=_KIND)] = None,
    subject_kind: Annotated[str | None, Query(pattern=_SUBJECT)] = None,
    subject_id: Annotated[UUID | None, Query()] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    severity: Annotated[str | None, Query(pattern=_SEVERITY)] = None,
    trigger: Annotated[str | None, Query(pattern=_TRIGGER)] = None,
    since: Annotated[datetime | None, Query()] = None,
) -> Any:
    filters = {
        "kind": kind,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "agent_id": agent_id,
        "severity": severity,
        "trigger": trigger,
        "since": since,
    }
    page = PageQuery.of(limit, cursor, **filters)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM sibyl.sentinel_finding WHERE tenant_id = $1"
        for column, value in filters.items():
            if value is None:
                continue
            args.append(value)
            op = ">=" if column == "since" else "="
            name = "created_at" if column == "since" else column
            sql += f" AND {name} {op} ${len(args)}"
        return await keyset_page(
            conn, ctx, select=sql, args=args, page=page, descending=True, serialize=finding_view
        )

    return await run_read(ctx, work)


@router.get(BASE + "/{finding_id}")
async def get_sentinel_finding(
    finding_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getSentinelFinding"))],
) -> Any:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(_GET_SQL, ctx.tenant_id, finding_id)
        if row is None:
            raise ProblemError("not_found")
        return Outcome(finding_view(row))

    return await run_read(ctx, work)


@router.post(BASE + "/{finding_id}/feedback")
async def record_sentinel_feedback(
    finding_id: UUID,
    body: SentinelFeedbackBody,
    ctx: Annotated[AuthContext, Depends(guard("recordSentinelFeedback"))],
) -> Any:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            _FEEDBACK_SQL, ctx.tenant_id, finding_id, body.feedback.value, user_id(ctx)
        )
        if row is None:
            raise ProblemError("not_found")
        receipt = await audit(
            conn,
            ctx,
            "sentinel.feedback_recorded",
            resource_type=RESOURCE,
            resource_id=row["id"],
            detail={"finding_id": row["id"], "feedback": body.feedback.value, "kind": row["kind"]},
        )
        return Outcome(finding_view(row), receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


async def _subject(conn: Any, ctx: AuthContext, body: SentinelExplainBody) -> tuple[Subject, Any]:
    subject_id = UUID(body.subject_id)
    reader = content_reader(ctx)
    if body.subject_kind == "incident":
        doc = await gather.incident_doc(conn, ctx.tenant_id, subject_id)
        task = SentinelTask.INCIDENT_EXPLANATION
        agent = None if doc is None else UUID(doc["agent"]["id"])
    else:
        doc = await gather.hold_doc(conn, ctx.tenant_id, subject_id, reader)
        task = SentinelTask.HELD_ACTION_REVIEW
        agent = None if doc is None else UUID(doc["agent"]["id"])
    if doc is None:
        raise ProblemError("not_found", f"no {body.subject_kind} {subject_id}")
    return Subject(task, body.subject_kind, subject_id, agent, None), doc


@router.post(EXPLAIN, status_code=201)
async def explain_with_sentinel(
    body: SentinelExplainBody,
    ctx: Annotated[AuthContext, Depends(guard("explainWithSentinel"))],
) -> Any:
    services = services_of(ctx)
    db = services.db
    tenant = ctx.tenant_id
    principal = ctx.principal
    assert principal is not None
    actor = audit_actor(principal)

    async def prelude() -> tuple[Any, Subject, engine.Prepared, engine.CallResult]:
        assert db is not None
        async with db.tenant_tx(tenant, readonly=True) as conn:
            session = await open_session(conn, ctx, require_enabled=True)
            subject, doc = await _subject(conn, ctx, body)
        prepared = engine.prepare(subject.kind, doc, session.cfg, session.client)
        day = engine.utc_day(datetime.now(UTC))
        if not await engine.reserve(db, services.audit, tenant, session.cfg, prepared, day, actor):
            raise ProblemError("conflict", "today's Sentinel budget is spent")
        result = await engine.call(session.client, prepared)
        async with db.tenant_tx(tenant) as conn:
            await budget.settle(
                conn, tenant, day, engine.settlement(prepared, result, finding=result.ok)
            )
        if not result.ok:
            raise ProblemError(
                "service_unavailable", f"the model call failed ({result.error_code})"
            )
        return session.cfg, subject, prepared, result

    async def work(
        conn: Any, pre: tuple[Any, Subject, engine.Prepared, engine.CallResult]
    ) -> Outcome:
        cfg, subject, prepared, result = pre
        draft = engine.draft(
            cfg, subject, prepared, result, trigger="on_demand", requested_by=user_id(ctx)
        )
        row = await insert_finding(conn, tenant, draft)
        assert row is not None  # on-demand findings carry no dedupe key
        record = finding_record(row, actor)
        receipt = await audit(
            conn,
            ctx,
            "sentinel.finding_created",
            resource_type=RESOURCE,
            resource_id=row["id"],
            detail=record.detail,
        )
        return Outcome(
            finding_view(row),
            status=201,
            receipt=receipt,
            headers={"Location": f"{BASE}/{row['id']}"},
        )

    return await run_after_claim(ctx, prelude, work)
