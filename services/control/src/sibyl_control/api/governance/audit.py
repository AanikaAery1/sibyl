"""Audit log, anchors, signing keys and verification (API.md §5.11).

* ``GET /audit/events`` (keyset on ``seq``) and ``/audit/events/{seq}``: ``audit:read``; a
  group-limited grant (engineer G) sees only rows whose resource is an agent in its groups.
  ``detail`` can never hold content: ``audit_append`` refuses content keys.
* ``GET /audit/anchors``, ``/audit/signing-keys``: the signed checkpoints and the public
  ``audit_anchor`` keys that verify them (offline too, ``sibyl audit verify``).
* ``POST /audit/verifications``: up to ``SYNC_ROW_LIMIT`` (100k, the contract's sync limit)
  rows are verified inline (chain walk in Postgres plus anchor signatures here) and recorded as
  ``audit.verified`` / ``audit.verify_failed``; larger ranges enqueue an ``audit_verify`` job
  (B14; params ``from_seq``, ``to_seq``) and answer 202 ``JobAccepted`` with ``Location:
  /jobs/{id}``. The jobs worker runs the same verification (``worker.jobs.audit``) and records
  the outcome once (actor ``system``, ``detail.job_id``); ``GET /jobs/{id}`` polls it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sibyl_schemas.values import JobKind

from ...core.jobs import Requester, enqueue_job
from ...core.problems import ProblemError
from ...worker.housekeeping.verification import SYNC_ROW_LIMIT, head_seq, verify_chain
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    Outcome,
    PageQuery,
    audit,
    keyset_page,
    require_db,
    run_read,
    run_write,
    services_of,
)
from .models import VerificationRequest
from .views import ANCHOR_VIEW, audit_event_view, signing_key_view

router = APIRouter()
ANCHOR_KINDS = ("hourly", "partition_boundary", "erasure", "export", "rekey", "break_glass")
ACTOR_TYPES = ("human", "rule", "policy", "system", "agent", "api_key")
_GROUP_ROWS = (
    " AND e.resource_type = 'agent' AND e.resource_id IN (SELECT a.id FROM sibyl.agent a"
    " WHERE a.tenant_id = $1 AND a.agent_group_id = ANY(${n}::uuid[]))"
)
_AGENT_ROWS = (
    " AND ((e.resource_type = 'agent' AND e.resource_id = ${n})"
    " OR (e.detail ? 'agent_id' AND e.detail ->> 'agent_id' = ${n}::text))"
)
ORDER = "^(asc|desc)$"


@router.get(API_PREFIX + "/audit/events")
async def list_audit_events(
    ctx: Annotated[AuthContext, Depends(guard("listAuditEvents"))],
    limit: int | None = None,
    cursor: str | None = None,
    from_seq: Annotated[int | None, Query(ge=0)] = None,
    to_seq: Annotated[int | None, Query(ge=0)] = None,
    action: Annotated[str | None, Query(max_length=60)] = None,
    actor_type: Annotated[str | None, Query(max_length=20)] = None,
    actor_id: UUID | None = None,
    resource_type: Annotated[str | None, Query(max_length=60)] = None,
    resource_id: UUID | None = None,
    is_evidence: bool | None = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
    agent_id: UUID | None = None,
    order: Annotated[str, Query(pattern=ORDER)] = "asc",
) -> Response:
    """AG-LIVE: ``occurred_after`` / ``occurred_before`` bound ``occurred_at`` (``recorded_at``
    when the row has none), exclusive; ``agent_id`` matches rows whose resource is the agent or
    whose ``detail.agent_id`` names it (Action Gate rows about a held action or a policy);
    ``order=desc`` pages newest first."""
    if actor_type is not None and actor_type not in ACTOR_TYPES:
        raise ProblemError("validation_failed", "actor_type is not a known actor type")
    filters = {
        "from_seq": from_seq,
        "to_seq": to_seq,
        "action": action,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "is_evidence": is_evidence,
        "from": start,
        "to": end,
        "occurred_after": occurred_after,
        "occurred_before": occurred_before,
        "agent_id": agent_id,
    }
    page = PageQuery.of(limit, cursor, **filters)
    groups = ctx.group_filter()

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT e.* FROM sibyl.audit_events e WHERE e.tenant_id = $1"
        for column, op, value in (
            ("e.seq", ">=", from_seq),
            ("e.seq", "<=", to_seq),
            ("e.action", "=", action),
            ("e.actor_type", "=", actor_type),
            ("e.actor_id", "=", actor_id),
            ("e.resource_type", "=", resource_type),
            ("e.resource_id", "=", resource_id),
            ("e.is_evidence", "=", is_evidence),
            ("e.recorded_at", ">=", start),
            ("e.recorded_at", "<", end),
            ("coalesce(e.occurred_at, e.recorded_at)", ">", occurred_after),
            ("coalesce(e.occurred_at, e.recorded_at)", "<", occurred_before),
        ):
            if value is not None:
                args.append(value)
                sql += f" AND {column} {op} ${len(args)}"
        if agent_id is not None:
            args.append(agent_id)
            sql += _AGENT_ROWS.replace("{n}", str(len(args)))
        if groups is not None:
            args.append(list(groups))
            sql += _GROUP_ROWS.replace("{n}", str(len(args)))
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("e.seq",),
            key_types="i",
            descending=order == "desc",
            serialize=audit_event_view,
        )

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/audit/events/{seq}")
async def get_audit_event(
    seq: str, ctx: Annotated[AuthContext, Depends(guard("getAuditEvent"))]
) -> Response:
    try:
        number = int(seq)
    except ValueError:
        raise ProblemError("not_found") from None
    if number < 0:
        raise ProblemError("not_found")

    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT e.*, a.agent_group_id AS resource_group FROM sibyl.audit_events e"
            " LEFT JOIN sibyl.agent a ON e.resource_type = 'agent' AND a.tenant_id = e.tenant_id"
            " AND a.id = e.resource_id WHERE e.tenant_id = $1 AND e.seq = $2",
            ctx.tenant_id,
            number,
        )
        if row is None:
            raise ProblemError("not_found")
        grant = ctx.grant
        if grant is not None and grant.group_ids is not None:
            # a group-limited grant reaches only rows about an agent in its groups
            group = row["resource_group"] if row["resource_type"] == "agent" else None
            ctx.check(resource_group_id=group)
        else:
            ctx.object_rule_checked("group")
        return Outcome(audit_event_view(row))

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/audit/anchors")
async def list_audit_anchors(
    ctx: Annotated[AuthContext, Depends(guard("listAuditAnchors"))],
    limit: int | None = None,
    cursor: str | None = None,
    kind: Annotated[str | None, Query(max_length=40)] = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    order: Annotated[str, Query(pattern=ORDER)] = "asc",
) -> Response:
    if kind is not None and kind not in ANCHOR_KINDS:
        raise ProblemError("validation_failed", "kind is not an anchor kind")
    page = PageQuery.of(limit, cursor, kind=kind, start=start, end=end)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1"
        for column, op, value in (
            ("kind", "=", kind),
            ("anchored_at", ">=", start),
            ("anchored_at", "<", end),
        ):
            if value is not None:
                args.append(value)
                sql += f" AND {column} {op} ${len(args)}"
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("anchored_at", "id"),
            key_types="tu",
            descending=order == "desc",
            serialize=ANCHOR_VIEW,
        )

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/audit/signing-keys")
async def list_audit_signing_keys(
    ctx: Annotated[AuthContext, Depends(guard("listAuditSigningKeys"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        rows = await conn.fetch(
            "SELECT * FROM sibyl.signing_key WHERE purpose = 'audit_anchor'"
            " ORDER BY activated_at, kid"
        )
        return Outcome({"data": [signing_key_view(r) for r in rows]})

    return await run_read(ctx, work)


@router.post(API_PREFIX + "/audit/verifications")
async def verify_audit_chain(
    body: VerificationRequest,
    ctx: Annotated[AuthContext, Depends(guard("verifyAuditChain"))],
) -> Response:
    db = require_db(services_of(ctx))
    tenant = ctx.tenant_id
    from_seq = body.from_seq or 0

    async def measure(conn: Any) -> int | None:
        return await head_seq(conn, tenant)

    head = await db.run_in_tenant_tx(tenant, measure, readonly=True)
    if head is None or from_seq > head or (body.to_seq is not None and body.to_seq > head):
        raise ProblemError("validation_failed", "the range lies beyond the audit chain head")
    last = head if body.to_seq is None else body.to_seq
    if last - from_seq + 1 > SYNC_ROW_LIMIT:
        return await _verify_async(ctx, from_seq, body.to_seq)

    async def check(conn: Any) -> Any:
        return await verify_chain(conn, tenant, from_seq, body.to_seq)

    result = await db.run_in_tenant_tx(tenant, check, readonly=True)

    async def record(conn: Any) -> Outcome:
        receipt = await audit(
            conn,
            ctx,
            result.action,
            resource_type="tenant",
            resource_id=tenant,
            detail=result.audit_detail(),
        )
        return Outcome(result.body(), receipt=receipt)

    return await run_write(ctx, record, idempotent=True)


async def _verify_async(ctx: AuthContext, from_seq: int, to_seq: int | None) -> Response:
    principal = ctx.principal
    if principal is None:  # guard() always resolves one; never enqueue an anonymous job
        raise ProblemError("unauthenticated")
    outbox = services_of(ctx).outbox

    async def enqueue(conn: Any) -> Outcome:
        job = await enqueue_job(
            conn,
            outbox,
            ctx.tenant_id,
            kind=JobKind.AUDIT_VERIFY,
            requester=Requester.of(principal),
            params={"from_seq": from_seq, "to_seq": to_seq},
        )
        return Outcome(
            {"job_id": str(job.id)},
            status=202,
            headers={"Location": f"{API_PREFIX}/jobs/{job.id}"},
        )

    return await run_write(ctx, enqueue, idempotent=True)
