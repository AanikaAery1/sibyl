"""queue API module (lane S): the operator queue and handoff tasks (API.md §5.8).

* ``GET /queue`` — ``HandoffTaskSummary`` page ordered ``(priority, deadline_at, id)``, never the
  packet, plus a ``summary`` block with the ``completed_despite_failure`` counter (B13, demo B6).
* ``GET /handoff-tasks/{id}`` — task metadata; ``GET …/packet`` — the ``sibyl-handoff/1`` packet
  (``packets:read``; an auditor's audited grant writes ``data.revealed``).
* ``POST /handoff-tasks/{id}/actions`` — ``claim`` (30-minute lock), ``extend_lock``,
  ``release_claim``, ``complete`` (outcome required), ``return`` (only from queued), ``reassign``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from sibyl_control.api._stubs import stub_router

from ...core.audit import AuditRecord, audit_actor
from ...core.outbox import OutboxMessage
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..incidents.common import audited
from ..incidents.models import HandoffTaskAction
from ..incidents.views import task_summary, task_view
from ..registry._kit import (
    Outcome,
    PageQuery,
    keyset_page,
    load_agent,
    request_uuid,
    run_read,
    run_write,
    services_of,
)

_routes = APIRouter()
QUEUE_STATES = ("queued", "claimed", "expired")
_TASK_SQL = "SELECT * FROM sibyl.handoff_task WHERE tenant_id = $1 AND id = $2"
_LOCKED_TASK_SQL = _TASK_SQL + " FOR UPDATE"
CLAIM_LOCK = timedelta(minutes=30)
SUMMARY_WINDOW = timedelta(days=30)
_SUMMARY_SQL = """
SELECT count(*) FILTER (WHERE state = 'queued') AS queued,
       count(*) FILTER (WHERE state = 'claimed') AS claimed,
       count(*) FILTER (WHERE state = 'expired') AS expired,
       count(*) FILTER (WHERE state = 'returned') AS returned,
       count(*) FILTER (WHERE state = 'completed') AS completed,
       count(*) FILTER (WHERE state = 'completed' AND outcome = 'resolved') AS
         completed_despite_failure,
       count(*) FILTER (WHERE state IN ('queued', 'claimed') AND deadline_at < now()) AS overdue,
       count(*) AS total
  FROM sibyl.handoff_task WHERE tenant_id = $1 AND created_at > now() - $2::interval
"""


def _summary(row: Any) -> dict[str, Any]:
    out: dict[str, Any] = {k: int(row[k] or 0) for k in row.keys()}
    decided = out["completed"] + out["expired"] + out["returned"]
    out["completed_despite_failure_pct"] = (
        round(100 * out["completed_despite_failure"] / decided) if decided else None
    )
    out["window_days"] = SUMMARY_WINDOW.days
    return out


@_routes.get(API_PREFIX + "/queue")
async def list_queue(
    ctx: Annotated[AuthContext, Depends(guard("listQueue"))],
    state: Annotated[
        str | None, Query(pattern="^(queued|claimed|completed|returned|expired)$")
    ] = None,
    priority: Annotated[int | None, Query(ge=0)] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    mine: Annotated[bool | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    page = PageQuery.of(limit, cursor, state=state, priority=priority, agent_id=agent_id, mine=mine)
    principal = ctx.principal
    assert principal is not None

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM sibyl.handoff_task WHERE tenant_id = $1"
        if state is not None:
            args.append(state)
            sql += f" AND state = ${len(args)}"
        else:
            args.append(list(QUEUE_STATES))
            sql += f" AND state = ANY(${len(args)}::text[])"
        for column, value in (("priority", priority), ("agent_id", agent_id)):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        if mine:
            args.append(principal.id)
            sql += f" AND claimed_by_user_id = ${len(args)}"
        outcome = await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("priority", "deadline_at", "id"),
            key_types="itu",
            serialize=task_summary,
        )
        summary = await conn.fetchrow(_SUMMARY_SQL, ctx.tenant_id, SUMMARY_WINDOW)
        outcome.body["summary"] = _summary(summary)
        return outcome

    return await run_read(ctx, work)


async def _task(
    conn: Any, ctx: AuthContext, task_id: UUID, *, lock: bool = False
) -> dict[str, Any]:
    row = await conn.fetchrow(_LOCKED_TASK_SQL if lock else _TASK_SQL, ctx.tenant_id, task_id)
    if row is None:
        raise ProblemError("not_found")
    return dict(row)


@_routes.get(API_PREFIX + "/handoff-tasks/{task_id}")
async def get_handoff_task(
    task_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getHandoffTask"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await _task(conn, ctx, task_id)
        await load_agent(conn, ctx, row["agent_id"])
        return Outcome(task_view(row))

    return await run_read(ctx, work)


async def _ref_packet(ctx: AuthContext, conn: Any, ref_id: UUID) -> bytes:
    """An SDK-assembled packet stored as an encrypted payload (``packet_ref_id``)."""
    from ...core.blob.base import BlobNotFound
    from ...core.crypto.envelope import DecryptionError
    from ...core.crypto.sealed import SealedFormatError, open_payload
    from ..auth import runtime
    from ..reads.payloads import blob_store

    ref = await conn.fetchrow(
        "SELECT * FROM sibyl.payload_refs WHERE tenant_id = $1 AND id = $2 LIMIT 1",
        ctx.tenant_id,
        ref_id,
    )
    if ref is None or ref["state"] != "stored":
        raise ProblemError("packet_shredded")
    request = ctx.request
    assert request is not None
    try:
        body = await open_payload(
            blob_store(request), runtime.deks_for(request), ctx.tenant_id, ref["uri"], ref_id
        )
    except (BlobNotFound, DecryptionError, SealedFormatError):
        raise ProblemError("packet_shredded") from None
    if not hmac.compare_digest(hashlib.sha256(body).digest(), bytes(ref["sha256"])):
        raise ProblemError("internal_error")
    return bytes(body)


@_routes.get(API_PREFIX + "/handoff-tasks/{task_id}/packet")
async def get_handoff_packet(
    task_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getHandoffPacket"))],
) -> Response:
    """The packet; an auditor's audited ``packets:read`` (A) writes ``data.revealed``."""
    principal = ctx.principal
    assert principal is not None
    grant = principal.grants.get("packets:read")
    reveal = grant is not None and grant.audited
    ctx.object_rule_checked("auditor_reveal")

    async def work(conn: Any, start: int) -> Outcome:
        row = await _task(conn, ctx, task_id)
        await load_agent(conn, ctx, row["agent_id"])
        if row["packet"] is not None:
            packet = row["packet"]
            body = json.dumps(packet, separators=(",", ":"), ensure_ascii=False).encode()
        else:
            body = await _ref_packet(ctx, conn, row["packet_ref_id"])
            packet = json.loads(body)
        digest = bytes(row["packet_sha256"]).hex()
        receipt = None
        if reveal:
            receipt = await services_of(ctx).audit.append(
                conn,
                ctx.tenant_id,
                AuditRecord(
                    action="data.revealed",
                    resource_type="handoff_task",
                    resource_id=row["id"],
                    detail={
                        "payload_ref": str(row["packet_ref_id"] or row["id"]),
                        "payload_sha256": digest,
                        "agent_id": str(row["agent_id"]),
                        "reveal_reason": "handoff packet read by an audited grant",
                        "kind": "handoff_packet",
                    },
                    request_id=request_uuid(ctx),
                    **audit_actor(principal).fields(),
                ),
            )
        return Outcome(packet, etag=f'"{digest}"', receipt=receipt)

    if reveal:
        return await run_write(ctx, audited(ctx, work), idempotent=False)

    async def read(conn: Any) -> Outcome:
        return await work(conn, -1)

    return await run_read(ctx, read)


# --- task actions -----------------------------------------------------------------------------


def _detail(row: dict[str, Any], operator: UUID | None, outcome: str | None) -> dict[str, Any]:
    return {
        "task_id": str(row["task_id"]),
        "handoff_task_id": str(row["id"]),
        "operator_id": None if operator is None else str(operator),
        "outcome": outcome,
    }


async def _emit(ctx: AuthContext, conn: Any, event: str, row: dict[str, Any]) -> None:
    await services_of(ctx).outbox.emit(
        conn,
        ctx.tenant_id,
        OutboxMessage.for_event(
            event,
            "handoff_task",
            row["id"],
            {"handoff_task_id": str(row["id"]), "agent_id": str(row["agent_id"])},
        ),
    )


async def _act(
    conn: Any, ctx: AuthContext, row: dict[str, Any], body: HandoffTaskAction
) -> tuple[str, str | None, str | None]:
    """Apply one action; returns ``(audit action, outbox event, outcome)``."""
    principal = ctx.principal
    assert principal is not None
    me = principal.id
    tenant = ctx.tenant_id
    lapsed = bool(
        row["claim_lock_until"] is not None
        and await conn.fetchval("SELECT $1::timestamptz <= now()", row["claim_lock_until"])
    )
    claimant = row["claimed_by_user_id"]
    action = body.action
    if action == "claim":
        if row["state"] == "claimed" and claimant != me and not lapsed:
            raise ProblemError("claimed_by_other")
        if row["state"] not in ("queued", "expired", "claimed"):
            raise ProblemError(
                "invalid_transition", extensions={"from_state": row["state"], "action": action}
            )
        reclaim = row["state"] == "claimed" and claimant != me
        await conn.execute(
            "UPDATE sibyl.handoff_task SET state = 'claimed', claimed_by_user_id = $3,"
            " claimed_at = now(), claim_lock_until = now() + $5::interval,"
            " reclaim_count = reclaim_count + $4, outcome = NULL"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["id"],
            me,
            1 if reclaim or row["state"] == "expired" else 0,
            CLAIM_LOCK,
        )
        return "handoff.claimed", "handoff.claimed", None
    if action == "return":
        if row["state"] != "queued":
            raise ProblemError(
                "invalid_transition", extensions={"from_state": row["state"], "action": action}
            )
        await conn.execute(
            "UPDATE sibyl.handoff_task SET state = 'returned', outcome = 'returned_to_agent'"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["id"],
        )
        return "handoff.returned", "handoff.returned", "returned_to_agent"
    if action == "reassign":
        if body.accountable_user_id is None:
            raise ProblemError("validation_failed", "accountable_user_id is required")
        exists = await conn.fetchval(
            "SELECT 1 FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2",
            tenant,
            body.accountable_user_id,
        )
        if not exists:
            raise ProblemError("validation_failed", "unknown accountable_user_id")
        await conn.execute(
            "UPDATE sibyl.handoff_task SET accountable_user_id = $3"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["id"],
            body.accountable_user_id,
        )
        return "handoff.reassigned", None, None
    # claimant-only actions
    if row["state"] != "claimed":
        raise ProblemError(
            "invalid_transition", extensions={"from_state": row["state"], "action": action}
        )
    if claimant != me:
        raise ProblemError("claimed_by_other")
    if action == "release_claim":
        await conn.execute(
            "UPDATE sibyl.handoff_task SET state = 'queued', claimed_by_user_id = NULL,"
            " claimed_at = NULL, claim_lock_until = NULL WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["id"],
        )
        return "handoff.claim_released", "handoff.returned", None
    if lapsed:
        raise ProblemError("lock_lapsed", "the 30-minute claim lock lapsed; claim the task again")
    if action == "extend_lock":
        await conn.execute(
            "UPDATE sibyl.handoff_task SET claim_lock_until = now() + $3::interval"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["id"],
            CLAIM_LOCK,
        )
        return "handoff.lock_extended", None, None
    if body.outcome is None:
        raise ProblemError("validation_failed", "complete needs an outcome")
    await conn.execute(
        "UPDATE sibyl.handoff_task SET state = 'completed', outcome = $3, outcome_note = $4,"
        " completed_at = now(), next_action = coalesce($5, next_action), rating = $6"
        " WHERE tenant_id = $1 AND id = $2",
        tenant,
        row["id"],
        body.outcome,
        body.outcome_note,
        body.next_action,
        body.rating,
    )
    if body.rating is not None or body.outcome is not None:
        await conn.execute(
            "INSERT INTO sibyl.label (tenant_id, agent_id, kind, label_strength, judges_kind,"
            " judges_id, judged_as_of, labeller_kind, labeller_ref, value)"
            " VALUES ($1, $2, 'handoff_outcome', 'outcome', 'packet', $3, now(), 'operator', $4,"
            " $5::jsonb)",
            tenant,
            row["agent_id"],
            str(row["packet_id"]),
            str(me),
            {"outcome": body.outcome, "rating": body.rating, "handoff_task_id": str(row["id"])},
        )
    return "handoff.completed", "handoff.completed", body.outcome


@_routes.post(API_PREFIX + "/handoff-tasks/{task_id}/actions")
async def act_on_handoff_task(
    task_id: UUID,
    body: HandoffTaskAction,
    ctx: Annotated[AuthContext, Depends(guard("actOnHandoffTask"))],
) -> Response:
    ctx.action(body.action)
    principal = ctx.principal
    assert principal is not None

    async def write(conn: Any, start: int) -> Outcome:
        row = await _task(conn, ctx, task_id, lock=True)
        audit_action, event, outcome = await _act(conn, ctx, row, body)
        detail = _detail(row, principal.id, outcome)
        if audit_action in ("handoff.lock_extended", "handoff.claim_released"):
            detail = {"task_id": detail["task_id"], "handoff_task_id": detail["handoff_task_id"]}
        receipt = await services_of(ctx).audit.append(
            conn,
            ctx.tenant_id,
            AuditRecord(
                action=audit_action,
                resource_type="handoff_task",
                resource_id=row["id"],
                reason=body.reason or body.outcome_note,
                detail=detail,
                request_id=request_uuid(ctx),
                **audit_actor(principal).fields(),
            ),
        )
        if event is not None:
            await _emit(ctx, conn, event, row)
        fresh = await _task(conn, ctx, task_id)
        return Outcome(task_view(fresh), receipt=receipt)

    return await run_write(ctx, audited(ctx, write), idempotent=True)


router = stub_router("queue", _routes)
