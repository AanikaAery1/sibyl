"""Erasure requests (API.md §5.12, §10.4; DATAMODEL §6.5 steps 1-2).

The api owns the human steps: request (with the server-side hold check), approve / reject /
cancel, and the certificate read. Execution (``executing`` → ``completed``) is the worker's
(``worker/housekeeping/erasure_exec.py``). Safety rules enforced here, and again by the
database (guard and requester-not-approver triggers, ``erasure_blocking_holds``):

* two humans: approver ≠ requester (409 ``self_approval``), approve and reject need step-up;
  tenant scope needs ``owner`` for both, and a tenant with a single active owner cannot file a
  tenant-scope request (409 ``second_owner_required``);
* holds are checked server-side and visible (``blocking_hold_ids``); an approval re-checks them;
* one live request per scope (409 ``erasure_in_progress``); an agent that is the backup in an
  approved chain cannot be requested (409 ``erasure_blocked_by_chain``, G0-7, DB trigger);
* subject scope (Phase 1 ``agent_window`` resolution): the identifier is hashed with
  ``SIBYL_SUBJECT_SALT`` and never stored or echoed; the operator supplies ``agent_ids`` and
  the window, stored as ``affected_objects.subject_set``.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from ...core.canonical import canonicalize
from ...core.problems import ProblemError
from ..auth.common import parse_uuid
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    Outcome,
    PageQuery,
    audit,
    jsonable,
    keyset_page,
    refuse,
    run_read,
    run_write,
    user_id,
)
from .lifecycle import (
    TERMINAL,
    blocking_holds,
    request_agents,
    retained_tables,
    step_event,
    subject_hash,
    system_audit,
)
from .models import ErasureAction, ErasureRequestCreate
from .views import erasure_view

router = APIRouter()
STATES = (
    "requested",
    "hold_blocked",
    "approved",
    "executing",
    "keys_shredded",
    "objects_deleted",
    "derived_purged",
    "verified",
    "completed",
    "rejected",
    "cancelled",
)
_OWNERS_SQL = (
    "SELECT count(DISTINCT m.user_id) FROM sibyl.membership m JOIN sibyl.app_user u"
    " ON u.tenant_id = m.tenant_id AND u.id = m.user_id"
    " WHERE m.tenant_id = $1 AND m.role_name = 'owner' AND m.revoked_at IS NULL"
    " AND (m.expires_at IS NULL OR m.expires_at > now()) AND u.status = 'active'"
    " AND m.user_id <> $2"
)


def _is_owner(ctx: AuthContext) -> bool:
    return ctx.principal is not None and "owner" in ctx.principal.roles


async def _view(conn: Any, row: Any) -> dict[str, Any]:
    return erasure_view(row, await retained_tables(conn))


@router.get(API_PREFIX + "/erasure-requests")
async def list_erasure_requests(
    ctx: Annotated[AuthContext, Depends(guard("listErasureRequests"))],
    limit: int | None = None,
    cursor: str | None = None,
    state: str | None = None,
) -> Response:
    if state is not None and state not in STATES:
        raise ProblemError("validation_failed", "state is not an erasure state")
    page = PageQuery.of(limit, cursor, state=state)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM sibyl.erasure_request WHERE tenant_id = $1"
        if state is not None:
            args.append(state)
            sql += f" AND state = ${len(args)}"
        retained = await retained_tables(conn)
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            serialize=lambda r: erasure_view(r, retained),
        )

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/erasure-requests/{request_id}")
async def get_erasure_request(
    request_id: str, ctx: Annotated[AuthContext, Depends(guard("getErasureRequest"))]
) -> Response:
    rid = parse_uuid(request_id)

    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.erasure_request WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            rid,
        )
        if row is None:
            raise ProblemError("not_found")
        return Outcome(await _view(conn, row))

    return await run_read(ctx, work)


async def _scope(conn: Any, ctx: AuthContext, body: ErasureRequestCreate) -> tuple[Any, Any]:
    """→ (stored scope_ref, affected_objects) after the per-scope validation."""
    if body.scope_kind == "tenant":
        if body.scope_ref is not None or body.agent_ids:
            raise ProblemError("validation_failed", "a tenant-scope request names no scope_ref")
        return None, None
    if body.scope_ref is None:
        raise ProblemError("scope_ref_required")
    if body.scope_kind == "agent":
        try:
            agent = UUID(body.scope_ref)
        except ValueError:
            raise ProblemError("validation_failed", "scope_ref must be an agent id") from None
        found = await conn.fetchval(
            "SELECT id FROM sibyl.agent WHERE tenant_id = $1 AND id = $2", ctx.tenant_id, agent
        )
        if found is None:
            raise ProblemError("not_found")
        return str(agent), None
    if not body.agent_ids or body.window_from is None:
        raise ProblemError(
            "validation_failed", "subject scope needs agent_ids and window_from (agent_window)"
        )
    if body.window_to is not None and body.window_to <= body.window_from:
        raise ProblemError("validation_failed", "window_to must be after window_from")
    agents = sorted({str(a) for a in body.agent_ids})
    known = await conn.fetchval(
        "SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
        ctx.tenant_id,
        agents,
    )
    if int(known) != len(agents):
        raise ProblemError("not_found")
    subject_set = {
        "agent_ids": agents,
        "window_from": jsonable(body.window_from),
        "window_to": jsonable(body.window_to),
    }
    return subject_hash(ctx, body.scope_ref), {
        "subject_set": subject_set,
        "resolution": "agent_window",
    }


async def _in_progress(conn: Any, ctx: AuthContext, scope_kind: str, scope_ref: Any) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.erasure_request WHERE tenant_id = $1"
            " AND state <> ALL($2::text[]) AND (scope_kind = 'tenant'"
            " OR (scope_kind = $3 AND scope_ref IS NOT DISTINCT FROM $4)))",
            ctx.tenant_id,
            list(TERMINAL),
            scope_kind,
            scope_ref,
        )
    )


@router.post(API_PREFIX + "/erasure-requests", status_code=201)
async def request_erasure(
    body: ErasureRequestCreate,
    ctx: Annotated[AuthContext, Depends(guard("requestErasure"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        ctx.object_rule_checked("owner_for_tenant_scope")
        if body.scope_kind == "tenant":
            if not _is_owner(ctx):
                raise await refuse(ctx, "forbidden", "a tenant-scope erasure is filed by an owner")
            others = await conn.fetchval(_OWNERS_SQL, ctx.tenant_id, user_id(ctx))
            if int(others or 0) < 1:
                raise ProblemError("second_owner_required")
        scope_ref, affected = await _scope(conn, ctx, body)
        if await _in_progress(conn, ctx, body.scope_kind, scope_ref):
            raise ProblemError("erasure_in_progress")
        agents = [] if affected is None else [UUID(a) for a in affected["subject_set"]["agent_ids"]]
        if body.scope_kind == "agent":
            agents = [UUID(scope_ref)]
        holds = await blocking_holds(conn, ctx.tenant_id, body.scope_kind, scope_ref, agents)
        state = "hold_blocked" if holds else "requested"
        row = await conn.fetchrow(
            "INSERT INTO sibyl.erasure_request (tenant_id, scope_kind, scope_ref, legal_basis,"
            " requested_by, state, hold_check_at, blocking_hold_ids, affected_objects,"
            " execution_log) VALUES ($1, $2, $3, $4, $5, $6, now(), $7, $8,"
            " jsonb_build_array(jsonb_build_object('step', 'requested', 'at', now(),"
            " 'reason', $9::text))) RETURNING *",
            ctx.tenant_id,
            body.scope_kind,
            scope_ref,
            body.legal_basis,
            user_id(ctx),
            state,
            holds,
            affected,
            body.reason,
        )
        rid = row["id"]
        receipt = await audit(
            conn,
            ctx,
            "erasure.requested",
            resource_type="erasure_request",
            resource_id=rid,
            reason=body.reason,
            detail={
                "request_id": str(rid),
                "scope_kind": body.scope_kind,
                "legal_basis": body.legal_basis,
                "hold_ids": [str(h) for h in holds],
            },
        )
        if holds:
            await system_audit(
                ctx,
                conn,
                "erasure.blocked_by_hold",
                rid,
                {"request_id": str(rid), "hold_ids": [str(h) for h in holds]},
            )
        await step_event(ctx, conn, rid, state)
        return Outcome(await _view(conn, row), status=201, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


async def _approve(conn: Any, ctx: AuthContext, row: Any, reason: str) -> Any:
    ctx.action("approve")
    if row["requested_by"] is not None and row["requested_by"] == user_id(ctx):
        raise ProblemError("self_approval", "the approver must not be the requester")
    if row["scope_kind"] == "tenant" and not _is_owner(ctx):
        raise await refuse(ctx, "forbidden", "a tenant-scope erasure is approved by an owner")
    if row["state"] not in ("requested", "hold_blocked"):
        raise ProblemError("invalid_transition", f"an erasure request in {row['state']} is final")
    holds = await blocking_holds(
        conn, ctx.tenant_id, row["scope_kind"], row["scope_ref"], request_agents(row)
    )
    if holds:
        raise ProblemError(
            "hold_blocked",
            "active legal holds block this erasure",
            extensions={"blocking_hold_ids": [str(h) for h in holds]},
        )
    if row["state"] == "hold_blocked":  # the successful re-check reopens it first
        await conn.execute(
            "UPDATE sibyl.erasure_request SET state = 'requested', blocking_hold_ids = '{}'"
            " WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            row["id"],
        )
    return await conn.fetchrow(
        "UPDATE sibyl.erasure_request SET state = 'approved', approved_by = $3,"
        " approved_at = now(), hold_check_at = now(), blocking_hold_ids = '{}',"
        " execution_log = execution_log || jsonb_build_array(jsonb_build_object("
        "'step', 'approved', 'at', now(), 'reason', $4::text))"
        " WHERE tenant_id = $1 AND id = $2 RETURNING *",
        ctx.tenant_id,
        row["id"],
        user_id(ctx),
        reason,
    )


async def _close(conn: Any, ctx: AuthContext, row: Any, verb: str, reason: str) -> Any:
    target = "rejected" if verb == "reject" else "cancelled"
    allowed = ("requested", "hold_blocked") + (("approved",) if verb == "cancel" else ())
    ctx.action(verb)
    if verb == "reject":
        if row["requested_by"] is not None and row["requested_by"] == user_id(ctx):
            raise ProblemError("self_approval", "the requester cannot decide their own request")
    elif row["requested_by"] != user_id(ctx) and not _is_owner(ctx):
        raise await refuse(ctx, "forbidden", "only the requester or an owner may cancel")
    if row["state"] not in allowed:
        raise ProblemError("invalid_transition", f"cannot {verb} a request in {row['state']}")
    return await conn.fetchrow(
        "UPDATE sibyl.erasure_request SET state = $3, execution_log = execution_log"
        " || jsonb_build_array(jsonb_build_object('step', $3::text, 'at', now(),"
        " 'reason', $4::text)) WHERE tenant_id = $1 AND id = $2 RETURNING *",
        ctx.tenant_id,
        row["id"],
        target,
        reason,
    )


AUDIT_FOR = {
    "approve": "erasure.approved",
    "reject": "erasure.rejected",
    "cancel": "erasure.cancelled",
}


@router.post(API_PREFIX + "/erasure-requests/{request_id}/actions")
async def act_on_erasure_request(
    request_id: str,
    body: ErasureAction,
    ctx: Annotated[AuthContext, Depends(guard("actOnErasureRequest"))],
) -> Response:
    rid = parse_uuid(request_id)

    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.erasure_request WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            ctx.tenant_id,
            rid,
        )
        if row is None:
            raise ProblemError("not_found")
        if body.action == "approve":
            updated = await _approve(conn, ctx, row, body.reason)
        else:
            updated = await _close(conn, ctx, row, body.action, body.reason)
        detail: dict[str, Any] = {"request_id": str(rid)}
        if body.action != "cancel":
            detail["approver_id"] = str(user_id(ctx))
        receipt = await audit(
            conn,
            ctx,
            AUDIT_FOR[body.action],
            resource_type="erasure_request",
            resource_id=rid,
            reason=body.reason,
            detail=detail,
        )
        await step_event(ctx, conn, rid, updated["state"])
        return Outcome(await _view(conn, updated), receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


@router.get(API_PREFIX + "/erasure-requests/{request_id}/certificate")
async def get_erasure_certificate(
    request_id: str, ctx: Annotated[AuthContext, Depends(guard("getErasureCertificate"))]
) -> Response:
    rid = parse_uuid(request_id)

    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.erasure_request WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            rid,
        )
        if row is None:
            raise ProblemError("not_found")
        entry = next(
            (e for e in reversed(list(row["execution_log"] or [])) if e.get("step") == "completed"),
            None,
        )
        if row["state"] != "completed" or entry is None or row["certificate_sha256"] is None:
            raise ProblemError("not_completed")
        certificate = entry["certificate"]
        digest = hashlib.sha256(canonicalize(certificate)).digest()
        if digest != bytes(row["certificate_sha256"]):
            raise ProblemError("internal_error", "the stored certificate does not match its hash")
        return Outcome(
            {
                "request_id": str(rid),
                "certificate": certificate,
                "certificate_sha256": digest.hex(),
                "anchor_id": jsonable(row["completion_anchor_id"]),
                "backups_expire_at": certificate.get("backups_expire_at"),
            }
        )

    return await run_read(ctx, work)
