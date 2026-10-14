"""Legal holds (API.md §5.12, §10.4 rules 2, 7-9; R14).

``POST /legal-holds`` and ``POST /legal-holds/{id}/release`` need ``holds:manage`` with a fresh
step-up and a reason; both are evidence-grade audit rows. Scope rules (422 ``scope_mismatch``):

* ``tenant``: no ``scope_ref``, no incident; holds everything the tenant has.
* ``agent``: ``scope_ref`` is the agent id; ``agent_ids`` is materialised to that agent.
* ``incident``: ``provider_incident_id`` required (no ``scope_ref``); ``agent_ids``
  materialised from the incident's affected agents; may be open-ended (ends with the incident).
* ``subject``: ``scope_ref`` is the subject identifier, hashed with ``SIBYL_SUBJECT_SALT``
  exactly as erasure requests hash it; the operator supplies ``agent_ids`` (agent_window).

Every non-incident hold needs ``expires_at`` within two years. A hold never widens read access.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import Response

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
    run_read,
    run_write,
    user_id,
)
from .lifecycle import block_on_new_hold, subject_hash, unblock_on_release
from .models import LegalHoldCreate, ReasonBody
from .views import hold_view

router = APIRouter()
MAX_HOLD = timedelta(days=730)
HOLD_STATES = ("active", "released", "expired")


def _mismatch(detail: str) -> ProblemError:
    return ProblemError("scope_mismatch", detail)


@router.get(API_PREFIX + "/legal-holds")
async def list_legal_holds(
    ctx: Annotated[AuthContext, Depends(guard("listLegalHolds"))],
    limit: int | None = None,
    cursor: str | None = None,
    state: str | None = None,
) -> Response:
    if state is not None and state not in HOLD_STATES:
        raise ProblemError("validation_failed", "state is not a hold state")
    page = PageQuery.of(limit, cursor, state=state)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM sibyl.legal_hold WHERE tenant_id = $1"
        if state is not None:
            args.append(state)
            sql += f" AND state = ${len(args)}"
        return await keyset_page(conn, ctx, select=sql, args=args, page=page, serialize=hold_view)

    return await run_read(ctx, work)


async def _agents_exist(conn: Any, ctx: AuthContext, agents: list[UUID]) -> None:
    known = await conn.fetchval(
        "SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
        ctx.tenant_id,
        agents,
    )
    if int(known) != len(set(agents)):
        raise _mismatch("agent_ids name agents that do not exist")


async def _materialise(
    conn: Any, ctx: AuthContext, body: LegalHoldCreate
) -> tuple[str | None, list[UUID]]:
    """→ (stored scope_ref, materialised agent_ids)."""
    agents = list(dict.fromkeys(body.agent_ids or []))
    if body.scope_kind != "incident" and body.provider_incident_id is not None:
        raise _mismatch("provider_incident_id belongs to incident-scope holds only")
    if body.scope_kind == "tenant":
        if body.scope_ref is not None or agents:
            raise _mismatch("a tenant hold names no scope_ref and no agent_ids")
        return None, []
    if body.scope_kind == "incident":
        if body.provider_incident_id is None or body.scope_ref is not None:
            raise _mismatch("an incident hold names provider_incident_id and no scope_ref")
        affected = await conn.fetchval(
            "SELECT affected_agent_ids FROM sibyl.provider_incident WHERE tenant_id = $1"
            " AND id = $2",
            ctx.tenant_id,
            body.provider_incident_id,
        )
        if affected is None:
            raise _mismatch("provider_incident_id does not name an incident of this tenant")
        return None, sorted(set(affected) | set(agents))
    if body.scope_ref is None:
        raise _mismatch(f"a {body.scope_kind} hold needs scope_ref")
    if body.scope_kind == "agent":
        try:
            agent = UUID(body.scope_ref)
        except ValueError:
            raise _mismatch("scope_ref of an agent hold is the agent id") from None
        if agents and agents != [agent]:
            raise _mismatch("agent_ids of an agent hold can only be its agent")
        await _agents_exist(conn, ctx, [agent])
        return str(agent), [agent]
    if not agents:
        raise _mismatch("a subject hold needs the operator-resolved agent_ids (agent_window)")
    await _agents_exist(conn, ctx, agents)
    return subject_hash(ctx, body.scope_ref), agents


@router.post(API_PREFIX + "/legal-holds", status_code=201)
async def place_legal_hold(
    body: LegalHoldCreate,
    ctx: Annotated[AuthContext, Depends(guard("placeLegalHold"))],
) -> Response:
    if body.window_to is not None and body.window_to < body.window_from:
        raise ProblemError("validation_failed", "window_to must not be before window_from")

    async def work(conn: Any) -> Outcome:
        now = await conn.fetchval("SELECT now()")
        if body.scope_kind != "incident" and body.expires_at is None:
            raise _mismatch("a hold that is not incident-bound needs expires_at (≤ 2 years)")
        if body.expires_at is not None and not now < body.expires_at <= now + MAX_HOLD:
            raise ProblemError("validation_failed", "expires_at must be in the next two years")
        scope_ref, agents = await _materialise(conn, ctx, body)
        row = await conn.fetchrow(
            "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, scope_ref,"
            " provider_incident_id, agent_ids, window_from, window_to, reason, placed_by,"
            " placed_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
            " RETURNING *",
            ctx.tenant_id,
            body.scope_kind,
            scope_ref,
            body.provider_incident_id,
            agents,
            body.window_from,
            body.window_to,
            body.reason,
            user_id(ctx),
            now,
            body.expires_at,
        )
        receipt = await audit(
            conn,
            ctx,
            "hold.placed",
            resource_type="legal_hold",
            resource_id=row["id"],
            reason=body.reason,
            detail={
                "hold_id": str(row["id"]),
                "scope_kind": body.scope_kind,
                "scope_ref": scope_ref,
                "incident_id": jsonable(body.provider_incident_id),
                "expires_at": jsonable(body.expires_at),
                "agent_ids": [str(a) for a in agents],
            },
        )
        await block_on_new_hold(ctx, conn)
        return Outcome(hold_view(row), status=201, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


@router.post(API_PREFIX + "/legal-holds/{hold_id}/release")
async def release_legal_hold(
    hold_id: str,
    body: ReasonBody,
    ctx: Annotated[AuthContext, Depends(guard("releaseLegalHold"))],
) -> Response:
    hid = parse_uuid(hold_id)

    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.legal_hold WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            ctx.tenant_id,
            hid,
        )
        if row is None:
            raise ProblemError("not_found")
        if row["state"] != "active":
            raise ProblemError("not_active", f"the hold is {row['state']}")
        updated = await conn.fetchrow(
            "UPDATE sibyl.legal_hold SET state = 'released', released_by = $3,"
            " released_at = now(), release_reason = $4 WHERE tenant_id = $1 AND id = $2"
            " RETURNING *",
            ctx.tenant_id,
            hid,
            user_id(ctx),
            body.reason,
        )
        receipt = await audit(
            conn,
            ctx,
            "hold.released",
            resource_type="legal_hold",
            resource_id=hid,
            reason=body.reason,
            detail={
                "hold_id": str(hid),
                "scope_kind": row["scope_kind"],
                "scope_ref": row["scope_ref"],
                "incident_id": jsonable(row["provider_incident_id"]),
                "expires_at": jsonable(row["expires_at"]),
            },
        )
        reopened = await unblock_on_release(ctx, conn)
        view = hold_view(updated)
        view["reopened_erasure_ids"] = [str(r) for r in reopened]
        return Outcome(view, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)
