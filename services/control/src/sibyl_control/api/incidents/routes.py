"""``/incidents`` (API.md §5.7, §6.3): list, get, open an operator saga, act on one.

Incident = failover saga row (B1). Reads apply the ``group`` object rule through the agent
(out-of-group incidents are 404); writes run in one tenant transaction with the Idempotency-Key
contract, the per-action second scope (``x-sibyl-actions``) and the action's step-up.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    Outcome,
    PageQuery,
    agent_visibility,
    keyset_page,
    load_agent,
    run_read,
    run_write,
)
from . import actions
from .common import audited
from .models import IncidentAction, IncidentCreate
from .views import incident_view, incident_views

router = APIRouter()
LIVE = ("pending", "running", "waiting_approval")
_INCIDENT_SQL = "SELECT * FROM sibyl.failover WHERE tenant_id = $1 AND id = $2"
_LOCKED_SQL = _INCIDENT_SQL + " FOR UPDATE"


@router.get(API_PREFIX + "/incidents")
async def list_incidents(
    ctx: Annotated[AuthContext, Depends(guard("listIncidents"))],
    agent_id: Annotated[UUID | None, Query()] = None,
    state: Annotated[
        str | None, Query(pattern="^(pending|running|waiting_approval|done|cancelled|failed)$")
    ] = None,
    kind: Annotated[str | None, Query(max_length=32)] = None,
    since: Annotated[datetime | None, Query()] = None,
    open: Annotated[bool | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    page = PageQuery.of(
        limit, cursor, agent_id=agent_id, state=state, kind=kind, since=since, open=open
    )

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = (
            "SELECT f.* FROM sibyl.failover f JOIN sibyl.agent a"
            " ON a.tenant_id = f.tenant_id AND a.id = f.agent_id WHERE f.tenant_id = $1"
        )
        sql += agent_visibility(ctx, "a", args)
        for column, value in (("f.agent_id", agent_id), ("f.state", state), ("f.kind", kind)):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        if since is not None:
            args.append(since)
            sql += f" AND f.created_at >= ${len(args)}"
        if open is not None:
            args.append(list(LIVE))
            sql += f" AND ({'' if open else 'NOT '}f.state = ANY(${len(args)}::text[]))"
        outcome = await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("f.created_at", "f.id"),
            descending=True,
            serialize=lambda r: r,
        )
        outcome.body["data"] = await incident_views(conn, ctx.tenant_id, outcome.body["data"])
        return outcome

    return await run_read(ctx, work)


async def _incident(
    conn: Any, ctx: AuthContext, incident_id: UUID, *, lock: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    sql = _LOCKED_SQL if lock else _INCIDENT_SQL
    row = await conn.fetchrow(sql, ctx.tenant_id, incident_id)
    if row is None:
        raise ProblemError("not_found")
    agent = await load_agent(conn, ctx, row["agent_id"])
    return dict(row), agent


@router.get(API_PREFIX + "/incidents/{incident_id}")
async def get_incident(
    incident_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getIncident"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        await _incident(conn, ctx, incident_id, lock=False)
        return Outcome(await incident_view(conn, ctx.tenant_id, incident_id))

    return await run_read(ctx, work)


@router.post(API_PREFIX + "/incidents", status_code=201)
async def open_incident(
    body: IncidentCreate,
    ctx: Annotated[AuthContext, Depends(guard("openIncident"))],
) -> Response:
    async def write(conn: Any, start: int) -> Outcome:
        agent = await load_agent(conn, ctx, body.agent_id, lock=True)
        done = await actions.open_incident(conn, ctx, body, agent)
        view = await incident_view(conn, ctx.tenant_id, done.incident_id)
        return Outcome(view, status=done.status)

    return await run_write(ctx, audited(ctx, write), idempotent=True)


@router.post(API_PREFIX + "/incidents/{incident_id}/actions")
async def act_on_incident(
    incident_id: UUID,
    body: IncidentAction,
    ctx: Annotated[AuthContext, Depends(guard("actOnIncident"))],
) -> Response:
    async def write(conn: Any, start: int) -> Outcome:
        incident, agent = await _incident(conn, ctx, incident_id, lock=True)
        status = await actions.act(conn, ctx, incident, agent, body)
        view = await incident_view(conn, ctx.tenant_id, incident_id)
        return Outcome(view, status=status)

    return await run_write(ctx, audited(ctx, write), idempotent=True)
