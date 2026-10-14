"""approvals API module (lane S): read-only ``/approvals`` (decided via incident actions, R24).

``GET /approvals?state=&agent_id=&tier=`` and ``GET /approvals/{id}``; the ``group`` object
rule applies through the approval's agent (out-of-group approvals are 404).
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from sibyl_control.api._stubs import stub_router

from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..incidents.views import full_approval_view
from ..registry._kit import (
    Outcome,
    PageQuery,
    agent_visibility,
    keyset_page,
    load_agent,
    run_read,
)

_routes = APIRouter()


@_routes.get(API_PREFIX + "/approvals")
async def list_approvals(
    ctx: Annotated[AuthContext, Depends(guard("listApprovals"))],
    state: Annotated[
        str | None, Query(pattern="^(pending|approved|denied|expired|cancelled)$")
    ] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    tier: Annotated[int | None, Query(ge=1, le=3)] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    page = PageQuery.of(limit, cursor, state=state, agent_id=agent_id, tier=tier)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = (
            "SELECT p.* FROM sibyl.approval p JOIN sibyl.agent a"
            " ON a.tenant_id = p.tenant_id AND a.id = p.agent_id WHERE p.tenant_id = $1"
        )
        sql += agent_visibility(ctx, "a", args)
        for column, value in (("p.state", state), ("p.agent_id", agent_id), ("p.tier", tier)):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("p.created_at", "p.id"),
            descending=True,
            serialize=full_approval_view,
        )

    return await run_read(ctx, work)


@_routes.get(API_PREFIX + "/approvals/{approval_id}")
async def get_approval(
    approval_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getApproval"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.approval WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            approval_id,
        )
        if row is None:
            raise ProblemError("not_found")
        await load_agent(conn, ctx, row["agent_id"])
        return Outcome(full_approval_view(row))

    return await run_read(ctx, work)


router = stub_router("approvals", _routes)
