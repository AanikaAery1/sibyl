"""Provider incidents (API.md §5.9): list and one with its member alerts. Tenant-wide reads
(``agents:read``, no object rule in the contract)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.problems import ProblemError
from ..auth.common import parse_uuid
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import Outcome, PageQuery, keyset_page, run_read
from .views import ALERT_SELECT, INCIDENT_SELECT, alert_view, incident_view

router = APIRouter()


@router.get(API_PREFIX + "/provider-incidents")
async def list_provider_incidents(
    ctx: Annotated[AuthContext, Depends(guard("listProviderIncidents"))],
    state: Annotated[str | None, Query(max_length=20)] = None,
    provider_id: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> Response:
    if state is not None and state not in ("open", "resolved"):
        raise ProblemError("validation_failed", "state is open or resolved")
    provider = parse_uuid(provider_id) if provider_id is not None else None
    page = PageQuery.of(limit, cursor, state=state, provider_id=provider)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = INCIDENT_SELECT
        if state is not None:
            args.append(state)
            sql += f" AND state = ${len(args)}"
        if provider is not None:
            args.append(provider)
            sql += f" AND provider_id = ${len(args)}"
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("started_at", "id"),
            descending=True,
            serialize=incident_view,
        )

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/provider-incidents/{provider_incident_id}")
async def get_provider_incident(
    provider_incident_id: str,
    ctx: Annotated[AuthContext, Depends(guard("getProviderIncident"))],
) -> Response:
    pid = parse_uuid(provider_incident_id)

    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(INCIDENT_SELECT + " AND id = $2", ctx.tenant_id, pid)
        if row is None:
            raise ProblemError("not_found")
        members = await conn.fetch(
            ALERT_SELECT.format(where="AND a.provider_incident_id = $2")
            + " ORDER BY first_fired_at, id",
            ctx.tenant_id,
            pid,
        )
        body = incident_view(row)
        body["alerts"] = [alert_view(m) for m in members]
        return Outcome(body)

    return await run_read(ctx, work)
