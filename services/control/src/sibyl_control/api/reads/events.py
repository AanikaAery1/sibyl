"""Events, one event, one trace (``payloads:read`` G): metadata only, never bodies (API.md §5.10).

A group-scoped caller sees only events of agents in its groups; agent-less events
(``provider.status``, ``observation.gap``) are tenant-level and hidden from it. Keyset
``(ts desc, event_id desc)``; the window defaults to 24 h and may span at most 31 days.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import Response

from ...core.problems import ProblemError
from ..auth.common import Paging, json_response, page_response, parse_uuid, tenant_tx
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from .common import event_view, group_scope, window

router = APIRouter()
EVENTS = Paging("GET /api/v1/events", "ts desc,event_id desc", "tu")
DEFAULT_WINDOW = timedelta(hours=24)
MAX_WINDOW = timedelta(days=31)
EventType = Literal[
    "gen_ai.request",
    "tool.call",
    "agent.invoke",
    "checkpoint",
    "handoff.requested",
    "handoff.completed",
    "handoff.returned",
    "feedback",
    "task.outcome",
    "agent.discovered",
    "policy.decision",
    "observation.gap",
    "provider.status",
    "health.transition",
]

_SELECT = (
    "SELECT e.event_id, e.event_type, e.ts, e.agent_id, e.status, e.trace_id, e.span_id,"
    " e.task_id, e.call_id, e.provider, e.model, e.attrs, e.payload_ref_id, e.payload_sha256,"
    " e.payload_bytes, pr.kind AS pr_kind, pr.state AS pr_state"
    " FROM sibyl.events e"
    " LEFT JOIN sibyl.agent a ON a.tenant_id = e.tenant_id AND a.id = e.agent_id"
    " LEFT JOIN LATERAL (SELECT p.kind, p.state FROM sibyl.payload_refs p"
    "   WHERE p.tenant_id = e.tenant_id AND p.id = e.payload_ref_id LIMIT 1) pr ON true"
    " WHERE e.tenant_id = $1 AND ($2::uuid[] IS NULL OR a.agent_group_id = ANY ($2::uuid[]))"
)


@router.get(API_PREFIX + "/events")
async def list_events(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("listEvents"))],
    agent_id: Annotated[UUID | None, Query()] = None,
    event_type: Annotated[EventType | None, Query()] = None,
    status: Annotated[Literal["ok", "error", "handed_off", "cancelled"] | None, Query()] = None,
    trace_id: Annotated[str | None, Query(pattern=r"^[0-9a-f]{32}$")] = None,
    task_id: Annotated[UUID | None, Query()] = None,
    call_id: Annotated[UUID | None, Query()] = None,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    lo, hi = window(start, end, now=ctx.now, default=DEFAULT_WINDOW, maximum=MAX_WINDOW)
    filters = {
        "agent_id": agent_id,
        "event_type": event_type,
        "status": status,
        "trace_id": trace_id,
        "task_id": task_id,
        "call_id": call_id,
        "from": start,
        "to": end,
    }
    size, after = EVENTS.params(limit, cursor, filters)
    groups = group_scope(ctx)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        rows = await conn.fetch(
            _SELECT + " AND e.ts >= $3 AND e.ts < $4"
            " AND ($5::uuid IS NULL OR e.agent_id = $5) AND ($6::text IS NULL OR e.event_type = $6)"
            " AND ($7::text IS NULL OR e.status = $7) AND ($8::uuid IS NULL OR e.trace_id = $8)"
            " AND ($9::uuid IS NULL OR e.task_id = $9) AND ($10::uuid IS NULL OR e.call_id = $10)"
            " AND ($11::timestamptz IS NULL OR (e.ts, e.event_id) < ($11, $12::uuid))"
            " ORDER BY e.ts DESC, e.event_id DESC LIMIT $13",
            ctx.tenant_id,
            groups,
            lo,
            hi,
            agent_id,
            event_type,
            status,
            UUID(hex=trace_id) if trace_id else None,
            task_id,
            call_id,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )
    return page_response(
        request, EVENTS, list(rows), size, lambda r: (r["ts"], r["event_id"]), filters, event_view
    )


@router.get(API_PREFIX + "/events/{event_id}")
async def get_event(
    request: Request, event_id: str, ctx: Annotated[AuthContext, Depends(guard("getEvent"))]
) -> Response:
    eid = parse_uuid(event_id)
    groups = group_scope(ctx)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        row = await conn.fetchrow(
            _SELECT + " AND e.event_id = $3 LIMIT 1", ctx.tenant_id, groups, eid
        )
    if row is None:
        raise ProblemError("not_found")
    return json_response(event_view(row))


@router.get(API_PREFIX + "/traces/{trace_id}")
async def get_trace(
    request: Request,
    trace_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    ctx: Annotated[AuthContext, Depends(guard("getTrace"))],
) -> Response:
    groups = group_scope(ctx)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        rows = await conn.fetch(
            _SELECT + " AND e.trace_id = $3 ORDER BY e.ts, e.event_id LIMIT 5000",
            ctx.tenant_id,
            groups,
            UUID(hex=trace_id),
        )
    if not rows:
        raise ProblemError("not_found")
    return json_response({"trace_id": trace_id, "spans": [event_view(r) for r in rows]})
