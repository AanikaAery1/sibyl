"""sse API module (lane V): ``GET /api/v1/events/stream`` (API.md §7, R58, R60).

Humans (``agents:read``, group-filtered) receive every topic; API keys (``routing:read``) receive
only ``policy`` and ``killswitch`` (``key_sees_policy_topics_only``), and a bound key only rows
about its own agent or the tenant. Payloads are the outbox's refs and versions; clients re-fetch
through authorised GETs. Streams per principal: 20 per session, 5 per key (429 ``stream_limit``).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import StreamingResponse

from ...core.authz import PrincipalKind
from ...core.outbox import EVENT_TOPICS, TOPICS
from ...core.problems import ProblemError
from .._stubs import stub_router
from ..auth.common import lane_state, principal_of, record_denials, require_db, tenant_tx
from ..auth.principals import NO_TOUCH_STATE
from ..contract import API_PREFIX
from ..deps import AuthContext, Services, get_services, guard
from .hub import NotifyHub
from .stream import (
    NIL,
    Cursor,
    OutboxStream,
    StreamConfig,
    Visibility,
    frame,
    head_cursor,
    oldest_cursor,
    reset,
)

router = APIRouter(dependencies=[Depends(record_denials)])
KEY_TOPICS = frozenset({"policy", "killswitch"})
MAX_SINCE = timedelta(days=7)
STREAMS_PER_SESSION = 20
STREAMS_PER_KEY = 5
_XID_CURSOR = re.compile(r"^(\d{1,20})\|([0-9a-f-]{36})$")
_TS_CURSOR = re.compile(r"^\d{4}-\d{2}-\d{2}T[^|]+Z\|([0-9a-f-]{36})$")


def _tokens(topics: str | None) -> tuple[set[str], set[str]]:
    wanted_topics: set[str] = set()
    wanted_events: set[str] = set()
    for token in (t.strip() for t in (topics or "").split(",")):
        if not token:
            continue
        if token in TOPICS:
            wanted_topics.add(token)
        elif token in EVENT_TOPICS:
            wanted_events.add(token)
        else:
            raise ProblemError("validation_failed", f"unknown topic or event {token!r}")
    return wanted_topics, wanted_events


def _hub(request: Request, services: Services) -> NotifyHub:
    state = lane_state(request)
    hub: NotifyHub | None = state.get("sse_hub")
    if hub is None:
        settings = services.settings
        if settings is None:
            raise ProblemError("service_unavailable", "streaming needs a database DSN")
        dsn = settings.dsn()

        async def connect() -> Any:
            import asyncpg

            return await asyncpg.connect(dsn, server_settings={"application_name": "sibyl-api-sse"})

        hub = NotifyHub(connect)
        state["sse_hub"] = hub
    return hub


def _stream_key(principal: Any) -> tuple[str, int]:
    if principal.kind is PrincipalKind.API_KEY:
        return f"key:{principal.id}", STREAMS_PER_KEY
    if principal.session_id is not None:
        return f"session:{principal.session_id}", STREAMS_PER_SESSION
    return f"user:{principal.id}", STREAMS_PER_SESSION


async def _start_cursor(
    conn: Any, tenant: UUID, last_event_id: str | None, since: datetime | None, now: datetime
) -> tuple[Cursor | None, bool]:
    """→ (start cursor or None when the resume point expired, whether to announce it)."""
    if last_event_id:
        match = _XID_CURSOR.fullmatch(last_event_id.strip())
        legacy = _TS_CURSOR.fullmatch(last_event_id.strip())
        try:
            row_id = UUID(match.group(2)) if match else UUID(legacy.group(1)) if legacy else None
        except ValueError:
            row_id = None
        if row_id is None:
            raise ProblemError("validation_failed", "Last-Event-ID is not a stream cursor")
        if row_id == NIL and match:
            return Cursor(int(match.group(1)), NIL), False
        row = await conn.fetchrow(
            "SELECT xid::text::numeric AS xid_n, id FROM sibyl.outbox WHERE tenant_id = $1 AND id"
            " = $2",
            tenant,
            row_id,
        )
        if row is None or (match and int(match.group(1)) != int(row["xid_n"])):
            return None, False
        return Cursor(int(row["xid_n"]), row["id"]), False
    if since is not None:
        if since < now - MAX_SINCE or since > now + timedelta(minutes=5):
            raise ProblemError("validation_failed", "since must be within the last 7 days")
        row = await conn.fetchrow(
            "SELECT xid::text::numeric AS xid_n FROM sibyl.outbox WHERE tenant_id = $1"
            " AND created_at >= $2 ORDER BY xid, id LIMIT 1",
            tenant,
            since,
        )
        if row is not None:  # (first xid, nil) sorts before every row of that transaction
            return Cursor(int(row["xid_n"]), NIL), False
    head = await head_cursor(conn, tenant)
    return head, head.id != NIL  # announce only a real row (a resume can be verified)


@router.get(API_PREFIX + "/events/stream")
async def stream_events(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("streamEvents"))],
    topics: Annotated[str | None, Query(max_length=1024)] = None,
    agent_id: Annotated[UUID | None, Query()] = None,
    since: Annotated[datetime | None, Query()] = None,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID", max_length=128)] = None,
) -> StreamingResponse:
    services = get_services(request)
    principal = principal_of(ctx)
    tenant = principal.tenant_id
    is_key = principal.kind is PrincipalKind.API_KEY
    wanted_topics, wanted_events = _tokens(topics)
    ctx.object_rule_checked("key_sees_policy_topics_only")
    db_topics: set[str] | None = None
    if wanted_topics or wanted_events:
        db_topics = wanted_topics | {EVENT_TOPICS[e] for e in wanted_events}
    if is_key:
        db_topics = (db_topics or set(KEY_TOPICS)) & KEY_TOPICS
        if not db_topics:
            raise ProblemError("forbidden", "API keys receive policy and killswitch topics only")
    groups = ctx.group_filter()
    db = require_db(services)
    async with tenant_tx(services, tenant, readonly=True) as conn:
        focus = agent_id
        if agent_id is not None:
            agent = await conn.fetchrow(
                "SELECT id, agent_group_id FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
                tenant,
                agent_id,
            )
            if agent is None:
                raise ProblemError("not_found")
            ctx.check(resource_group_id=agent["agent_group_id"], resource_agent_id=agent["id"])
        if principal.bound_agent_id is not None:
            focus = principal.bound_agent_id
        agents = None
        if groups is not None:
            rows = await conn.fetch(
                "SELECT id FROM sibyl.agent WHERE tenant_id = $1 AND agent_group_id = ANY"
                " ($2::uuid[])",
                tenant,
                list(groups),
            )
            agents = frozenset(r["id"] for r in rows)
        start, announce = await _start_cursor(conn, tenant, last_event_id, since, ctx.now)
        oldest = await oldest_cursor(conn, tenant) if start is None else None

    config: StreamConfig = lane_state(request).get("sse_config") or StreamConfig()
    if start is None:

        async def expired() -> AsyncIterator[bytes]:
            yield f"retry: {config.retry_ms}\n\n".encode()
            yield reset("cursor_expired", oldest)

        return _response(expired())

    counts: Counter[str] = lane_state(request).setdefault("sse_streams", Counter())
    slot, cap = _stream_key(principal)
    if counts[slot] >= cap:
        raise ProblemError(
            "stream_limit", extensions={"retry_after_s": 30}, headers={"Retry-After": "30"}
        )
    hub = _hub(request, services)
    await hub.start()

    async def revalidate() -> bool:
        setattr(request.state, NO_TOUCH_STATE, True)  # re-check only, no idle slide
        try:
            again = await services.principals.resolve(request)
        except ProblemError:
            return False
        return again is not None and again.id == principal.id

    visibility = Visibility(
        topics=frozenset(db_topics) if db_topics is not None and not wanted_events else None,
        event_types=frozenset(wanted_events) | _events_of(wanted_topics) if wanted_events else None,
        agent_id=focus,
        agents=agents,
    )
    stream = OutboxStream(
        db,
        hub,
        tenant,
        start,
        visibility,
        db_topics=db_topics,
        revalidate=revalidate,
        config=config,
        announce=announce,
    )
    counts[slot] += 1

    async def body() -> AsyncIterator[bytes]:
        try:
            async for chunk in stream.frames():
                yield chunk
        finally:
            counts[slot] -= 1

    return _response(body())


def _events_of(topics: set[str]) -> frozenset[str]:
    return frozenset(e for e, t in EVENT_TOPICS.items() if t in topics)


def _response(body: AsyncIterator[bytes]) -> StreamingResponse:
    return StreamingResponse(
        body,
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"},
    )


_ = frame
stub_router("sse", router)
