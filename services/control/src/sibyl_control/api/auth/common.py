"""Helpers shared by the lane A/V handlers (auth, tenancy, keys, reads, sse).

Everything here composes the kernel's public helpers (``tenant_tx``, ``guard``/``AuthContext``,
``audit_actor``, the idempotency store, the outbox writer); nothing re-implements them.
Lane-local runtime objects (OIDC client, KEK, blob store, SSE hub) live on ``app.state`` under
``LANE_STATE`` and are built lazily from ``Settings`` so the steward-owned ``app.py`` needs no
edit; tests pre-seed them.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from fastapi import Request
from fastapi.responses import Response

from ...core.audit import RECEIPT_HEADER, AuditReceipt, AuditRecord, audit_actor
from ...core.authz import Principal
from ...core.db import Database
from ...core.idempotency import (
    IDEMPOTENCY_HEADER,
    MAX_STORED_BODY_BYTES,
    REPLAY_HEADER,
    Fresh,
    PgIdempotencyStore,
    RecordKey,
    StoredResponse,
    begin_or_raise,
    require_key,
)
from ...core.outbox import OutboxMessage
from ...core.paging import PageResult, decode_cursor, link_header, paginate, validate_limit
from ...core.problems import ProblemError, problem_from_db_error
from ..deps import (
    AuthContext,
    Services,
    audit_reason,
    get_services,
    idempotency_fingerprint,
    idempotency_principal_kind,
    write_denial,
)
from ..middleware import AUTH_CONTEXT_STATE

LANE_STATE = "sibyl_lane_a"
JSON_MEDIA = "application/json"


def iso(value: datetime | None) -> str | None:
    """RFC 3339 UTC with microseconds and ``Z`` (API.md §2.9)."""
    if value is None:
        return None
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return iso(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    if isinstance(value, set | frozenset | tuple):
        return list(value)
    raise TypeError(f"not JSON serialisable: {type(value).__name__}")


def dumps(body: Any) -> bytes:
    return json.dumps(body, default=_default, separators=(",", ":"), ensure_ascii=False).encode()


def json_response(
    body: Any, status: int = 200, headers: Mapping[str, str] | None = None
) -> Response:
    return Response(dumps(body), status_code=status, media_type=JSON_MEDIA, headers=headers)


def lane_state(request: Request) -> dict[str, Any]:
    """Per-app dict for lane-local runtime objects (lazy, see module docstring)."""
    state = getattr(request.app.state, LANE_STATE, None)
    if state is None:
        state = {}
        setattr(request.app.state, LANE_STATE, state)
    return state


def require_db(services: Services) -> Database:
    if services.db is None:
        raise ProblemError("database_unavailable", "no database configured")
    return services.db


def principal_of(ctx: AuthContext) -> Principal:
    if ctx.principal is None:
        raise ProblemError("unauthenticated")
    return ctx.principal


def request_id(request: Request) -> UUID | None:
    raw = getattr(request.state, "request_id", None)
    try:
        return UUID(raw) if raw else None
    except ValueError:
        return None


def human_reason(request: Request, body_reason: str | None, operation_id: str) -> str:
    """The audit ``reason`` for a human write.

    Uses the body's ``reason`` when sent, else ``X-Sibyl-Reason`` (≥ 10 chars), else a fixed
    operation label (``deps.audit_reason``).
    """
    return audit_reason(request, body_reason, f"{operation_id} via api")


def actor_record(
    ctx: AuthContext,
    action: str,
    *,
    resource_type: str,
    resource_id: UUID | None = None,
    resource_ref: str | None = None,
    detail: Mapping[str, Any] | None = None,
    reason: str | None = None,
) -> AuditRecord:
    principal = principal_of(ctx)
    actor = audit_actor(principal)
    return AuditRecord(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_ref=resource_ref,
        reason=reason,
        detail=dict(detail or {}),
        request_id=request_id(ctx.request) if ctx.request is not None else None,
        **actor.fields(),
    )


async def append_audit(
    services: Services, conn: Any, tenant_id: UUID, record: AuditRecord
) -> AuditReceipt:
    return await services.audit.append(conn, tenant_id, record)


async def emit(services: Services, conn: Any, tenant_id: UUID, message: OutboxMessage) -> None:
    await services.outbox.emit(conn, tenant_id, message)


@asynccontextmanager
async def db_errors() -> AsyncIterator[None]:
    """Map asyncpg errors to problems without echoing database messages."""
    import asyncpg

    try:
        yield
    except asyncpg.PostgresError as exc:
        raise problem_from_db_error(exc) from None


AUDIT_LOCK_SQL = "SELECT sibyl.audit_lock($1)"


@asynccontextmanager
async def tenant_tx(
    services: Services, tenant_id: UUID, *, readonly: bool = False, audit_lock: bool = False
) -> AsyncIterator[Any]:
    """The kernel tenant transaction; ``audit_lock`` takes ``sibyl.audit_lock`` first, before any
    row lock, so a handler that appends audit after locking rows cannot deadlock (DB ruling)."""
    db = require_db(services)
    async with db_errors(), db.tenant_tx(tenant_id, readonly=readonly) as conn:
        if audit_lock and services.db is not None:
            await conn.execute(AUDIT_LOCK_SQL, tenant_id)
        yield conn


@dataclass(frozen=True)
class Outcome:
    """What a mutation handler produced: status, JSON body, extra headers, audit receipt."""

    status: int
    body: Any
    headers: Mapping[str, str] | None = None
    receipt: AuditReceipt | None = None
    replay_body: Any = None
    """What an ``Idempotency-Key`` replay returns instead of ``body`` (e.g. without a one-time
    secret, which must never be stored); ``None`` = replay ``body`` itself."""

    def response(self, *, replay: bool = False) -> Response:
        headers = dict(self.headers or {})
        if self.receipt is not None:
            headers[RECEIPT_HEADER] = self.receipt.header_value()
        body = self.replay_body if replay and self.replay_body is not None else self.body
        if body is None:
            return Response(status_code=self.status, headers=headers)
        return json_response(body, self.status, headers)


Mutation = Callable[[Any], Awaitable[Outcome]]


async def run_mutation(
    request: Request, ctx: AuthContext, mutate: Mutation, *, idempotent: bool
) -> Response:
    """One tenant transaction around ``mutate(conn)``; with ``idempotent`` the response is
    recorded in that same transaction under the caller's ``Idempotency-Key`` (API.md §2.6)."""
    services = get_services(request)
    principal = principal_of(ctx)
    tenant = principal.tenant_id
    if not idempotent:
        async with tenant_tx(services, tenant, audit_lock=True) as conn:
            outcome = await mutate(conn)
        return outcome.response()
    key = require_key(request.headers.get(IDEMPOTENCY_HEADER))
    store = services.idempotency
    if store is None:
        raise ProblemError("service_unavailable", "idempotency store not configured")
    body = await request.body()
    begun = await begin_or_raise(
        store,
        tenant,
        principal.id,
        ctx.op.operation_id,
        key,
        idempotency_fingerprint(request, body),
        principal_kind=idempotency_principal_kind(principal),
    )
    if not isinstance(begun, Fresh):
        # A replay returns this same principal's earlier, already-authorised response (with
        # one-time secrets removed); the object rules were evaluated when it was produced.
        for rule in ctx.op.object_rules:
            if rule != "self" or ctx.self_only:
                ctx.object_rule_checked(rule)
        if ctx.op.step_up == "conditional":
            ctx.step_up_if(False)
        stored = begun.response
        headers = {**stored.headers, REPLAY_HEADER: "true"}
        return Response(
            stored.body, status_code=stored.status, headers=headers, media_type=JSON_MEDIA
        )
    try:
        async with tenant_tx(services, tenant, audit_lock=True) as conn:
            outcome = await mutate(conn)
            response = outcome.response()
            await _record(store, conn, begun.token, outcome.response(replay=True))
    except BaseException:
        await store.abandon(begun.token)
        raise
    return response


async def _record(store: Any, conn: Any, token: RecordKey, response: Response) -> None:
    raw = bytes(response.body)
    if len(raw) > MAX_STORED_BODY_BYTES:
        raise ProblemError("internal_error", "idempotent response exceeds 64 KB")
    headers = {
        k: v
        for k, v in response.headers.items()
        if k.lower() not in ("content-length", "content-type")
    }
    stored = StoredResponse(response.status_code, headers, raw)
    if isinstance(store, PgIdempotencyStore):
        await store.complete_in(conn, token, stored)
    else:
        await store.complete(token, stored)


@dataclass(frozen=True)
class Paging:
    """One list route's keyset contract: the route label, sort label and key part types."""

    route: str
    sort: str
    key_types: str

    def params(
        self, limit: int | None, cursor: str | None, filters: Mapping[str, Any]
    ) -> tuple[int, tuple[Any, ...] | None]:
        size = validate_limit(limit)
        if not cursor:
            return size, None
        keyset = decode_cursor(
            cursor, filters, route=self.route, sort=self.sort, key_types=self.key_types
        )
        return size, keyset


def page_response[T](
    request: Request,
    paging: Paging,
    rows: list[T],
    limit: int,
    key_of: Callable[[T], Any],
    filters: Mapping[str, Any],
    serialize: Callable[[T], Any],
) -> Response:
    page: PageResult[T] = paginate(
        rows, limit, key_of, filters, route=paging.route, sort=paging.sort
    )
    headers: dict[str, str] = {}
    link = link_header(
        str(request.url).split("?", 1)[0], dict(request.query_params), page.next_cursor
    )
    if link:
        headers["Link"] = link
    return json_response(page.envelope(serialize), headers=headers)


async def record_denials(request: Request) -> AsyncIterator[None]:
    """Router dependency: a handler-level refusal (object rule) flagged ``audit_denied`` writes
    ``access.denied`` like a guard refusal does (best effort, separate transaction)."""
    try:
        yield
    except ProblemError as exc:
        ctx = getattr(request.state, AUTH_CONTEXT_STATE, None)
        if exc.audit_denied and isinstance(ctx, AuthContext) and ctx.principal is not None:
            await write_denial(get_services(request), request, ctx.principal, ctx.op.scope)
        raise


def parse_uuid(value: str) -> UUID:
    """Path ids that are not UUIDs are simply unknown (404), never a 422 oracle."""
    try:
        return UUID(value)
    except ValueError:
        raise ProblemError("not_found") from None
