"""Lane R handler kit: shared by the registry, policy and credentials modules.

One request = one tenant transaction, run through ``Database.run_in_tenant_tx`` so a deadlock or
serialization failure re-runs the whole (idempotent) body. Write transactions take
``sibyl.audit_lock`` first (G0: audit is appended after other row locks). State-changing POSTs
run under the kernel Idempotency-Key store: claim, record the response inside the handler's own
transaction when the store is Postgres (a lost claim rolls the business writes back), abandon on
failure. Every audited write goes through ``audit()`` (kernel ``AuditWriter``, actor from
``audit_actor``) on the handler's connection, and the receipt header is stored with the response
so a replay returns it too. ``policy_changed()`` writes the outbox row that makes the snapshot
rebuild. Object rules are evaluated through the ``AuthContext`` (``check``, ``group_filter``,
``agent_filter``, ``object_rule_checked``, ``step_up_if``); a refusal writes ``access.denied``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import asyncpg
from fastapi.responses import JSONResponse, Response

from ...core.audit import RECEIPT_HEADER, AuditReceipt, AuditRecord, audit_actor
from ...core.authz import NOT_APPLICABLE, Grant, _NotApplicable, authorize
from ...core.canonical import canonicalize
from ...core.db import Database
from ...core.etag import check_if_match, if_none_match_hit
from ...core.idempotency import (
    IDEMPOTENCY_HEADER,
    REPLAY_HEADER,
    IdempotencyStore,
    PgIdempotencyStore,
    RecordKey,
    Replay,
    StoredResponse,
    begin_or_raise,
    require_key,
)
from ...core.outbox import OutboxMessage
from ...core.paging import KeyPart, decode_cursor, encode_cursor, link_header, validate_limit
from ...core.problems import ProblemError, problem_from_db_error
from ..deps import (
    STEP_UP_URL,
    AuthContext,
    Services,
    audit_reason,
    get_services,
    idempotency_fingerprint,
    idempotency_principal_kind,
    write_denial,
)

JSON = dict[str, Any]
Row = Mapping[str, Any]

# Unique constraints whose violation has a contract problem code of its own.
UNIQUE_PROBLEMS: Mapping[str, str] = {
    "uq_agent_tenant_slug": "slug_exists",
    "uq_tool_slug": "slug_exists",
    "uq_data_source_slug": "slug_exists",
    "uq_business_process_slug": "slug_exists",
    "uq_provider_slug": "slug_exists",
    "uq_model_name": "model_exists",
    "ux_dependency_edge_open": "edge_exists",
    "uq_alert_rule_code": "code_exists",
}


# --- plumbing -------------------------------------------------------------------------------


def services_of(ctx: AuthContext) -> Services:
    if ctx.request is None:  # pragma: no cover - the guard always attaches the request
        raise ProblemError("internal_error")
    return get_services(ctx.request)


def require_db(services: Services) -> Database:
    if services.db is None:
        raise ProblemError("database_unavailable", "no database configured")
    return services.db


def request_uuid(ctx: AuthContext) -> UUID | None:
    raw = getattr(ctx.request.state, "request_id", None) if ctx.request is not None else None
    try:
        return UUID(str(raw)) if raw else None
    except ValueError:
        return None


def user_id(ctx: AuthContext) -> UUID | None:
    """The acting ``app_user.id`` (``None`` for API-key principals)."""
    principal = ctx.principal
    return principal.id if principal is not None and principal.is_human else None


def map_db_error(exc: BaseException) -> ProblemError:
    if isinstance(exc, asyncpg.UniqueViolationError):
        code = UNIQUE_PROBLEMS.get(getattr(exc, "constraint_name", "") or "")
        return ProblemError(code or "conflict")
    if isinstance(exc, asyncpg.ForeignKeyViolationError):
        return ProblemError("validation_failed", "a referenced object does not exist")
    if isinstance(exc, asyncpg.CheckViolationError):
        return ProblemError("validation_failed", "a value is outside its allowed set")
    return problem_from_db_error(exc)


# --- JSON -----------------------------------------------------------------------------------


def jsonable(value: Any) -> Any:
    """Plain JSON for API bodies: uuid/timestamps as strings, bytes as hex, Decimal as text."""
    if value is None or isinstance(value, bool | int | str | float):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    if isinstance(value, Mapping):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [jsonable(v) for v in value]
    return str(value)


def money(value: Decimal | None) -> str | None:
    """4-dp decimal string (API.md §2.9)."""
    return None if value is None else f"{value.quantize(Decimal('0.0001'))}"


def parse_money(value: str | None) -> Decimal | None:
    return None if value is None else Decimal(value)


def sha256_hex(document: Any) -> str:
    """sha256 over the canonical (JCS) JSON of ``document`` (floats are refused by JCS)."""
    return hashlib.sha256(canonicalize(jsonable(document))).hexdigest()


def digest_ref(document: Any) -> str:
    """A content reference for audit ``detail``: never the free-form document itself.

    Free-form JSON may hold floats, which JCS refuses, so this digests sorted compact JSON.
    """
    raw = json.dumps(jsonable(document), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


# --- responses ------------------------------------------------------------------------------


@dataclass
class Outcome:
    body: Any
    status: int = 200
    etag: str | None = None
    receipt: AuditReceipt | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def response_headers(self) -> dict[str, str]:
        out = dict(self.headers)
        if self.etag is not None:
            out["ETag"] = self.etag
        if self.receipt is not None:
            out[RECEIPT_HEADER] = self.receipt.header_value()
        return out

    def to_response(self) -> JSONResponse:
        return JSONResponse(self.body, status_code=self.status, headers=self.response_headers())


Work = Callable[[Any], Awaitable[Outcome]]


async def run_read(ctx: AuthContext, work: Work) -> Response:
    """Read-only tenant transaction; honours ``If-None-Match`` when the outcome has an ETag."""
    db = require_db(services_of(ctx))
    try:
        outcome = await db.run_in_tenant_tx(ctx.tenant_id, work, readonly=True)
    except asyncpg.PostgresError as exc:
        raise map_db_error(exc) from None
    except ProblemError as exc:
        await _record_denial(ctx, exc)
        raise
    request = ctx.request
    if request is not None and if_none_match_hit(
        request.headers.get("if-none-match"), outcome.etag
    ):
        return Response(status_code=304, headers={"ETag": outcome.etag or ""})
    return outcome.to_response()


async def run_write(ctx: AuthContext, work: Work, *, idempotent: bool) -> Response:
    """One write transaction; with ``idempotent`` the Idempotency-Key contract (API.md §2.6)."""
    services = services_of(ctx)
    db = require_db(services)
    if not idempotent:
        return (await _execute(db, ctx, work, None, None)).to_response()
    request = ctx.request
    principal = ctx.principal
    assert request is not None and principal is not None
    key = require_key(request.headers.get(IDEMPOTENCY_HEADER))
    store = services.idempotency
    if store is None:
        raise ProblemError("service_unavailable", "idempotency store not configured")
    outcome = await begin_or_raise(
        store,
        ctx.tenant_id,
        principal.id,
        f"{request.method} {request.url.path}",
        key,
        idempotency_fingerprint(request, await request.body()),
        principal_kind=idempotency_principal_kind(principal),
    )
    if isinstance(outcome, Replay):
        _replayed(ctx)
        stored = outcome.response
        return Response(
            stored.body,
            status_code=stored.status,
            headers={**stored.headers, REPLAY_HEADER: "true"},
        )
    token = outcome.token
    try:
        result = await _execute(db, ctx, work, store, token)
    except BaseException:
        await store.abandon(token)
        raise
    response = result.to_response()
    if not isinstance(store, PgIdempotencyStore):
        await store.complete(token, _stored(result, response))
    return response


def _replayed(ctx: AuthContext) -> None:
    """A replay re-sends a response this same principal already obtained (the record is
    principal-bound), after its object rules passed on the first execution."""
    for rule in ctx.op.object_rules:
        if rule != "self":
            ctx.object_rule_checked(rule)
    if ctx.op.step_up == "conditional":
        ctx.step_up_if(False)


def _stored(result: Outcome, response: JSONResponse) -> StoredResponse:
    headers = {"content-type": "application/json", **result.response_headers()}
    return StoredResponse(result.status, headers, bytes(response.body))


async def _execute(
    db: Database,
    ctx: AuthContext,
    work: Work,
    store: IdempotencyStore | None,
    token: RecordKey | None,
) -> Outcome:
    async def body(conn: Any) -> Outcome:
        await conn.execute("SELECT sibyl.audit_lock($1)", ctx.tenant_id)
        result = await work(conn)
        if isinstance(store, PgIdempotencyStore) and token is not None:
            await store.complete_in(conn, token, _stored(result, result.to_response()))
        return result

    try:
        return await db.run_in_tenant_tx(ctx.tenant_id, body)
    except asyncpg.PostgresError as exc:
        raise map_db_error(exc) from None
    except ProblemError as exc:
        await _record_denial(ctx, exc)
        raise


# --- audit / outbox -------------------------------------------------------------------------


async def audit(
    conn: Any,
    ctx: AuthContext,
    action: str,
    *,
    resource_type: str,
    detail: Mapping[str, Any],
    resource_id: UUID | None = None,
    resource_ref: str | None = None,
    reason: str | None = None,
) -> AuditReceipt:
    principal = ctx.principal
    assert principal is not None
    record = AuditRecord(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_ref=resource_ref,
        reason=reason,
        detail=jsonable(dict(detail)),
        request_id=request_uuid(ctx),
        **audit_actor(principal).fields(),
    )
    return await services_of(ctx).audit.append(conn, ctx.tenant_id, record)


def op_reason(ctx: AuthContext, given: str | None, *, label: str | None = None) -> str:
    """Human audit rows need a reason: the body's ``reason``, else ``X-Sibyl-Reason``
    (>= 10 chars), else ``label`` or the route name (``deps.audit_reason``)."""
    return audit_reason(ctx.request, given, label or f"via api: {ctx.op.operation_id}")


async def config_changed(
    conn: Any,
    ctx: AuthContext,
    *,
    resource_type: str,
    resource_id: UUID | None,
    field_name: str,
    before: Any,
    after: Any,
    reason: str | None = None,
) -> AuditReceipt:
    return await audit(
        conn,
        ctx,
        "config.changed",
        resource_type=resource_type,
        resource_id=resource_id,
        reason=op_reason(ctx, reason),
        detail={"field": field_name, "before": before, "after": after},
    )


async def policy_changed(
    conn: Any, ctx: AuthContext, *, aggregate_kind: str, aggregate_id: UUID, agent_id: UUID | None
) -> None:
    """Outbox ``policy_changed`` in the writer's transaction: the snapshot rebuilds on commit."""
    version = await conn.fetchval(
        "SELECT routing_version FROM sibyl.tenant WHERE id = $1", ctx.tenant_id
    )
    payload: JSON = {"tenant_id": str(ctx.tenant_id), "routing_version": int(version or 0)}
    if agent_id is not None:
        payload["agent_id"] = str(agent_id)
    message = OutboxMessage.for_event("policy_changed", aggregate_kind, aggregate_id, payload)
    await services_of(ctx).outbox.emit(conn, ctx.tenant_id, message)


# --- object rules ---------------------------------------------------------------------------


async def deny(ctx: AuthContext, exc: ProblemError) -> ProblemError:
    """Hand back an object-rule refusal to raise. ``access.denied`` is written by the runner
    after the request transaction has ended: writing it from inside would wait on the audit
    lock this same request already holds."""
    return exc


async def _record_denial(ctx: AuthContext, exc: ProblemError) -> None:
    if exc.audit_denied and ctx.principal is not None and ctx.request is not None:
        await write_denial(services_of(ctx), ctx.request, ctx.principal, ctx.op.scope)


async def check_object(
    ctx: AuthContext,
    *,
    group_id: UUID | _NotApplicable | None = NOT_APPLICABLE,
    agent_id: UUID | None = None,
) -> Grant:
    """``ctx.check`` with the loaded resource; marks ``group`` / ``bound_agent`` as evaluated."""
    try:
        grant = ctx.check(resource_group_id=group_id, resource_agent_id=agent_id)
    except ProblemError as exc:
        raise await deny(ctx, exc) from None
    if agent_id is None and "bound_agent" in ctx.op.object_rules:
        ctx.object_rule_checked("bound_agent")  # no agent resource: the binding cannot apply
    return grant


async def require_scope(
    ctx: AuthContext,
    scope: str,
    *,
    group_id: UUID | _NotApplicable | None = NOT_APPLICABLE,
    agent_id: UUID | None = None,
) -> Grant:
    """A second, data-dependent scope (``agents:approve`` for tier changes, ...)."""
    try:
        return authorize(
            ctx.principal,
            scope,
            now=ctx.now,
            key_scopes=ctx.op.key_scopes,
            step_up_url=STEP_UP_URL,
            resource_group_id=group_id,
            resource_agent_id=agent_id,
        )
    except ProblemError as exc:
        raise await deny(ctx, exc) from None


async def refuse(ctx: AuthContext, code: str, detail: str | None = None) -> ProblemError:
    """An object-rule refusal with its own problem code (audited like ``forbidden``)."""
    return await deny(ctx, ProblemError(code, detail, audit_denied=True))


TENANT_WIDE_RULE = "tenant_wide"


async def require_tenant_wide(ctx: AuthContext) -> None:
    """The ``tenant_wide`` object rule: catalog, provider, model and alert-rule writes are for
    tenant-wide roles only (API.md §5.4/§5.5): a group-limited grant of the route scope
    (engineer G) is refused 403 ``forbidden``, audited."""
    if TENANT_WIDE_RULE in ctx.op.object_rules:
        ctx.object_rule_checked(TENANT_WIDE_RULE)
    grant = ctx.grant
    if grant is not None and grant.group_ids is not None:
        raise await refuse(ctx, "forbidden", "this catalog is managed by tenant-wide roles")


def has_scope(ctx: AuthContext, scope: str) -> bool:
    return ctx.principal is not None and ctx.principal.has(scope)


async def load_agent(conn: Any, ctx: AuthContext, agent_id: UUID, *, lock: bool = False) -> JSON:
    """The agent row, after the group and bound-agent object rules (404 otherwise)."""
    sql = "SELECT * FROM sibyl.agent WHERE tenant_id = $1 AND id = $2"
    row = await conn.fetchrow(sql + (" FOR UPDATE" if lock else ""), ctx.tenant_id, agent_id)
    if row is None:
        raise ProblemError("not_found")
    group: UUID | _NotApplicable | None = (
        row["agent_group_id"] if "group" in ctx.op.object_rules else NOT_APPLICABLE
    )
    await check_object(ctx, group_id=group, agent_id=row["id"])
    return dict(row)


def agent_visibility(ctx: AuthContext, alias: str, args: list[Any]) -> str:
    """SQL limiting a list to the caller's groups / bound agent (``args`` grows in place)."""
    clauses: list[str] = []
    if "group" in ctx.op.object_rules:
        groups = ctx.group_filter()
        if groups is not None:
            args.append(list(groups))
            clauses.append(f"{alias}.agent_group_id = ANY(${len(args)}::uuid[])")
    if "bound_agent" in ctx.op.object_rules:
        bound = ctx.agent_filter()
        if bound is not None:
            args.append(bound)
            clauses.append(f"{alias}.id = ${len(args)}")
    return "".join(f" AND {c}" for c in clauses)


# --- concurrency ----------------------------------------------------------------------------


def require_if_match(
    ctx: AuthContext, current: str | None, *, allow_star_create: bool = False, body: Any = None
) -> None:
    header = ctx.request.headers.get("if-match") if ctx.request is not None else None
    check_if_match(header, current, allow_star_create=allow_star_create, current_body=body)


# --- paging ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class PageQuery:
    limit: int
    cursor: str | None
    filters: Mapping[str, Any]

    @classmethod
    def of(cls, limit: int | None, cursor: str | None, **filters: Any) -> PageQuery:
        return cls(validate_limit(limit), cursor, filters)


def _type_tag(value: Any) -> str:
    if isinstance(value, datetime):
        return "t"
    if isinstance(value, UUID):
        return "u"
    if isinstance(value, int):
        return "i"
    return "s"


def _query(request: Any) -> dict[str, Any]:
    """Query parameters with repeated keys kept as lists (``state=a&state=b``)."""
    out: dict[str, Any] = {}
    for key, value in request.query_params.multi_items():
        if key in out:
            prior = out[key]
            out[key] = [*prior, value] if isinstance(prior, list) else [prior, value]
        else:
            out[key] = value
    return out


async def keyset_page(
    conn: Any,
    ctx: AuthContext,
    *,
    select: str,
    args: list[Any],
    page: PageQuery,
    keys: Sequence[str] = ("created_at", "id"),
    key_types: str = "tu",
    descending: bool = False,
    serialize: Callable[[JSON], Any],
) -> Outcome:
    """Append the keyset predicate, ORDER BY and LIMIT to ``select`` (which ends in a WHERE).

    Cursors are bound to the route, the sort and the key types (G0 paging).
    """
    args = list(args)
    route = ctx.op.route_key
    sort = ",".join(keys) + (":desc" if descending else ":asc")
    sql = select
    if page.cursor:
        parts = decode_cursor(
            page.cursor, page.filters, route=route, sort=sort, key_types=key_types
        )
        placeholders = []
        for part in parts:
            args.append(part)
            placeholders.append(f"${len(args)}")
        op = "<" if descending else ">"
        sql += f" AND ({', '.join(keys)}) {op} ({', '.join(placeholders)})"
    direction = " DESC" if descending else ""
    sql += " ORDER BY " + ", ".join(k + direction for k in keys)
    args.append(page.limit + 1)
    sql += f" LIMIT ${len(args)}"
    rows = [dict(r) for r in await conn.fetch(sql, *args)]
    has_more = len(rows) > page.limit
    rows = rows[: page.limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        key: list[KeyPart] = [last[k.rsplit(".", 1)[-1]] for k in keys]
        if "".join(_type_tag(p) for p in key) != key_types:  # pragma: no cover - handler bug
            raise ProblemError("internal_error")
        next_cursor = encode_cursor(key, page.filters, route=route, sort=sort)
    body = {"data": [serialize(r) for r in rows], "next_cursor": next_cursor, "has_more": has_more}
    headers: dict[str, str] = {}
    request = ctx.request
    if request is not None and next_cursor is not None:
        link = link_header(str(request.url.path), _query(request), next_cursor)
        if link:
            headers["Link"] = link
    return Outcome(body, headers=headers)
