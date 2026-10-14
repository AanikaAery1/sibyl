"""Shared request dependencies: services container, principal resolution, contract-driven guard.

Handlers never re-encode scopes. They declare ``ctx: AuthContext = Depends(guard("getAgent"))``;
the guard reads ``x-sibyl-scope``, ``-scope-any``, ``-key-scopes``, ``-principals``,
``-step-up`` and ``-rate-limit`` from the contract, authenticates, rate-limits, authorises and
writes ``access.denied`` on refusal.

Object rules that need the resource are the handler's job, and they fail closed (security M3):
every rule in ``x-sibyl-object-rules`` must be evaluated through the context (``ctx.check`` for a
loaded resource, ``ctx.group_filter`` / ``ctx.agent_filter`` / ``ctx.self_filter`` for lists,
``ctx.check_self``, ``ctx.object_rule_checked`` for route-specific rules) and a conditional
step-up decided with ``ctx.step_up_if``. ``RequestContextMiddleware`` turns a 2xx from a handler
that skipped any of them into a 500 before a byte of the response is sent.

Credentials are throttled per client IP before any lookup: once a client IP has run up
``KEY_FAILURE_POLICY`` failed credentials, its requests get 429 without touching the database
(security LOW). The client IP honours ``X-Forwarded-For`` only from ``SIBYL_TRUSTED_PROXIES``.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from fastapi import Request

from ..core.apikeys import (
    ApiKeyRejected,
    KeyLookup,
    KeyRecord,
    reject_key_from_browser,
    verify_api_key,
)
from ..core.audit import AuditReceipt, AuditWriter, PgAuditWriter, access_denied, audit_actor
from ..core.authz import (
    NOT_APPLICABLE,
    STEP_UP_WINDOW,
    Grant,
    Principal,
    PrincipalKind,
    _NotApplicable,
    authorize,
    grants_for_api_key,
)
from ..core.db import Database
from ..core.idempotency import IdempotencyStore, PrincipalKindName, fingerprint
from ..core.monitor_keys import MonitorLookup, monitor_grants
from ..core.outbox import OutboxWriter, PgOutboxWriter
from ..core.problems import ProblemError
from ..core.ratelimit import POLICIES, InMemoryRateLimiter, RateLimiter, RatePolicy, enforce
from ..core.settings import Settings
from .contract import API_PREFIX, ContractOperation, operation
from .middleware import AUTH_CONTEXT_STATE, CLIENT_IP_STATE

log = logging.getLogger("sibyl.api")
STEP_UP_URL = f"{API_PREFIX}/auth/step-up"
STEP_UP_RULE = "step_up"  # pseudo object rule: a conditional step-up was decided
KEY_FAILURE_POLICY = RatePolicy("credential_failures", quota=20, window_s=60)
"""Failed credentials allowed per client IP per minute before the IP is refused pre-lookup."""


def utcnow() -> datetime:
    return datetime.now(UTC)


class PrincipalResolver(Protocol):
    async def resolve(self, request: Request) -> Principal | None:
        """Return the caller, ``None`` when no credential was presented, or raise 401."""
        ...


class NullPrincipalResolver:
    """Wave-0 default: nobody is authenticated until lane A installs the real resolver."""

    async def resolve(self, request: Request) -> Principal | None:
        return None


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


class StaticTokenResolver:
    """Maps bearer tokens to fixed principals (tests, demos, contract harness)."""

    def __init__(self, tokens: Mapping[str, Principal]) -> None:
        self._tokens = dict(tokens)

    def add(self, token: str, principal: Principal) -> None:
        self._tokens[token] = principal

    async def resolve(self, request: Request) -> Principal | None:
        token = bearer_token(request)
        if token is None:
            return None
        principal = self._tokens.get(token)
        if principal is None:
            raise ProblemError("unauthenticated")
        return principal


class ApiKeyResolver:
    """Resolves ``Authorization: Bearer sbl_…`` keys; other bearer tokens are not its business."""

    def __init__(
        self,
        lookup: KeyLookup,
        pepper: bytes,
        *,
        expected_env: str | None = None,
        clock: Callable[[], datetime] = utcnow,
        monitors: MonitorLookup | None = None,
    ) -> None:
        self._lookup = lookup
        self._pepper = pepper
        self._env = expected_env
        self._clock = clock
        self._monitors = monitors

    async def resolve(self, request: Request) -> Principal | None:
        token = bearer_token(request)
        if token is None or not token.startswith("sbl_"):
            return None
        reject_key_from_browser(dict(request.headers))
        try:
            verified = await verify_api_key(
                token, self._lookup, self._pepper, now=self._clock(), expected_env=self._env
            )
        except ApiKeyRejected as exc:
            request.state.key_reject_reason = exc.reason.value
            raise exc.problem() from None
        record = verified.record
        grants = grants_for_api_key(record.scopes)
        if record.monitor_id is not None:
            grants = await self._monitor_grants(request, record)
        return Principal(
            kind=PrincipalKind.API_KEY,
            tenant_id=record.tenant_id,
            id=record.id,
            grants=grants,
            bound_agent_id=record.agent_id,
            monitor_id=record.monitor_id,
        )

    async def _monitor_grants(self, request: Request, record: KeyRecord) -> dict[str, Grant]:
        """D53: narrow a monitor key to its monitor's watched groups; fail closed (401) when the
        monitor is revoked or this resolver cannot read monitors (e.g. ingest)."""
        assert record.monitor_id is not None
        binding = None
        if self._monitors is not None:
            binding = await self._monitors(record.tenant_id, record.monitor_id)
        if binding is None or not binding.usable:
            request.state.key_reject_reason = "monitor_unavailable"
            raise ProblemError("unauthenticated")
        return monitor_grants(record.scopes, binding)


class ChainResolver:
    """First resolver that recognises the credential wins."""

    def __init__(self, *resolvers: PrincipalResolver) -> None:
        self._resolvers = resolvers

    async def resolve(self, request: Request) -> Principal | None:
        for resolver in self._resolvers:
            principal = await resolver.resolve(request)
            if principal is not None:
                return principal
        return None


_KEY_LOOKUP_SQL = (
    "SELECT tenant_id, id, env, secret_hash, scopes, agent_id, status, expires_at,"
    " rotation_grace_until, monitor_id FROM sibyl.api_key_lookup($1)"
)


def pg_key_lookup(db: Database) -> Callable[[str], Awaitable[KeyRecord | None]]:
    """``sibyl.api_key_lookup(prefix)`` (SECURITY DEFINER; the only pre-tenant read)."""

    async def lookup(prefix: str) -> KeyRecord | None:
        async with db.pre_tenant() as conn:
            row = await conn.fetchrow(_KEY_LOOKUP_SQL, prefix)
        if row is None:
            return None
        return KeyRecord(
            tenant_id=row["tenant_id"],
            id=row["id"],
            env=row["env"],
            secret_hash=bytes(row["secret_hash"]),
            scopes=frozenset(row["scopes"]),
            agent_id=row["agent_id"],
            status=row["status"],
            expires_at=row["expires_at"],
            rotation_grace_until=row["rotation_grace_until"],
            monitor_id=row["monitor_id"],
        )

    return lookup


@dataclass
class Services:
    principals: PrincipalResolver = field(default_factory=NullPrincipalResolver)
    audit: AuditWriter = field(default_factory=PgAuditWriter)
    outbox: OutboxWriter = field(default_factory=PgOutboxWriter)
    idempotency: IdempotencyStore | None = None
    rate_limiter: RateLimiter = field(default_factory=InMemoryRateLimiter)
    db: Database | None = None
    settings: Settings | None = None
    clock: Callable[[], datetime] = utcnow


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


async def write_denial(
    services: Services, request: Request, principal: Principal, permission: str
) -> None:
    """Best effort: a failed audit write must not turn a 403 into a 500."""
    record = access_denied(
        permission=permission,
        resource_type="route",
        resource_id=None,
        actor_type=audit_actor(principal).actor_type,
        actor_id=principal.id if principal.is_human else None,
        actor_key_id=principal.id if not principal.is_human else None,
        actor_session_id=principal.session_id,
    )
    try:
        if services.db is None:
            await services.audit.append(None, principal.tenant_id, record)
            return
        async with services.db.tenant_tx(principal.tenant_id) as conn:
            await services.audit.append(conn, principal.tenant_id, record)
    except Exception:
        log.exception("access.denied audit write failed")


@dataclass(frozen=True)
class AuthContext:
    op: ContractOperation
    principal: Principal | None
    grant: Grant | None
    now: datetime
    self_only: bool = False
    request: Request | None = field(default=None, repr=False, compare=False)
    _evaluated: set[str] = field(default_factory=set, repr=False, compare=False)

    @property
    def tenant_id(self) -> UUID:
        if self.principal is None:
            raise ProblemError("unauthenticated")
        return self.principal.tenant_id

    def _mark(self, *rules: str) -> None:
        self._evaluated.update(rules)

    def required_rules(self) -> frozenset[str]:
        """The object rules (plus a conditional step-up) this request must evaluate."""
        rules = set(self.op.object_rules)
        if not self.self_only:
            rules.discard("self")  # the principal holds the scope itself
        if self.op.step_up == "conditional":
            rules.add(STEP_UP_RULE)
        return frozenset(rules)

    def unchecked_rules(self) -> frozenset[str]:
        return self.required_rules() - self._evaluated

    def check(
        self,
        *,
        resource_group_id: UUID | _NotApplicable | None = NOT_APPLICABLE,
        resource_agent_id: UUID | None = None,
    ) -> Grant:
        """Re-run ``authorize`` with the loaded resource (group rule, bound-agent rule)."""
        op = self.op
        grant = authorize(
            self.principal,
            op.scope,
            now=self.now,
            scope_any=op.scope_any,
            key_scopes=op.key_scopes,
            resource_group_id=resource_group_id,
            resource_agent_id=resource_agent_id,
        )
        if resource_group_id is not NOT_APPLICABLE:
            self._mark("group")
        if resource_agent_id is not None:
            self._mark("bound_agent")
        return grant

    def group_filter(self) -> frozenset[UUID] | None:
        """For list routes: the groups to filter on in SQL (``None`` = tenant-wide)."""
        self._mark("group")
        return self.grant.group_ids if self.grant is not None else None

    def agent_filter(self) -> UUID | None:
        """For list routes: the only agent a bound key may see (``None`` = unrestricted)."""
        self._mark("bound_agent")
        return self.principal.bound_agent_id if self.principal is not None else None

    def self_filter(self) -> UUID | None:
        """For ``self`` routes: the owner to filter on (``None`` when the scope is held)."""
        self._mark("self")
        if self.self_only and self.principal is not None:
            return self.principal.id
        return None

    def check_self(self, owner_id: UUID | None) -> None:
        """For ``self`` routes on one resource: 404 unless the caller owns it or holds the scope."""
        self._mark("self")
        if self.self_only and (self.principal is None or owner_id != self.principal.id):
            raise ProblemError("not_found", audit_denied=True)

    def object_rule_checked(self, rule: str) -> None:
        """Record that the handler evaluated a route-specific rule (``job_owner``, ``rank`` …)."""
        if rule not in self.op.object_rules:
            raise ValueError(f"{rule!r} is not an object rule of {self.op.operation_id}")
        self._mark(rule)

    def step_up_if(self, required: bool) -> None:
        """Decide a conditional step-up (``x-sibyl-step-up: conditional``)."""
        self._mark(STEP_UP_RULE)
        if required:
            self._require_step_up()

    def _require_step_up(self) -> None:
        principal = self.principal
        if principal is None or not principal.is_human:
            return
        fresh = (
            principal.kind is PrincipalKind.SESSION
            and principal.step_up_at is not None
            and self.now - principal.step_up_at <= STEP_UP_WINDOW
        )
        if not fresh:
            raise ProblemError(
                "step_up_required", extensions={"step_up_url": STEP_UP_URL}, audit_denied=True
            )

    def action(
        self,
        name: str,
        *,
        resource_group_id: UUID | _NotApplicable | None = NOT_APPLICABLE,
        resource_agent_id: UUID | None = None,
        step_up_required: bool | None = None,
    ) -> Grant:
        """Authorise one ``POST …/actions`` verb from ``x-sibyl-actions``.

        An action whose step-up is ``conditional`` must say whether it applies
        (``step_up_required``); leaving it undecided is a programming error.
        """
        rule = self.op.actions.get(name)
        if rule is None:
            raise ProblemError("validation_failed", f"unknown action {name!r}")
        mode = rule.get("step_up")
        if mode == "conditional" and step_up_required is None:
            raise TypeError(f"action {name!r} has a conditional step-up: pass step_up_required")
        grant = authorize(
            self.principal,
            rule["scope"],
            now=self.now,
            scope_any=tuple(rule.get("scope_any", ())),
            key_scopes=self.op.key_scopes,
            step_up=mode == "always" or (mode == "conditional" and bool(step_up_required)),
            step_up_url=STEP_UP_URL,
            resource_group_id=resource_group_id,
            resource_agent_id=resource_agent_id,
        )
        if resource_group_id is not NOT_APPLICABLE:
            self._mark("group")
        if resource_agent_id is not None:
            self._mark("bound_agent")
        return grant

    def attach_receipt(self, receipt: AuditReceipt) -> None:
        if self.request is not None:
            self.request.state.audit_receipt = receipt.header_value()


REASON_HEADER = "X-Sibyl-Reason"
REASON_MIN_CHARS = 10
REASON_MAX_CHARS = 2000


def audit_reason(request: Request | None, body_reason: str | None, label: str) -> str:
    """The audit ``reason`` of a human write: the body's ``reason`` when sent, else
    ``X-Sibyl-Reason`` (>= 10 chars, capped at 2000), else the fixed ``label``."""
    if body_reason and body_reason.strip():
        return body_reason.strip()
    header = (request.headers.get(REASON_HEADER) or "").strip() if request is not None else ""
    if len(header) >= REASON_MIN_CHARS:
        return header[:REASON_MAX_CHARS]
    return label


def client_ip(request: Request) -> str:
    """The real client address (``X-Forwarded-For`` only via ``SIBYL_TRUSTED_PROXIES``).

    Use it for rate-limit keys and for ``ip_hash`` audit fields.
    """
    resolved = getattr(request.state, CLIENT_IP_STATE, None)
    if resolved:
        return str(resolved)
    return request.client.host if request.client else "unknown"


def idempotency_fingerprint(request: Request, body: bytes) -> bytes:
    """The request fingerprint for ``Idempotency-Key`` records: method, path, query and body."""
    return fingerprint(body, method=request.method, path=request.url.path, query=request.url.query)


def idempotency_principal_kind(principal: Principal) -> PrincipalKindName:
    """``principal_kind`` for idempotency records (required, G0-8)."""
    return "api_key" if principal.kind is PrincipalKind.API_KEY else "user"


def _client_key(request: Request) -> str:
    return f"ip:{client_ip(request)}"


def _presented_credential(request: Request) -> bool:
    return bool(request.headers.get("authorization", "").strip())


async def _refuse_throttled_client(services: Services, request: Request) -> None:
    """429 before any credential lookup when this client IP has failed too often."""
    decision = await services.rate_limiter.peek(_client_key(request), KEY_FAILURE_POLICY)
    if not decision.allowed:
        enforce(decision)


async def _resolve(services: Services, request: Request) -> Principal | None:
    if not _presented_credential(request):
        return await services.principals.resolve(request)
    await _refuse_throttled_client(services, request)
    try:
        return await services.principals.resolve(request)
    except ProblemError as exc:
        if exc.status == 401:
            await services.rate_limiter.hit(_client_key(request), KEY_FAILURE_POLICY)
        raise


async def _rate_limit(
    services: Services, request: Request, op: ContractOperation, key: str
) -> None:
    policy = POLICIES[op.rate_limit]
    decision = await services.rate_limiter.hit(key, policy)
    request.state.rate_headers = enforce(decision)


def _kind_allowed(op: ContractOperation, principal: Principal) -> bool:
    kinds = set(op.principals)
    if principal.kind is PrincipalKind.API_KEY:
        return "api_key" in kinds
    return "session" in kinds or "oidc" in kinds


async def _authorize_route(
    services: Services, request: Request, op: ContractOperation, principal: Principal
) -> AuthContext:
    now = services.clock()
    if not _kind_allowed(op, principal):
        if principal.is_break_glass:
            raise ProblemError("break_glass_key_misuse", audit_denied=True)
        raise ProblemError("forbidden", audit_denied=True)
    if op.scope == "authenticated":
        if principal.is_break_glass:
            raise ProblemError("break_glass_key_misuse", audit_denied=True)
        return AuthContext(op, principal, None, now, request=request)
    try:
        grant = authorize(
            principal,
            op.scope,
            now=now,
            scope_any=op.scope_any,
            key_scopes=op.key_scopes,
            step_up=op.step_up == "always",
            step_up_url=STEP_UP_URL,
        )
    except ProblemError as exc:
        if "self" in op.object_rules and exc.code == "forbidden":
            return AuthContext(op, principal, None, now, self_only=True, request=request)
        raise
    return AuthContext(op, principal, grant, now, request=request)


def _remember(request: Request, ctx: AuthContext) -> AuthContext:
    """Expose the context to the response middleware, which enforces the object rules."""
    setattr(request.state, AUTH_CONTEXT_STATE, ctx)
    return ctx


def guard(operation_id: str) -> Callable[[Request], Awaitable[AuthContext]]:
    """FastAPI dependency enforcing the contract's route-level rules for ``operation_id``."""
    op = operation(operation_id)

    async def dependency(request: Request) -> AuthContext:
        services = get_services(request)
        if op.scope == "public":
            await _rate_limit(services, request, op, _client_key(request))
            return _remember(
                request, AuthContext(op, None, None, services.clock(), request=request)
            )
        principal = await _resolve(services, request)
        if principal is None:
            await _rate_limit(services, request, op, _client_key(request))
            raise ProblemError("unauthenticated")
        await _rate_limit(services, request, op, f"principal:{principal.id}")
        try:
            return _remember(request, await _authorize_route(services, request, op, principal))
        except ProblemError as exc:
            if exc.audit_denied:
                await write_denial(services, request, principal, op.scope)
            raise

    dependency.__name__ = f"guard_{operation_id}"
    return dependency


def request_state(request: Request) -> Mapping[str, Any]:
    return dict(vars(request.state)) if hasattr(request.state, "__dict__") else {}
