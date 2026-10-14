"""Human principals: console sessions and CLI/script OIDC bearer JWTs (API.md §2.1).

* **Session** — the console BFF forwards ``Authorization: Bearer sibyl_sess_<value>``; the value is
  the ``__Host-sibyl_session`` cookie. ``session.token_hash = sha256(value)``; resolved pre-tenant
  through ``sibyl.session_resolve`` (SECURITY DEFINER), then checked for revocation, absolute
  (8 h) and idle (30 min) expiry, and slid forward at most once per ``session_touch_s``.
* **OIDC bearer** — a JWT from the tenant's issuer with ``aud = sibyl-api`` and a lifetime of at
  most one hour. The tenant is resolved **first** (``X-Sibyl-Tenant`` slug or a host prefix) and the
  token's ``iss`` must be one of *that* tenant's active issuers, so a shared issuer (dex) cannot
  cross tenants. Every failure is the same 401.

Scopes are derived live from ``membership`` x ``role_permission`` on every request (R21); a
``scoped`` permission held through an agent-group membership covers that group and its
descendants, everything else is tenant-wide (mirrors ``authz.grants_from_memberships``).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
from fastapi import Request

from ...core.authz import SCOPES, Grant, Principal, PrincipalKind
from ...core.db import Database
from ...core.monitor_keys import pg_monitor_lookup
from ...core.problems import ProblemError
from ...core.settings import Settings
from ..deps import ApiKeyResolver, ChainResolver, Services, bearer_token, pg_key_lookup
from .config import SESSION_BEARER_PREFIX, AuthSettings, auth_settings
from .jose import JoseError, looks_like_jwt, parse_compact
from .oidc import OidcClient, OidcError

log = logging.getLogger("sibyl.auth")
TENANT_HEADER = "x-sibyl-tenant"
MIN_SESSION_VALUE = 32
MAX_SESSION_VALUE = 128

_GRANTS_SQL = """
SELECT m.role_name, m.scope_kind, m.scope_id, rp.permission, rp.scope_rule, rp.self_audited
  FROM sibyl.membership m
  JOIN sibyl.role_permission rp ON rp.role_name = m.role_name
 WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.revoked_at IS NULL
   AND (m.expires_at IS NULL OR m.expires_at > now())
"""
_GROUPS_SQL = "SELECT id, parent_group_id FROM sibyl.agent_group WHERE tenant_id = $1"


NO_TOUCH_STATE = "sibyl_session_no_touch"
_TOUCH_SQL = (
    "UPDATE sibyl.session SET last_seen_at = $3::timestamptz,"
    " idle_expires_at = least(absolute_expires_at,"
    " $3::timestamptz + make_interval(secs => $4::float8))"
    " WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL"
    " AND last_seen_at < $3::timestamptz - make_interval(secs => $5::float8)"
)


def session_token_hash(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii", "replace")).digest()


def _descendants(roots: Iterable[UUID], edges: Mapping[UUID, UUID | None]) -> frozenset[UUID]:
    children: dict[UUID, list[UUID]] = {}
    for child, parent in edges.items():
        if parent is not None:
            children.setdefault(parent, []).append(child)
    out: set[UUID] = set()
    stack = list(roots)
    while stack:
        node = stack.pop()
        if node in out:
            continue
        out.add(node)
        stack.extend(children.get(node, ()))
    return frozenset(out)


def _merge(existing: Grant | None, incoming: Grant) -> Grant:
    if existing is None:
        return incoming
    audited = existing.audited or incoming.audited
    if existing.group_ids is None or incoming.group_ids is None:
        return Grant(incoming.scope, None, audited)
    return Grant(incoming.scope, existing.group_ids | incoming.group_ids, audited)


@dataclass(frozen=True)
class UserGrants:
    grants: dict[str, Grant]
    roles: frozenset[str]


async def load_grants(conn: Any, tenant_id: UUID, user_id: UUID) -> UserGrants:
    """Live grants of one user from ``membership`` x ``role_permission``."""
    rows = await conn.fetch(_GRANTS_SQL, tenant_id, user_id)
    edges: dict[UUID, UUID | None] | None = None
    grants: dict[str, Grant] = {}
    roles: set[str] = set()
    for row in rows:
        roles.add(row["role_name"])
        scope = row["permission"]
        if scope not in SCOPES:
            continue
        groups: frozenset[UUID] | None = None
        if row["scope_rule"] == "scoped" and row["scope_kind"] == "agent_group":
            if edges is None:
                edges = {
                    r["id"]: r["parent_group_id"] for r in await conn.fetch(_GROUPS_SQL, tenant_id)
                }
            groups = _descendants([row["scope_id"]], edges)
        grant = Grant(scope, groups, bool(row["self_audited"]))
        grants[scope] = _merge(grants.get(scope), grant)
    return UserGrants(grants, frozenset(roles))


async def tenant_by_slug(db: Database, slug: str) -> UUID | None:
    """Pre-tenant read of the allowlisted ``tenant`` table (no RLS, SELECT granted)."""
    async with db.pre_tenant() as conn:
        value: UUID | None = await conn.fetchval(
            "SELECT id FROM sibyl.tenant WHERE slug = $1 AND status = 'active'", slug
        )
    return value


def _unauthenticated() -> ProblemError:
    return ProblemError("unauthenticated")


class SessionResolver:
    """``Bearer sibyl_sess_<value>`` → session principal (one tenant transaction)."""

    def __init__(
        self,
        services: Services,
        settings: AuthSettings | None = None,
    ) -> None:
        self._services = services
        self._settings = settings or auth_settings()

    async def resolve(self, request: Request) -> Principal | None:
        token = bearer_token(request)
        if token is None or not token.startswith(SESSION_BEARER_PREFIX):
            return None
        value = token[len(SESSION_BEARER_PREFIX) :]
        if not MIN_SESSION_VALUE <= len(value) <= MAX_SESSION_VALUE:
            raise _unauthenticated()
        db = self._services.db
        if db is None:
            raise ProblemError("database_unavailable")
        now = self._services.clock()
        async with db.pre_tenant() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM sibyl.session_resolve($1)", session_token_hash(value)
            )
        if (
            row is None
            or row["revoked_at"] is not None
            or row["absolute_expires_at"] <= now
            or row["idle_expires_at"] <= now
        ):
            raise _unauthenticated()
        tenant, user_id, session_id = row["tenant_id"], row["user_id"], row["id"]
        async with db.tenant_tx(tenant) as conn:
            status = await conn.fetchval(
                "SELECT status FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2",
                tenant,
                user_id,
            )
            if status != "active":
                raise _unauthenticated()
            granted = await load_grants(conn, tenant, user_id)
            # A re-check (the SSE heartbeat) is not user activity: it must not slide the idle
            # window, or an open console tab would keep a session alive forever.
            if not getattr(request.state, NO_TOUCH_STATE, False):
                await conn.execute(_TOUCH_SQL, tenant, session_id, now,
                                   float(self._settings.session_idle_s),
                                   float(self._settings.session_touch_s))  # fmt: skip
        request.state.session_id = str(session_id)
        return Principal(
            kind=PrincipalKind.SESSION,
            tenant_id=tenant,
            id=user_id,
            grants=granted.grants,
            session_id=session_id,
            step_up_at=row["step_up_at"],
            roles=granted.roles,
        )


def requested_tenant_slug(request: Request, settings: AuthSettings) -> str | None:
    header = (request.headers.get(TENANT_HEADER) or "").strip().lower()
    if header:
        return header
    suffix = settings.tenant_host_suffix
    host = (request.headers.get("host") or "").split(":", 1)[0].lower()
    if suffix and host.endswith("." + suffix.lstrip(".")):
        return host[: -len(suffix.lstrip(".")) - 1] or None
    return None


OidcClientFactory = Callable[[], OidcClient]


class OidcBearerResolver:
    """``Bearer <JWT>`` from the tenant's issuer (``aud = sibyl-api``, ≤ 1 h)."""

    def __init__(
        self,
        services: Services,
        oidc: OidcClientFactory,
        settings: AuthSettings | None = None,
    ) -> None:
        self._services = services
        self._oidc = oidc
        self._settings = settings or auth_settings()

    async def resolve(self, request: Request) -> Principal | None:
        token = bearer_token(request)
        if token is None or not looks_like_jwt(token):
            return None
        db = self._services.db
        if db is None:
            raise ProblemError("database_unavailable")
        slug = requested_tenant_slug(request, self._settings)
        try:
            iss = parse_compact(token).claims.get("iss")
        except JoseError:
            raise _unauthenticated() from None
        tenant = await tenant_by_slug(db, slug) if slug else None
        if tenant is None or not isinstance(iss, str):
            raise _unauthenticated()
        async with db.tenant_tx(tenant, readonly=True) as conn:
            issuer_id = await conn.fetchval(
                "SELECT id FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND issuer_url = $2"
                " AND status = 'active'",
                tenant,
                iss,
            )
        if issuer_id is None:
            raise _unauthenticated()
        try:
            claims = await self._oidc().verify(
                token,
                issuer_url=iss,
                audience=self._settings.oidc_api_audience,
                now=self._services.clock(),
                max_lifetime_s=self._settings.bearer_max_lifetime_s,
            )
        except OidcError as exc:
            request.state.oidc_reject_cause = exc.cause
            raise _unauthenticated() from None
        async with db.tenant_tx(tenant, readonly=True) as conn:
            user = await conn.fetchrow(
                "SELECT id, status FROM sibyl.app_user WHERE tenant_id = $1"
                " AND oidc_issuer_id = $2 AND subject = $3",
                tenant,
                issuer_id,
                claims["sub"],
            )
            if user is None or user["status"] != "active":
                raise _unauthenticated()
            granted = await load_grants(conn, tenant, user["id"])
        return Principal(
            kind=PrincipalKind.OIDC,
            tenant_id=tenant,
            id=user["id"],
            grants=granted.grants,
            roles=granted.roles,
        )


def default_oidc_client(settings: Settings | None) -> OidcClient:
    rewrite = settings.oidc_internal if settings is not None else (lambda url: url)
    return OidcClient(httpx.AsyncClient(follow_redirects=False), rewrite=rewrite)


def build_principal_resolver(
    services: Services,
    settings: Settings,
    *,
    oidc: OidcClientFactory | None = None,
    auth: AuthSettings | None = None,
) -> ChainResolver:
    """The production resolver chain: API key → console session → OIDC bearer JWT.

    CHANGE REQUEST (steward, ``api/app.py`` lifespan): replace the key-only chain with
    ``services.principals = build_principal_resolver(services, settings)`` once ``services.db``
    is set.
    """
    if services.db is None:
        raise RuntimeError("build_principal_resolver needs services.db")
    client: OidcClient | None = None

    def factory() -> OidcClient:
        nonlocal client
        if client is None:
            client = default_oidc_client(settings)
        return client

    resolvers: list[Any] = []
    if settings.key_pepper is not None:
        resolvers.append(
            ApiKeyResolver(
                pg_key_lookup(services.db),
                settings.pepper(),
                expected_env=settings.env,
                monitors=pg_monitor_lookup(services.db),
            )
        )
    resolvers.append(SessionResolver(services, auth))
    resolvers.append(OidcBearerResolver(services, oidc or factory, auth))
    return ChainResolver(*resolvers)


def session_window(settings: AuthSettings, now: datetime) -> tuple[datetime, datetime]:
    absolute = now + timedelta(seconds=settings.session_absolute_s)
    idle = min(absolute, now + timedelta(seconds=settings.session_idle_s))
    return absolute, idle
