"""The OIDC code flow behind ``/auth/login``, ``/auth/callback`` and ``/auth/step-up``.

Login: tenant first (slug) → that tenant's active issuer → authorization code + PKCE (S256) with
``state`` and ``nonce`` sealed into ``__Host-sibyl_oidc_state``. Callback: state cookie must
match, code exchanged with the verifier, ID token verified against the issuer's JWKS (``iss``
exact, ``aud`` = the issuer row's ``client_id``, ``nonce``), the user resolved by
``(tenant, issuer, sub)`` (an invited row is bound by verified email; JIT only when the issuer
allows it and the email domain is allowed), then a ``session`` row and ``access.login``. A
step-up re-runs the flow with ``prompt=login max_age=0`` and requires a fresh ``auth_time`` for
the same subject; it sets ``session.step_up_at`` and writes ``access.step_up``. Every refused
callback whose tenant is known writes ``access.login_failed`` with a ``cause``.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

from fastapi import Request

from ...core.audit import AuditRecord
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import Services, client_ip, get_services
from . import runtime
from .common import iso, request_id, require_db, tenant_tx
from .config import AuthSettings
from .dek import open_issuer_secret
from .oidc import OidcError
from .principals import session_token_hash, session_window
from .state import LoginState, open_state, pkce_challenge

log = logging.getLogger("sibyl.auth")
CALLBACK_PATH = f"{API_PREFIX}/auth/callback"
STEP_UP_FRESHNESS_SLACK_S = 5


class LoginFailed(Exception):
    def __init__(self, cause: str) -> None:
        super().__init__(cause)
        self.cause = cause


@dataclass(frozen=True)
class Issuer:
    id: UUID
    issuer_url: str
    client_id: str
    client_secret_ct: bytes | None
    client_secret_key_id: UUID | None
    allowed_email_domains: tuple[str, ...]
    jit_default_role: str | None


_ISSUER_COLS = (
    "id, issuer_url, client_id, client_secret_ct, client_secret_key_id, allowed_email_domains,"
    " jit_default_role"
)


def _issuer(row: Any) -> Issuer:
    return Issuer(
        row["id"],
        row["issuer_url"],
        row["client_id"],
        bytes(row["client_secret_ct"]) if row["client_secret_ct"] is not None else None,
        row["client_secret_key_id"],
        tuple(row["allowed_email_domains"] or ()),
        row["jit_default_role"],
    )


async def default_issuer(services: Services, tenant_id: UUID) -> Issuer | None:
    """The tenant's oldest active issuer (one per tenant is the normal case)."""
    async with tenant_tx(services, tenant_id, readonly=True) as conn:
        row = await conn.fetchrow(
            f"SELECT {_ISSUER_COLS} FROM sibyl.oidc_issuer WHERE tenant_id = $1"  # noqa: S608 (constant SQL fragments, no input)
            " AND status = 'active' ORDER BY created_at, id LIMIT 1",
            tenant_id,
        )
    return _issuer(row) if row is not None else None


def redirect_uri(request: Request) -> str:
    return runtime.public_url(request) + CALLBACK_PATH


async def authorization_url(
    request: Request, issuer: Issuer, state: LoginState, *, step_up: bool
) -> str:
    settings = runtime.settings_for(request)
    try:
        meta = await runtime.oidc_for(request).metadata(issuer.issuer_url)
    except OidcError:
        raise ProblemError("service_unavailable", "the identity provider is unreachable") from None
    params = {
        "response_type": "code",
        "client_id": issuer.client_id,
        "redirect_uri": redirect_uri(request),
        "scope": settings.oidc_scopes,
        "state": state.state,
        "nonce": state.nonce,
        "code_challenge": pkce_challenge(state.verifier),
        "code_challenge_method": "S256",
    }
    if step_up:
        params |= {"prompt": "login", "max_age": "0"}
    sep = "&" if "?" in meta.authorization_endpoint else "?"
    return f"{meta.authorization_endpoint}{sep}{urlencode(params)}"


def read_state(request: Request, cookie: str | None) -> LoginState | None:
    settings = runtime.settings_for(request)
    key = runtime.session_secret_key(request, "oidc-state")
    return open_state(key, cookie, now=get_services(request).clock(), ttl_s=settings.state_ttl_s)


def ip_hash_hex(request: Request) -> str | None:
    digest = runtime.settings_for(request).ip_hash(client_ip(request))
    return digest.hex() if digest is not None else None


def ua_class(request: Request) -> str:
    agent = request.headers.get("user-agent", "")
    if "Mozilla/" in agent:
        return "browser"
    return "cli" if agent.lower().startswith(("sibyl", "python", "curl", "httpx")) else "other"


async def write_login_failed(request: Request, state: LoginState, cause: str) -> None:
    """Best effort: a failing audit write must not turn a 401 into a 500."""
    services = get_services(request)
    tenant = UUID(state.tenant_id)
    record = AuditRecord(
        action="access.login_failed",
        actor_type="system",
        resource_type="tenant",
        resource_id=tenant,
        detail={
            "issuer_id": state.issuer_id,
            "cause": cause,
            "ip_hash": ip_hash_hex(request),
            "purpose": state.purpose,
        },
        request_id=request_id(request),
    )
    try:
        async with tenant_tx(services, tenant, audit_lock=True) as conn:
            await services.audit.append(conn, tenant, record)
    except Exception:
        log.exception("access.login_failed audit write failed")


async def _client_secret(request: Request, issuer: Issuer, tenant: UUID) -> str | None:
    if issuer.client_secret_ct is not None and issuer.client_secret_key_id is not None:
        services = get_services(request)
        async with tenant_tx(services, tenant, readonly=True) as conn:
            return await open_issuer_secret(
                runtime.deks_for(request),
                conn,
                tenant,
                issuer.id,
                issuer.client_secret_ct,
                issuer.client_secret_key_id,
            )
    fallback = runtime.settings_for(request).oidc_client_secret
    return fallback.get_secret_value() if fallback is not None else None


async def verified_claims(
    request: Request, state: LoginState, code: str
) -> tuple[Issuer, dict[str, Any]]:
    services = get_services(request)
    tenant = UUID(state.tenant_id)
    async with tenant_tx(services, tenant, readonly=True) as conn:
        row = await conn.fetchrow(
            f"SELECT {_ISSUER_COLS}, status FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND id ="  # noqa: S608 (constant SQL fragments, no input)
            " $2",
            tenant,
            UUID(state.issuer_id),
        )
    if row is None or row["status"] != "active":
        raise LoginFailed("issuer_disabled")
    issuer = _issuer(row)
    oidc = runtime.oidc_for(request)
    try:
        meta = await oidc.metadata(issuer.issuer_url)
        tokens = await oidc.exchange_code(
            meta,
            code=code,
            verifier=state.verifier,
            redirect_uri=redirect_uri(request),
            client_id=issuer.client_id,
            client_secret=await _client_secret(request, issuer, tenant),
        )
        claims = await oidc.verify(
            tokens["id_token"],
            issuer_url=issuer.issuer_url,
            audience=issuer.client_id,
            now=services.clock(),
            nonce=state.nonce,
        )
    except OidcError as exc:
        raise LoginFailed(exc.cause) from None
    if claims.get("azp") not in (None, issuer.client_id):
        raise LoginFailed("azp_mismatch")
    return issuer, claims


def _numeric_claim(claims: dict[str, Any], name: str) -> int | None:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(value)


def _fresh_auth(claims: dict[str, Any], state: LoginState, *, require_auth_time: bool) -> bool:
    """The step-up proof: the IdP authenticated the user after the step-up began.

    ``auth_time`` is the real evidence. dex omits it, so by default a token *issued* after the
    step-up began (``iat``) is accepted, since the request carried ``prompt=login max_age=0``
    (dex re-prompts). Set ``SIBYL_STEP_UP_REQUIRE_AUTH_TIME=true`` for IdPs that may answer
    ``prompt=login`` from an existing SSO session.
    """
    moment = _numeric_claim(claims, "auth_time")
    if moment is None and not require_auth_time:
        moment = _numeric_claim(claims, "iat")
    return moment is not None and moment >= state.issued_at - STEP_UP_FRESHNESS_SLACK_S


def _email(claims: dict[str, Any]) -> tuple[str | None, bool]:
    email = claims.get("email")
    if not isinstance(email, str) or "@" not in email or len(email) > 320:
        return None, False
    return email, claims.get("email_verified") is True


async def _resolve_user(
    conn: Any, tenant: UUID, issuer: Issuer, claims: dict[str, Any], now: datetime
) -> tuple[UUID, bool]:
    """→ (user id, was JIT-provisioned). Raises ``LoginFailed``."""
    sub = claims["sub"]
    email, verified = _email(claims)
    row = await conn.fetchrow(
        "SELECT id, status FROM sibyl.app_user WHERE tenant_id = $1 AND oidc_issuer_id = $2"
        " AND subject = $3 FOR UPDATE",
        tenant,
        issuer.id,
        sub,
    )
    if row is None and email is not None and verified:
        row = await conn.fetchrow(
            "SELECT id, status FROM sibyl.app_user WHERE tenant_id = $1 AND oidc_issuer_id = $2"
            " AND status = 'invited' AND subject LIKE 'invite:%' AND email = $3 FOR UPDATE",
            tenant,
            issuer.id,
            email,
        )
        if row is not None:
            await conn.execute(
                "UPDATE sibyl.app_user SET subject = $3 WHERE tenant_id = $1 AND id = $2",
                tenant,
                row["id"],
                sub,
            )
    if row is None:
        return await _jit(conn, tenant, issuer, sub, email, verified), True
    if row["status"] in ("disabled", "deprovisioned"):
        raise LoginFailed("user_disabled")
    await conn.execute(
        "UPDATE sibyl.app_user SET status = 'active', last_login_at = $3,"
        " email_verified = email_verified OR $4,"
        " display_name = coalesce(display_name, $5)"
        " WHERE tenant_id = $1 AND id = $2",
        tenant,
        row["id"],
        now,
        verified,
        _display_name(claims),
    )
    return row["id"], False


def _display_name(claims: dict[str, Any]) -> str | None:
    name = claims.get("name") or claims.get("preferred_username")
    return name[:120] if isinstance(name, str) and name else None


async def _jit(
    conn: Any, tenant: UUID, issuer: Issuer, sub: str, email: str | None, verified: bool
) -> UUID:
    if issuer.jit_default_role is None or email is None or not verified:
        raise LoginFailed("user_unknown")
    domain = email.rsplit("@", 1)[1].lower()
    if domain not in {d.lower() for d in issuer.allowed_email_domains}:
        raise LoginFailed("email_domain_not_allowed")
    user_id: UUID = await conn.fetchval(
        "INSERT INTO sibyl.app_user (tenant_id, oidc_issuer_id, subject, email, email_verified,"
        " status, last_login_at) VALUES ($1, $2, $3, $4, true, 'active', now()) RETURNING id",
        tenant,
        issuer.id,
        sub,
        email,
    )
    await conn.execute(
        "INSERT INTO sibyl.membership (tenant_id, user_id, role_name, scope_kind)"
        " VALUES ($1, $2, $3, 'tenant')",
        tenant,
        user_id,
        issuer.jit_default_role,
    )
    return user_id


async def _has_membership(conn: Any, tenant: UUID, user_id: UUID) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.membership WHERE tenant_id = $1 AND user_id = $2"
            " AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()))",
            tenant,
            user_id,
        )
    )


def new_session_value() -> str:
    return secrets.token_urlsafe(32)


async def complete_login(
    request: Request,
    state: LoginState,
    issuer: Issuer,
    claims: dict[str, Any],
    settings: AuthSettings,
) -> str:
    """Create the session; returns the cookie value. Raises ``LoginFailed``."""
    services = get_services(request)
    tenant = UUID(state.tenant_id)
    now = services.clock()
    value = new_session_value()
    absolute, idle = session_window(settings, now)
    ip_digest = settings.ip_hash(client_ip(request))
    async with tenant_tx(services, tenant, audit_lock=True) as conn:
        user_id, jit = await _resolve_user(conn, tenant, issuer, claims, now)
        if not await _has_membership(conn, tenant, user_id):
            raise LoginFailed("no_membership")
        session_id: UUID = await conn.fetchval(
            "INSERT INTO sibyl.session (tenant_id, user_id, token_hash, issued_at,"
            " absolute_expires_at, idle_expires_at, last_seen_at, ip_hash, ua_class)"
            " VALUES ($1, $2, $3, $4, $5, $6, $4, $7, $8) RETURNING id",
            tenant,
            user_id,
            session_token_hash(value),
            now,
            absolute,
            idle,
            ip_digest,
            ua_class(request),
        )
        rid = request_id(request)
        if jit:
            await services.audit.append(
                conn,
                tenant,
                AuditRecord(
                    action="user.provisioned",
                    actor_type="system",
                    resource_type="app_user",
                    resource_id=user_id,
                    detail={
                        "user_id": str(user_id),
                        "issuer_id": str(issuer.id),
                        "via": "jit",
                        "role": issuer.jit_default_role,
                    },
                    request_id=rid,
                ),
            )
        amr = claims.get("amr")
        await services.audit.append(
            conn,
            tenant,
            AuditRecord(
                action="access.login",
                actor_type="human",
                actor_id=user_id,
                actor_session_id=session_id,
                resource_type="session",
                resource_id=session_id,
                detail={
                    "session_id": str(session_id),
                    "issuer_id": str(issuer.id),
                    "amr": [str(a) for a in amr] if isinstance(amr, list) else [],
                    "ip_hash": ip_digest.hex() if ip_digest else None,
                    "absolute_expires_at": iso(absolute),
                },
                request_id=rid,
            ),
        )
    return value


async def complete_step_up(
    request: Request, state: LoginState, issuer: Issuer, claims: dict[str, Any]
) -> None:
    services = get_services(request)
    tenant = UUID(state.tenant_id)
    strict = runtime.settings_for(request).step_up_require_auth_time
    if not _fresh_auth(claims, state, require_auth_time=strict):
        raise LoginFailed("stale_authentication")
    if state.session_id is None:
        raise LoginFailed("state_mismatch")
    now = services.clock()
    async with tenant_tx(services, tenant, audit_lock=True) as conn:
        row = await conn.fetchrow(
            "SELECT s.id, s.user_id, s.revoked_at, s.absolute_expires_at, s.idle_expires_at,"
            " u.subject, u.oidc_issuer_id, u.status FROM sibyl.session s"
            " JOIN sibyl.app_user u ON u.tenant_id = s.tenant_id AND u.id = s.user_id"
            " WHERE s.tenant_id = $1 AND s.id = $2 FOR UPDATE OF s",
            tenant,
            UUID(state.session_id),
        )
        if (
            row is None
            or row["revoked_at"] is not None
            or row["absolute_expires_at"] <= now
            or row["idle_expires_at"] <= now
            or row["status"] != "active"
        ):
            raise LoginFailed("session_inactive")
        if row["oidc_issuer_id"] != issuer.id or not hmac.compare_digest(
            str(row["subject"]), str(claims["sub"])
        ):
            raise LoginFailed("subject_mismatch")
        await conn.execute(
            "UPDATE sibyl.session SET step_up_at = $3 WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["id"],
            now,
        )
        await services.audit.append(
            conn,
            tenant,
            AuditRecord(
                action="access.step_up",
                actor_type="human",
                actor_id=row["user_id"],
                actor_session_id=row["id"],
                resource_type="session",
                resource_id=row["id"],
                detail={
                    "session_id": str(row["id"]),
                    "for_action": state.for_action or "unspecified",
                },
                request_id=request_id(request),
            ),
        )


def require_services_db(request: Request) -> None:
    require_db(get_services(request))
