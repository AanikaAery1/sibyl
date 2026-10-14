"""auth API module (lane A): OIDC login, callback, step-up, logout and ``/auth/me``.

API.md §2.1, §5.1.

The api is bearer-only; the only cookies it reads are its own ``__Host-sibyl_oidc_state`` on the
callback. It *sets* ``__Host-sibyl_session`` on the callback (Caddy serves api and console on one
origin), which the console BFF forwards as ``Authorization: Bearer sibyl_sess_<value>``.
"""

from __future__ import annotations

import hmac
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from ...core.authz import STEP_UP_WINDOW, PrincipalKind
from ...core.problems import ProblemError
from .._stubs import stub_router
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from . import runtime
from .common import (
    actor_record,
    iso,
    json_response,
    principal_of,
    record_denials,
    require_db,
    tenant_tx,
)
from .config import SESSION_COOKIE, STATE_COOKIE
from .flows import (
    LoginFailed,
    authorization_url,
    complete_login,
    complete_step_up,
    default_issuer,
    read_state,
    verified_claims,
    write_login_failed,
)
from .principals import tenant_by_slug
from .state import new_login_state, safe_return_to, seal_state

router = APIRouter(dependencies=[Depends(record_denials)])
SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{1,62}$"


class ReturnTo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    return_to: str | None = Field(default=None, max_length=2048)


def _set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        name, value, max_age=max_age, path="/", secure=True, httponly=True, samesite="lax"
    )


def _clear_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="lax")


def _redirect(location: str) -> RedirectResponse:
    return RedirectResponse(location, status_code=302)


@router.get(API_PREFIX + "/auth/login")
async def auth_login(
    request: Request,
    tenant: Annotated[str, Query(pattern=SLUG_PATTERN)],
    ctx: Annotated[AuthContext, Depends(guard("authLogin"))],
    return_to: Annotated[str | None, Query(max_length=2048)] = None,
) -> Response:
    services = get_services(request)
    tenant_id = await tenant_by_slug(require_db(services), tenant)
    issuer = await default_issuer(services, tenant_id) if tenant_id is not None else None
    if tenant_id is None or issuer is None:
        raise ProblemError("tenant_unknown")
    state = new_login_state(
        tenant_id=str(tenant_id),
        issuer_id=str(issuer.id),
        return_to=safe_return_to(return_to),
        now=ctx.now,
    )
    response = _redirect(await authorization_url(request, issuer, state, step_up=False))
    key = runtime.session_secret_key(request, "oidc-state")
    _set_cookie(
        response, STATE_COOKIE, seal_state(key, state), runtime.settings_for(request).state_ttl_s
    )
    return response


@router.get(API_PREFIX + "/auth/callback")
async def auth_callback(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("authCallback"))],
    code: Annotated[str | None, Query(max_length=2048)] = None,
    state: Annotated[str | None, Query(max_length=512)] = None,
    error: Annotated[str | None, Query(max_length=256)] = None,
) -> Response:
    login = read_state(request, request.cookies.get(STATE_COOKIE))
    if login is None:
        raise ProblemError("oidc_failed", "the login state is missing or expired; start again")
    try:
        if state is None or not hmac.compare_digest(login.state, state):
            raise LoginFailed("state_mismatch")
        if error or not code:
            raise LoginFailed("idp_error")
        issuer, claims = await verified_claims(request, login, code)
        if login.purpose == "step_up":
            await complete_step_up(request, login, issuer, claims)
            response = _redirect(login.return_to)
        else:
            value = await complete_login(
                request, login, issuer, claims, runtime.settings_for(request)
            )
            response = _redirect(login.return_to)
            _set_cookie(
                response, SESSION_COOKIE, value, runtime.settings_for(request).session_absolute_s
            )
    except LoginFailed as failed:
        await write_login_failed(request, login, failed.cause)
        problem = ProblemError("oidc_failed")
        problem.headers["Set-Cookie"] = (
            f"{STATE_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=lax"
        )
        raise problem from None
    _clear_cookie(response, STATE_COOKIE)
    return response


@router.post(API_PREFIX + "/auth/step-up")
async def auth_step_up(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("authStepUp"))],
    body: Annotated[ReturnTo | None, Body()] = None,
    for_action: Annotated[
        str | None, Query(max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_.:-]*$")
    ] = None,
) -> Response:
    principal = principal_of(ctx)
    if principal.kind is not PrincipalKind.SESSION or principal.session_id is None:
        raise ProblemError(
            "forbidden", "step-up is per console session; bearer tokens cannot step up"
        )
    services = get_services(request)
    async with tenant_tx(services, principal.tenant_id, readonly=True) as conn:
        issuer_id = await conn.fetchval(
            "SELECT oidc_issuer_id FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2",
            principal.tenant_id,
            principal.id,
        )
    issuer = await _issuer_by_id(services, principal.tenant_id, issuer_id)
    state = new_login_state(
        tenant_id=str(principal.tenant_id),
        issuer_id=str(issuer.id),
        return_to=safe_return_to(body.return_to if body else None),
        now=ctx.now,
        purpose="step_up",
        session_id=str(principal.session_id),
        for_action=for_action,
    )
    response = _redirect(await authorization_url(request, issuer, state, step_up=True))
    key = runtime.session_secret_key(request, "oidc-state")
    _set_cookie(
        response, STATE_COOKIE, seal_state(key, state), runtime.settings_for(request).state_ttl_s
    )
    return response


async def _issuer_by_id(services: Any, tenant: UUID, issuer_id: UUID | None) -> Any:
    from .flows import _ISSUER_COLS, _issuer

    async with tenant_tx(services, tenant, readonly=True) as conn:
        row = await conn.fetchrow(
            f"SELECT {_ISSUER_COLS} FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND id = $2"  # noqa: S608 (constant SQL fragments, no input)
            " AND status = 'active'",
            tenant,
            issuer_id,
        )
    if row is None:
        raise ProblemError("service_unavailable", "the user's identity provider is disabled")
    return _issuer(row)


@router.post(API_PREFIX + "/auth/logout")
async def auth_logout(
    request: Request, ctx: Annotated[AuthContext, Depends(guard("authLogout"))]
) -> Response:
    principal = principal_of(ctx)
    services = get_services(request)
    async with tenant_tx(services, principal.tenant_id, audit_lock=True) as conn:
        if principal.session_id is not None:
            await conn.execute(
                "UPDATE sibyl.session SET revoked_at = now(), revoke_reason = 'logout'"
                " WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
                principal.tenant_id,
                principal.session_id,
            )
        record = actor_record(
            ctx,
            "access.logout",
            resource_type="session",
            resource_id=principal.session_id,
            detail={
                "session_id": str(principal.session_id) if principal.session_id else None,
                "cause": "logout" if principal.session_id else "logout_bearer",
            },
        )
        receipt = await services.audit.append(conn, principal.tenant_id, record)
    response = Response(status_code=204)
    response.headers["X-Sibyl-Audit-Receipt"] = receipt.header_value()
    _clear_cookie(response, SESSION_COOKIE)
    return response


@router.get(API_PREFIX + "/auth/me")
async def auth_me(
    request: Request, ctx: Annotated[AuthContext, Depends(guard("authMe"))]
) -> Response:
    from ..tenancy.views import membership_view, tenant_view, user_view

    principal = principal_of(ctx)
    services = get_services(request)
    async with tenant_tx(services, principal.tenant_id, readonly=True) as conn:
        user = await conn.fetchrow(
            "SELECT * FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2",
            principal.tenant_id,
            principal.id,
        )
        tenant = await conn.fetchrow(
            "SELECT * FROM sibyl.tenant WHERE id = $1", principal.tenant_id
        )
        memberships = await conn.fetch(
            "SELECT * FROM sibyl.membership WHERE tenant_id = $1 AND user_id = $2"
            " AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())"
            " ORDER BY created_at, id",
            principal.tenant_id,
            principal.id,
        )
    if user is None or tenant is None:
        raise ProblemError("unauthenticated")
    valid_until = (
        iso(principal.step_up_at + STEP_UP_WINDOW)
        if principal.step_up_at is not None and principal.step_up_at + STEP_UP_WINDOW > ctx.now
        else None
    )
    return json_response(
        {
            "user": user_view(user),
            "tenant": tenant_view(tenant),
            "memberships": [membership_view(m) for m in memberships],
            "scopes": sorted(principal.scopes),
            "step_up_valid_until": valid_until,
        }
    )


stub_router("auth", router)
