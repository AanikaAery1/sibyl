"""Users, sessions, invitations and memberships (API.md §5.1-§5.2, security-auditor §3.4).

Object rules: ``self`` (a user without ``users:manage`` sees and revokes only their own rows),
``rank`` (a caller may grant or revoke only roles at or below their own highest role) and
``owner_grants_privileged`` (``owner``/``security_admin`` grants need an owner). The last-owner
guard is the deferred DB trigger (→ 409 ``last_owner``); disabling or deprovisioning the last
active owner is refused in the handler too.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from ...core.etag import check_if_match, if_none_match_hit
from ...core.problems import ProblemError
from ..auth.common import (
    Outcome,
    Paging,
    actor_record,
    human_reason,
    json_response,
    page_response,
    parse_uuid,
    principal_of,
    run_mutation,
    tenant_tx,
)
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from .views import membership_view, row_etag, session_view, user_view

router = APIRouter()
Role = Literal["owner", "admin", "security_admin", "engineer", "operator", "auditor", "viewer"]
ROLE_RANK: dict[str, int] = {
    "viewer": 1,
    "auditor": 2,
    "operator": 3,
    "engineer": 4,
    "security_admin": 5,
    "admin": 6,
    "owner": 7,
}
PRIVILEGED = frozenset({"owner", "security_admin"})
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
EMAIL_PATTERN = rf"^[^@\s]{{1,64}}@{_LABEL}(?:\.{_LABEL})+$"
TENANT_ONLY_ROLES = frozenset({"owner", "admin", "security_admin", "auditor"})
USERS_PAGING = Paging("GET /api/v1/users", "created_at,id", "tu")
SESSIONS_PAGING = Paging("GET /api/v1/sessions", "created_at,id", "tu")


def caller_rank(roles: frozenset[str]) -> int:
    return max((ROLE_RANK.get(r, 0) for r in roles), default=0)


def check_grant_rank(ctx: AuthContext, role: str, *, revoke: bool = False) -> None:
    """``rank`` and (for grants) ``owner_grants_privileged``; 403 ``forbidden`` when refused."""
    principal = principal_of(ctx)
    ctx.object_rule_checked("rank")
    if ROLE_RANK[role] > caller_rank(principal.roles):
        raise ProblemError("forbidden", f"cannot {'revoke' if revoke else 'grant'} {role}")
    if not revoke:
        ctx.object_rule_checked("owner_grants_privileged")
        if role in PRIVILEGED and "owner" not in principal.roles:
            raise ProblemError("forbidden", f"only an owner may grant {role}")
    elif role == "owner" and "owner" not in principal.roles:
        raise ProblemError("forbidden", "only an owner may revoke owner")


def check_scope(role: str, scope_kind: str, scope_id: UUID | None) -> None:
    if role in TENANT_ONLY_ROLES and scope_kind != "tenant":
        raise ProblemError("role_requires_tenant_scope")
    if (scope_kind == "agent_group") != (scope_id is not None):
        raise ProblemError("validation_failed", "scope_id is required exactly for agent_group")


# ---- users ---------------------------------------------------------------------------------


@router.get(API_PREFIX + "/users")
async def list_users(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("listUsers"))],
    status: Annotated[
        Literal["invited", "active", "disabled", "deprovisioned"] | None, Query()
    ] = None,
    q: Annotated[str | None, Query(max_length=120)] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    only = ctx.self_filter()
    filters = {"status": status, "q": q}
    size, after = USERS_PAGING.params(limit, cursor, filters)
    pattern = None
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        rows = await conn.fetch(
            "SELECT * FROM sibyl.app_user WHERE tenant_id = $1"
            " AND ($2::uuid IS NULL OR id = $2) AND ($3::text IS NULL OR status = $3)"
            " AND ($4::text IS NULL OR email::text ILIKE $4 OR display_name ILIKE $4)"
            " AND ($5::timestamptz IS NULL OR (created_at, id) > ($5, $6::uuid))"
            " ORDER BY created_at, id LIMIT $7",
            ctx.tenant_id,
            only,
            status,
            pattern,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )
    return page_response(
        request,
        USERS_PAGING,
        list(rows),
        size,
        lambda r: (r["created_at"], r["id"]),
        filters,
        user_view,
    )


async def _user(conn: Any, tenant: UUID, user_id: UUID, *, lock: bool = False) -> Any:
    return await conn.fetchrow(
        "SELECT * FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2"  # noqa: S608 (constant SQL fragments, no input)
        + (" FOR UPDATE" if lock else ""),
        tenant,
        user_id,
    )


async def _live_memberships(conn: Any, tenant: UUID, user_id: UUID) -> list[Any]:
    rows: list[Any] = await conn.fetch(
        "SELECT * FROM sibyl.membership WHERE tenant_id = $1 AND user_id = $2"
        " AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())"
        " ORDER BY created_at, id",
        tenant,
        user_id,
    )
    return rows


@router.get(API_PREFIX + "/users/{user_id}")
async def get_user(
    request: Request,
    user_id: str,
    ctx: Annotated[AuthContext, Depends(guard("getUser"))],
    if_none_match: Annotated[str | None, Header()] = None,
) -> Response:
    uid = parse_uuid(user_id)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        row = await _user(conn, ctx.tenant_id, uid)
        ctx.check_self(row["id"] if row is not None else None)
        if row is None:
            raise ProblemError("not_found")
        memberships = await _live_memberships(conn, ctx.tenant_id, uid)
    etag = row_etag(row)
    if if_none_match_hit(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    body = user_view(row) | {"memberships": [membership_view(m) for m in memberships]}
    return json_response(body, headers={"ETag": etag})


class UserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["invited", "active", "disabled", "deprovisioned"] | None = None
    display_name: str | None = Field(default=None, max_length=120)
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


_STATUS_EDGES = {
    ("active", "disabled"),
    ("invited", "disabled"),
    ("disabled", "active"),
    ("active", "deprovisioned"),
    ("disabled", "deprovisioned"),
    ("invited", "deprovisioned"),
}


async def _is_last_active_owner(conn: Any, tenant: UUID, user_id: UUID) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.membership m WHERE m.tenant_id = $1"
            "  AND m.user_id = $2 AND m.role_name = 'owner' AND m.revoked_at IS NULL)"
            " AND NOT EXISTS (SELECT 1 FROM sibyl.membership m"
            "  JOIN sibyl.app_user u ON u.tenant_id = m.tenant_id AND u.id = m.user_id"
            "  WHERE m.tenant_id = $1 AND m.user_id <> $2 AND m.role_name = 'owner'"
            "  AND m.revoked_at IS NULL AND (m.expires_at IS NULL OR m.expires_at > now())"
            "  AND u.status = 'active')",
            tenant,
            user_id,
        )
    )


async def _revoke_sessions(conn: Any, tenant: UUID, user_id: UUID, reason: str) -> int:
    result: str = await conn.execute(
        "UPDATE sibyl.session SET revoked_at = now(), revoke_reason = $3"
        " WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
        tenant,
        user_id,
        reason,
    )
    return int(result.rsplit(" ", 1)[-1])


@router.patch(API_PREFIX + "/users/{user_id}")
async def update_user(
    request: Request,
    user_id: str,
    body: UserPatch,
    ctx: Annotated[AuthContext, Depends(guard("updateUser"))],
    if_match: Annotated[str | None, Header()] = None,
) -> Response:
    uid = parse_uuid(user_id)
    if not body.model_fields_set - {"reason"}:
        raise ProblemError("validation_failed", "send status or display_name")
    reason = human_reason(request, body.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        tenant = ctx.tenant_id
        current = await _user(conn, tenant, uid, lock=True)
        if current is None:
            raise ProblemError("not_found")
        check_if_match(if_match, row_etag(current), current_body=user_view(current))
        receipt = None
        status: str = body.status or current["status"]
        if status != current["status"]:
            receipt = await _change_status(ctx, conn, current, status, reason)
        if "display_name" in body.model_fields_set and body.display_name != current["display_name"]:
            if status == "deprovisioned":
                raise ProblemError("conflict", "a deprovisioned user has no display name")
            await conn.execute(
                "UPDATE sibyl.app_user SET display_name = $3 WHERE tenant_id = $1 AND id = $2",
                tenant,
                uid,
                body.display_name,
            )
            receipt = await services.audit.append(
                conn,
                tenant,
                actor_record(
                    ctx,
                    "config.changed",
                    resource_type="app_user",
                    resource_id=uid,
                    detail={"field": "app_user.display_name", "before": None, "after": None},
                    reason=reason,
                ),
            )
        updated = await _user(conn, tenant, uid)
        return Outcome(200, user_view(updated), {"ETag": row_etag(updated)}, receipt)

    return await run_mutation(request, ctx, mutate, idempotent=False)


async def _change_status(
    ctx: AuthContext, conn: Any, current: Any, status: str, reason: str
) -> Any:
    services = get_services(ctx.request)  # type: ignore[arg-type]
    tenant, uid = ctx.tenant_id, current["id"]
    if (current["status"], status) not in _STATUS_EDGES:
        raise ProblemError("conflict", f"cannot move a user from {current['status']} to {status}")
    if status in ("disabled", "deprovisioned") and await _is_last_active_owner(conn, tenant, uid):
        raise ProblemError("last_owner")
    if status == "deprovisioned":
        await conn.execute(
            "UPDATE sibyl.app_user SET status = 'deprovisioned', display_name = NULL,"
            " email = sibyl.pseudonymise(email::text) WHERE tenant_id = $1 AND id = $2",
            tenant,
            uid,
        )
        await conn.execute(
            "UPDATE sibyl.membership SET revoked_at = now(), revoked_by = $3"
            " WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            tenant,
            uid,
            ctx.principal.id if ctx.principal else None,
        )
    else:
        await conn.execute(
            "UPDATE sibyl.app_user SET status = $3 WHERE tenant_id = $1 AND id = $2",
            tenant,
            uid,
            status,
        )
    sessions = 0
    if status in ("disabled", "deprovisioned"):
        sessions = await _revoke_sessions(conn, tenant, uid, f"user_{status}")
    action = {"disabled": "user.disabled", "deprovisioned": "user.deprovisioned"}.get(status)
    detail = {
        "user_id": str(uid),
        "issuer_id": str(current["oidc_issuer_id"]),
        "via": "api",
        "sessions_revoked": sessions,
    }
    if action is None:  # re-enable: not a lifecycle action in the taxonomy
        return await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "config.changed",
                resource_type="app_user",
                resource_id=uid,
                detail={"field": "app_user.status", "before": current["status"], "after": status},
                reason=reason,
            ),
        )
    return await services.audit.append(
        conn,
        tenant,
        actor_record(
            ctx, action, resource_type="app_user", resource_id=uid, detail=detail, reason=reason
        ),
    )


# ---- invitations and memberships ---------------------------------------------------------------


class UserInvite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=320, pattern=EMAIL_PATTERN)
    oidc_issuer_id: UUID
    role_name: Role
    scope_kind: Literal["tenant", "agent_group"]
    scope_id: UUID | None = None
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


async def _insert_membership(
    conn: Any,
    tenant: UUID,
    user_id: UUID,
    role: str,
    scope_kind: str,
    scope_id: UUID | None,
    granted_by: UUID,
    expires_at: datetime | None,
) -> Any:
    """Grant (or re-grant a revoked row: the unique index spans revoked grants)."""
    existing = await conn.fetchrow(
        "SELECT id, revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) AS live"
        " FROM sibyl.membership WHERE tenant_id = $1 AND user_id = $2 AND role_name = $3"
        " AND scope_kind = $4 AND coalesce(scope_id, sibyl.nil_uuid()) = coalesce($5,"
        " sibyl.nil_uuid())"
        " FOR UPDATE",
        tenant,
        user_id,
        role,
        scope_kind,
        scope_id,
    )
    if existing is not None:
        if existing["live"]:
            raise ProblemError("membership_exists")
        return await conn.fetchrow(
            "UPDATE sibyl.membership SET revoked_at = NULL, revoked_by = NULL, granted_by = $3,"
            " expires_at = $4 WHERE tenant_id = $1 AND id = $2 RETURNING *",
            tenant,
            existing["id"],
            granted_by,
            expires_at,
        )
    return await conn.fetchrow(
        "INSERT INTO sibyl.membership (tenant_id, user_id, role_name, scope_kind, scope_id,"
        " granted_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        tenant,
        user_id,
        role,
        scope_kind,
        scope_id,
        granted_by,
        expires_at,
    )


async def _check_group(conn: Any, tenant: UUID, scope_id: UUID | None) -> None:
    if scope_id is not None and not await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM sibyl.agent_group WHERE tenant_id = $1 AND id = $2)",
        tenant,
        scope_id,
    ):
        raise ProblemError("reference_unknown", "scope_id is not an agent group of this tenant")


def _granted_detail(m: Any) -> dict[str, Any]:
    return {
        "membership_id": str(m["id"]),
        "user_id": str(m["user_id"]),
        "role": m["role_name"],
        "scope_kind": m["scope_kind"],
        "scope_id": str(m["scope_id"]) if m["scope_id"] else None,
    }


@router.post(API_PREFIX + "/users/invitations")
async def invite_user(
    request: Request, body: UserInvite, ctx: Annotated[AuthContext, Depends(guard("inviteUser"))]
) -> Response:
    check_scope(body.role_name, body.scope_kind, body.scope_id)
    check_grant_rank(ctx, body.role_name)
    principal = principal_of(ctx)
    reason = human_reason(request, body.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        tenant = principal.tenant_id
        if not await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND id = $2"
            " AND status = 'active')",
            tenant,
            body.oidc_issuer_id,
        ):
            raise ProblemError("reference_unknown", "oidc_issuer_id is not an active issuer")
        await _check_group(conn, tenant, body.scope_id)
        if await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.app_user WHERE tenant_id = $1"
            " AND oidc_issuer_id = $2 AND email = $3)",
            tenant,
            body.oidc_issuer_id,
            str(body.email),
        ):
            raise ProblemError("user_exists")
        user = await conn.fetchrow(
            "INSERT INTO sibyl.app_user (tenant_id, oidc_issuer_id, subject, email, status)"
            " VALUES ($1, $2, 'invite:' || sibyl.uuidv7()::text, $3, 'invited') RETURNING *",
            tenant,
            body.oidc_issuer_id,
            str(body.email),
        )
        membership = await _insert_membership(
            conn,
            tenant,
            user["id"],
            body.role_name,
            body.scope_kind,
            body.scope_id,
            principal.id,
            None,
        )
        await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "user.provisioned",
                resource_type="app_user",
                resource_id=user["id"],
                detail={
                    "user_id": str(user["id"]),
                    "issuer_id": str(body.oidc_issuer_id),
                    "via": "invitation",
                },
                reason=reason,
            ),
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "membership.granted",
                resource_type="membership",
                resource_id=membership["id"],
                detail=_granted_detail(membership),
                reason=reason,
            ),
        )
        return Outcome(
            201,
            {"user": user_view(user), "membership": membership_view(membership)},
            receipt=receipt,
        )

    return await run_mutation(request, ctx, mutate, idempotent=True)


class MembershipCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: UUID
    role_name: Role
    scope_kind: Literal["tenant", "agent_group"]
    scope_id: UUID | None = None
    expires_at: datetime | None = None
    reason: str = Field(min_length=10, max_length=2000)


@router.post(API_PREFIX + "/memberships")
async def grant_membership(
    request: Request,
    body: MembershipCreate,
    ctx: Annotated[AuthContext, Depends(guard("grantMembership"))],
) -> Response:
    check_scope(body.role_name, body.scope_kind, body.scope_id)
    check_grant_rank(ctx, body.role_name)
    principal = principal_of(ctx)
    if body.expires_at is not None and body.expires_at <= ctx.now:
        raise ProblemError("validation_failed", "expires_at must be in the future")

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        tenant = principal.tenant_id
        user = await _user(conn, tenant, body.user_id)
        if user is None or user["status"] == "deprovisioned":
            raise ProblemError("reference_unknown", "user_id is not a user of this tenant")
        await _check_group(conn, tenant, body.scope_id)
        membership = await _insert_membership(
            conn,
            tenant,
            body.user_id,
            body.role_name,
            body.scope_kind,
            body.scope_id,
            principal.id,
            body.expires_at,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "membership.granted",
                resource_type="membership",
                resource_id=membership["id"],
                detail=_granted_detail(membership),
                reason=body.reason,
            ),
        )
        return Outcome(201, membership_view(membership), receipt=receipt)

    return await run_mutation(request, ctx, mutate, idempotent=True)


@router.delete(API_PREFIX + "/memberships/{membership_id}")
async def revoke_membership(
    request: Request,
    membership_id: str,
    ctx: Annotated[AuthContext, Depends(guard("revokeMembership"))],
    reason: Annotated[str, Query(min_length=10, max_length=2000)],
) -> Response:
    mid = parse_uuid(membership_id)
    principal = principal_of(ctx)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        tenant = principal.tenant_id
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.membership WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            tenant,
            mid,
        )
        if row is None or row["revoked_at"] is not None:
            ctx.object_rule_checked("rank")
            raise ProblemError("not_found")
        check_grant_rank(ctx, row["role_name"], revoke=True)
        await conn.execute(
            "UPDATE sibyl.membership SET revoked_at = now(), revoked_by = $3"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            mid,
            principal.id,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "membership.revoked",
                resource_type="membership",
                resource_id=mid,
                detail=_granted_detail(row),
                reason=reason,
            ),
        )
        return Outcome(204, None, receipt=receipt)

    return await run_mutation(request, ctx, mutate, idempotent=False)


# ---- sessions ----------------------------------------------------------------------------------


@router.get(API_PREFIX + "/sessions")
async def list_sessions(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("listSessions"))],
    user_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    own = ctx.self_filter()
    if own is not None and user_id is not None and user_id != own:
        user_id = UUID(int=0)  # someone else's sessions: an empty page, never an oracle
    who = own if user_id is None else user_id
    filters = {"user_id": user_id}
    size, after = SESSIONS_PAGING.params(limit, cursor, filters)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        rows = await conn.fetch(
            "SELECT * FROM sibyl.session WHERE tenant_id = $1 AND revoked_at IS NULL"
            " AND absolute_expires_at > now() AND idle_expires_at > now()"
            " AND ($2::uuid IS NULL OR user_id = $2)"
            " AND ($3::timestamptz IS NULL OR (created_at, id) > ($3, $4::uuid))"
            " ORDER BY created_at, id LIMIT $5",
            ctx.tenant_id,
            who,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )
    current = principal_of(ctx).session_id
    return page_response(
        request,
        SESSIONS_PAGING,
        list(rows),
        size,
        lambda r: (r["created_at"], r["id"]),
        filters,
        lambda r: session_view(r, current),
    )


@router.delete(API_PREFIX + "/sessions/{session_id}")
async def revoke_session(
    request: Request, session_id: str, ctx: Annotated[AuthContext, Depends(guard("revokeSession"))]
) -> Response:
    sid = parse_uuid(session_id)
    principal = principal_of(ctx)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        row = await conn.fetchrow(
            "SELECT id, user_id, revoked_at FROM sibyl.session WHERE tenant_id = $1 AND id = $2"
            " FOR UPDATE",
            principal.tenant_id,
            sid,
        )
        ctx.check_self(row["user_id"] if row is not None else None)
        if row is None or row["revoked_at"] is not None:
            raise ProblemError("not_found")
        cause = "revoked_by_user" if row["user_id"] == principal.id else "revoked_by_admin"
        await conn.execute(
            "UPDATE sibyl.session SET revoked_at = now(), revoke_reason = $3"
            " WHERE tenant_id = $1 AND id = $2",
            principal.tenant_id,
            sid,
            cause,
        )
        receipt = await services.audit.append(
            conn,
            principal.tenant_id,
            actor_record(
                ctx,
                "session.revoked",
                resource_type="session",
                resource_id=sid,
                detail={"session_id": str(sid), "cause": cause, "user_id": str(row["user_id"])},
            ),
        )
        return Outcome(204, None, receipt=receipt)

    return await run_mutation(request, ctx, mutate, idempotent=False)
