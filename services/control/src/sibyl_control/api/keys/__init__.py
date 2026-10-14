"""keys API module (lane A): tenant API keys (API.md §5.3, security-auditor §2.2, §2.5).

* ``apikeys:manage`` reaches every key; ``apikeys:manage_agent`` (engineer G) reaches only
  agent-bound keys of agents in the caller's groups. Anything else is 404, never 403.
* Scopes ⊆ M (400 ``invalid_scope``). ``killswitch:pull`` is exclusive, tenant-level and live
  (422 ``break_glass_scope_exclusive``; ≤ 2 active per tenant, DB trigger) and its creation or
  rotation additionally needs ``killswitch:pull`` held with a fresh step-up (D20).
* A key's env must be the deployment's env (``SIBYL_ENV``): a key the deployment would refuse
  as ``env_mismatch`` is never issued.
* Keys are immutable in place (DB trigger SB044): rotation inserts a new row (``rotated_from_id``)
  and moves the old one to ``rotating`` with ``rotation_grace_until`` (≤ 24 h); scopes may narrow.
* Create, rotate and revoke emit ``policy_changed`` in the same transaction so the gateway
  picks the key set up (revocation < 2 s target).
* The secret is returned exactly once (201); list/get never carry hash or secret.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from ...core.apikeys import (
    DEFAULT_KEY_LIFETIME,
    MAX_KEY_LIFETIME,
    generate_api_key,
    validate_expiry,
    validate_key_scopes,
)
from ...core.authz import BREAK_GLASS_SCOPE, NOT_APPLICABLE
from ...core.outbox import OutboxMessage
from ...core.problems import ProblemError
from .._stubs import stub_router
from ..auth.common import (
    Outcome,
    Paging,
    actor_record,
    human_reason,
    iso,
    json_response,
    page_response,
    parse_uuid,
    principal_of,
    record_denials,
    run_mutation,
    tenant_tx,
)
from ..contract import API_PREFIX
from ..deps import AuthContext, Services, get_services, guard

router = APIRouter(dependencies=[Depends(record_denials)])
MANAGE = "apikeys:manage"
MANAGE_AGENT = "apikeys:manage_agent"
MAX_GRACE_S = 86_400
KEYS_PAGING = Paging("GET /api/v1/api-keys", "created_at,id", "tu")


def key_view(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "env": row["env"],
        "prefix": row["prefix"],
        "scopes": list(row["scopes"]),
        "agent_id": str(row["agent_id"]) if row["agent_id"] else None,
        "monitor_id": str(row["monitor_id"]) if row.get("monitor_id") else None,
        "status": row["status"],
        "expires_at": iso(row["expires_at"]),
        "last_used_at": iso(row["last_used_at"]),
        "last_used_ip_hash": bytes(row["last_used_ip_hash"]).hex()
        if row["last_used_ip_hash"] is not None
        else None,
        "rotated_from_id": str(row["rotated_from_id"]) if row["rotated_from_id"] else None,
        "rotation_grace_until": iso(row["rotation_grace_until"]),
        "created_by": str(row["created_by"]) if row["created_by"] else None,
        "created_at": iso(row["created_at"]),
    }


_KEY_COLS = (
    "k.id, k.name, k.env, k.prefix, k.scopes, k.agent_id, k.monitor_id, k.status, k.expires_at,"
    " k.last_used_at,"
    " k.last_used_ip_hash, k.rotated_from_id, k.rotation_grace_until, k.created_by, k.created_at,"
    " a.agent_group_id"
)


def _is_break_glass(scopes: Any) -> bool:
    return frozenset(scopes) == {BREAK_GLASS_SCOPE}


def _manages_all(ctx: AuthContext) -> bool:
    principal = principal_of(ctx)
    return principal.has(MANAGE)


def _deployment_env(services: Services) -> str | None:
    return services.settings.env if services.settings is not None else None


def _pepper(services: Services) -> bytes:
    if services.settings is None or services.settings.key_pepper is None:
        raise ProblemError("service_unavailable", "SIBYL_KEY_PEPPER is not set")
    return services.settings.pepper()


async def _load_key(conn: Any, tenant: UUID, key_id: UUID, *, lock: bool = False) -> Any:
    return await conn.fetchrow(
        f"SELECT {_KEY_COLS} FROM sibyl.api_key k"  # noqa: S608 (constant column list)
        " LEFT JOIN sibyl.agent a ON a.tenant_id = k.tenant_id AND a.id = k.agent_id"
        " WHERE k.tenant_id = $1 AND k.id = $2" + (" FOR UPDATE OF k" if lock else ""),
        tenant,
        key_id,
    )


def _check_visible(ctx: AuthContext, row: Any | None) -> Any:
    """Object rule ``group``: manage_agent-only callers see only in-group agent-bound keys."""
    if row is None:
        ctx.check(resource_group_id=NOT_APPLICABLE)
        ctx.object_rule_checked("group")
        raise ProblemError("not_found")
    if _manages_all(ctx):
        ctx.check(resource_group_id=NOT_APPLICABLE)
        ctx.object_rule_checked("group")
        return row
    if row["agent_id"] is None:
        ctx.object_rule_checked("group")
        raise ProblemError("not_found", audit_denied=True)
    ctx.check(resource_group_id=row["agent_group_id"])
    return row


async def _policy_changed(
    services: Services, conn: Any, tenant: UUID, agent_id: UUID | None
) -> None:
    version = await conn.fetchval("SELECT routing_version FROM sibyl.tenant WHERE id = $1", tenant)
    await services.outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "policy_changed",
            "agent" if agent_id else "tenant",
            agent_id or tenant,
            {
                "tenant_id": str(tenant),
                "routing_version": int(version or 0),
                "agent_id": str(agent_id) if agent_id else None,
            },
        ),
    )


def _key_detail(row: Any, **extra: Any) -> dict[str, Any]:
    return {
        "key_id": str(row["id"]),
        "prefix": row["prefix"],
        "scopes": sorted(row["scopes"]),
        "agent_id": str(row["agent_id"]) if row["agent_id"] else None,
        "grace_until": iso(row["rotation_grace_until"]),
        "env": row["env"],
        "break_glass": _is_break_glass(row["scopes"]),
        **extra,
    }


# ---- reads -------------------------------------------------------------------------------------


@router.get(API_PREFIX + "/api-keys")
async def list_api_keys(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("listApiKeys"))],
    agent_id: Annotated[UUID | None, Query()] = None,
    status: Annotated[Literal["active", "rotating", "revoked", "expired"] | None, Query()] = None,
    env: Annotated[Literal["live", "test"] | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    groups = ctx.group_filter()
    everything = _manages_all(ctx)
    filters = {"agent_id": agent_id, "status": status, "env": env}
    size, after = KEYS_PAGING.params(limit, cursor, filters)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        rows = await conn.fetch(
            f"SELECT {_KEY_COLS} FROM sibyl.api_key k"  # noqa: S608 (constant column list)
            " LEFT JOIN sibyl.agent a ON a.tenant_id = k.tenant_id AND a.id = k.agent_id"
            " WHERE k.tenant_id = $1"
            " AND ($2 OR (k.agent_id IS NOT NULL AND ($3::uuid[] IS NULL"
            "      OR a.agent_group_id = ANY($3::uuid[]))))"
            " AND ($4::uuid IS NULL OR k.agent_id = $4) AND ($5::text IS NULL OR k.status = $5)"
            " AND ($6::text IS NULL OR k.env = $6)"
            " AND ($7::timestamptz IS NULL OR (k.created_at, k.id) > ($7, $8::uuid))"
            " ORDER BY k.created_at, k.id LIMIT $9",
            ctx.tenant_id,
            everything,
            None if everything or groups is None else list(groups),
            agent_id,
            status,
            env,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )
    return page_response(
        request,
        KEYS_PAGING,
        list(rows),
        size,
        lambda r: (r["created_at"], r["id"]),
        filters,
        key_view,
    )


@router.get(API_PREFIX + "/api-keys/{key_id}")
async def get_api_key(
    request: Request, key_id: str, ctx: Annotated[AuthContext, Depends(guard("getApiKey"))]
) -> Response:
    kid = parse_uuid(key_id)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        row = _check_visible(ctx, await _load_key(conn, ctx.tenant_id, kid))
    return json_response(key_view(row))


# ---- create ------------------------------------------------------------------------------------


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    env: Literal["live", "test"]
    scopes: list[str] = Field(min_length=1, max_length=16)
    agent_id: UUID | None = None
    expires_at: datetime | None = None
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


def _check_break_glass_authority(ctx: AuthContext, scopes: frozenset[str]) -> None:
    """D20: issuing or rotating a break-glass key needs ``apikeys:manage`` and ``killswitch:pull``
    held by the caller, with a fresh step-up (conditional step-up of the route)."""
    principal = principal_of(ctx)
    breaking = BREAK_GLASS_SCOPE in scopes
    if breaking and not (principal.has(MANAGE) and principal.has(BREAK_GLASS_SCOPE)):
        raise ProblemError(
            "forbidden", extensions={"permission": BREAK_GLASS_SCOPE}, audit_denied=True
        )
    ctx.step_up_if(breaking)


@router.post(API_PREFIX + "/api-keys")
async def create_api_key(
    request: Request,
    body: ApiKeyCreate,
    ctx: Annotated[AuthContext, Depends(guard("createApiKey"))],
) -> Response:
    if len(set(body.scopes)) != len(body.scopes):
        raise ProblemError("validation_failed", "scopes must be unique")
    scopes = validate_key_scopes(body.scopes, agent_id=body.agent_id, env=body.env)
    breaking = _is_break_glass(scopes)
    ctx.object_rule_checked("break_glass_create")
    _check_break_glass_authority(ctx, scopes)
    principal = principal_of(ctx)
    if body.agent_id is None and not principal.has(MANAGE):
        ctx.object_rule_checked("group")
        raise ProblemError(
            "forbidden",
            "tenant-level keys need apikeys:manage",
            extensions={"permission": MANAGE},
            audit_denied=True,
        )
    services = get_services(request)
    expected_env = _deployment_env(services)
    if expected_env is not None and body.env != expected_env:
        raise ProblemError(
            "validation_failed",
            f"this deployment accepts only {expected_env} keys (env_mismatch)",
            extensions={
                "errors": [
                    {
                        "pointer": "/env",
                        "code": "env_mismatch",
                        "message": f"expected {expected_env}",
                    }
                ]
            },
        )
    expires_at = validate_expiry(body.expires_at, now=ctx.now)
    pepper = _pepper(services)
    reason = human_reason(request, body.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Outcome:
        tenant = principal.tenant_id
        if body.agent_id is not None:
            agent = await conn.fetchrow(
                "SELECT id, agent_group_id, lifecycle FROM sibyl.agent WHERE tenant_id = $1 AND id"
                " = $2",
                tenant,
                body.agent_id,
            )
            if agent is None:
                ctx.object_rule_checked("group")
                raise ProblemError("not_found")
            ctx.check(resource_group_id=agent["agent_group_id"])
            if agent["lifecycle"] == "retired":
                raise ProblemError("conflict", "the agent is retired")
        else:
            ctx.check(resource_group_id=NOT_APPLICABLE)
            ctx.object_rule_checked("group")
        if not breaking and not await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.capture_policy WHERE tenant_id = $1"
            " AND scope_kind = 'tenant' AND superseded_by IS NULL)",
            tenant,
        ):
            raise ProblemError("capture_policy_missing")
        generated = generate_api_key(body.env, pepper)
        row = await conn.fetchrow(
            "INSERT INTO sibyl.api_key (tenant_id, agent_id, name, env, prefix, secret_hash,"
            " scopes,"
            " expires_at, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
            " RETURNING *, NULL::uuid AS agent_group_id",
            tenant,
            body.agent_id,
            body.name,
            body.env,
            generated.prefix,
            generated.secret_hash,
            sorted(scopes),
            expires_at,
            principal.id,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "api_key.created",
                resource_type="api_key",
                resource_id=row["id"],
                resource_ref=row["prefix"],
                detail=_key_detail(row, expires_at=iso(expires_at)),
                reason=reason,
            ),
        )
        await _policy_changed(services, conn, tenant, body.agent_id)
        return _created(key_view(row), generated.plaintext, receipt)

    return await run_mutation(request, ctx, mutate, idempotent=True)


def _created(view: dict[str, Any], secret: str, receipt: Any) -> Outcome:
    """201 with the secret exactly once; an ``Idempotency-Key`` replay gets ``secret: null``
    (the plaintext is never written to ``idempotency_record``; lost secret → rotate)."""
    return Outcome(
        201, view | {"secret": secret}, receipt=receipt, replay_body=view | {"secret": None}
    )


# ---- rotate / revoke ---------------------------------------------------------------------------


class ApiKeyRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grace_s: int = Field(default=3600, ge=0, le=MAX_GRACE_S)
    scopes: list[str] | None = Field(default=None, min_length=1, max_length=16)
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=2000)


def _rotated_expiry(old: Any, now: datetime) -> datetime:
    lifetime = old["expires_at"] - old["created_at"]
    lifetime = min(max(lifetime, timedelta(days=1)), MAX_KEY_LIFETIME)
    return now + (lifetime if lifetime > timedelta(0) else DEFAULT_KEY_LIFETIME)


@router.post(API_PREFIX + "/api-keys/{key_id}/rotate")
async def rotate_api_key(
    request: Request,
    key_id: str,
    ctx: Annotated[AuthContext, Depends(guard("rotateApiKey"))],
    body: Annotated[ApiKeyRotate | None, Body()] = None,
) -> Response:
    kid = parse_uuid(key_id)
    rotate = body or ApiKeyRotate()
    principal = principal_of(ctx)
    services = get_services(request)
    reason = human_reason(request, rotate.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Outcome:
        tenant = principal.tenant_id
        old = _check_visible(ctx, await _load_key(conn, tenant, kid, lock=True))
        old_scopes = frozenset(old["scopes"])
        _check_break_glass_authority(ctx, old_scopes)
        if old["status"] != "active":
            raise ProblemError("key_not_active")
        scopes = frozenset(rotate.scopes) if rotate.scopes is not None else old_scopes
        if rotate.scopes is not None and len(set(rotate.scopes)) != len(rotate.scopes):
            raise ProblemError("validation_failed", "scopes must be unique")
        if not scopes <= old_scopes:
            raise ProblemError("invalid_scope", "rotation may only narrow scopes")
        validate_key_scopes(
            scopes, agent_id=old["agent_id"], env=old["env"], monitor_id=old["monitor_id"]
        )
        now = ctx.now
        grace_until = now + timedelta(seconds=rotate.grace_s)
        await conn.execute(
            "UPDATE sibyl.api_key SET status = 'rotating', rotation_grace_until = $3"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            kid,
            grace_until,
        )
        generated = generate_api_key(old["env"], _pepper(services))
        new = await conn.fetchrow(
            "INSERT INTO sibyl.api_key (tenant_id, agent_id, name, env, prefix, secret_hash,"
            " scopes,"
            " expires_at, created_by, rotated_from_id, monitor_id) VALUES ($1, $2, $3, $4, $5, $6,"
            " $7, $8, $9, $10, $11)"
            " RETURNING *, NULL::uuid AS agent_group_id",
            tenant,
            old["agent_id"],
            old["name"],
            old["env"],
            generated.prefix,
            generated.secret_hash,
            sorted(scopes),
            _rotated_expiry(old, now),
            principal.id,
            kid,
            old["monitor_id"],
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "api_key.rotated",
                resource_type="api_key",
                resource_id=new["id"],
                resource_ref=new["prefix"],
                detail=_key_detail(
                    new,
                    grace_until=iso(grace_until),
                    rotated_from_id=str(kid),
                    rotated_from_prefix=old["prefix"],
                ),
                reason=reason,
            ),
        )
        await _policy_changed(services, conn, tenant, old["agent_id"])
        return _created(key_view(new), generated.plaintext, receipt)

    return await run_mutation(request, ctx, mutate, idempotent=True)


@router.post(API_PREFIX + "/api-keys/{key_id}/revoke")
async def revoke_api_key(
    request: Request,
    key_id: str,
    body: ReasonBody,
    ctx: Annotated[AuthContext, Depends(guard("revokeApiKey"))],
) -> Response:
    kid = parse_uuid(key_id)
    principal = principal_of(ctx)
    services = get_services(request)

    async def mutate(conn: Any) -> Outcome:
        tenant = principal.tenant_id
        old = _check_visible(ctx, await _load_key(conn, tenant, kid, lock=True))
        if old["status"] == "revoked":
            raise ProblemError("already_revoked")
        row = await conn.fetchrow(
            "UPDATE sibyl.api_key SET status = 'revoked', revoked_at = now(), revoked_by = $3,"
            " revoke_reason = $4 WHERE tenant_id = $1 AND id = $2"
            " RETURNING *, NULL::uuid AS agent_group_id",
            tenant,
            kid,
            principal.id if principal.is_human else None,
            body.reason,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "api_key.revoked",
                resource_type="api_key",
                resource_id=kid,
                resource_ref=row["prefix"],
                detail=_key_detail(row, previous_status=old["status"]),
                reason=body.reason,
            ),
        )
        await _policy_changed(services, conn, tenant, row["agent_id"])
        return Outcome(200, key_view(row), receipt=receipt)

    return await run_mutation(request, ctx, mutate, idempotent=True)


stub_router("keys", router)
