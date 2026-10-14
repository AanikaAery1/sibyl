"""``GET/PATCH /tenant`` and ``GET /tenant-keys``, ``POST /tenant-keys/{purpose}/rotate``."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, Path, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from ...core.crypto.deks import new_wrapped_dek
from ...core.etag import check_if_match, if_none_match_hit
from ...core.problems import ProblemError
from ..auth import runtime
from ..auth.common import (
    Outcome,
    actor_record,
    human_reason,
    json_response,
    principal_of,
    run_mutation,
    tenant_tx,
)
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from .views import row_etag, tenant_key_view, tenant_view

router = APIRouter()
Purpose = Literal["payload", "credential", "config"]
PATCHABLE = (
    "name",
    "region_declared",
    "unknown_agent_fail_mode",
    "hold_on_incident",
    "raw_retention_days",
    "audit_retention_days",
    "backup_retention_days",
)


class TenantPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=120)
    region_declared: str | None = Field(default=None, max_length=32)
    unknown_agent_fail_mode: Literal["open", "closed"] | None = None
    hold_on_incident: bool | None = None
    raw_retention_days: int | None = Field(default=None, ge=1, le=30)
    audit_retention_days: int | None = Field(default=None, ge=400, le=2557)
    backup_retention_days: int | None = Field(default=None, ge=1, le=35)
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


class TenantKeyRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=10, max_length=500)


_TENANT_SQL = "SELECT * FROM sibyl.tenant WHERE id = $1"


async def _load_tenant(conn: Any, tenant_id: Any, *, lock: bool = False) -> Any:
    sql = "SELECT * FROM sibyl.tenant WHERE id = $1 FOR UPDATE" if lock else _TENANT_SQL
    row = await conn.fetchrow(sql, tenant_id)
    if row is None:
        raise ProblemError("not_found")
    return row


@router.get(API_PREFIX + "/tenant")
async def get_tenant(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("getTenant"))],
    if_none_match: Annotated[str | None, Header()] = None,
) -> Response:
    services = get_services(request)
    async with tenant_tx(services, ctx.tenant_id, readonly=True) as conn:
        row = await _load_tenant(conn, ctx.tenant_id)
    etag = row_etag(row)
    if if_none_match_hit(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    return json_response(tenant_view(row), headers={"ETag": etag})


@router.patch(API_PREFIX + "/tenant")
async def update_tenant(
    request: Request,
    body: TenantPatch,
    ctx: Annotated[AuthContext, Depends(guard("updateTenant"))],
    if_match: Annotated[str | None, Header()] = None,
) -> Response:
    changes = {k: getattr(body, k) for k in body.model_fields_set if k != "reason"}
    if not changes:
        raise ProblemError("validation_failed", "send at least one field")
    for name in (
        "name",
        "unknown_agent_fail_mode",
        "hold_on_incident",
        "raw_retention_days",
        "audit_retention_days",
        "backup_retention_days",
    ):
        if name in changes and changes[name] is None:
            raise ProblemError("validation_failed", f"{name} cannot be null")
    reason = human_reason(request, body.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        current = await _load_tenant(conn, ctx.tenant_id, lock=True)
        check_if_match(if_match, row_etag(current), current_body=tenant_view(current))
        diff = {k: v for k, v in changes.items() if current[k] != v}
        if not diff:
            return Outcome(200, tenant_view(current), {"ETag": row_etag(current)})
        sets = ", ".join(f"{name} = ${i + 2}" for i, name in enumerate(diff))
        updated = await conn.fetchrow(
            f"UPDATE sibyl.tenant SET {sets} WHERE id = $1 RETURNING *",  # noqa: S608 (whitelisted)
            ctx.tenant_id,
            *diff.values(),
        )
        receipt = None
        for name, after in diff.items():
            receipt = await services.audit.append(
                conn,
                ctx.tenant_id,
                actor_record(
                    ctx,
                    "config.changed",
                    resource_type="tenant",
                    resource_id=ctx.tenant_id,
                    detail={"field": f"tenant.{name}", "before": current[name], "after": after},
                    reason=reason,
                ),
            )
        return Outcome(200, tenant_view(updated), {"ETag": row_etag(updated)}, receipt)

    assert set(changes) <= set(PATCHABLE)
    return await run_mutation(request, ctx, mutate, idempotent=False)


@router.get(API_PREFIX + "/tenant-keys")
async def list_tenant_keys(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("listTenantKeys"))],
    purpose: Annotated[Purpose | None, Query()] = None,
    state: Annotated[Literal["active", "retired", "shredded"] | None, Query()] = None,
) -> Response:
    services = get_services(request)
    async with tenant_tx(services, ctx.tenant_id, readonly=True) as conn:
        rows = await conn.fetch(
            "SELECT id, purpose, version, algorithm, kek_id, state, activated_at, retired_at,"
            " shredded_at FROM sibyl.tenant_key WHERE tenant_id = $1"
            " AND ($2::text IS NULL OR purpose = $2) AND ($3::text IS NULL OR state = $3)"
            " ORDER BY purpose, version DESC",
            ctx.tenant_id,
            purpose,
            state,
        )
    return json_response({"data": [tenant_key_view(r) for r in rows]})


@router.post(API_PREFIX + "/tenant-keys/{purpose}/rotate")
async def rotate_tenant_key(
    request: Request,
    purpose: Annotated[Purpose, Path()],
    body: TenantKeyRotate,
    ctx: Annotated[AuthContext, Depends(guard("rotateTenantKey"))],
) -> Response:
    principal = principal_of(ctx)
    kek = runtime.kek_for(request)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        version = await conn.fetchval(
            "SELECT version FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = $2"
            " AND state = 'active'",
            principal.tenant_id,
            purpose,
        )
        if version is None:
            raise ProblemError("conflict", f"no active {purpose} key to rotate")
        wrapped = new_wrapped_dek(kek, principal.tenant_id, purpose, int(version) + 1)
        ids = await conn.fetchrow(
            "SELECT active_id, retired_id FROM sibyl.tenant_key_rotate($1, $2, $3)",
            purpose,
            wrapped.wrapped,
            kek.kek_id,
        )
        rows = {
            r["id"]: r
            for r in await conn.fetch(
                "SELECT * FROM sibyl.tenant_key WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
                principal.tenant_id,
                [ids["active_id"], ids["retired_id"]],
            )
        }
        active, retired = rows[ids["active_id"]], rows[ids["retired_id"]]
        receipt = await services.audit.append(
            conn,
            principal.tenant_id,
            actor_record(
                ctx,
                "tenant_key.rotated",
                resource_type="tenant_key",
                resource_id=active["id"],
                resource_ref=f"{purpose}:v{active['version']}",
                detail={
                    "key_id": str(active["id"]),
                    "purpose": purpose,
                    "version": active["version"],
                    "kek_id": kek.kek_id,
                    "retired_key_id": str(retired["id"]),
                    "retired_version": retired["version"],
                },
                reason=body.reason,
            ),
        )
        return Outcome(
            201,
            {"active": tenant_key_view(active), "retired": tenant_key_view(retired)},
            receipt=receipt,
        )

    response = await run_mutation(request, ctx, mutate, idempotent=True)
    deks = runtime.get(request, "deks")
    if deks is not None:
        deks.invalidate(principal.tenant_id, purpose)
    return response
