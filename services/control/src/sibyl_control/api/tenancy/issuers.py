"""OIDC issuers (``oidc:manage``↑) and agent groups (``users:manage``), API.md §5.2.

``client_secret`` is write-only: sealed under the tenant ``config`` DEK (AAD binds the issuer row)
and never serialised. ``issuer_url`` must be ``https`` with no userinfo, query or fragment.
``jit_default_role`` and every ``role_claim_map`` value must be a non-privileged role
(422 ``jit_role_forbidden``). The last active issuer cannot be disabled (409).
"""

from __future__ import annotations

from typing import Annotated, Any
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from ...core.etag import check_if_match, if_none_match_hit
from ...core.problems import ProblemError
from ..auth import runtime
from ..auth.common import (
    Outcome,
    Paging,
    actor_record,
    human_reason,
    json_response,
    page_response,
    parse_uuid,
    run_mutation,
    tenant_tx,
)
from ..auth.dek import seal_issuer_secret
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from .people import Role
from .views import group_view, issuer_view, row_etag

router = APIRouter()
FORBIDDEN_JIT = frozenset({"owner", "admin", "security_admin"})
ISSUERS_PAGING = Paging("GET /api/v1/oidc-issuers", "created_at,id", "tu")
GROUPS_PAGING = Paging("GET /api/v1/agent-groups", "created_at,id", "tu")
SLUG = r"^[a-z0-9][a-z0-9-]{1,62}$"


def check_issuer_url(url: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or len(url) > 2048
    ):
        raise ProblemError(
            "validation_failed", "issuer_url must be an https URL without credentials"
        )
    return url.rstrip("/")


def check_roles(jit: str | None, claim_map: dict[str, Any] | None) -> None:
    if jit is not None and jit in FORBIDDEN_JIT:
        raise ProblemError("jit_role_forbidden")
    for value in (claim_map or {}).values():
        if not isinstance(value, str) or value in FORBIDDEN_JIT:
            raise ProblemError("jit_role_forbidden")


class OidcIssuerCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer_url: str = Field(max_length=2048, pattern="^https://")
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str = Field(min_length=1, max_length=1024)
    allowed_email_domains: list[str] = Field(max_length=64)
    role_claim: str | None = Field(default=None, max_length=120)
    role_claim_map: dict[str, Role] | None = None
    jit_default_role: Role | None = None
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


class OidcIssuerPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_secret: str | None = Field(default=None, min_length=1, max_length=1024)
    allowed_email_domains: list[str] | None = Field(default=None, max_length=64)
    role_claim: str | None = Field(default=None, max_length=120)
    role_claim_map: dict[str, Role] | None = None
    jit_default_role: Role | None = None
    is_active: bool | None = None
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


def _domains(values: list[str]) -> list[str]:
    out = sorted({v.strip().lower() for v in values if v.strip()})
    if any("@" in d or "/" in d or len(d) > 253 for d in out):
        raise ProblemError("validation_failed", "allowed_email_domains holds bare domains")
    return out


@router.get(API_PREFIX + "/oidc-issuers")
async def list_issuers(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("listOidcIssuers"))],
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    size, after = ISSUERS_PAGING.params(limit, cursor, {})
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        rows = await conn.fetch(
            "SELECT * FROM sibyl.oidc_issuer WHERE tenant_id = $1"
            " AND ($2::timestamptz IS NULL OR (created_at, id) > ($2, $3::uuid))"
            " ORDER BY created_at, id LIMIT $4",
            ctx.tenant_id,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )
    return page_response(
        request,
        ISSUERS_PAGING,
        list(rows),
        size,
        lambda r: (r["created_at"], r["id"]),
        {},
        issuer_view,
    )


@router.get(API_PREFIX + "/oidc-issuers/{issuer_id}")
async def get_issuer(
    request: Request,
    issuer_id: str,
    ctx: Annotated[AuthContext, Depends(guard("getOidcIssuer"))],
    if_none_match: Annotated[str | None, Header()] = None,
) -> Response:
    iid = parse_uuid(issuer_id)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND id = $2", ctx.tenant_id, iid
        )
    if row is None:
        raise ProblemError("not_found")
    etag = row_etag(row)
    if if_none_match_hit(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    return json_response(issuer_view(row), headers={"ETag": etag})


@router.post(API_PREFIX + "/oidc-issuers")
async def create_issuer(
    request: Request,
    body: OidcIssuerCreate,
    ctx: Annotated[AuthContext, Depends(guard("createOidcIssuer"))],
) -> Response:
    url = check_issuer_url(body.issuer_url)
    check_roles(body.jit_default_role, body.role_claim_map)
    domains = _domains(body.allowed_email_domains)
    if body.jit_default_role is not None and not domains:
        raise ProblemError("validation_failed", "JIT provisioning needs allowed_email_domains")
    reason = human_reason(request, body.reason, ctx.op.operation_id)
    deks = runtime.deks_for(request)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        tenant = ctx.tenant_id
        if await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND issuer_url ="
            " $2)",
            tenant,
            url,
        ):
            raise ProblemError("issuer_exists")
        issuer_id: UUID = await conn.fetchval("SELECT sibyl.uuidv7()")
        ct, key_id = await seal_issuer_secret(deks, tenant, issuer_id, body.client_secret)
        row = await conn.fetchrow(
            "INSERT INTO sibyl.oidc_issuer (tenant_id, id, issuer_url, client_id, client_secret_ct,"
            " client_secret_key_id, allowed_email_domains, role_claim, role_claim_map,"
            " jit_default_role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *",
            tenant,
            issuer_id,
            url,
            body.client_id,
            ct,
            key_id,
            domains,
            body.role_claim,
            dict(body.role_claim_map or {}),
            body.jit_default_role,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "oidc_issuer.configured",
                resource_type="oidc_issuer",
                resource_id=issuer_id,
                detail={
                    "issuer_url": url,
                    "fields_changed": sorted(body.model_fields_set - {"reason"}),
                    "jit_default_role": body.jit_default_role,
                },
                reason=reason,
            ),
        )
        return Outcome(201, issuer_view(row), {"ETag": row_etag(row)}, receipt)

    return await run_mutation(request, ctx, mutate, idempotent=True)


@router.patch(API_PREFIX + "/oidc-issuers/{issuer_id}")
async def update_issuer(
    request: Request,
    issuer_id: str,
    body: OidcIssuerPatch,
    ctx: Annotated[AuthContext, Depends(guard("updateOidcIssuer"))],
    if_match: Annotated[str | None, Header()] = None,
) -> Response:
    iid = parse_uuid(issuer_id)
    fields = set(body.model_fields_set) - {"reason"}
    if not fields:
        raise ProblemError("validation_failed", "send at least one field")
    if "is_active" in fields and body.is_active is None:
        raise ProblemError("validation_failed", "is_active cannot be null")
    if "allowed_email_domains" in fields and body.allowed_email_domains is None:
        raise ProblemError("validation_failed", "allowed_email_domains cannot be null")
    check_roles(body.jit_default_role, body.role_claim_map)
    reason = human_reason(request, body.reason, ctx.op.operation_id)
    deks = runtime.deks_for(request) if "client_secret" in fields else None

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        tenant = ctx.tenant_id
        current = await conn.fetchrow(
            "SELECT * FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            tenant,
            iid,
        )
        if current is None:
            raise ProblemError("not_found")
        check_if_match(if_match, row_etag(current), current_body=issuer_view(current))
        sets: dict[str, Any] = {}
        if "allowed_email_domains" in fields:
            sets["allowed_email_domains"] = _domains(body.allowed_email_domains or [])
        for name in ("role_claim", "jit_default_role"):
            if name in fields:
                sets[name] = getattr(body, name)
        if "role_claim_map" in fields:
            sets["role_claim_map"] = dict(body.role_claim_map or {})
        if "client_secret" in fields and body.client_secret is not None and deks is not None:
            ct, key_id = await seal_issuer_secret(deks, tenant, iid, body.client_secret)
            sets |= {"client_secret_ct": ct, "client_secret_key_id": key_id}
        disabling = (
            "is_active" in fields and body.is_active is False and current["status"] == "active"
        )
        if "is_active" in fields:
            sets["status"] = "active" if body.is_active else "disabled"
        jit = sets.get("jit_default_role", current["jit_default_role"])
        if jit is not None and not sets.get(
            "allowed_email_domains", current["allowed_email_domains"]
        ):
            raise ProblemError("validation_failed", "JIT provisioning needs allowed_email_domains")
        if disabling and not await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND id <> $2"
            " AND status = 'active')",
            tenant,
            iid,
        ):
            raise ProblemError("last_active_issuer")
        assignments = ", ".join(f"{name} = ${i + 3}" for i, name in enumerate(sets))
        updated = await conn.fetchrow(
            f"UPDATE sibyl.oidc_issuer SET {assignments} WHERE tenant_id = $1 AND id = $2"  # noqa: S608
            " RETURNING *",
            tenant,
            iid,
            *sets.values(),
        )
        if disabling:
            await conn.execute(
                "UPDATE sibyl.session s SET revoked_at = now(), revoke_reason = 'issuer_disabled'"
                " FROM sibyl.app_user u WHERE s.tenant_id = $1 AND u.tenant_id = s.tenant_id"
                " AND u.id = s.user_id AND u.oidc_issuer_id = $2 AND s.revoked_at IS NULL",
                tenant,
                iid,
            )
        action = "oidc_issuer.disabled" if disabling else "oidc_issuer.changed"
        changed = sorted(f for f in fields if f != "client_secret") + (
            ["client_secret"] if "client_secret" in fields else []
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                action,
                resource_type="oidc_issuer",
                resource_id=iid,
                detail={"issuer_url": current["issuer_url"], "fields_changed": changed},
                reason=reason,
            ),
        )
        return Outcome(200, issuer_view(updated), {"ETag": row_etag(updated)}, receipt)

    return await run_mutation(request, ctx, mutate, idempotent=False)


# ---- agent groups ------------------------------------------------------------------------------


class AgentGroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=SLUG)
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    parent_group_id: UUID | None = None
    owner_user_id: UUID | None = None
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


class AgentGroupPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    parent_group_id: UUID | None = None
    owner_user_id: UUID | None = None
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


async def _refs(conn: Any, tenant: UUID, parent: UUID | None, owner: UUID | None) -> None:
    if parent is not None and not await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM sibyl.agent_group WHERE tenant_id = $1 AND id = $2)",
        tenant,
        parent,
    ):
        raise ProblemError("reference_unknown", "parent_group_id is not a group of this tenant")
    if owner is not None and not await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2"
        " AND status <> 'deprovisioned')",
        tenant,
        owner,
    ):
        raise ProblemError("reference_unknown", "owner_user_id is not a user of this tenant")


async def _would_cycle(conn: Any, tenant: UUID, group: UUID, parent: UUID | None) -> bool:
    if parent is None:
        return False
    return bool(
        await conn.fetchval(
            "WITH RECURSIVE up(id, parent, depth) AS ("
            "  SELECT id, parent_group_id, 0 FROM sibyl.agent_group WHERE tenant_id = $1 AND id ="
            " $3"
            "  UNION ALL SELECT g.id, g.parent_group_id, up.depth + 1 FROM sibyl.agent_group g"
            "  JOIN up ON g.tenant_id = $1 AND g.id = up.parent WHERE up.depth < 64)"
            " SELECT EXISTS (SELECT 1 FROM up WHERE id = $2)",
            tenant,
            group,
            parent,
        )
    )


@router.get(API_PREFIX + "/agent-groups")
async def list_groups(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("listAgentGroups"))],
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    size, after = GROUPS_PAGING.params(limit, cursor, {})
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        rows = await conn.fetch(
            "SELECT * FROM sibyl.agent_group WHERE tenant_id = $1"
            " AND ($2::timestamptz IS NULL OR (created_at, id) > ($2, $3::uuid))"
            " ORDER BY created_at, id LIMIT $4",
            ctx.tenant_id,
            after[0] if after else None,
            after[1] if after else None,
            size + 1,
        )
    return page_response(
        request,
        GROUPS_PAGING,
        list(rows),
        size,
        lambda r: (r["created_at"], r["id"]),
        {},
        group_view,
    )


@router.get(API_PREFIX + "/agent-groups/{group_id}")
async def get_group(
    request: Request,
    group_id: str,
    ctx: Annotated[AuthContext, Depends(guard("getAgentGroup"))],
    if_none_match: Annotated[str | None, Header()] = None,
) -> Response:
    gid = parse_uuid(group_id)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.agent_group WHERE tenant_id = $1 AND id = $2", ctx.tenant_id, gid
        )
    if row is None:
        raise ProblemError("not_found")
    etag = row_etag(row)
    if if_none_match_hit(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    return json_response(group_view(row), headers={"ETag": etag})


@router.post(API_PREFIX + "/agent-groups")
async def create_group(
    request: Request,
    body: AgentGroupCreate,
    ctx: Annotated[AuthContext, Depends(guard("createAgentGroup"))],
) -> Response:
    reason = human_reason(request, body.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        tenant = ctx.tenant_id
        await _refs(conn, tenant, body.parent_group_id, body.owner_user_id)
        if await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.agent_group WHERE tenant_id = $1 AND slug = $2)",
            tenant,
            body.slug,
        ):
            raise ProblemError("slug_exists")
        row = await conn.fetchrow(
            "INSERT INTO sibyl.agent_group (tenant_id, slug, name, description, parent_group_id,"
            " owner_user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
            tenant,
            body.slug,
            body.name,
            body.description,
            body.parent_group_id,
            body.owner_user_id,
        )
        receipt = await services.audit.append(
            conn,
            tenant,
            actor_record(
                ctx,
                "config.changed",
                resource_type="agent_group",
                resource_id=row["id"],
                resource_ref=body.slug,
                detail={"field": "agent_group", "before": None, "after": body.slug},
                reason=reason,
            ),
        )
        return Outcome(201, group_view(row), {"ETag": row_etag(row)}, receipt)

    return await run_mutation(request, ctx, mutate, idempotent=True)


@router.patch(API_PREFIX + "/agent-groups/{group_id}")
async def update_group(
    request: Request,
    group_id: str,
    body: AgentGroupPatch,
    ctx: Annotated[AuthContext, Depends(guard("updateAgentGroup"))],
    if_match: Annotated[str | None, Header()] = None,
) -> Response:
    gid = parse_uuid(group_id)
    fields = set(body.model_fields_set) - {"reason"}
    if not fields:
        raise ProblemError("validation_failed", "send at least one field")
    if "name" in fields and body.name is None:
        raise ProblemError("validation_failed", "name cannot be null")
    reason = human_reason(request, body.reason, ctx.op.operation_id)

    async def mutate(conn: Any) -> Outcome:
        services = get_services(request)
        tenant = ctx.tenant_id
        # Serialise hierarchy edits per tenant so two concurrent re-parents cannot form a cycle.
        await conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended('agent_group:' || $1::uuid::text, 0))",
            tenant,
        )
        current = await conn.fetchrow(
            "SELECT * FROM sibyl.agent_group WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            tenant,
            gid,
        )
        if current is None:
            raise ProblemError("not_found")
        check_if_match(if_match, row_etag(current), current_body=group_view(current))
        await _refs(conn, tenant, body.parent_group_id, body.owner_user_id)
        if "parent_group_id" in fields and await _would_cycle(
            conn, tenant, gid, body.parent_group_id
        ):
            raise ProblemError("group_cycle")
        diff = {f: getattr(body, f) for f in fields if current[f] != getattr(body, f)}
        if not diff:
            return Outcome(200, group_view(current), {"ETag": row_etag(current)})
        assignments = ", ".join(f"{name} = ${i + 3}" for i, name in enumerate(diff))
        updated = await conn.fetchrow(
            f"UPDATE sibyl.agent_group SET {assignments} WHERE tenant_id = $1 AND id = $2"  # noqa: S608
            " RETURNING *",
            tenant,
            gid,
            *diff.values(),
        )
        receipt = None
        for name, after in diff.items():
            before = current[name]
            receipt = await services.audit.append(
                conn,
                tenant,
                actor_record(
                    ctx,
                    "config.changed",
                    resource_type="agent_group",
                    resource_id=gid,
                    resource_ref=current["slug"],
                    detail={
                        "field": f"agent_group.{name}",
                        "before": str(before) if isinstance(before, UUID) else before,
                        "after": str(after) if isinstance(after, UUID) else after,
                    },
                    reason=reason,
                ),
            )
        return Outcome(200, group_view(updated), {"ETag": row_etag(updated)}, receipt)

    return await run_mutation(request, ctx, mutate, idempotent=False)
