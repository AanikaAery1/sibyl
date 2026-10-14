"""Capture policies and redaction profiles (API.md §5.6, D12, D28, R15).

A capture policy is never edited: ``POST /capture-policies`` supersedes the active row of its
scope (``If-Match`` = ETag ``"<version_no>"`` of that row, ``*`` for the first one). Redaction
profiles are immutable and content-addressed; every profile covers the ``secrets_only``
baseline (the database CHECK is the backstop, the handler answers 422 first).
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.canonical import canonicalize
from ...core.etag import etag_for_version
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    JSON,
    Outcome,
    PageQuery,
    audit,
    jsonable,
    keyset_page,
    op_reason,
    policy_changed,
    require_if_match,
    run_read,
    run_write,
    user_id,
)
from .models import CapturePolicyCreate, RedactionProfileCreate

DEFAULT_REPLACEMENT = "[{kind}:{hash8}]"
DEFAULT_MAX_PAYLOAD_BYTES = 262_144
# Same list as ck_capture_policy_headers (0005): credentials never become capturable headers.
FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "x-api-key",
        "api-key",
        "proxy-authorization",
        "set-cookie",
        "x-sibyl-key",
    }
)

router = APIRouter()


# --- serializers ----------------------------------------------------------------------------


def capture_view(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "scope_kind": row["scope_kind"],
        "agent_id": jsonable(row["agent_id"]),
        "capture_mode": row["capture_mode"],
        "redaction_profile_id": str(row["redaction_profile_id"]),
        "payload_retention_days": row["payload_retention_days"],
        "max_payload_bytes": row["max_payload_bytes"],
        "header_allowlist": list(row["header_allowlist"]),
        "consequences_version": row["consequences_version"],
        "version_no": row["version_no"],
        "superseded_by": jsonable(row["superseded_by"]),
        "chosen_by": jsonable(row["chosen_by"]),
        "created_at": jsonable(row["created_at"]),
    }


def profile_view(row: dict[str, Any]) -> JSON:
    detectors = row["detectors"] or []
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "version_no": row["version_no"],
        "detectors": [d["id"] if isinstance(d, dict) else d for d in detectors],
        "replacement_format": row["replacement_format"],
        "content_hash": bytes(row["content_hash"]).hex(),
        "is_system": row["origin"] == "system",
        "created_at": jsonable(row["created_at"]),
    }


# --- capture policies -----------------------------------------------------------------------


@router.get(API_PREFIX + "/capture-policies")
async def list_capture_policies(
    ctx: Annotated[AuthContext, Depends(guard("listCapturePolicies"))],
    scope_kind: Annotated[str | None, Query(pattern="^(tenant|agent)$")] = None,
    agent_id: UUID | None = None,
    include_superseded: bool = False,
    limit: int | None = None,
    cursor: str | None = None,
) -> Response:
    page = PageQuery.of(
        limit,
        cursor,
        scope_kind=scope_kind,
        agent_id=agent_id,
        include_superseded=include_superseded,
    )

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM sibyl.capture_policy WHERE tenant_id = $1"
        if not include_superseded:
            sql += " AND superseded_by IS NULL"
        if scope_kind is not None:
            args.append(scope_kind)
            sql += f" AND scope_kind = ${len(args)}"
        if agent_id is not None:
            args.append(agent_id)
            sql += f" AND agent_id = ${len(args)}"
        return await keyset_page(
            conn, ctx, select=sql, args=args, page=page, serialize=capture_view
        )

    return await run_read(ctx, work)


async def _active_policy(conn: Any, tenant: UUID, scope_kind: str, agent: UUID | None) -> Any:
    return await conn.fetchrow(
        "SELECT * FROM sibyl.capture_policy WHERE tenant_id = $1 AND scope_kind = $2"
        " AND agent_id IS NOT DISTINCT FROM $3 AND superseded_by IS NULL FOR UPDATE",
        tenant,
        scope_kind,
        agent,
    )


def _validate_capture(body: CapturePolicyCreate) -> None:
    if body.capture_mode is None:
        raise ProblemError("capture_mode_required", "capture_mode has no default (D12)")
    if (body.scope_kind == "agent") != (body.agent_id is not None):
        raise ProblemError(
            "validation_failed", "agent_id is required for scope agent and refused for tenant"
        )
    bad = sorted({h.lower() for h in body.header_allowlist} & FORBIDDEN_HEADERS)
    if bad:
        raise ProblemError("header_forbidden", f"headers never capturable: {', '.join(bad)}")


@router.post(API_PREFIX + "/capture-policies", status_code=201)
async def set_capture_policy(
    body: CapturePolicyCreate, ctx: Annotated[AuthContext, Depends(guard("setCapturePolicy"))]
) -> Response:
    _validate_capture(body)

    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        if body.agent_id is not None and not await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.agent WHERE tenant_id = $1 AND id = $2)",
            tenant,
            body.agent_id,
        ):
            raise ProblemError("validation_failed", "agent_id names no agent of this tenant")
        profile = await conn.fetchrow(
            "SELECT content_hash FROM sibyl.redaction_profile WHERE tenant_id = $1 AND id = $2",
            tenant,
            body.redaction_profile_id,
        )
        if profile is None:
            raise ProblemError("validation_failed", "redaction_profile_id names no profile")
        current = await _active_policy(conn, tenant, body.scope_kind, body.agent_id)
        current_etag = etag_for_version(current["version_no"]) if current is not None else None
        require_if_match(
            ctx,
            current_etag,
            allow_star_create=True,
            body=capture_view(dict(current)) if current is not None else None,
        )
        new_id = await conn.fetchval("SELECT sibyl.uuidv7()")
        previous = current["version_no"] if current is not None else None
        if current is not None:
            await conn.execute("SET CONSTRAINTS sibyl.fk_capture_policy_superseded_by DEFERRED")
            await conn.execute(
                "UPDATE sibyl.capture_policy SET superseded_by = $3"
                " WHERE tenant_id = $1 AND id = $2",
                tenant,
                current["id"],
                new_id,
            )
        row = await conn.fetchrow(
            "INSERT INTO sibyl.capture_policy (tenant_id, id, scope_kind, agent_id, capture_mode,"
            " redaction_profile_id, payload_retention_days, max_payload_bytes, header_allowlist,"
            " consequences_version, chosen_by, version_no)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *",
            tenant,
            new_id,
            body.scope_kind,
            body.agent_id,
            body.capture_mode,
            body.redaction_profile_id,
            body.payload_retention_days,
            body.max_payload_bytes or DEFAULT_MAX_PAYLOAD_BYTES,
            [h.lower() for h in body.header_allowlist],
            body.consequences_version,
            user_id(ctx),
            (previous or 0) + 1,
        )
        scope = "tenant" if body.agent_id is None else f"agent:{body.agent_id}"
        receipt = await audit(
            conn,
            ctx,
            "capture.policy_set",
            resource_type="capture_policy",
            resource_id=row["id"],
            reason=op_reason(
                ctx,
                body.reason,
                label=f"capture policy set, consequences {body.consequences_version}",
            ),
            detail={
                "capture_mode": body.capture_mode,
                "retention_days": body.payload_retention_days,
                "redaction_profile_hash": bytes(profile["content_hash"]).hex(),
                "previous_version": previous,
                "scope": scope,
            },
        )
        await policy_changed(
            conn,
            ctx,
            aggregate_kind="capture_policy",
            aggregate_id=row["id"],
            agent_id=body.agent_id,
        )
        return Outcome(
            capture_view(dict(row)),
            status=201,
            etag=etag_for_version(row["version_no"]),
            receipt=receipt,
        )

    return await run_write(ctx, work, idempotent=True)


@router.get(API_PREFIX + "/capture-policies/effective")
async def get_effective_capture_policy(
    ctx: Annotated[AuthContext, Depends(guard("getEffectiveCapturePolicy"))],
    agent_id: UUID | None = None,
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        if agent_id is not None and not await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.agent WHERE tenant_id = $1 AND id = $2)",
            tenant,
            agent_id,
        ):
            raise ProblemError("not_found")
        row, source = None, "tenant"
        if agent_id is not None:
            row = await conn.fetchrow(
                "SELECT * FROM sibyl.capture_policy WHERE tenant_id = $1 AND scope_kind = 'agent'"
                " AND agent_id = $2 AND superseded_by IS NULL",
                tenant,
                agent_id,
            )
            source = "agent"
        if row is None:
            row = await conn.fetchrow(
                "SELECT * FROM sibyl.capture_policy WHERE tenant_id = $1"
                " AND scope_kind = 'tenant' AND superseded_by IS NULL",
                tenant,
            )
            source = "tenant"
        if row is None:
            raise ProblemError(
                "capture_policy_missing", "no capture policy has been chosen yet", status=404
            )
        profile = await conn.fetchrow(
            "SELECT * FROM sibyl.redaction_profile WHERE tenant_id = $1 AND id = $2",
            tenant,
            row["redaction_profile_id"],
        )
        body = {
            "agent_id": jsonable(agent_id),
            "policy": capture_view(dict(row)),
            "redaction_profile": profile_view(dict(profile)),
            "source": source,
        }
        return Outcome(body, etag=etag_for_version(row["version_no"]))

    return await run_read(ctx, work)


# --- redaction profiles ---------------------------------------------------------------------


@router.get(API_PREFIX + "/redaction-profiles")
async def list_redaction_profiles(
    ctx: Annotated[AuthContext, Depends(guard("listRedactionProfiles"))],
    limit: int | None = None,
    cursor: str | None = None,
) -> Response:
    page = PageQuery.of(limit, cursor)

    async def work(conn: Any) -> Outcome:
        return await keyset_page(
            conn,
            ctx,
            select="SELECT * FROM sibyl.redaction_profile WHERE tenant_id = $1",
            args=[ctx.tenant_id],
            page=page,
            serialize=profile_view,
        )

    return await run_read(ctx, work)


def profile_document(detector_ids: list[str], replacement_format: str) -> tuple[list[JSON], str]:
    """The stored ``detectors`` and the JCS text the content hash is taken over (R15)."""
    detectors: list[JSON] = [{"id": d, "params": {}} for d in detector_ids]
    canonical = canonicalize({"detectors": detectors, "replacement_format": replacement_format})
    return detectors, canonical.decode("utf-8")


@router.post(API_PREFIX + "/redaction-profiles", status_code=201)
async def create_redaction_profile(
    body: RedactionProfileCreate,
    ctx: Annotated[AuthContext, Depends(guard("createRedactionProfile"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        tenant = ctx.tenant_id
        baseline = await conn.fetchval("SELECT sibyl.secrets_baseline_detector_ids()")
        missing = sorted(set(baseline) - set(body.detectors))
        if missing:
            raise ProblemError(
                "below_secrets_baseline",
                "a profile must keep every secrets_only detector",
                extensions={"missing": missing},
            )
        fmt = body.replacement_format or DEFAULT_REPLACEMENT
        detectors, canonical = profile_document(body.detectors, fmt)
        content_hash = hashlib.sha256(canonical.encode("utf-8")).digest()
        await conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            f"redaction_profile:{tenant}:{body.name}",
        )
        version = await conn.fetchval(
            "SELECT coalesce(max(version_no), 0) + 1 FROM sibyl.redaction_profile"
            " WHERE tenant_id = $1 AND name = $2",
            tenant,
            body.name,
        )
        row = await conn.fetchrow(
            "INSERT INTO sibyl.redaction_profile (tenant_id, name, version_no, origin, detectors,"
            " replacement_format, content_canonical, content_hash, created_by)"
            " VALUES ($1, $2, $3, 'custom', $4::jsonb, $5, $6, $7, $8) RETURNING *",
            tenant,
            body.name,
            version,
            detectors,
            fmt,
            canonical,
            content_hash,
            user_id(ctx),
        )
        receipt = await audit(
            conn,
            ctx,
            "redaction.profile_created",
            resource_type="redaction_profile",
            resource_id=row["id"],
            resource_ref=f"{body.name}:v{version}",
            detail={
                "profile_id": row["id"],
                "version": version,
                "content_hash": content_hash.hex(),
            },
        )
        return Outcome(profile_view(dict(row)), status=201, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)
