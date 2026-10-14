"""Agent versions and AI-BOM reads (API.md §5.4). Versions are immutable rows."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from ...core.authz import PrincipalKind
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ._kit import (
    Outcome,
    PageQuery,
    audit,
    jsonable,
    keyset_page,
    load_agent,
    policy_changed,
    run_read,
    run_write,
    user_id,
)
from .models import AgentVersionCreate
from .views import profile_hash, version_view

router = APIRouter()
VERSIONS = API_PREFIX + "/agents/{agent_id}/versions"
BOM = VERSIONS + "/{version_no}/bom"
MAX_CONFIG_BYTES = 4096
CYCLONEDX = "application/vnd.cyclonedx+json"


async def _missing(conn: Any, tenant_id: UUID, table: str, ids: list[UUID]) -> list[UUID]:
    if not ids:
        return []
    found = await conn.fetch(
        f"SELECT id FROM sibyl.{table} WHERE tenant_id = $1 AND id = ANY($2::uuid[])",  # noqa: S608
        tenant_id,
        ids,
    )
    have = {r["id"] for r in found}
    return [i for i in ids if i not in have]


def _prompt_digest(spec: AgentVersionCreate) -> bytes | None:
    """sha256 of the prompt. The prompt text itself is not stored here.

    CHANGE REQUEST (lane I): store ``prompt`` as a ``payload_refs`` object (kind=prompt) through
    the BlobStore and set ``prompt_ref_id``; until then only its digest is kept.
    """
    given = bytes.fromhex(spec.prompt_sha256) if spec.prompt_sha256 else None
    if spec.prompt is None:
        return given
    digest = hashlib.sha256(spec.prompt.encode()).digest()
    if given is not None and given != digest:
        raise ProblemError("validation_failed", "prompt_sha256 does not match prompt")
    return digest


async def insert_version(
    conn: Any, ctx: AuthContext, agent_id: UUID, spec: AgentVersionCreate
) -> dict[str, Any]:
    """Insert the next version and make it current (caller holds the agent row lock)."""
    tenant = ctx.tenant_id
    errors = []
    if not await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM sibyl.model WHERE tenant_id = $1 AND id = $2)",
        tenant,
        spec.primary_model_id,
    ):
        errors.append(
            {
                "pointer": "/primary_model_id",
                "code": "unknown_reference",
                "message": "no such model",
            }
        )
    for name, table, ids in (
        ("declared_tool_ids", "tool", spec.declared_tool_ids),
        ("declared_data_source_ids", "data_source", spec.declared_data_source_ids),
    ):
        if await _missing(conn, tenant, table, ids):
            errors.append(
                {"pointer": f"/{name}", "code": "unknown_reference", "message": f"no such {table}"}
            )
    config = spec.config or {}
    if len(json.dumps(config, separators=(",", ":")).encode()) > MAX_CONFIG_BYTES:
        errors.append({"pointer": "/config", "code": "too_large", "message": "config > 4 KB"})
    if errors:
        raise ProblemError("validation_failed", extensions={"errors": errors})
    principal = ctx.principal
    source = "sdk" if principal is not None and principal.kind is PrincipalKind.API_KEY else "api"
    row = await conn.fetchrow(
        "INSERT INTO sibyl.agent_version (tenant_id, agent_id, version_no, primary_model_id,"
        " prompt_sha256, config, declared_tool_ids, declared_data_source_ids, source,"
        " created_by_user_id) SELECT $1, $2, coalesce(max(version_no), 0) + 1, $3, $4, $5, $6,"
        " $7, $8, $9 FROM sibyl.agent_version WHERE tenant_id = $1 AND agent_id = $2"
        " RETURNING *",
        tenant,
        agent_id,
        spec.primary_model_id,
        _prompt_digest(spec),
        config,
        spec.declared_tool_ids,
        spec.declared_data_source_ids,
        source,
        user_id(ctx),
    )
    await conn.execute(
        "UPDATE sibyl.agent SET current_version_id = $3 WHERE tenant_id = $1 AND id = $2",
        tenant,
        agent_id,
        row["id"],
    )
    return dict(row)


@router.get(VERSIONS, operation_id="listAgentVersions")
async def list_versions(
    agent_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("listAgentVersions"))],
    limit: int | None = None,
    cursor: str | None = None,
) -> Response:
    page = PageQuery.of(limit, cursor)

    async def work(conn: Any) -> Outcome:
        await load_agent(conn, ctx, agent_id)
        return await keyset_page(
            conn,
            ctx,
            select="SELECT * FROM sibyl.agent_version WHERE tenant_id = $1 AND agent_id = $2",
            args=[ctx.tenant_id, agent_id],
            page=page,
            keys=("version_no",),
            key_types="i",
            descending=True,
            serialize=version_view,
        )

    return await run_read(ctx, work)


@router.post(VERSIONS, operation_id="createAgentVersion", status_code=201)
async def create_version(
    agent_id: UUID,
    body: AgentVersionCreate,
    ctx: Annotated[AuthContext, Depends(guard("createAgentVersion"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        agent = await load_agent(conn, ctx, agent_id, lock=True)
        version = await insert_version(conn, ctx, agent_id, body)
        receipt = await audit(
            conn,
            ctx,
            "asset.updated",
            resource_type="agent",
            resource_id=agent_id,
            resource_ref=agent["slug"],
            detail={
                "fields_changed": ["current_version"],
                "profile_hash": profile_hash({**agent, "current_version_id": version["id"]}),
                "version_no": version["version_no"],
            },
        )
        await policy_changed(
            conn, ctx, aggregate_kind="agent", aggregate_id=agent_id, agent_id=agent_id
        )
        return Outcome(version_view(version), status=201, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


@router.get(BOM, operation_id="getAgentBom")
async def get_bom(
    agent_id: UUID,
    version_no: int,
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("getAgentBom"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        await load_agent(conn, ctx, agent_id)
        version_id = await conn.fetchval(
            "SELECT id FROM sibyl.agent_version WHERE tenant_id = $1 AND agent_id = $2"
            " AND version_no = $3",
            ctx.tenant_id,
            agent_id,
            version_no,
        )
        if version_id is None:
            raise ProblemError("not_found")
        bom = await conn.fetchrow(
            "SELECT * FROM sibyl.ai_bom WHERE tenant_id = $1 AND agent_version_id = $2"
            " ORDER BY generated_at DESC LIMIT 1",
            ctx.tenant_id,
            version_id,
        )
        if bom is None:
            raise ProblemError("bom_not_generated")
        return Outcome(
            {
                "agent_id": str(agent_id),
                "version_no": version_no,
                "bom_sha256": bytes(bom["content_sha256"]).hex(),
                "spec_version": bom["format"].removeprefix("cyclonedx-"),
                "generated_at": jsonable(bom["generated_at"]),
                "document": jsonable(bom["content"]),
            }
        )

    response = await run_read(ctx, work)
    if CYCLONEDX in request.headers.get("accept", "") and response.status_code == 200:
        document = json.loads(bytes(response.body))["document"]
        return Response(json.dumps(document), media_type=CYCLONEDX)
    return response
