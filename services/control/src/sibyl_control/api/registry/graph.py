"""Dependency graph: temporal edges and blast radius (API.md §5.4, DATAMODEL §4.2).

Edges close, never delete. Group rule for edge writes: an end that is an agent must be inside
the caller's groups; an edge with no agent end is not in any group, so only tenant-wide grants
write it. Blast radius is a cache (``sibyl.blast_radius``) refreshed when ``graph_version``
moved on since it was computed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from ...core.authz import NOT_APPLICABLE
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ._kit import (
    JSON,
    Outcome,
    PageQuery,
    audit,
    check_object,
    jsonable,
    keyset_page,
    load_agent,
    run_read,
    run_write,
    sha256_hex,
    user_id,
)
from .models import DependencyEdgeCreate

router = APIRouter()
EDGES = API_PREFIX + "/dependency-edges"
GRAPH_KINDS = frozenset({"agent", "model", "tool", "data_source", "provider"})
EDGE_TYPES = frozenset(
    {
        "uses_model",
        "calls_tool",
        "reads_data",
        "writes_data",
        "delegates_to",
        "fallback_to",
        "served_by",
        "exposes",
    }
)


def edge_view(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "src_kind": row["src_kind"],
        "src_id": str(row["src_id"]),
        "dst_kind": row["dst_kind"],
        "dst_id": str(row["dst_id"]),
        "edge_type": row["edge_type"],
        "origin": row["origin"],
        "attrs": jsonable(row["attrs"]),
        "valid_from": jsonable(row["valid_from"]),
        "valid_to": jsonable(row["valid_to"]),
    }


@router.get(API_PREFIX + "/agents/{agent_id}/dependencies", operation_id="listAgentDependencies")
async def list_dependencies(
    agent_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("listAgentDependencies"))],
    limit: int | None = None,
    cursor: str | None = None,
    direction: Literal["in", "out", "both"] = "both",
    as_of: datetime | None = None,
) -> Response:
    page = PageQuery.of(limit, cursor, direction=direction, as_of=as_of)

    async def work(conn: Any) -> Outcome:
        await load_agent(conn, ctx, agent_id)
        args: list[Any] = [ctx.tenant_id, agent_id]
        ends = {
            "out": "(src_kind = 'agent' AND src_id = $2)",
            "in": "(dst_kind = 'agent' AND dst_id = $2)",
        }
        where = ends[direction] if direction != "both" else f"({ends['out']} OR {ends['in']})"
        if as_of is None:
            temporal = "valid_to IS NULL"
        else:
            args.append(as_of)
            n = len(args)
            temporal = f"valid_from <= ${n} AND (valid_to IS NULL OR valid_to > ${n})"
        return await keyset_page(
            conn,
            ctx,
            select=f"SELECT * FROM sibyl.dependency_edge WHERE tenant_id = $1 AND {where}"  # noqa: S608
            f" AND {temporal}",
            args=args,
            page=page,
            serialize=edge_view,
        )

    return await run_read(ctx, work)


async def _blast(conn: Any, tenant_id: UUID, kind: str, node_id: UUID) -> Outcome:
    version = await conn.fetchval("SELECT graph_version FROM sibyl.tenant WHERE id = $1", tenant_id)
    row = await conn.fetchrow(
        "SELECT * FROM sibyl.blast_radius WHERE tenant_id = $1 AND node_kind = $2 AND node_id = $3",
        tenant_id,
        kind,
        node_id,
    )
    if row is None or row["graph_version"] != version:
        await conn.execute(
            "SELECT sibyl.blast_radius_refresh($1, $2, $3)", tenant_id, kind, node_id
        )
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.blast_radius WHERE tenant_id = $1 AND node_kind = $2"
            " AND node_id = $3",
            tenant_id,
            kind,
            node_id,
        )
    return Outcome(
        {
            "node_kind": kind,
            "node_id": str(node_id),
            "graph_version": row["graph_version"],
            "affected_agent_ids": [str(a) for a in row["affected_agent_ids"]],
            "affected_process_ids": [str(p) for p in row["affected_process_ids"]],
            "by_depth": jsonable(row["by_depth"]),
            "computed_at": jsonable(row["computed_at"]),
        }
    )


async def _cache_write(ctx: AuthContext, work: Any) -> Response:
    """A GET that may refresh the blast-radius cache: a write transaction, never audited."""
    return await run_write(ctx, work, idempotent=False)


@router.get(API_PREFIX + "/agents/{agent_id}/blast-radius", operation_id="getAgentBlastRadius")
async def get_agent_blast_radius(
    agent_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getAgentBlastRadius"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        await load_agent(conn, ctx, agent_id)
        return await _blast(conn, ctx.tenant_id, "agent", agent_id)

    return await _cache_write(ctx, work)


@router.get(API_PREFIX + "/blast-radius/{node_kind}/{node_id}", operation_id="getBlastRadius")
async def get_blast_radius(
    node_kind: Literal["agent", "tool", "data_source", "model", "provider", "business_process"],
    node_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getBlastRadius"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        if node_kind not in GRAPH_KINDS or not await conn.fetchval(
            "SELECT sibyl.graph_node_exists($1, $2, $3)", ctx.tenant_id, node_kind, node_id
        ):
            raise ProblemError("not_found")
        return await _blast(conn, ctx.tenant_id, node_kind, node_id)

    return await _cache_write(ctx, work)


async def _edge_scope(conn: Any, ctx: AuthContext, ends: list[tuple[str, UUID]]) -> UUID | None:
    """Group rule over the agent ends of an edge; returns the first agent end (audit subject)."""
    agents = [node for kind, node in ends if kind == "agent"]
    for agent_id in agents:
        row = await conn.fetchrow(
            "SELECT agent_group_id FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            agent_id,
        )
        if row is None:
            raise ProblemError("node_unknown")
        await check_object(ctx, group_id=row["agent_group_id"])
    if not agents:
        await check_object(ctx, group_id=None)  # ungrouped: tenant-wide grants only
    return agents[0] if agents else None


@router.post(EDGES, operation_id="createDependencyEdge", status_code=201)
async def create_edge(
    body: DependencyEdgeCreate,
    ctx: Annotated[AuthContext, Depends(guard("createDependencyEdge"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        for kind in (body.src_kind, body.dst_kind):
            if kind not in GRAPH_KINDS:
                raise ProblemError("node_unknown", f"{kind} is not a graph node kind")
        if body.edge_type not in EDGE_TYPES:
            raise ProblemError(
                "validation_failed",
                extensions={
                    "errors": [
                        {"pointer": "/edge_type", "code": "enum", "message": "unknown edge type"}
                    ]
                },
            )
        subject = await _edge_scope(
            conn, ctx, [(body.src_kind, body.src_id), (body.dst_kind, body.dst_id)]
        )
        for kind, node in ((body.src_kind, body.src_id), (body.dst_kind, body.dst_id)):
            if not await conn.fetchval(
                "SELECT sibyl.graph_node_exists($1, $2, $3)", ctx.tenant_id, kind, node
            ):
                raise ProblemError("node_unknown")
        row = dict(
            await conn.fetchrow(
                "INSERT INTO sibyl.dependency_edge (tenant_id, src_kind, src_id, dst_kind, dst_id,"
                " edge_type, origin, attrs, created_by_user_id) VALUES ($1, $2, $3, $4, $5, $6,"
                " 'declared', $7, $8) RETURNING *",
                ctx.tenant_id,
                body.src_kind,
                body.src_id,
                body.dst_kind,
                body.dst_id,
                body.edge_type,
                body.attrs,
                user_id(ctx),
            )
        )
        receipt = await audit(
            conn,
            ctx,
            "asset.updated",
            resource_type="agent" if subject else "dependency_edge",
            resource_id=subject or row["id"],
            detail={
                "fields_changed": ["dependency_edge"],
                "profile_hash": sha256_hex(edge_view(row) | {"valid_from": None}),
                "edge_id": str(row["id"]),
                "edge_type": body.edge_type,
            },
        )
        return Outcome(edge_view(row), status=201, receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


@router.delete(EDGES + "/{edge_id}", operation_id="closeDependencyEdge")
async def close_edge(
    edge_id: UUID,
    reason: Annotated[str, Query(min_length=10, max_length=2000)],
    ctx: Annotated[AuthContext, Depends(guard("closeDependencyEdge"))],
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.dependency_edge WHERE tenant_id = $1 AND id = $2"
            " AND valid_to IS NULL FOR UPDATE",
            ctx.tenant_id,
            edge_id,
        )
        if row is None:
            raise ProblemError("not_found")
        subject = await _edge_scope(
            conn, ctx, [(row["src_kind"], row["src_id"]), (row["dst_kind"], row["dst_id"])]
        )
        closed = dict(
            await conn.fetchrow(
                "UPDATE sibyl.dependency_edge SET valid_to = greatest(now(), valid_from)"
                " WHERE tenant_id = $1 AND id = $2 RETURNING *",
                ctx.tenant_id,
                edge_id,
            )
        )
        receipt = await audit(
            conn,
            ctx,
            "asset.updated",
            resource_type="agent" if subject else "dependency_edge",
            resource_id=subject or edge_id,
            reason=reason,
            detail={
                "fields_changed": ["dependency_edge"],
                "profile_hash": sha256_hex({"edge_id": str(edge_id), "closed": True}),
                "edge_id": str(edge_id),
            },
        )
        return Outcome(edge_view(closed), receipt=receipt)

    return await run_write(ctx, work, idempotent=False)


__all__ = ["NOT_APPLICABLE", "edge_view", "router"]
