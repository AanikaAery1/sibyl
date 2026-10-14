"""Tenant catalogs: tools, data sources, business processes (API.md §5.4).

Tenant-wide roles only (no group rule). ``tool.is_approved`` set to true (on create or patch)
needs ``agents:approve`` (object rule ``approve_flag``). Writes audit ``config.changed`` with the
changed scalar fields; free-form JSON (``attrs``, ``permissions``) is referenced by digest only.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel

from ...core.etag import etag_for_row
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ._kit import (
    JSON,
    Outcome,
    PageQuery,
    config_changed,
    digest_ref,
    jsonable,
    keyset_page,
    require_if_match,
    require_scope,
    require_tenant_wide,
    run_read,
    run_write,
)
from .models import (
    BusinessProcessCreate,
    BusinessProcessPatch,
    DataSourceCreate,
    DataSourcePatch,
    ToolCreate,
    ToolPatch,
)

router = APIRouter()
JSON_FIELDS = frozenset({"attrs", "permissions"})


@dataclass(frozen=True)
class Catalog:
    table: str
    path: str
    id_param: str
    ops: tuple[str, str, str, str]  # list, create, get, update
    columns: tuple[str, ...]  # writable columns besides slug
    view: Callable[[dict[str, Any]], JSON]


def _tool(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "slug": row["slug"],
        "name": row["name"],
        "kind": row["kind"],
        "parent_tool_id": jsonable(row["parent_tool_id"]),
        "endpoint": row["endpoint"],
        "permissions": jsonable(row["permissions"]) if isinstance(row["permissions"], list) else [],
        "is_approved": row["is_approved"],
        "created_at": jsonable(row["created_at"]),
    }


def _data_source(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "slug": row["slug"],
        "name": row["name"],
        "kind": row["kind"],
        "classification": row["classification"],
        "residency_region": row["residency_region"],
        "attrs": jsonable(row["attrs"]),
        "created_at": jsonable(row["created_at"]),
    }


def _process(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "slug": row["slug"],
        "name": row["name"],
        "owner_user_id": jsonable(row["owner_user_id"]),
        "criticality": row["criticality"],
        "created_at": jsonable(row["created_at"]),
    }


TOOLS = Catalog(
    "tool",
    "/tools",
    "tool_id",
    ("listTools", "createTool", "getTool", "updateTool"),
    ("name", "kind", "parent_tool_id", "endpoint", "permissions", "is_approved"),
    _tool,
)
DATA_SOURCES = Catalog(
    "data_source",
    "/data-sources",
    "data_source_id",
    ("listDataSources", "createDataSource", "getDataSource", "updateDataSource"),
    ("name", "kind", "classification", "residency_region", "attrs"),
    _data_source,
)
PROCESSES = Catalog(
    "business_process",
    "/business-processes",
    "business_process_id",
    (
        "listBusinessProcesses",
        "createBusinessProcess",
        "getBusinessProcess",
        "updateBusinessProcess",
    ),
    ("name", "owner_user_id", "criticality"),
    _process,
)


def _audit_value(column: str, value: Any) -> Any:
    return digest_ref(value) if column in JSON_FIELDS else jsonable(value)


async def _approve_flag(ctx: AuthContext, approving: bool) -> None:
    if "approve_flag" not in ctx.op.object_rules:
        return
    ctx.object_rule_checked("approve_flag")
    if approving:
        await require_scope(ctx, "agents:approve")


async def _load(
    conn: Any, ctx: AuthContext, cat: Catalog, row_id: UUID, *, lock: bool
) -> dict[str, Any]:
    row = await conn.fetchrow(
        f"SELECT * FROM sibyl.{cat.table} WHERE tenant_id = $1 AND id = $2"  # noqa: S608
        + (" FOR UPDATE" if lock else ""),
        ctx.tenant_id,
        row_id,
    )
    if row is None:
        raise ProblemError("not_found")
    return dict(row)


def _register(cat: Catalog, create_model: type[BaseModel], patch_model: type[BaseModel]) -> None:
    base = API_PREFIX + cat.path
    item = base + "/{" + cat.id_param + "}"
    list_op, create_op, get_op, update_op = cat.ops

    async def list_items(
        ctx: Annotated[AuthContext, Depends(guard(list_op))],
        limit: int | None = None,
        cursor: str | None = None,
        q: Annotated[str | None, Query(max_length=120)] = None,
    ) -> Response:
        page = PageQuery.of(limit, cursor, q=q)

        async def work(conn: Any) -> Outcome:
            args: list[Any] = [ctx.tenant_id]
            sql = f"SELECT * FROM sibyl.{cat.table} WHERE tenant_id = $1"  # noqa: S608
            if q:
                args.append(f"%{q}%")
                sql += f" AND (slug ILIKE ${len(args)} OR name ILIKE ${len(args)})"
            return await keyset_page(
                conn, ctx, select=sql, args=args, page=page, serialize=cat.view
            )

        return await run_read(ctx, work)

    async def create_item(
        body: create_model,  # type: ignore[valid-type]
        ctx: Annotated[AuthContext, Depends(guard(create_op))],
    ) -> Response:
        values = body.model_dump()  # type: ignore[attr-defined]
        reason: str | None = values.pop("reason", None)

        async def work(conn: Any) -> Outcome:
            await require_tenant_wide(ctx)
            await _approve_flag(ctx, bool(values.get("is_approved")))
            columns = ("slug", *cat.columns)
            placeholders = ", ".join(f"${i}" for i in range(2, len(columns) + 2))
            row = dict(
                await conn.fetchrow(
                    f"INSERT INTO sibyl.{cat.table} (tenant_id, {', '.join(columns)})"  # noqa: S608
                    f" VALUES ($1, {placeholders}) RETURNING *",
                    ctx.tenant_id,
                    *(values[c] for c in columns),
                )
            )
            receipt = await config_changed(
                conn,
                ctx,
                resource_type=cat.table,
                resource_id=row["id"],
                field_name=cat.table,
                before=None,
                after={c: _audit_value(c, values[c]) for c in columns},
                reason=reason,
            )
            return Outcome(
                cat.view(row),
                status=201,
                receipt=receipt,
                etag=etag_for_row(row["updated_at"], row["id"]),
            )

        return await run_write(ctx, work, idempotent=True)

    async def get_item(
        row_id: Annotated[UUID, Depends(_path_uuid(cat.id_param))],
        ctx: Annotated[AuthContext, Depends(guard(get_op))],
    ) -> Response:
        async def work(conn: Any) -> Outcome:
            row = await _load(conn, ctx, cat, row_id, lock=False)
            return Outcome(cat.view(row), etag=etag_for_row(row["updated_at"], row["id"]))

        return await run_read(ctx, work)

    async def update_item(
        row_id: Annotated[UUID, Depends(_path_uuid(cat.id_param))],
        body: patch_model,  # type: ignore[valid-type]
        ctx: Annotated[AuthContext, Depends(guard(update_op))],
    ) -> Response:
        sent = body.changes()  # type: ignore[attr-defined]
        reason: str | None = body.reason  # type: ignore[attr-defined]

        async def work(conn: Any) -> Outcome:
            await require_tenant_wide(ctx)
            row = await _load(conn, ctx, cat, row_id, lock=True)
            require_if_match(ctx, etag_for_row(row["updated_at"], row["id"]), body=cat.view(row))
            changes = {c: v for c, v in sent.items() if v != row[c]}
            await _approve_flag(ctx, "is_approved" in changes)
            if not changes:
                return Outcome(cat.view(row), etag=etag_for_row(row["updated_at"], row["id"]))
            sets = ", ".join(f"{c} = ${i}" for i, c in enumerate(changes, start=3))
            updated = dict(
                await conn.fetchrow(
                    f"UPDATE sibyl.{cat.table} SET {sets} WHERE tenant_id = $1 AND id = $2"  # noqa: S608
                    " RETURNING *",
                    ctx.tenant_id,
                    row_id,
                    *changes.values(),
                )
            )
            receipt = await config_changed(
                conn,
                ctx,
                resource_type=cat.table,
                resource_id=row_id,
                field_name=",".join(f"{cat.table}.{c}" for c in sorted(changes)),
                before={c: _audit_value(c, row[c]) for c in changes},
                after={c: _audit_value(c, v) for c, v in changes.items()},
                reason=reason,
            )
            return Outcome(
                cat.view(updated),
                receipt=receipt,
                etag=etag_for_row(updated["updated_at"], updated["id"]),
            )

        return await run_write(ctx, work, idempotent=False)

    router.add_api_route(base, list_items, methods=["GET"], operation_id=list_op)
    router.add_api_route(
        base, create_item, methods=["POST"], operation_id=create_op, status_code=201
    )
    router.add_api_route(item, get_item, methods=["GET"], operation_id=get_op)
    router.add_api_route(item, update_item, methods=["PATCH"], operation_id=update_op)


def _path_uuid(name: str) -> Callable[..., Any]:
    """A dependency reading the catalog's own path parameter (``tool_id`` ...) as a UUID."""

    async def dependency(request: Request) -> UUID:
        try:
            return UUID(str(request.path_params[name]))
        except (KeyError, ValueError):
            raise ProblemError(
                "validation_failed",
                extensions={
                    "errors": [{"pointer": f"path:{name}", "code": "uuid", "message": "not a UUID"}]
                },
            ) from None

    dependency.__name__ = f"path_{name}"
    return dependency


_register(TOOLS, ToolCreate, ToolPatch)
_register(DATA_SOURCES, DataSourceCreate, DataSourcePatch)
_register(PROCESSES, BusinessProcessCreate, BusinessProcessPatch)
