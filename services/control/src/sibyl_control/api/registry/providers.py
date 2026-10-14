"""Providers, models, model catalog and provider status (API.md §5.5).

``base_url`` / ``status_feed_url`` pass ``ssrf.check_base_url`` at every write (allowlist plus
resolver check, basis recorded as ``is_known_provider``). Disabling a provider still used by an
approved fallback step or by a live agent's current model is 409 ``provider_in_use``. Provider
and model changes feed the snapshot, so they emit ``policy_changed``.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from ...core.etag import etag_for_row
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ._kit import (
    JSON,
    Outcome,
    PageQuery,
    config_changed,
    jsonable,
    keyset_page,
    money,
    parse_money,
    policy_changed,
    require_if_match,
    require_tenant_wide,
    run_read,
    run_write,
)
from .models import ModelCreate, ModelPatch, ProviderCreate, ProviderPatch
from .ssrf import check_base_url

router = APIRouter()
PROVIDERS = API_PREFIX + "/providers"
PROVIDER = PROVIDERS + "/{provider_id}"
MODELS = API_PREFIX + "/models"

PROVIDER_SELECT = """
SELECT p.*, s.status AS s_status, s.observed_at AS s_observed_at, s.source AS s_source
  FROM sibyl.provider p
  LEFT JOIN LATERAL (
        SELECT st.status, st.observed_at, st.source FROM sibyl.provider_status st
         WHERE st.tenant_id = p.tenant_id AND st.provider_id = p.id
         ORDER BY st.observed_at DESC LIMIT 1) s ON true
 WHERE p.tenant_id = $1"""


def provider_view(row: dict[str, Any]) -> JSON:
    latest = None
    if row.get("s_status") is not None:
        latest = {
            "provider_id": str(row["id"]),
            "status": row["s_status"],
            "observed_at": jsonable(row["s_observed_at"]),
            "source": row["s_source"],
        }
    return {
        "id": str(row["id"]),
        "slug": row["slug"],
        "name": row["name"],
        "provider_kind": row["provider_kind"],
        "dialect": row["dialect"],
        "base_url": row["base_url"],
        "status_feed_url": row["status_feed_url"],
        "allowlist_basis": "known_provider" if row["is_known_provider"] else "resolver_checked",
        "is_enabled": row["is_enabled"],
        "latest_status": latest,
    }


async def _provider(
    conn: Any, tenant_id: UUID, provider_id: UUID, *, lock: bool = False
) -> dict[str, Any]:
    if lock:
        await conn.execute(
            "SELECT 1 FROM sibyl.provider WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            tenant_id,
            provider_id,
        )
    row = await conn.fetchrow(PROVIDER_SELECT + " AND p.id = $2", tenant_id, provider_id)
    if row is None:
        raise ProblemError("not_found")
    return dict(row)


def _audit_provider(row: dict[str, Any]) -> JSON:
    return {
        k: row[k]
        for k in (
            "slug",
            "name",
            "provider_kind",
            "dialect",
            "base_url",
            "status_feed_url",
            "is_enabled",
        )
    }


@router.get(PROVIDERS, operation_id="listProviders")
async def list_providers(
    ctx: Annotated[AuthContext, Depends(guard("listProviders"))],
    limit: int | None = None,
    cursor: str | None = None,
) -> Response:
    page = PageQuery.of(limit, cursor)

    async def work(conn: Any) -> Outcome:
        return await keyset_page(
            conn,
            ctx,
            select="SELECT * FROM (" + PROVIDER_SELECT + ") v WHERE true",  # noqa: S608
            args=[ctx.tenant_id],
            page=page,
            serialize=provider_view,
        )

    return await run_read(ctx, work)


@router.get(PROVIDER, operation_id="getProvider")
async def get_provider(
    provider_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getProvider"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await _provider(conn, ctx.tenant_id, provider_id)
        return Outcome(provider_view(row), etag=etag_for_row(row["updated_at"], row["id"]))

    return await run_read(ctx, work)


@router.post(PROVIDERS, operation_id="createProvider", status_code=201)
async def create_provider(
    body: ProviderCreate, ctx: Annotated[AuthContext, Depends(guard("createProvider"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        await require_tenant_wide(ctx)
        base = await check_base_url(conn, body.base_url)
        if body.status_feed_url is not None:
            await check_base_url(conn, body.status_feed_url)
        pid = await conn.fetchval(
            "INSERT INTO sibyl.provider (tenant_id, slug, name, provider_kind, dialect, base_url,"
            " is_known_provider, status_feed_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
            " RETURNING id",
            ctx.tenant_id,
            body.slug,
            body.name,
            body.provider_kind,
            body.dialect,
            body.base_url,
            base.basis == "known_provider",
            body.status_feed_url,
        )
        row = await _provider(conn, ctx.tenant_id, pid)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="provider",
            resource_id=pid,
            field_name="provider",
            before=None,
            after={**_audit_provider(row), "allowlist_basis": base.basis},
            reason=body.reason,
        )
        await policy_changed(conn, ctx, aggregate_kind="provider", aggregate_id=pid, agent_id=None)
        return Outcome(
            provider_view(row),
            status=201,
            receipt=receipt,
            etag=etag_for_row(row["updated_at"], row["id"]),
        )

    return await run_write(ctx, work, idempotent=True)


async def _provider_in_use(conn: Any, tenant_id: UUID, provider_id: UUID) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.fallback_step s JOIN sibyl.fallback_chain c"
            "   ON c.tenant_id = s.tenant_id AND c.id = s.chain_id"
            "  WHERE s.tenant_id = $1 AND c.status = 'approved' AND (s.provider_id = $2"
            "     OR s.model_id IN (SELECT id FROM sibyl.model WHERE tenant_id = $1"
            "                        AND provider_id = $2)))"
            " OR EXISTS (SELECT 1 FROM sibyl.agent a JOIN sibyl.agent_version v"
            "   ON v.tenant_id = a.tenant_id AND v.id = a.current_version_id"
            "   JOIN sibyl.model m ON m.tenant_id = v.tenant_id AND m.id = v.primary_model_id"
            "  WHERE a.tenant_id = $1 AND m.provider_id = $2"
            "    AND a.lifecycle IN ('approved', 'deployed', 'monitored'))",
            tenant_id,
            provider_id,
        )
    )


@router.patch(PROVIDER, operation_id="updateProvider")
async def update_provider(
    provider_id: UUID,
    body: ProviderPatch,
    ctx: Annotated[AuthContext, Depends(guard("updateProvider"))],
) -> Response:
    sent = body.changes()

    async def work(conn: Any) -> Outcome:
        await require_tenant_wide(ctx)
        row = await _provider(conn, ctx.tenant_id, provider_id, lock=True)
        require_if_match(ctx, etag_for_row(row["updated_at"], row["id"]), body=provider_view(row))
        changes = {c: v for c, v in sent.items() if v != row[c]}
        extra: dict[str, Any] = {}
        if "base_url" in changes:
            checked = await check_base_url(conn, changes["base_url"])
            extra["is_known_provider"] = checked.basis == "known_provider"
        if changes.get("status_feed_url") is not None:
            await check_base_url(conn, changes["status_feed_url"])
        if changes.get("is_enabled") is False and await _provider_in_use(
            conn, ctx.tenant_id, provider_id
        ):
            raise ProblemError("provider_in_use")
        if not changes:
            return Outcome(provider_view(row), etag=etag_for_row(row["updated_at"], row["id"]))
        columns = {**changes, **extra}
        sets = ", ".join(f"{c} = ${i}" for i, c in enumerate(columns, start=3))
        await conn.execute(
            f"UPDATE sibyl.provider SET {sets} WHERE tenant_id = $1 AND id = $2",  # noqa: S608
            ctx.tenant_id,
            provider_id,
            *columns.values(),
        )
        updated = await _provider(conn, ctx.tenant_id, provider_id)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="provider",
            resource_id=provider_id,
            field_name=",".join(f"provider.{c}" for c in sorted(changes)),
            before={c: row[c] for c in changes},
            after=changes,
            reason=body.reason,
        )
        await policy_changed(
            conn, ctx, aggregate_kind="provider", aggregate_id=provider_id, agent_id=None
        )
        return Outcome(
            provider_view(updated),
            receipt=receipt,
            etag=etag_for_row(updated["updated_at"], updated["id"]),
        )

    return await run_write(ctx, work, idempotent=False)


def _status_view(row: dict[str, Any]) -> JSON:
    return {
        "provider_id": str(row["provider_id"]),
        "status": row["status"],
        "observed_at": jsonable(row["observed_at"]),
        "source": row["source"],
        "detail": row["component"] or row["incident_ref"],
    }


@router.get(PROVIDER + "/status", operation_id="getProviderStatusHistory")
async def provider_status(
    provider_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("getProviderStatusHistory"))],
    limit: int | None = None,
    cursor: str | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
) -> Response:
    page = PageQuery.of(limit, cursor, **{"from": from_, "to": to})

    async def work(conn: Any) -> Outcome:
        await _provider(conn, ctx.tenant_id, provider_id)
        args: list[Any] = [ctx.tenant_id, provider_id]
        sql = "SELECT * FROM sibyl.provider_status WHERE tenant_id = $1 AND provider_id = $2"
        if from_ is not None:
            args.append(from_)
            sql += f" AND observed_at >= ${len(args)}"
        if to is not None:
            args.append(to)
            sql += f" AND observed_at < ${len(args)}"
        return await keyset_page(
            conn,
            ctx,
            select=sql,
            args=args,
            page=page,
            keys=("observed_at", "id"),
            descending=True,
            serialize=_status_view,
        )

    return await run_read(ctx, work)


# --- models ---------------------------------------------------------------------------------

MODEL_SELECT = """
SELECT m.*, c.context_window AS c_context
  FROM sibyl.model m
  LEFT JOIN sibyl.model_catalog c ON c.id = m.catalog_id
 WHERE m.tenant_id = $1"""


def model_view(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "provider_id": str(row["provider_id"]),
        "model_name": row["model_name"],
        "catalog_id": jsonable(row["catalog_id"]),
        "input_usd_per_1m": money(row["input_usd_per_1m"]),
        "output_usd_per_1m": money(row["output_usd_per_1m"]),
        "is_allowed": row["is_allowed"],
        "is_discovered": row["is_discovered"],
        "context_limit": row.get("c_context"),
        "deprecated_on": jsonable(row["deprecated_on"]),
        "retires_on": jsonable(row["retires_on"]),
    }


async def _model(conn: Any, tenant_id: UUID, model_id: UUID) -> dict[str, Any]:
    row = await conn.fetchrow(MODEL_SELECT + " AND m.id = $2", tenant_id, model_id)
    if row is None:
        raise ProblemError("not_found")
    return dict(row)


def _audit_model(row: dict[str, Any]) -> JSON:
    return {
        "provider_id": str(row["provider_id"]),
        "model_name": row["model_name"],
        "is_allowed": row["is_allowed"],
        "input_usd_per_1m": money(row["input_usd_per_1m"]),
        "output_usd_per_1m": money(row["output_usd_per_1m"]),
    }


@router.get(MODELS, operation_id="listModels")
async def list_models(
    ctx: Annotated[AuthContext, Depends(guard("listModels"))],
    limit: int | None = None,
    cursor: str | None = None,
    provider_id: UUID | None = None,
    is_allowed: bool | None = None,
    is_discovered: bool | None = None,
) -> Response:
    page = PageQuery.of(
        limit, cursor, provider_id=provider_id, is_allowed=is_allowed, is_discovered=is_discovered
    )

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = MODEL_SELECT
        for column, value in (
            ("m.provider_id", provider_id),
            ("m.is_allowed", is_allowed),
            ("m.is_discovered", is_discovered),
        ):
            if value is not None:
                args.append(value)
                sql += f" AND {column} = ${len(args)}"
        return await keyset_page(
            conn,
            ctx,
            select="SELECT * FROM (" + sql + ") v WHERE true",  # noqa: S608
            args=args,
            page=page,
            serialize=model_view,
        )

    return await run_read(ctx, work)


async def _catalog_entry(
    conn: Any, catalog_id: str | None, provider_kind: str
) -> dict[str, Any] | None:
    if catalog_id is None:
        return None
    try:
        cid = UUID(catalog_id)
    except ValueError:
        cid = None
    row = (
        await conn.fetchrow("SELECT * FROM sibyl.model_catalog WHERE id = $1", cid) if cid else None
    )
    if row is None or row["provider_kind"] != provider_kind:
        raise ProblemError(
            "validation_failed",
            extensions={
                "errors": [
                    {
                        "pointer": "/catalog_id",
                        "code": "unknown_reference",
                        "message": "no such catalog entry for this provider kind",
                    }
                ]
            },
        )
    return dict(row)


@router.post(MODELS, operation_id="createModel", status_code=201)
async def create_model(
    body: ModelCreate, ctx: Annotated[AuthContext, Depends(guard("createModel"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        await require_tenant_wide(ctx)
        kind = await conn.fetchval(
            "SELECT provider_kind FROM sibyl.provider WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            body.provider_id,
        )
        if kind is None:
            raise ProblemError(
                "validation_failed",
                extensions={
                    "errors": [
                        {
                            "pointer": "/provider_id",
                            "code": "unknown_reference",
                            "message": "no such provider",
                        }
                    ]
                },
            )
        entry = await _catalog_entry(conn, body.catalog_id, kind)
        price_in = parse_money(body.input_usd_per_1m)
        price_out = parse_money(body.output_usd_per_1m)
        if entry is not None:
            price_in = price_in if price_in is not None else entry["input_usd_per_1m"]
            price_out = price_out if price_out is not None else entry["output_usd_per_1m"]
        mid = await conn.fetchval(
            "INSERT INTO sibyl.model (tenant_id, provider_id, model_name, catalog_id,"
            " input_usd_per_1m, output_usd_per_1m, deprecated_on, retires_on)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
            ctx.tenant_id,
            body.provider_id,
            body.model_name,
            entry["id"] if entry else None,
            price_in,
            price_out,
            entry["deprecated_on"] if entry else None,
            entry["retires_on"] if entry else None,
        )
        row = await _model(conn, ctx.tenant_id, mid)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="model",
            resource_id=mid,
            field_name="model",
            before=None,
            after=_audit_model(row),
            reason=body.reason,
        )
        await policy_changed(conn, ctx, aggregate_kind="model", aggregate_id=mid, agent_id=None)
        return Outcome(
            model_view(row),
            status=201,
            receipt=receipt,
            etag=etag_for_row(row["updated_at"], row["id"]),
        )

    return await run_write(ctx, work, idempotent=True)


@router.patch(MODELS + "/{model_id}", operation_id="updateModel")
async def update_model(
    model_id: UUID, body: ModelPatch, ctx: Annotated[AuthContext, Depends(guard("updateModel"))]
) -> Response:
    sent: dict[str, Any] = body.changes()
    for price in ("input_usd_per_1m", "output_usd_per_1m"):
        if price in sent:
            sent[price] = parse_money(sent[price])

    async def work(conn: Any) -> Outcome:
        await require_tenant_wide(ctx)
        await conn.execute(
            "SELECT 1 FROM sibyl.model WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
            ctx.tenant_id,
            model_id,
        )
        row = await _model(conn, ctx.tenant_id, model_id)
        require_if_match(ctx, etag_for_row(row["updated_at"], row["id"]), body=model_view(row))
        changes = {c: v for c, v in sent.items() if v != row[c]}
        if not changes:
            return Outcome(model_view(row), etag=etag_for_row(row["updated_at"], row["id"]))
        sets = ", ".join(f"{c} = ${i}" for i, c in enumerate(changes, start=3))
        await conn.execute(
            f"UPDATE sibyl.model SET {sets} WHERE tenant_id = $1 AND id = $2",  # noqa: S608
            ctx.tenant_id,
            model_id,
            *changes.values(),
        )
        updated = await _model(conn, ctx.tenant_id, model_id)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="model",
            resource_id=model_id,
            field_name=",".join(f"model.{c}" for c in sorted(changes)),
            before={c: _price(row[c]) for c in changes},
            after={c: _price(v) for c, v in changes.items()},
            reason=body.reason,
        )
        await policy_changed(
            conn, ctx, aggregate_kind="model", aggregate_id=model_id, agent_id=None
        )
        return Outcome(
            model_view(updated),
            receipt=receipt,
            etag=etag_for_row(updated["updated_at"], updated["id"]),
        )

    return await run_write(ctx, work, idempotent=False)


def _price(value: Any) -> Any:
    return money(value) if isinstance(value, Decimal) else jsonable(value)


def catalog_view(row: dict[str, Any]) -> JSON:
    return {
        "catalog_id": str(row["id"]),
        "provider_kind": row["provider_kind"],
        "model_name": row["model_name"],
        "input_usd_per_1m": money(row["input_usd_per_1m"]),
        "output_usd_per_1m": money(row["output_usd_per_1m"]),
        "context_limit": row["context_window"],
    }


@router.get(API_PREFIX + "/model-catalog", operation_id="listModelCatalog")
async def list_model_catalog(
    ctx: Annotated[AuthContext, Depends(guard("listModelCatalog"))],
    limit: int | None = None,
    cursor: str | None = None,
    provider_kind: Annotated[str | None, Query(max_length=40)] = None,
    q: Annotated[str | None, Query(max_length=120)] = None,
) -> Response:
    page = PageQuery.of(limit, cursor, provider_kind=provider_kind, q=q)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = []
        sql = "SELECT * FROM sibyl.model_catalog WHERE true"
        if provider_kind:
            args.append(provider_kind)
            sql += f" AND provider_kind = ${len(args)}"
        if q:
            args.append(f"%{q}%")
            sql += f" AND model_name ILIKE ${len(args)}"
        return await keyset_page(
            conn, ctx, select=sql, args=args, page=page, serialize=catalog_view
        )

    return await run_read(ctx, work)
