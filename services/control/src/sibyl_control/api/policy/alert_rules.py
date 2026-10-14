"""Alert-rule editing (API.md §5.6, R18): tenant copies of ``rules/v1`` plus custom rules.

Editing a seed rule marks it ``overridden``; ``POST …/reset`` restores it from
``sibyl.rules_seed()`` (the same mapping ``tenant_create`` uses). Custom rules cannot be reset.
Rules drive the worker's health engine, not the gateway snapshot, so no outbox row is written.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.etag import etag_for_row
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import (
    JSON,
    Outcome,
    PageQuery,
    config_changed,
    jsonable,
    keyset_page,
    require_if_match,
    require_tenant_wide,
    run_read,
    run_write,
)
from ._refs import content_ref
from .models import AlertRuleCreate, AlertRulePatch, OptionalReasonBody

CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
MAX_THRESHOLDS_BYTES = 8192
CUSTOM_METRIC = "custom"
CUSTOM_COMPARATOR = "composite"

router = APIRouter()

# body field -> column for the scalar fields a PATCH may set
_SCALARS = (
    "window_s",
    "min_samples",
    "cooldown_s",
    "severity",
    "penalty",
    "what_to_do_template",
    "enabled",
)


def rule_view(row: dict[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "code": row["code"],
        "short_code": row["short_code"],
        "kind": row["kind"],
        "scope": row["scope"],
        "origin": row["origin"],
        "overridden": row["overridden"],
        "metric": row["metric"],
        "comparator": row["comparator"],
        "thresholds": row["thresholds"],
        "window_s": row["window_s"],
        "min_samples": row["min_samples"],
        "hysteresis": {"in": row["hysteresis_in"], "out": row["hysteresis_out"]},
        "cooldown_s": row["cooldown_s"],
        "severity": row["severity"],
        "penalty": row["penalty"],
        "horizon_s": row["horizon_s"],
        "tier_applicability": list(row["tier_applicability"]),
        "what_to_do_template": row["what_to_do_template"],
        "enabled": row["enabled"],
        "seed_version": row["seed_version"],
        "updated_at": jsonable(row["updated_at"]),
    }


def _etag(row: Any) -> str:
    return etag_for_row(row["updated_at"], row["id"])


def _audit_view(row: dict[str, Any]) -> JSON:
    """Rule settings for audit ``detail``: free-form text and thresholds by reference only."""
    view = rule_view(row)
    for key in ("thresholds", "what_to_do_template"):
        view[key] = content_ref(view[key])
    view.pop("updated_at")
    return view


def _check_thresholds(thresholds: dict[str, Any] | None) -> None:
    if thresholds is not None and len(json.dumps(thresholds)) > MAX_THRESHOLDS_BYTES:
        raise ProblemError("validation_failed", "thresholds are at most 8 KB")


async def _load(conn: Any, tenant: UUID, rule_id: UUID) -> Any:
    row = await conn.fetchrow(
        "SELECT * FROM sibyl.alert_rule WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        tenant,
        rule_id,
    )
    if row is None:
        raise ProblemError("not_found")
    return row


@router.get(API_PREFIX + "/alert-rules")
async def list_alert_rules(
    ctx: Annotated[AuthContext, Depends(guard("listAlertRules"))],
    kind: Annotated[str | None, Query(max_length=20)] = None,
    scope: Annotated[str | None, Query(max_length=40)] = None,
    enabled: bool | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> Response:
    page = PageQuery.of(limit, cursor, kind=kind, scope=scope, enabled=enabled)

    async def work(conn: Any) -> Outcome:
        args: list[Any] = [ctx.tenant_id]
        sql = "SELECT * FROM sibyl.alert_rule WHERE tenant_id = $1"
        if kind == "custom":
            sql += " AND origin = 'custom'"
        elif kind is not None:
            args.append(kind)
            sql += f" AND kind = ${len(args)}"
        if scope is not None:
            args.append(scope)
            sql += f" AND scope = ${len(args)}"
        if enabled is not None:
            args.append(enabled)
            sql += f" AND enabled = ${len(args)}"
        return await keyset_page(conn, ctx, select=sql, args=args, page=page, serialize=rule_view)

    return await run_read(ctx, work)


@router.get(API_PREFIX + "/alert-rules/{rule_id}")
async def get_alert_rule(
    rule_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getAlertRule"))]
) -> Response:
    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.alert_rule WHERE tenant_id = $1 AND id = $2",
            ctx.tenant_id,
            rule_id,
        )
        if row is None:
            raise ProblemError("not_found")
        return Outcome(rule_view(dict(row)), etag=_etag(row))

    return await run_read(ctx, work)


@router.post(API_PREFIX + "/alert-rules", status_code=201)
async def create_alert_rule(
    body: AlertRuleCreate, ctx: Annotated[AuthContext, Depends(guard("createAlertRule"))]
) -> Response:
    if not CODE_PATTERN.fullmatch(body.code):
        raise ProblemError("code_pattern", "code is lower snake case, 3-41 characters")
    _check_thresholds(body.thresholds)
    hysteresis = body.hysteresis

    async def work(conn: Any) -> Outcome:
        await require_tenant_wide(ctx)
        row = await conn.fetchrow(
            "INSERT INTO sibyl.alert_rule (tenant_id, code, kind, scope, metric, comparator,"
            " thresholds, window_s, min_samples, hysteresis_in, hysteresis_out, cooldown_s,"
            " severity, penalty, horizon_s, tier_applicability, what_to_do_template, enabled,"
            " origin) VALUES ($1, $2, 'detected', $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11,"
            " $12, $13, $14, $15::smallint[], $16, $17, 'custom') RETURNING *",
            ctx.tenant_id,
            body.code,
            body.scope,
            CUSTOM_METRIC,
            CUSTOM_COMPARATOR,
            body.thresholds or {},
            body.window_s,
            body.min_samples if body.min_samples is not None else 0,
            hysteresis.in_ if hysteresis and hysteresis.in_ is not None else 2,
            hysteresis.out if hysteresis and hysteresis.out is not None else 6,
            body.cooldown_s if body.cooldown_s is not None else 600,
            body.severity,
            body.penalty if body.penalty is not None else 0,
            body.horizon_s or 0,
            body.tier_applicability or [1, 2, 3],
            body.what_to_do_template or "",
            body.enabled if body.enabled is not None else True,
        )
        result = dict(row)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="alert_rule",
            resource_id=result["id"],
            field_name="alert_rule",
            before=None,
            after=_audit_view(result),
            reason=body.reason,
        )
        return Outcome(rule_view(result), status=201, etag=_etag(row), receipt=receipt)

    return await run_write(ctx, work, idempotent=True)


@router.patch(API_PREFIX + "/alert-rules/{rule_id}")
async def update_alert_rule(
    rule_id: UUID,
    body: AlertRulePatch,
    ctx: Annotated[AuthContext, Depends(guard("updateAlertRule"))],
) -> Response:
    _check_thresholds(body.thresholds)
    given = body.model_fields_set

    async def work(conn: Any) -> Outcome:
        await require_tenant_wide(ctx)
        tenant = ctx.tenant_id
        current = await _load(conn, tenant, rule_id)
        require_if_match(ctx, _etag(current), body=rule_view(dict(current)))
        sets: list[str] = []
        args: list[Any] = [tenant, rule_id]

        def put(column: str, value: Any, cast: str = "") -> None:
            args.append(value)
            sets.append(f"{column} = ${len(args)}{cast}")

        for name in _SCALARS:
            if name in given and getattr(body, name) is not None:
                put(name, getattr(body, name))
        if "thresholds" in given and body.thresholds is not None:
            put("thresholds", body.thresholds, "::jsonb")
        if "horizon_s" in given:
            put("horizon_s", body.horizon_s or 0)
        if "tier_applicability" in given and body.tier_applicability is not None:
            put("tier_applicability", body.tier_applicability, "::smallint[]")
        if body.hysteresis is not None:
            if body.hysteresis.in_ is not None:
                put("hysteresis_in", body.hysteresis.in_)
            if body.hysteresis.out is not None:
                put("hysteresis_out", body.hysteresis.out)
        if current["origin"] == "seed":
            sets.append("overridden = true")
        if not sets:
            raise ProblemError("validation_failed", "nothing to change")
        row = await conn.fetchrow(
            f"UPDATE sibyl.alert_rule SET {', '.join(sets)}"  # noqa: S608 (fixed column names)
            " WHERE tenant_id = $1 AND id = $2 RETURNING *",
            *args,
        )
        result = dict(row)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="alert_rule",
            resource_id=rule_id,
            field_name=f"alert_rule.{current['code']}",
            before=_audit_view(dict(current)),
            after=_audit_view(result),
            reason=body.reason,
        )
        return Outcome(rule_view(result), etag=_etag(row), receipt=receipt)

    return await run_write(ctx, work, idempotent=False)


async def _seed_rule(conn: Any, code: str) -> tuple[dict[str, Any], Any]:
    seed = await conn.fetchrow("SELECT * FROM sibyl.rules_seed()")
    for rule in seed["rules"]:
        if rule.get("code") == code:
            return rule, seed
    raise ProblemError("custom_rule", f"{code} is no longer in the seed rule set")


@router.post(API_PREFIX + "/alert-rules/{rule_id}/reset")
async def reset_alert_rule(
    rule_id: UUID,
    ctx: Annotated[AuthContext, Depends(guard("resetAlertRule"))],
    body: OptionalReasonBody | None = None,
) -> Response:
    reason = body.reason if body is not None else None

    async def work(conn: Any) -> Outcome:
        await require_tenant_wide(ctx)
        tenant = ctx.tenant_id
        current = await _load(conn, tenant, rule_id)
        if current["origin"] != "seed":
            raise ProblemError("custom_rule", "a custom rule has no seed to reset to")
        r, seed = await _seed_rule(conn, current["code"])
        row = await conn.fetchrow(
            "UPDATE sibyl.alert_rule SET short_code = $3, kind = $4, scope = $5, metric = $6,"
            " comparator = $7, thresholds = $8::jsonb, window_s = $9, min_samples = $10,"
            " trend_windows = $11, hysteresis_in = $12, hysteresis_out = $13, cooldown_s = $14,"
            " severity = $15, penalty = $16, horizon_s = $17, tier_applicability = $18::smallint[],"
            " collapses_to_provider = $19, what_to_do_template = $20, enabled = true,"
            " overridden = false, seed_version = $21, yaml_sha256 = $22"
            " WHERE tenant_id = $1 AND id = $2 RETURNING *",
            tenant,
            rule_id,
            r.get("short_code"),
            r["kind"],
            r["scope"],
            r["metric"],
            r["comparator"],
            r["thresholds"],
            int(r["window_s"]),
            int(r["min_samples"]),
            int(r["trend_windows"]) if r.get("trend_windows") is not None else None,
            int(r["hysteresis_in"]),
            int(r["hysteresis_out"]),
            int(r["cooldown_s"]),
            r["severity"],
            int(r["penalty"]),
            int(r["horizon_s"]),
            [int(t) for t in r["tier_applicability"]],
            bool(r["collapses_to_provider"]),
            r["what_to_do"],
            seed["seed_version"],
            seed["yaml_sha256"],
        )
        result = dict(row)
        receipt = await config_changed(
            conn,
            ctx,
            resource_type="alert_rule",
            resource_id=rule_id,
            field_name=f"alert_rule.{current['code']}",
            before=_audit_view(dict(current)),
            after={**_audit_view(result), "reset_to_seed": seed["seed_version"]},
            reason=reason,
        )
        return Outcome(rule_view(result), etag=_etag(row), receipt=receipt)

    return await run_write(ctx, work, idempotent=True)
