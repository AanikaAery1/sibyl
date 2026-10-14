"""One drift tick for one tenant (D51), on the caller's ``tenant_tx`` connection.

1. **Discover**: every (agent, provider, requested model) seen in the last ``eval_window``
   without a current baseline gets a ``collecting`` one starting at its first call there.
2. **Freeze**: a collecting baseline with ``baseline_min_samples`` calls over at least
   ``baseline_min_span`` freezes on its oldest ``max_samples`` calls (distributions, served
   models, fingerprints). One that never fills slides its start to ``now - baseline_max_span``.
3. **Evaluate** (each frozen baseline every ``eval_every``): the newest calls of the last
   ``eval_window`` against the frozen distributions, plus the identity checks; one immutable
   ``drift_report``; hysteresis; ``silent_drift`` / ``model_change`` alerts.
4. **Retention**: reports older than ``report_retention`` and baselines superseded more than
   ``baseline_retention`` ago (B24) go, in bounded batches.

Each baseline runs in a savepoint: one bad key is logged and skipped, never the tenant.

The tenant's threshold overrides (``drift_thresholds``, wave 4 HARDEN) are resolved once per
tick onto the deployment config; each report's ``config`` keeps the effective tunable values
and which of them the tenant overrode.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from sibyl_schemas.values import DriftVerdict

from ...core.audit import AuditWriter, PgAuditWriter
from ...core.outbox import OutboxWriter, PgOutboxWriter
from . import features as fx
from . import hysteresis as hy
from . import identity as idn
from . import store
from .alerts import MODEL_CHANGE, SILENT_DRIFT, AlertWriter, DriftRule, dedupe_key, ensure_rules
from .alerts import live_alert as find_live
from .config import DEFAULT_CONFIG, DriftConfig, tunable_values

log = logging.getLogger("sibyl.drift")


@dataclass
class TenantResult:
    created: list[UUID] = field(default_factory=list)
    frozen: list[UUID] = field(default_factory=list)
    reports: list[UUID] = field(default_factory=list)
    fired: list[UUID] = field(default_factory=list)
    resolved: list[UUID] = field(default_factory=list)
    purged: int = 0
    purged_baselines: int = 0
    failed: list[UUID] = field(default_factory=list)


def _key(row: dict[str, Any]) -> store.Key:
    return store.Key(row["agent_id"], row["provider"], row["model"])


def config_json(cfg: DriftConfig) -> dict[str, Any]:
    """The settings a report was computed with (kept on the report for explainability)."""
    return {
        "eval_window_s": int(cfg.eval_window.total_seconds()),
        "eval_min_samples": cfg.eval_min_samples,
        "tool_min_samples": cfg.tool_min_samples,
        "identity_min_count": cfg.identity_min_count,
        "numeric_bins": cfg.numeric_bins,
        "raise_after": cfg.raise_after,
        "clear_after": cfg.clear_after,
        "identity_clear_after": cfg.identity_clear_after,
        "thresholds": tunable_values(cfg),
        "overrides": list(cfg.overrides),
    }


async def _discover(conn: Any, tenant: UUID, now: datetime, cfg: DriftConfig) -> list[UUID]:
    current = {_key(r) for r in await store.current_baselines(conn, tenant)}
    created = []
    for key, first_ts in await store.discover(
        conn, tenant, now - cfg.eval_window, now, cfg.max_keys_per_tick
    ):
        if key in current:
            continue
        baseline = await store.create_baseline(conn, tenant, key, first_ts)
        if baseline is not None:
            created.append(baseline)
    return created


async def _try_freeze(
    conn: Any, tenant: UUID, row: dict[str, Any], now: datetime, cfg: DriftConfig
) -> bool:
    key = _key(row)
    start: datetime = row["window_start"]
    if now - start > cfg.baseline_max_span:
        start = now - cfg.baseline_max_span
        await store.slide(conn, tenant, row["id"], start)
    if now - start < cfg.baseline_min_span:
        return False
    if await store.count_calls(conn, tenant, key, start, now) < cfg.baseline_min_samples:
        return False
    window, last = await store.load_window(
        conn,
        tenant,
        key,
        start,
        now,
        oldest_first=True,
        max_calls=cfg.max_samples,
        max_tools=cfg.max_tool_samples,
    )
    return await store.freeze(
        conn,
        tenant,
        row["id"],
        window_end=last or now,
        window=window,
        features=fx.freeze(window, cfg),
        served=idn.top_values((c.response_model for c in window.calls), cfg.served_set_limit),
        fingerprints=idn.top_values((c.fingerprint for c in window.calls), cfg.served_set_limit),
        now=now,
    )


def _summary(row: dict[str, Any], results: list[fx.FeatureResult]) -> str:
    worst = [r for r in results if r.verdict is DriftVerdict.DRIFT]
    named = ", ".join(f"{r.feature.value} {r.statistic.value} {r.value:.3f}" for r in worst[:3])
    return f"Behavioural drift on {row['provider'] or '?'}/{row['model']}: {named}"


def _behaviour_evidence(
    row: dict[str, Any], report_id: UUID, results: list[fx.FeatureResult]
) -> dict[str, Any]:
    return {
        "rule": SILENT_DRIFT,
        "watch_only": True,
        "baseline_id": str(row["id"]),
        "report_id": str(report_id),
        "provider": row["provider"],
        "model": row["model"],
        "features": [
            {
                "feature": r.feature.value,
                "statistic": r.statistic.value,
                "value": None if r.value is None else round(r.value, 4),
                "drift": r.drift,
                "verdict": r.verdict.value,
            }
            for r in results
            if r.status == "ok" and r.verdict is not DriftVerdict.NONE
        ],
        "link": f"/api/v1/drift/reports/{report_id}",
    }


def _identity_evidence(
    row: dict[str, Any], report_id: UUID, found: list[idn.IdentityFinding]
) -> dict[str, Any]:
    return {
        "rule": MODEL_CHANGE,
        "watch_only": True,
        "baseline_id": str(row["id"]),
        "report_id": str(report_id),
        "provider": row["provider"],
        "model": row["model"],
        "changes": [f.as_json() for f in found[:10]],
        "baseline_served_models": list(row["served_models"])[:10],
        "link": f"/api/v1/drift/reports/{report_id}",
    }


async def _apply(
    writer: AlertWriter,
    rule: DriftRule | None,
    action: hy.Action,
    agent_id: UUID,
    key: str,
    evidence: dict[str, Any],
    summary: str,
) -> None:
    if rule is None or action is hy.Action.NONE:
        return
    if action is hy.Action.RESOLVE:
        live = await find_live(writer.conn, writer.tenant, key)
        if live is not None:
            await writer.resolve(rule.code, live.id)
        return
    await writer.fire(rule, agent_id, key, evidence, summary)


async def _evaluate(
    conn: Any,
    tenant: UUID,
    row: dict[str, Any],
    now: datetime,
    cfg: DriftConfig,
    rules: dict[str, DriftRule],
    writer: AlertWriter,
) -> UUID | None:
    key = _key(row)
    start = now - cfg.eval_window
    window, _ = await store.load_window(
        conn,
        tenant,
        key,
        start,
        now,
        oldest_first=False,
        max_calls=cfg.max_samples,
        max_tools=cfg.max_tool_samples,
    )
    streaks = hy.Streaks(row["drift_streak"], row["clear_streak"], row["identity_clear_streak"])
    if len(window.calls) < cfg.identity_min_count:
        await store.save_streaks(conn, tenant, row["id"], *_tuple(streaks), now)
        return None
    results = fx.compare(row["features"] or {}, window, cfg)
    found = idn.changes(
        row["model"],
        window.calls,
        row["served_models"],
        row["fingerprints"],
        cfg.identity_min_count,
    )
    verdict = fx.overall(results)
    behaviour_evaluated = fx.evaluated(results)
    report_id = await store.write_report(
        conn,
        tenant,
        {
            "baseline_id": row["id"],
            "agent_id": row["agent_id"],
            "provider": row["provider"],
            "model": row["model"],
            "evaluated_at": now,
            "window_start": start,
            "window_end": now,
            "sample_count": len(window.calls),
            "tool_sample_count": len(window.tools),
            "verdict": verdict.value,
            "behaviour_evaluated": behaviour_evaluated,
            "identity_changed": bool(found),
            "max_ratio": round(fx.drift_ratio(results), 6),
            "features": [r.as_json() for r in results],
            "identity": [f.as_json() for f in found[:64]],
            "config": config_json(cfg),
        },
    )
    drift_key = dedupe_key(SILENT_DRIFT, key.agent_id, key.provider, key.model)
    change_key = dedupe_key(MODEL_CHANGE, key.agent_id, key.provider, key.model)
    drift_live = await find_live(conn, tenant, drift_key) is not None
    change_live = await find_live(conn, tenant, change_key) is not None
    streaks, behaviour_action = hy.behaviour(
        streaks, verdict, drift_live, cfg, evaluated=behaviour_evaluated
    )
    streaks, identity_action = hy.identity(streaks, bool(found), change_live, cfg)
    await _apply(
        writer,
        rules.get(SILENT_DRIFT),
        behaviour_action,
        key.agent_id,
        drift_key,
        _behaviour_evidence(row, report_id, results),
        _summary(row, results),
    )
    await _apply(
        writer,
        rules.get(MODEL_CHANGE),
        identity_action,
        key.agent_id,
        change_key,
        _identity_evidence(row, report_id, found),
        f"Model identity changed on {row['provider'] or '?'}/{row['model']}: "
        + ", ".join(f"{f.kind.value} {f.value}" for f in found[:3]),
    )
    await store.save_streaks(conn, tenant, row["id"], *_tuple(streaks), now)
    return report_id


def _tuple(s: hy.Streaks) -> tuple[int, int, int]:
    return s.drift, s.clear, s.identity_clear


def _due(row: dict[str, Any], now: datetime, cfg: DriftConfig) -> bool:
    last = row["last_evaluated_at"]
    return last is None or now - last >= cfg.eval_every


async def run_tenant(
    conn: Any,
    tenant: UUID,
    *,
    now: datetime | None = None,
    cfg: DriftConfig = DEFAULT_CONFIG,
    outbox: OutboxWriter | None = None,
    audit: AuditWriter | None = None,
) -> TenantResult:
    """``cfg`` is the deployment config; the tenant's ``drift_thresholds`` overrides (if any)
    replace its thresholds and window minimums value by value for this tenant's tick."""
    now = now or await conn.fetchval("SELECT now()")
    cfg = (await store.tenant_thresholds(conn, tenant)).apply(cfg)
    result = TenantResult()
    rules = await ensure_rules(conn, tenant)
    writer = AlertWriter(conn, tenant, now, outbox or PgOutboxWriter(), audit or PgAuditWriter())
    result.created = await _discover(conn, tenant, now, cfg)
    for row in (await store.current_baselines(conn, tenant))[: cfg.max_keys_per_tick]:
        try:
            async with conn.transaction():
                if row["state"] == "collecting":
                    if await _try_freeze(conn, tenant, row, now, cfg):
                        result.frozen.append(row["id"])
                elif _due(row, now, cfg):
                    report = await _evaluate(conn, tenant, row, now, cfg, rules, writer)
                    if report is not None:
                        result.reports.append(report)
        except Exception:
            log.exception("drift evaluation failed for baseline %s", row["id"])
            result.failed.append(row["id"])
    result.fired = list(writer.fired)
    result.resolved = list(writer.resolved)
    result.purged = await store.purge_reports(
        conn, tenant, now - cfg.report_retention, cfg.retention_batch
    )
    result.purged_baselines = await store.purge_baselines(
        conn, tenant, now - cfg.baseline_retention, cfg.retention_batch
    )
    return result
