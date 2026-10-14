"""The per-tenant Sentinel pass (scheduled, actor ``system``).

For an enabled tenant with a vaulted key, in priority order and at most ``max_calls`` analyses
per tick: explain new incidents, review pending held actions (a recommendation, never a
decision), sample recently active agents for semantic drift (``sampling_rate``; skips are
counted), and write one fleet summary per UTC day. Each analysis reserves budget first and is
skipped (and counted, the first skip of the day audited) when the day's budget is spent.

Scheduled findings are idempotent per subject (``dedupe_key``); two workers racing on the same
tenant can at worst make one redundant model call, which the budget still bounds.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sibyl_schemas.values import SentinelTask

from ...core.audit import AuditWriter, PgAuditWriter
from ...core.crypto.envelope import KeyEncryptionKey
from ...core.llm import LlmError
from ...core.outbox import OutboxWriter, PgOutboxWriter
from . import budget, engine, gather
from .config import (
    KeyUnavailable,
    SentinelConfig,
    TransportFactory,
    build_client,
    egress_policy,
    load_config,
    open_key,
)
from .findings import Subject

log = logging.getLogger("sibyl.sentinel")
_FLEET_DONE_SQL = "SELECT 1 FROM sibyl.sentinel_finding WHERE tenant_id = $1 AND dedupe_key = $2"


@dataclass
class Deps:
    settings: Any
    kek: KeyEncryptionKey
    transport_factory: TransportFactory | None = None
    content: gather.ContentReader | None = None
    rng: Callable[[], float] = random.random
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    client_kw: Mapping[str, Any] = field(default_factory=dict)
    audit: AuditWriter = field(default_factory=PgAuditWriter)
    outbox: OutboxWriter = field(default_factory=PgOutboxWriter)
    max_calls: int = 6


@dataclass
class TenantReport:
    tenant: UUID
    state: str = "ran"  # ran | disabled | no_key | key_unavailable | client_error
    outcomes: list[tuple[str, str]] = field(default_factory=list)
    skipped_sampling: int = 0

    def statuses(self, task: SentinelTask | None = None) -> list[str]:
        return [s for t, s in self.outcomes if task is None or t == task.value]


@dataclass(frozen=True)
class Work:
    subject: Subject
    data: dict[str, Any]


async def _collect(
    conn: Any, deps: Deps, tenant: UUID, cfg: SentinelConfig, now: datetime
) -> tuple[list[Work], int]:
    budget_left = deps.max_calls
    out: list[Work] = []
    sampled_out = 0
    if cfg.task_on(SentinelTask.INCIDENT_EXPLANATION):
        for incident, agent in await gather.new_incidents(conn, tenant, budget_left):
            doc = await gather.incident_doc(conn, tenant, incident)
            if doc is not None:
                subject = Subject(
                    SentinelTask.INCIDENT_EXPLANATION,
                    "incident",
                    incident,
                    agent,
                    f"incident:{incident}",
                )
                out.append(Work(subject, doc))
    if cfg.task_on(SentinelTask.HELD_ACTION_REVIEW) and len(out) < deps.max_calls:
        for held, agent in await gather.pending_holds(conn, tenant, deps.max_calls - len(out)):
            doc = await gather.hold_doc(conn, tenant, held, deps.content)
            if doc is not None:
                subject = Subject(
                    SentinelTask.HELD_ACTION_REVIEW,
                    "held_action",
                    held,
                    agent,
                    f"held_action:{held}",
                )
                out.append(Work(subject, doc))
    if cfg.task_on(SentinelTask.SEMANTIC_DRIFT) and len(out) < deps.max_calls:
        window = gather.drift_window(now)
        for agent in await gather.drift_candidates(conn, tenant, window, deps.max_calls * 4):
            if len(out) >= deps.max_calls:
                break
            if deps.rng() >= float(cfg.sampling_rate):
                sampled_out += 1
                continue
            doc = await gather.drift_doc(conn, tenant, agent, deps.content)
            subject = Subject(
                SentinelTask.SEMANTIC_DRIFT, "agent", agent, agent, f"drift:{agent}:{window}"
            )
            out.append(Work(subject, doc))
    if cfg.task_on(SentinelTask.FLEET_SUMMARY) and len(out) < deps.max_calls:
        key = f"fleet:{engine.utc_day(now).isoformat()}"
        if await conn.fetchval(_FLEET_DONE_SQL, tenant, key) is None:
            out.append(
                Work(
                    Subject(SentinelTask.FLEET_SUMMARY, "fleet", None, None, key),
                    await gather.fleet_doc(conn, tenant),
                )
            )
    return out, sampled_out


async def run_tenant(db: Any, deps: Deps, tenant: UUID) -> TenantReport:
    report = TenantReport(tenant)
    now = deps.clock()
    day = engine.utc_day(now)
    async with db.tenant_tx(tenant, readonly=True) as conn:
        cfg = await load_config(conn, tenant)
        if cfg is None or not cfg.enabled:
            report.state = "disabled"
            return report
        if not cfg.has_key:
            report.state = "no_key"
            return report
        try:
            api_key = await open_key(conn, deps.kek, tenant)
        except KeyUnavailable:
            report.state = "key_unavailable"
            return report
        policy = await egress_policy(conn, deps.settings)
        work, sampled_out = await _collect(conn, deps, tenant, cfg, now)
    try:
        client = build_client(cfg, api_key, policy, deps.transport_factory, **deps.client_kw)
    except LlmError as exc:
        log.warning("sentinel client for tenant %s refused: %s", tenant, exc.code)
        report.state = "client_error"
        return report
    finally:
        del api_key
    report.skipped_sampling = sampled_out
    if sampled_out:
        async with db.tenant_tx(tenant) as conn:
            await budget.record_sampling_skips(conn, tenant, day, sampled_out)
    for item in work:
        report.outcomes.append(
            (item.subject.kind.value, await _analyse(db, deps, tenant, cfg, client, item, day))
        )
    return report


async def _analyse(
    db: Any, deps: Deps, tenant: UUID, cfg: SentinelConfig, client: Any, item: Work, day: Any
) -> str:
    prepared = engine.prepare(item.subject.kind, item.data, cfg, client)
    if not await engine.reserve(db, deps.audit, tenant, cfg, prepared, day, engine.SYSTEM_ACTOR):
        return "skipped_budget"
    result = await engine.call(client, prepared)
    outcome = await engine.finish_scheduled(
        db, deps.audit, deps.outbox, tenant, cfg, item.subject, prepared, result, day, alert=True
    )
    if outcome.status == "failed":
        log.info(
            "sentinel %s for tenant %s failed: %s",
            item.subject.kind.value,
            tenant,
            outcome.error_code,
        )
    return outcome.status
