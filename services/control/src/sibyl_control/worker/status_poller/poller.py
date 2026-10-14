"""Poll provider status feeds into ``provider_status`` (source ``status_feed``).

Per tick: read every enabled provider with a feed (its own ``status_feed_url``, else the
configured default for its ``provider_kind`` when ``is_known_provider``), fetch each distinct URL
once (outside any transaction, bounded concurrency), then write per tenant:

* a row when the status changed, or when the last row is older than ``refresh_s`` (so
  ``provider_status_age_s`` stays meaningful for confidence);
* on a failed fetch, ``unknown`` only once the last good row is older than ``stale_s`` (a single
  failed poll never moves R4).

Configuration (env, ``SIBYL_STATUS_*``): ``FEEDS`` JSON ``{provider_kind: url}``, ``DEV_HOSTS``
JSON list (the sibyl-sim double), ``REFRESH_S``, ``STALE_S``, ``CONCURRENCY``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

import httpx
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..rollup.tenancy import active_tenants, try_lock
from .feeds import FeedStatus, parse_feed
from .fetch import FeedError, FetchPolicy, fetch_feed

SOURCE = "status_feed"
LOOP = "status_poller"

_TARGETS_SQL = """
SELECT p.id, p.provider_kind, p.is_known_provider, p.status_feed_url,
       sibyl.is_allowlisted_base_url(p.status_feed_url) AS allowed,
       s.status AS last_status, s.observed_at AS last_observed
  FROM sibyl.provider p
  LEFT JOIN LATERAL (
    SELECT status, observed_at FROM sibyl.provider_status ps
     WHERE ps.tenant_id = p.tenant_id AND ps.provider_id = p.id AND ps.source = 'status_feed'
     ORDER BY observed_at DESC, created_at DESC LIMIT 1) s ON true
 WHERE p.tenant_id = $1 AND p.is_enabled
"""
_INSERT_SQL = """
INSERT INTO sibyl.provider_status (tenant_id, provider_id, source, status, observed_at,
  incident_ref, raw)
VALUES ($1, $2, 'status_feed', $3, $4, $5, $6::jsonb)
"""


class PollerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIBYL_STATUS_", extra="ignore")

    feeds: dict[str, str] = {}
    dev_hosts: list[str] = []
    refresh_s: int = 600
    stale_s: int = 900
    concurrency: int = 8


@dataclass(frozen=True)
class Target:
    tenant_id: UUID
    provider_id: UUID
    url: str
    last_status: str | None
    last_observed: datetime | None


@dataclass
class PollResult:
    fetched: int = 0
    failed: int = 0
    written: int = 0
    skipped: list[str] = field(default_factory=list)


async def collect(
    conn: Any, tenant: UUID, settings: PollerSettings
) -> tuple[list[Target], list[str]]:
    targets: list[Target] = []
    skipped: list[str] = []
    for r in await conn.fetch(_TARGETS_SQL, tenant):
        url = r["status_feed_url"]
        if url and not r["allowed"]:
            skipped.append(f"{r['id']}: feed URL not allowlisted")
            continue
        if not url and r["is_known_provider"]:
            url = settings.feeds.get(r["provider_kind"])
        if url:
            targets.append(Target(tenant, r["id"], url, r["last_status"], r["last_observed"]))
    return targets, skipped


async def fetch_all(
    urls: Sequence[str], client: httpx.AsyncClient, policy: FetchPolicy, concurrency: int
) -> dict[str, FeedStatus | FeedError]:
    gate = asyncio.Semaphore(max(1, concurrency))

    async def one(url: str) -> tuple[str, FeedStatus | FeedError]:
        async with gate:
            try:
                return url, parse_feed(await fetch_feed(url, client, policy))
            except FeedError as exc:
                return url, exc

    return dict(await asyncio.gather(*(one(u) for u in sorted(set(urls)))))


def decide(
    target: Target, outcome: FeedStatus | FeedError, now: datetime, settings: PollerSettings
) -> tuple[str, str | None, Mapping[str, Any]] | None:
    age = (now - target.last_observed).total_seconds() if target.last_observed else None
    if isinstance(outcome, FeedError):
        stale = age is None or age >= settings.stale_s
        if stale and target.last_status != "unknown":
            return "unknown", None, {"error": str(outcome)[:200]}
        return None
    if outcome.status != target.last_status or age is None or age >= settings.refresh_s:
        return outcome.status, outcome.incident_ref, outcome.raw
    return None


async def poll(
    db: Any,
    *,
    client: httpx.AsyncClient,
    policy: FetchPolicy,
    settings: PollerSettings,
    tenants: Sequence[UUID] | None = None,
) -> PollResult:
    result = PollResult()
    plan: dict[UUID, list[Target]] = {}
    for tenant in tenants if tenants is not None else await active_tenants(db):
        async with db.tenant_tx(tenant, readonly=True) as conn:
            plan[tenant], skipped = await collect(conn, tenant, settings)
        result.skipped.extend(skipped)
    outcomes = await fetch_all(
        [t.url for ts in plan.values() for t in ts], client, policy, settings.concurrency
    )
    result.fetched = sum(1 for o in outcomes.values() if isinstance(o, FeedStatus))
    result.failed = len(outcomes) - result.fetched
    for tenant, targets in plan.items():
        if not targets:
            continue
        async with db.tenant_tx(tenant) as conn:
            if not await try_lock(conn, LOOP, tenant):
                continue
            now = await conn.fetchval("SELECT now()")
            for target in targets:
                row = decide(target, outcomes[target.url], now, settings)
                if row is None:
                    continue
                status, ref, raw = row
                await conn.execute(
                    _INSERT_SQL, tenant, target.provider_id, status, now, ref, dict(raw)
                )
                result.written += 1
    return result
