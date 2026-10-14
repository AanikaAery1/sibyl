"""History replay: a warm fleet before the scenario starts.

ML §3.8 keeps an agent provisional (band capped at `watch`, alerts at `warning`, no rule-actor
failover) until it has 50 requests and 30 active minutes in the last hour. A freshly seeded
world is all provisional, so a 3-minute scenario would only ever exercise cold start. Before
t = 0 the harness therefore replays `minutes` of healthy, gateway-shaped `gen_ai.request`
events through the real `POST /v1/events` with each tenant's ingest key (the same route and
key class the gateway uses). They are stored as late events in their true minute buckets, so
rollup and scoring see an hour of normal traffic. Event ids are UUIDv7 at the event's time with
hashed random bits (seed, scenario, agent, n): the same seed replays the same ids. A scenario
sets `warmup_min: 0` to test cold start itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sibyl_schemas.scrub import PROFILE_ID, PROFILE_VERSION

from ..harness.world import AgentInfo, Endpoints, TenantInfo, World
from ..scenarios.model import AgentRef
from .traffic import NAMESPACE, rng_for

BATCH = 400
EMITTER = "gateway:sim-history:0"
MAX_RETRIES = 20


def uuid7_at(ts: datetime, label: str) -> str:
    """A UUIDv7 for `ts` whose random bits are a hash of `label`: deterministic, sortable."""
    ms = int(ts.timestamp() * 1000)
    tail = hashlib.sha256(label.encode()).digest()[:10]
    raw = bytearray(ms.to_bytes(6, "big") + tail)
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def history_events(
    tenant: TenantInfo, agent: AgentInfo, seed: int, scenario: str, minutes: int, now: datetime
) -> list[dict[str, Any]]:
    ref = AgentRef(tenant.slug, agent.slug)
    rng = rng_for(seed, scenario, ref, "history")
    events = []
    for minute in range(minutes, 0, -1):
        for k in range(2):  # two calls a minute: 120/h, every minute active
            n = minute * 2 + k
            ts = now - timedelta(minutes=minute) + timedelta(seconds=rng.uniform(0, 59))
            latency = round(rng.uniform(250, 1800), 3)
            tokens_in, tokens_out = rng.randrange(200, 1500), rng.randrange(40, 400)
            events.append(
                {
                    "schema": "sibyl-event/1",
                    "event_id": uuid7_at(ts, f"history|{seed}|{scenario}|{ref}|{n}"),
                    "type": "gen_ai.request",
                    "tenant_id": str(tenant.id),
                    "agent_id": str(agent.id),
                    "task_id": None,
                    "call_id": uuid7_at(ts, f"history-call|{seed}|{scenario}|{ref}|{n}"),
                    "trace_id": uuid.uuid5(NAMESPACE, f"trace|{ref}|{n}").hex,
                    "span_id": uuid.uuid5(NAMESPACE, f"span|{ref}|{n}").hex[:16],
                    "ts": _iso(ts),
                    "source": "gateway",
                    "emitter_id": EMITTER,
                    "seq": n,
                    "capture_mode": "metadata",
                    "redaction_profile": {
                        "id": PROFILE_ID,
                        "version": PROFILE_VERSION,
                        "rules_fired": [],
                        "secrets_scrubbed": 0,
                    },
                    "policy_state": {"state": "fresh", "policy_version": 1, "fail_mode": "open"},
                    "attrs": {
                        "operation": "chat",
                        "provider": agent.provider,
                        "request_model": agent.model,
                        "response_model": agent.model,
                        "status": "ok",
                        "http_status": 200,
                        "latency_ms": latency,
                        "ttfb_ms": round(latency * 0.4, 3),
                        "streamed": False,
                        "route": {"decision": "primary"},
                        "contributions": ["gateway"],
                        "merge_state": "complete",
                        "usage": {"input_tokens": tokens_in, "output_tokens": tokens_out},
                        "finish_reasons": ["stop"],
                    },
                }
            )
    return events


async def _post(client: httpx.AsyncClient, url: str, key: str, batch: list[dict[str, Any]]) -> int:
    for _ in range(MAX_RETRIES):
        resp = await client.post(
            url,
            json={"schema": "sibyl-event/1", "events": batch},
            headers={"Authorization": f"Bearer {key}"},
            timeout=30,
        )
        if resp.status_code in (429, 503):
            await asyncio.sleep(float(resp.headers.get("retry-after", "1")))
            continue
        if resp.status_code >= 400:
            raise RuntimeError(f"history replay refused: {resp.status_code} {resp.text[:300]}")
        body = resp.json()
        rejected = body.get("rejected") or []
        if rejected:
            raise RuntimeError(f"history replay: {len(rejected)} events rejected: {rejected[:2]}")
        return int(body.get("accepted", len(batch)))
    raise RuntimeError("history replay: ingest kept answering 429")


async def replay(
    client: httpx.AsyncClient,
    endpoints: Endpoints,
    world: World,
    *,
    seed: int,
    scenario: str,
    minutes: int,
    tenants: Iterable[str] = ("meridian", "northstar"),
    per_agent: Mapping[AgentRef, int] | None = None,
) -> int:
    """`per_agent` overrides `minutes` for single agents (S-32: an established agent with a
    quiet hour, below the provisional volume threshold)."""
    if minutes <= 0:
        return 0
    per_agent = per_agent or {}
    now = datetime.now(UTC)
    accepted = 0
    for slug in tenants:
        tenant = world.tenant(slug)
        events = [
            e
            for agent in sorted(tenant.agents.values(), key=lambda a: a.slug)
            for e in history_events(
                tenant,
                agent,
                seed,
                scenario,
                per_agent.get(AgentRef(slug, agent.slug), minutes),
                now,
            )
        ]
        for i in range(0, len(events), BATCH):
            accepted += await _post(
                client, f"{endpoints.ingest}/v1/events", tenant.ingest_key, events[i : i + BATCH]
            )
    return accepted
