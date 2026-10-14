"""The oracle's only window on the product: the control-plane API, as persona principals.

* `SseCollector`: one `GET /api/v1/events/stream` per tenant (Operator; Admin in sandbox),
  started before the scenario so arrivals timestamp detection (TTD uses the SSE arrival, not a
  polling interval; qa-expert §1.3). Reconnects with `Last-Event-ID`.
* `ApiReader`: health, health series, agent listings, events, routing transitions, lane
  probes (a 501 means the owning lane has not merged) and deliberate cross-tenant reads.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import httpx

from ..harness.clock import RunClock
from ..harness.world import World
from ..scenarios.model import AgentRef
from .record import CrossRead, HealthRead, SseEvent

log = logging.getLogger("sibyl_sim.oracle")
API = "/api/v1"
LANE_PROBES: Mapping[str, tuple[str, ...]] = {
    "S": ("/incidents", "/kill-switches", "/approvals", "/queue"),
    "P": ("/alerts", "/provider-incidents"),
    "U": ("/audit/events", "/legal-holds"),
}
STREAM_PERSONA = {"meridian": "operator", "northstar": "operator", "sandbox": "admin"}
READ_PERSONA = {"meridian": "operator", "northstar": "operator", "sandbox": "admin"}
MAX_PAGES = 40
MAX_EVIDENCE = 25


class SseCollector:
    def __init__(
        self,
        client: httpx.AsyncClient,
        api: str,
        tenant: str,
        token: str,
        clock: RunClock,
        sink: list[SseEvent],
    ) -> None:
        self.client, self.api, self.tenant, self.token = client, api, tenant, token
        self.clock, self.sink = clock, sink
        self.connected = asyncio.Event()
        self.last_id: str | None = None
        self.errors: list[str] = []

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            headers = {"Authorization": f"Bearer {self.token}", "Accept": "text/event-stream"}
            if self.last_id:
                headers["Last-Event-ID"] = self.last_id
            try:
                async with self.client.stream(
                    "GET", f"{self.api}{API}/events/stream", headers=headers, timeout=None
                ) as resp:
                    if resp.status_code != 200:
                        self.errors.append(f"stream {resp.status_code}")
                        await asyncio.sleep(1)
                        continue
                    self.connected.set()
                    await self._consume(resp, stop)
            except (httpx.HTTPError, asyncio.CancelledError) as exc:
                if isinstance(exc, asyncio.CancelledError):
                    raise
                self.errors.append(type(exc).__name__)
                await asyncio.sleep(0.5)

    async def _consume(self, resp: httpx.Response, stop: asyncio.Event) -> None:
        event: str | None = None
        data: list[str] = []
        async for line in resp.aiter_lines():
            if stop.is_set():
                return
            if line.startswith("id:"):
                self.last_id = line[3:].strip()
            elif line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].strip())
            elif line == "":
                if event and data:
                    with contextlib.suppress(ValueError):
                        payload = json.loads("\n".join(data))
                        self.sink.append(SseEvent(self.clock.now(), self.tenant, event, payload))
                event, data = None, []


class ApiReader:
    def __init__(self, client: httpx.AsyncClient, api: str, world: World, clock: RunClock) -> None:
        self.client, self.api, self.world, self.clock = client, api, world, clock
        self.statuses: dict[str, int] = {}

    def token(self, tenant: str, persona: str | None = None) -> str:
        return self.world.tenant(tenant).token(persona or READ_PERSONA[tenant])

    async def get(self, token: str, path: str, **params: Any) -> tuple[int, Any]:
        resp = await self.client.get(
            f"{self.api}{API}{path}",
            params={k: v for k, v in params.items() if v is not None},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        self.statuses[path.split("?")[0]] = resp.status_code
        with contextlib.suppress(ValueError):
            return resp.status_code, resp.json()
        return resp.status_code, None

    async def pages(self, token: str, path: str, **params: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            status, body = await self.get(token, path, limit=200, cursor=cursor, **params)
            if status != 200 or not isinstance(body, dict):
                break
            out.extend(body.get("data") or [])
            cursor = body.get("next_cursor")
            if not cursor:
                break
        return out

    async def probe_lanes(self, tenant: str = "meridian") -> dict[str, bool]:
        token = self.token(tenant)
        lanes: dict[str, bool] = {}
        for lane, paths in LANE_PROBES.items():
            codes = [(await self.get(token, p))[0] for p in paths]
            lanes[lane] = all(code != 501 for code in codes)
        return lanes

    async def health(self, ref: AgentRef) -> HealthRead | None:
        agent = self.world.tenant(ref.tenant).agent(ref.slug)
        status, body = await self.get(self.token(ref.tenant), f"/agents/{agent.id}/health")
        if status != 200 or not isinstance(body, dict):
            return None
        read = HealthRead.from_doc(self.clock.now(), ref, body)
        return _with_schema_check(read, body)

    async def requests_last_hour(self, ref: AgentRef) -> int:
        agent = self.world.tenant(ref.tenant).agent(ref.slug)
        rows = await self.pages(self.token(ref.tenant), f"/agents/{agent.id}/metrics", grain="5m")
        return sum(int(r.get("requests") or 0) for r in rows)

    async def list_agents(self, tenant: str) -> list[dict[str, Any]]:
        return await self.pages(self.token(tenant), "/agents")

    async def events(self, ref: AgentRef, since: datetime) -> list[dict[str, Any]]:
        agent = self.world.tenant(ref.tenant).agent(ref.slug)
        return await self.pages(
            self.token(ref.tenant),
            "/events",
            agent_id=str(agent.id),
            **{"from": since.isoformat()},
        )

    async def transitions(self, ref: AgentRef, started_wall: float) -> list[dict[str, Any]]:
        agent = self.world.tenant(ref.tenant).agent(ref.slug)
        rows = await self.pages(self.token(ref.tenant), f"/agents/{agent.id}/routing/transitions")
        return sorted(
            (stamp(row, started_wall) for row in rows), key=lambda r: (r["t"] is None, r["t"] or 0)
        )

    async def evidence(
        self, health: Mapping[AgentRef, list[HealthRead]], limit: int = MAX_EVIDENCE
    ) -> dict[str, int]:
        """GET each distinct `evidence` link of a penalised factor (ML §3.6), as the tenant."""
        links: dict[str, str] = {}
        for ref, series in sorted(health.items()):
            for read in series:
                for f in read.factors:
                    link = f.get("evidence")
                    if int(f.get("penalty") or 0) > 0 and isinstance(link, str):
                        links.setdefault(link, ref.tenant)
        out: dict[str, int] = {}
        for link, tenant in sorted(links.items())[:limit]:
            resp = await self.client.get(
                f"{self.api}{link}",
                headers={"Authorization": f"Bearer {self.token(tenant)}"},
                timeout=30,
            )
            out[link] = resp.status_code
        return out

    async def cross_reads(self) -> list[CrossRead]:
        """Every tenant's reader asks for one agent of every other tenant: all must be 404."""
        out: list[CrossRead] = []
        for tenant in self.world.tenants.values():
            persona = READ_PERSONA[tenant.slug]
            for other in self.world.tenants.values():
                if other.slug == tenant.slug or not other.agents:
                    continue
                ref = AgentRef(other.slug, sorted(other.agents)[0])
                agent = other.agents[ref.slug]
                status, _ = await self.get(tenant.token(persona), f"/agents/{agent.id}/health")
                out.append(CrossRead(tenant.slug, persona, ref, status))
        return out

    async def lane_reads(
        self, lanes: Mapping[str, bool], started_wall: float, tenant: str = "meridian"
    ) -> dict[str, Any]:
        """Wave-2 listings, each row stamped with `t` (sim seconds) from its own timestamps."""
        token = self.token(tenant)
        reads: dict[str, Any] = {}
        if lanes.get("S"):
            for key, path in (("approvals", "/approvals"), ("queue", "/queue")):
                reads[key] = [stamp(r, started_wall) for r in await self.pages(token, path)]
            reads["kill_switches"] = await self.pages(token, "/kill-switches")
        if lanes.get("P"):
            alerts = await self.pages(token, "/alerts", include_suppressed="true")
            reads["alerts"] = [stamp(r, started_wall, "fired_at") for r in alerts]
        if lanes.get("U"):
            reads["audit"] = await self.pages(self.token(tenant, "auditor"), "/audit/events")
        sentinel = await self.sentinel(lanes, started_wall)
        if sentinel:
            reads["sentinel"] = sentinel
        return reads

    async def sentinel(self, lanes: Mapping[str, bool], started_wall: float) -> dict[str, Any]:
        """Sentinel findings, usage, holds, incidents, audit and what `sentinel-stub` was sent,
        for every tenant whose Sentinel is configured (S-33; `{}` otherwise)."""
        from .sentinel_reads import read_sentinel

        return await read_sentinel(self, lanes, started_wall)


def _sim_t(value: Any, started_wall: float) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        wall = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
    return round(wall - started_wall, 3)


def stamp(row: Mapping[str, Any], started_wall: float, field: str = "created_at") -> dict[str, Any]:
    """`t` from the row's own timestamp; `claimed_t` for handoff tasks."""
    out = {**row, "t": _sim_t(row.get(field) or row.get("created_at"), started_wall)}
    if "claimed_at" in row:
        out["claimed_t"] = _sim_t(row.get("claimed_at"), started_wall)
    return out


def _with_schema_check(read: HealthRead, body: Mapping[str, Any]) -> HealthRead:
    """Validate against `sibyl-health/1` (schemas package); errors are reported, not fatal."""
    try:
        from sibyl_schemas.models.health import HealthDocument
    except ImportError:  # pragma: no cover
        return read
    from pydantic import ValidationError

    try:
        HealthDocument.model_validate(dict(body))
    except ValidationError as exc:
        errors = tuple(str(e)[:160] for e in exc.errors()[:3])
        return HealthRead(**{**read.__dict__, "schema_errors": errors})
    return read


def window_start(started_wall: float) -> datetime:
    """t = 0 of the scenario: replayed warm-up history is older and never counted."""
    return datetime.fromtimestamp(started_wall, UTC)
