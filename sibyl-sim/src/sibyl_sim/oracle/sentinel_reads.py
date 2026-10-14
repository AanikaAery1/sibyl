"""Final reads for the Sentinel predicates (S-33), through the API as the tenant's personas.

Only tenants whose Sentinel is configured are read (`GET /sentinel/config` says so), so every
other scenario pays one cheap GET per tenant. Per configured tenant:

    config        GET /sentinel/config (with today's usage)                    Operator
    findings      GET /sentinel/findings, each stamped with `t` (sim seconds)  Operator
    held_actions  GET /held-actions?include=args (scrubbed args: the capture-mode positive
                  control proves the metadata agent's marker is stored)        Admin
    incidents     GET /incidents                          (lane S)            Operator
    kill_switches GET /kill-switches                      (lane S)            Operator
    transitions   GET /agents/{id}/routing/transitions for every finding's agent
    audit         GET /audit/events?from=<t=0>            (lane U)            Auditor

plus what `sentinel-stub` recorded since t = 0 (in-process: `live_stub(<doubles port>)`).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

from ..doubles.sentinel_stub import live_stub
from ..harness.world import World


class Reader(Protocol):
    world: World

    def token(self, tenant: str, persona: str | None = None) -> str: ...

    async def get(self, token: str, path: str, **params: Any) -> tuple[int, Any]: ...

    async def pages(self, token: str, path: str, **params: Any) -> list[dict[str, Any]]: ...


def _stamp(row: Mapping[str, Any], started_wall: float) -> dict[str, Any]:
    from .reader import stamp

    return stamp(row, started_wall)


async def read_tenant(
    reader: Reader, tenant: str, lanes: Mapping[str, bool], started_wall: float
) -> dict[str, Any] | None:
    status, config = await reader.get(reader.token(tenant), "/sentinel/config")
    if status != 200 or not isinstance(config, dict) or not config.get("configured"):
        return None
    operator = reader.token(tenant)
    personas = reader.world.tenant(tenant).personas
    admin = reader.token(tenant, "admin" if "admin" in personas else None)
    auditor = reader.token(tenant, "auditor" if "auditor" in personas else None)
    findings = [_stamp(r, started_wall) for r in await reader.pages(operator, "/sentinel/findings")]
    holds = await reader.pages(admin, "/held-actions", include="args")
    out: dict[str, Any] = {
        "config": config,
        "findings": sorted(findings, key=lambda r: (r["t"] is None, r["t"] or 0)),
        "held_actions": [_stamp(r, started_wall) for r in holds],
    }
    if lanes.get("S"):
        out["incidents"] = [
            _stamp(r, started_wall) for r in await reader.pages(operator, "/incidents")
        ]
        out["kill_switches"] = await reader.pages(operator, "/kill-switches")
    agents = sorted({str(f["agent_id"]) for f in findings if f.get("agent_id")})
    out["transitions"] = {
        agent: await reader.pages(operator, f"/agents/{agent}/routing/transitions")
        for agent in agents
    }
    if lanes.get("U"):
        since = datetime.fromtimestamp(started_wall, UTC).isoformat()
        out["audit"] = await reader.pages(auditor, "/audit/events", **{"from": since})
    return out


async def read_sentinel(
    reader: Reader, lanes: Mapping[str, bool], started_wall: float
) -> dict[str, Any]:
    tenants: dict[str, Any] = {}
    for slug in reader.world.tenants:
        read = await read_tenant(reader, slug, lanes, started_wall)
        if read is not None:
            tenants[slug] = read
    if not tenants:
        return {}
    stub = live_stub(reader.world.doubles_port)
    return {
        "tenants": tenants,
        "stub": stub.snapshot(since=started_wall) if stub is not None else None,
    }


__all__ = ["read_sentinel", "read_tenant"]
