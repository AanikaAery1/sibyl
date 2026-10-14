"""The in-process stack boots against PG17 in seconds, serves both tenants through one gateway
and drops its database on stop (skipped without PG17 on a developer machine)."""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest
from sibyl_sim.harness.chaos import agent_credential
from sibyl_sim.harness.inprocess import database as pg
from sibyl_sim.harness.inprocess.stack import InProcessStack, StackOptions
from sibyl_sim.harness.ports import free_base
from sibyl_sim.scenarios.model import AgentRef


def _require_pg() -> None:
    if asyncio.run(pg.available()):
        return
    message = f"PostgreSQL 17 not reachable at {pg.admin_dsn()} (make db-up)"
    required = any(
        os.environ.get(v, "").lower() in ("1", "true", "yes") for v in ("CI", "SIBYL_REQUIRE_PG")
    )
    if required:
        pytest.fail(message, pytrace=False)
    pytest.skip(message)


async def _exercise(stack: InProcessStack) -> dict[str, object]:
    assert stack.world is not None and stack.endpoints is not None
    world, ep = stack.world, stack.endpoints
    out: dict[str, object] = {"bridges": world.bridges}
    async with httpx.AsyncClient(trust_env=False, timeout=30) as client:
        for tenant, slug in (("meridian", "kb-summarizer"), ("northstar", "claims-coder")):
            t = world.tenant(tenant)
            agent = t.agent(slug)
            resp = await client.post(
                f"{ep.gateway}/v1/chat/completions",
                json={"model": agent.model, "messages": [{"role": "user", "content": "hi"}]},
                headers={
                    "X-Sibyl-Key": t.gateway_key,
                    "Authorization": f"Bearer {agent_credential(AgentRef(tenant, slug))}",
                    "X-Sibyl-Agent": str(agent.id),
                },
            )
            out[f"{tenant}:status"] = resp.status_code
            out[f"{tenant}:route"] = resp.headers.get("x-sibyl-route")
        operator = world.tenant("meridian").token("operator")
        listed = await client.get(
            f"{ep.api}/api/v1/agents", headers={"Authorization": f"Bearer {operator}"}
        )
        out["listed"] = listed.status_code
        # B-03: through the shared gateway, northstar's call is filed in northstar (its own
        # ingest key) and never shows up in meridian as an unclaimed agent
        north = world.tenant("northstar")
        claims = north.agent("claims-coder").id
        north_token = north.token("operator")
        stored: list[object] = []
        for _ in range(60):
            got = await client.get(
                f"{ep.api}/api/v1/events",
                params={"agent_id": str(claims)},
                headers={"Authorization": f"Bearer {north_token}"},
            )
            stored = list(got.json().get("data") or []) if got.status_code == 200 else []
            if stored:
                break
            await asyncio.sleep(0.5)
        out["northstar_events"] = len(stored)
        relisted = await client.get(
            f"{ep.api}/api/v1/agents", headers={"Authorization": f"Bearer {operator}"}
        )
        agents = relisted.json().get("data") or []
        out["meridian_unclaimed"] = [a["slug"] for a in agents if "/" in str(a.get("slug"))]
    # B38 probes: the tick-lag meter's calibration and the rollup data lag (read-only)
    out["intervals"] = stack.loop_intervals()
    out["data_lag"] = await stack.data_lag_s()
    return out


def test_stack_boots_proxies_both_tenants_and_cleans_up() -> None:
    _require_pg()

    async def scenario() -> tuple[dict[str, object], str, bool]:
        port = free_base((18590, 18595, 18690), width=1)
        assert port is not None, "no free doubles port"
        stack = InProcessStack(StackOptions(doubles_port=port))
        await stack.start()
        try:
            result = await _exercise(stack)
        finally:
            await stack.stop()
        return result, stack.database, await pg.exists(stack.database)

    result, name, still_there = asyncio.run(scenario())
    assert result["meridian:status"] == 200 and result["northstar:status"] == 200
    assert result["meridian:route"] == "primary"
    assert result["listed"] == 200
    assert result["northstar_events"] and result["meridian_unclaimed"] == []
    assert result["intervals"]["rollup"] > 0 and result["intervals"]["scoring"] > 0  # type: ignore[index]
    lag = result["data_lag"]
    assert isinstance(lag, float) and 0.0 <= lag < 600.0
    assert name.startswith(pg.RUN_PREFIX) and not still_there
