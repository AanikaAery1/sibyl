"""Scenario cadences (S-18): R9 `heartbeat_missing` needs a declared traffic cadence (ML §3.3,
"plans with cadence only"), which the admin sets on the continuity plan through the API."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from sibyl_sim.harness.budgets import apply_cadences
from sibyl_sim.scenarios.model import AgentRef, ScenarioError, parse_scenario

from .test_budgets import AGENT, PLAN, _world
from .test_scenario_model import MINIMAL


def test_cadences_name_agents_and_whole_seconds() -> None:
    assert parse_scenario(MINIMAL).cadences == {}
    s = parse_scenario({**MINIMAL, "cadences": {"quote-assistant": 30, "northstar/x": 60}})
    assert s.cadences == {
        AgentRef("meridian", "quote-assistant"): 30,
        AgentRef("northstar", "x"): 60,
    }


@pytest.mark.parametrize("bad", [0, -5, 2.5, "30", True, ["quote-assistant"]])
def test_invalid_cadences_are_refused(bad: Any) -> None:
    raw = {"quote-assistant": bad} if not isinstance(bad, list) else bad
    with pytest.raises(ScenarioError, match="cadences"):
        parse_scenario({**MINIMAL, "cadences": raw})


def test_put_keeps_the_plan_and_sets_only_the_cadence() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=PLAN, headers={"ETag": 'W/"3"'})
        return httpx.Response(200, json={**PLAN, **json.loads(request.content)})

    async def go() -> list[str]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await apply_cadences(
                client, "http://api", _world(), {AgentRef("meridian", "email-drafter"): 30}
            )

    notes = asyncio.run(go())
    get, put = seen
    assert get.method == "GET"
    assert str(put.url) == f"http://api/api/v1/agents/{AGENT}/continuity-plan"
    assert put.method == "PUT" and put.headers["If-Match"] == 'W/"3"'
    body = json.loads(put.content)
    assert body["expected_cadence_s"] == 30 and len(body["reason"]) >= 10
    for key in ("budget_usd_month", "degraded_mode", "fallback_chain_id", "max_inflight"):
        assert body[key] == PLAN[key]
    assert notes == ["cadence meridian/email-drafter: None -> 30 s"]
