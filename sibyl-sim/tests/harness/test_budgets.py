"""Scenario budgets are set through the continuity-plan API, keeping every other plan field."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import httpx
import pytest
from sibyl_sim.harness.budgets import apply_budgets
from sibyl_sim.harness.world import AgentInfo, PersonaInfo, TenantInfo, World
from sibyl_sim.scenarios.model import AgentRef

AGENT = uuid.uuid4()
PLAN: dict[str, Any] = {
    "agent_id": str(AGENT),
    "rto_s": 14400,
    "rpo_s": 900,
    "credential_mode": "passthrough",
    "degraded_mode": "safe_no_tools",
    "inline_fallback": True,
    "preemptive_mode": "auto",
    "approval_timeout_s": 600,
    "approval_timeout_policy": "hold",
    "fallback_chain_id": str(uuid.uuid4()),
    "on_call_user_id": None,
    "on_call_ref": "pagerduty:support",
    "budget_usd_month": "300.0000",
    "max_inflight": 10,
    "rps_limit": None,
    "drill_schedule": None,
    "expected_cadence_s": None,
    "approved_by_user_id": None,
    "approved_at": None,
    "row_version": 3,
    "updated_at": "2026-10-14T00:00:00Z",
}


def _world() -> World:
    agent = AgentInfo("email-drafter", AGENT, 3, "anthropic-stub", "claude-sonnet-5")
    admin = PersonaInfo("admin", uuid.uuid4(), ("owner",), token="tok-admin")  # noqa: S106 (fake)
    tenant = TenantInfo(
        "meridian", uuid.uuid4(), {"email-drafter": agent}, personas={"admin": admin}
    )
    return World({"meridian": tenant}, 18390)


def test_put_keeps_the_plan_and_changes_only_the_budget() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=PLAN, headers={"ETag": 'W/"3"'})
        return httpx.Response(200, json={**PLAN, **json.loads(request.content)})

    async def go() -> list[str]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await apply_budgets(
                client, "http://api", _world(), {AgentRef("meridian", "email-drafter"): "4.4100"}
            )

    notes = asyncio.run(go())
    get, put = seen
    url = f"http://api/api/v1/agents/{AGENT}/continuity-plan"
    assert str(get.url) == url and str(put.url) == url and put.method == "PUT"
    assert put.headers["If-Match"] == 'W/"3"' and put.headers["Idempotency-Key"]
    assert put.headers["Authorization"] == "Bearer tok-admin"
    body = json.loads(put.content)
    assert body["budget_usd_month"] == "4.4100" and len(body["reason"]) >= 10
    for key in ("degraded_mode", "fallback_chain_id", "inline_fallback", "max_inflight"):
        assert body[key] == PLAN[key]
    assert not {"agent_id", "row_version", "approved_at", "updated_at"} & set(body)
    assert notes == ["budget meridian/email-drafter: 300.0000 -> 4.4100 USD/month"]


def test_a_refused_change_stops_the_run() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=PLAN, headers={"ETag": 'W/"3"'})
        return httpx.Response(412, json={"code": "precondition_failed"})

    async def go() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await apply_budgets(
                client, "http://api", _world(), {AgentRef("meridian", "email-drafter"): "1.0000"}
            )

    with pytest.raises(RuntimeError, match="412"):
        asyncio.run(go())
