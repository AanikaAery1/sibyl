"""``POST /action-decisions`` on PG17, driven like an enforcement point: evaluate the approved
policy locally (``sibyl_schemas.action_gate``), send its ``needs_counter``; the control plane
answers ``within_cap`` with its own cap, replays never increment, a key of another rule is
refused, and concurrent decisions on one window allow exactly N."""

from __future__ import annotations

import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from typing import Any
from uuid import UUID

import asyncpg
from sibyl_ag_gate import Gate
from sibyl_control.api.action_gate import service
from sibyl_schemas import action_gate as ag

CAP_POLICY: dict[str, Any] = {
    "schema": "sibyl-action-policy/1",
    "default_effect": "allow",
    "rules": [
        {
            "rule_id": "too_big",
            "tool": "payments.transfer",
            "when": {"gt": ["/amount", 10000]},
            "effect": "block",
            "reason": "over the per-transfer limit",
        },
        {
            "rule_id": "daily_cap",
            "tool": "payments.transfer",
            "cumulative": {"sum": "/amount", "max": 1000, "window_s": 86400},
            "effect": "allow",
            "reason": "daily transfer cap",
        },
    ],
}


def _request(gate: Gate, policy_id: str, agent: UUID, call_id: str, amount: int) -> dict[str, Any]:
    document = gate.get(f"/action-policies/{policy_id}").json()["document"]
    policy = ag.parse_policy(document)
    args = {"amount": amount}
    need = ag.evaluate(policy, "payments.transfer", args).needs_counter
    assert need is not None
    return {
        "call_id": call_id,
        "agent_id": str(agent),
        "source": "gateway",
        "policy_id": policy_id,
        "policy_version": policy.version,
        "rule_id": need.rule_id,
        "tool": "payments.transfer",
        "counter_key": need.counter_key,
        "increment": need.increment,
        "max": need.max,
        "window_s": need.window_s,
        "args_sha256": ag.args_digest(args),
    }


def _decide(gate: Gate, body: dict[str, Any], who: str = "keys") -> Any:
    return gate.post("/action-decisions", body, who)


def test_within_cap_then_over_cap_and_replays_do_not_count(gate: Gate) -> None:
    agent = gate.agent()
    policy = gate.approved_policy(agent, CAP_POLICY)
    first = _decide(gate, _request(gate, policy, agent, "cap-1", 400))
    assert first.status_code == 200, first.text
    ag.ActionDecisionResult.model_validate(first.json())  # AG-ENFORCE's wire model
    assert first.json()["within_cap"] is True and first.json()["counter_value"] == "400"
    replay = _decide(gate, _request(gate, policy, agent, "cap-1", 400)).json()
    assert replay["replayed"] is True and replay["counter_value"] == "400"
    second = _decide(gate, _request(gate, policy, agent, "cap-2", 600)).json()
    assert second["counter_value"] == "1000"
    head = gate.head()
    over = _decide(gate, _request(gate, policy, agent, "cap-3", 1)).json()
    assert over["within_cap"] is False and over["effect"] == "escalate"
    assert over["counter_value"] == "1000"
    assert gate.audit_since(head) == ["action.escalated"]


def test_the_control_planes_cap_wins_over_the_callers(gate: Gate) -> None:
    agent = gate.agent()
    policy = gate.approved_policy(agent, CAP_POLICY)
    body = {**_request(gate, policy, agent, "cap-lie", 5000), "max": "999999"}
    resp = _decide(gate, body).json()
    assert resp["within_cap"] is False and resp["max"] == "1000"


def test_a_counter_key_of_another_rule_or_agent_is_refused(gate: Gate) -> None:
    agent, other = gate.agent(), gate.agent()
    policy = gate.approved_policy(agent, CAP_POLICY)
    body = {**_request(gate, policy, agent, "cap-key", 1), "counter_key": "x/daily_cap"}
    assert _decide(gate, body).status_code == 422
    stranger = {**_request(gate, policy, agent, "cap-other", 1), "agent_id": str(other)}
    assert _decide(gate, stranger).status_code == 404
    no_cap = {**_request(gate, policy, agent, "cap-rule", 1), "rule_id": "too_big"}
    assert _decide(gate, no_cap).status_code == 422


def test_a_bound_key_and_humans_cannot_decide_for_another_agent(gate: Gate) -> None:
    agent, other = gate.agent(), gate.agent()
    policy = gate.approved_policy(agent, CAP_POLICY)
    body = _request(gate, policy, agent, "cap-bound", 1)
    assert _decide(gate, body, gate.bound_key(other)).status_code == 404
    assert _decide(gate, body, "owner").status_code == 403


def test_a_cap_race_allows_exactly_n(gate: Gate) -> None:
    """20 concurrent check-and-increments of 1 against max 5, each on its own connection and
    transaction (no audit lock, no app serialisation): exactly 5 are accepted."""
    agent = gate.agent()
    tenant = gate.tenant
    cap = service.Cap(counter_key="p/race", increment=Decimal(1), max=Decimal(5), window_s=3600)
    dsn = sys.modules["sibyl_lane_r_harness"]._app_dsn(gate.w.db_name)

    async def one() -> bool:
        conn = await asyncpg.connect(dsn)
        try:
            async with conn.transaction():
                await conn.execute("SELECT sibyl.set_tenant($1)", tenant)
                now = await conn.fetchval("SELECT now()")
                result = await service.check_and_increment(conn, tenant, agent, cap, now)
                return result.accepted
        finally:
            await conn.close()

    async def race() -> list[bool]:
        return list(await asyncio.gather(*(one() for _ in range(20))))

    results = gate.w.loop.run_until_complete(race())
    assert sum(results) == 5
    value = gate.w.admin.fetchval(
        "SELECT value FROM sibyl.action_counter WHERE tenant_id = $1 AND agent_id = $2",
        tenant,
        agent,
    )
    assert value == 5


def test_the_api_race_also_allows_exactly_n(gate: Gate) -> None:
    """Concurrent API calls (distinct call ids) on one window: exactly max / increment pass."""
    agent = gate.agent()
    policy = gate.approved_policy(agent, CAP_POLICY)
    bodies = [_request(gate, policy, agent, f"race-{i}", 100) for i in range(15)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        answers = list(pool.map(lambda b: _decide(gate, b).json(), bodies))
    assert sum(1 for a in answers if a["within_cap"]) == 10
