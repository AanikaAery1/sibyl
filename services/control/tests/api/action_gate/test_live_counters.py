"""Lane AG-LIVE cumulative caps on PG17: an approved escalation counts toward its cap (once),
counters persist across versions of one policy, and concurrent approvals add up exactly."""

from __future__ import annotations

import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from typing import Any
from uuid import UUID

import asyncpg
from sibyl_ag_gate import REASON, Gate
from sibyl_control.api.action_gate import service
from sibyl_schemas import action_gate as ag


def _policy(effect: str = "allow", on_exceed: str = "escalate", cap: int = 1000) -> dict[str, Any]:
    return {
        "schema": "sibyl-action-policy/1",
        "default_effect": "allow",
        "rules": [
            {
                "rule_id": "daily_cap",
                "tool": "payments.transfer",
                "cumulative": {
                    "sum": "/amount",
                    "max": cap,
                    "window_s": 86400,
                    "on_exceed": on_exceed,
                },
                "effect": effect,
                "reason": "daily transfer cap",
            }
        ],
    }


def _decision(gate: Gate, policy_id: str, agent: UUID, call_id: str, amount: int) -> Any:
    document = gate.get(f"/action-policies/{policy_id}").json()["document"]
    policy = ag.parse_policy(document)
    args = {"amount": amount}
    need = ag.evaluate(policy, "payments.transfer", args).needs_counter
    assert need is not None
    body = {
        "call_id": call_id,
        "agent_id": str(agent),
        "source": "sdk",
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
    resp = gate.post("/action-decisions", body, "keys")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _hold(gate: Gate, agent: UUID, call_id: str, amount: int) -> dict[str, Any]:
    resp = gate.post("/held-actions", gate.hold_body(agent, call_id, {"amount": amount}), "keys")
    assert resp.status_code == 201, resp.text
    held: dict[str, Any] = resp.json()
    return held


def _act(gate: Gate, held: str, action: str = "approve", who: str = "operator") -> Any:
    return gate.post(f"/held-actions/{held}/actions", {"action": action, "reason": REASON}, who)


def _total(gate: Gate, agent: UUID) -> Decimal:
    value = gate.w.admin.fetchval(
        "SELECT coalesce(sum(value), 0) FROM sibyl.action_counter WHERE agent_id = $1", agent
    )
    return Decimal(value)


def test_an_approved_over_cap_escalation_counts_toward_the_cap(gate: Gate) -> None:
    agent = gate.agent()
    policy = gate.approved_policy(agent, _policy())
    assert _decision(gate, policy, agent, "cap-1", 600)["within_cap"] is True
    over = _decision(gate, policy, agent, "cap-2", 700)
    assert over["within_cap"] is False and over["effect"] == "escalate"
    held = _hold(gate, agent, "cap-2", 700)
    assert held["state"] == "pending"
    assert held["counter"]["amount"] == "700" and held["counter"]["applied_at"] is None
    approved = _act(gate, held["id"])
    assert approved.status_code == 200, approved.text
    assert approved.json()["counter"]["applied_at"] is not None
    assert _total(gate, agent) == Decimal(1300)  # past the cap: the human said yes
    assert _decision(gate, policy, agent, "cap-3", 1)["within_cap"] is False
    replay = _act(gate, held["id"])
    assert replay.status_code == 409 and _total(gate, agent) == Decimal(1300)


def test_a_within_cap_escalation_is_not_counted_twice(gate: Gate) -> None:
    agent = gate.agent()
    policy = gate.approved_policy(agent, _policy(effect="escalate"))
    answer = _decision(gate, policy, agent, "twice-1", 400)
    assert answer["within_cap"] is True and answer["effect"] == "escalate"
    held = _hold(gate, agent, "twice-1", 400)
    assert _act(gate, held["id"]).status_code == 200
    assert _total(gate, agent) == Decimal(400)


def test_an_escalation_without_a_decision_counts_on_approval(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, _policy())
    held = _hold(gate, agent, "direct-1", 250)  # the SDK escalated on its local counter
    assert _act(gate, held["id"]).status_code == 200
    assert _total(gate, agent) == Decimal(250)


def test_a_denied_or_expired_escalation_does_not_count(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, _policy())
    held = _hold(gate, agent, "deny-1", 250)
    assert _act(gate, held["id"], "deny").status_code == 200
    assert _total(gate, agent) == Decimal(0)


def test_a_four_eyes_first_approval_does_not_count_yet(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, _policy(), four_eyes=True)
    held = _hold(gate, agent, "4e-1", 300)
    assert _act(gate, held["id"]).json()["state"] == "pending"
    assert _total(gate, agent) == Decimal(0)
    assert _act(gate, held["id"], who="approver").json()["state"] == "approved"
    assert _total(gate, agent) == Decimal(300)


def test_counters_persist_across_versions_of_one_policy(gate: Gate) -> None:
    agent = gate.agent()
    v1 = gate.approved_policy(agent, _policy())
    assert _decision(gate, v1, agent, "ver-1", 800)["within_cap"] is True
    v2 = gate.approved_policy(agent, _policy())
    assert v2 != v1
    assert _decision(gate, v2, agent, "ver-2", 300)["within_cap"] is False  # 800 + 300 > 1000
    assert _decision(gate, v2, agent, "ver-3", 200)["within_cap"] is True
    keys = gate.w.admin.fetch(
        "SELECT counter_key, value FROM sibyl.action_counter WHERE agent_id = $1", agent
    )
    assert [(r["counter_key"], r["value"]) for r in keys] == [(f"{v1}/daily_cap", 1000)]


def test_concurrent_approvals_add_up_exactly(gate: Gate) -> None:
    agent = gate.agent()
    gate.approved_policy(agent, _policy(cap=50))
    holds = [_hold(gate, agent, f"conc-{i}", 100)["id"] for i in range(10)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(lambda h: _act(gate, h).status_code, holds))
    assert codes == [200] * 10
    assert _total(gate, agent) == Decimal(1000)


def test_add_approved_races_on_one_window_lose_nothing(gate: Gate) -> None:
    """20 concurrent forced increments of 7 on one window, each on its own connection: the
    window ends at exactly 140 with 20 calls (the upsert serialises on the row)."""
    agent = gate.agent()
    tenant = gate.tenant
    cap = service.Cap(counter_key="p/approved", increment=Decimal(7), max=Decimal(5), window_s=3600)
    dsn = sys.modules["sibyl_lane_r_harness"]._app_dsn(gate.w.db_name)

    async def one() -> Decimal:
        conn = await asyncpg.connect(dsn)
        try:
            async with conn.transaction():
                await conn.execute("SELECT sibyl.set_tenant($1)", tenant)
                now = await conn.fetchval("SELECT now()")
                result = await service.add_approved(conn, tenant, agent, cap, now)
                return result.value
        finally:
            await conn.close()

    async def race() -> list[Decimal]:
        return list(await asyncio.gather(*(one() for _ in range(20))))

    values = gate.w.loop.run_until_complete(race())
    assert max(values) == Decimal(140) and len(set(values)) == 20
    row = gate.w.admin.fetchrow(
        "SELECT value, calls FROM sibyl.action_counter WHERE agent_id = $1", agent
    )
    assert (row["value"], row["calls"]) == (140, 20)


def test_lineage_key_maps_only_the_version_prefix() -> None:
    version, lineage = "v-1", "l-1"
    assert service.lineage_key("v-1/cap/abc", version, lineage) == "l-1/cap/abc"
    assert service.lineage_key("v-1/cap", version, lineage) == "l-1/cap"
    assert service.lineage_key("other/cap", version, lineage) == "other/cap"
    assert service.lineage_key("v-10/cap", version, lineage) == "v-10/cap"
