"""Approval timeouts on PG17: hold, fail-safe, D22 forced hold, human-requested approvals."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from sibyl_control.core.settings import Settings
from sibyl_control.worker.approvals import timeouts
from sibyl_control.worker.saga import runner
from sibyl_lane_s_world import SWorld


def _waiting(s: SWorld, *, policy: str, tags: tuple[str, ...] = ()) -> dict[str, Any]:
    """A tier-1 agent whose detected failure waits for a backup-agent approval."""
    backup = s.agent(tier=2)
    agent = s.agent(tier=1, model=s.model(s.provider()), tags=tags)
    s.plan(agent, approval_timeout_policy="hold" if tags else policy)
    if policy == "fail_safe" and tags:
        # D22 layer (a) refuses fail_safe on PII agents through the api; plant it directly.
        s.in_tenant(
            s.a,
            "UPDATE sibyl.continuity_plan SET approval_timeout_policy = 'fail_safe'"
            " WHERE tenant_id = $1 AND agent_id = $2",
            s.a.id,
            agent,
        )
    s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup}])
    s.alert(agent)
    fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
    saga = s.saga(fid)
    assert saga["state"] == "waiting_approval"
    s.admin.execute(
        "UPDATE sibyl.approval SET expires_at = now() - interval '1 s' WHERE id = $1",
        saga["approval_id"],
    )
    return {"agent": agent, "fid": fid, "approval": saga["approval_id"], "backup": backup}


def _expire(s: SWorld) -> list[timeouts.Expired]:
    return s.run(timeouts.run_tenant(s.worker_db, s.env("approvals:test"), s.a.id))


def test_hold_policy_degrades_and_cancels(sworld: SWorld) -> None:
    s = sworld
    w = _waiting(s, policy="hold")
    head = s.head(s.a)
    out = _expire(s)
    assert [e.policy_applied for e in out] == ["hold"]
    assert s.routing(w["agent"])["state"] == "degraded"
    saga = s.saga(w["fid"])
    assert saga["state"] == "cancelled" and saga["error"] == "approval_timeout"
    approval = s.one("SELECT * FROM sibyl.approval WHERE id = $1", w["approval"])
    assert approval["state"] == "expired" and approval["resolved_by_timeout"]
    assert "approval.expired" in s.audit_actions(s.a, head)
    last = s.one(
        "SELECT trigger, actor_kind FROM sibyl.routing_transition WHERE id = $1",
        s.routing(w["agent"])["last_transition_id"],
    )
    assert last["trigger"] == "approval_timeout" and last["actor_kind"] == "system"


def test_fail_safe_policy_fails_over(sworld: SWorld) -> None:
    s = sworld
    w = _waiting(s, policy="fail_safe")
    out = _expire(s)
    assert [e.policy_applied for e in out] == ["fail_safe"]
    rs = s.routing(w["agent"])
    assert rs["state"] == "failed_over" and rs["target_agent_id"] == w["backup"]
    assert s.saga(w["fid"])["state"] == "done"


def test_d22_forces_hold_for_pii_tier1_agents(sworld: SWorld) -> None:
    s = sworld
    w = _waiting(s, policy="fail_safe", tags=("pii",))
    out = _expire(s)
    assert [e.policy_applied for e in out] == ["hold_forced_d22"]
    assert s.routing(w["agent"])["state"] == "degraded"
    detail = s.val(
        "SELECT detail->>'timeout_policy_applied' FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'approval.expired' AND resource_id = $2",
        s.a.id,
        w["approval"],
    )
    assert detail == "hold_forced_d22"


def test_unexpired_and_decided_approvals_are_left_alone(sworld: SWorld) -> None:
    s = sworld
    w = _waiting(s, policy="hold")
    s.admin.execute(
        "UPDATE sibyl.approval SET expires_at = now() + interval '1 hour' WHERE id = $1",
        w["approval"],
    )
    assert _expire(s) == []
    assert s.routing(w["agent"])["state"] == "awaiting_approval"


@pytest.mark.parametrize("policy", ["hold", "fail_safe"])
def test_applied_policy_function(policy: str) -> None:
    row = {"evidence": {}, "timeout_policy": policy, "tier": 2, "pii": True}
    assert timeouts.applied_policy(row) == policy
    row = {"evidence": {}, "timeout_policy": policy, "tier": 1, "pii": True}
    assert timeouts.applied_policy(row) == ("hold_forced_d22" if policy == "fail_safe" else "hold")
    row = {
        "evidence": {"timeout_policy_applied": "hold_forced_d22"},
        "timeout_policy": "hold",
        "tier": 1,
        "pii": True,
    }
    assert timeouts.applied_policy(row) == "hold_forced_d22"


def test_tick_entrypoint(sworld: SWorld) -> None:
    import logging

    from sibyl_control.worker.loops import LOOPS, LoopContext, resolve_tick

    tick = resolve_tick(next(x for x in LOOPS if x.name == "approvals"))
    assert tick is not None
    s = sworld
    w = _waiting(s, policy="hold")
    s.run(tick(LoopContext("approvals", s.worker_db, Settings(), logging.getLogger("t"))))
    assert s.saga(w["fid"])["state"] == "cancelled"
    assert isinstance(w["fid"], UUID)
