"""Regression tests for the lane S review findings (overlapping switches, quarantine kept
through a kill, failback not cancellable, poison steps, stale approved targets, stranded
awaiting_approval) and lane U's break-glass anchor payload."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import pytest
from sibyl_control.worker.approvals import timeouts
from sibyl_control.worker.saga import engine, runner
from sibyl_lane_s_world import SWorld

REASON = "review fix test: operator decision text"


def _pull(s: SWorld, who: str, scope_kind: str, scope_id: Any = None) -> Any:
    body: dict[str, Any] = {"scope_kind": scope_kind, "reason": "kill switch overlap test pull"}
    if scope_id is not None:
        body["scope_id"] = str(scope_id)
    resp = s.post(who, "/kill-switches", body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _release(s: SWorld, ks: dict[str, Any], who: str = "owner") -> None:
    resp = s.post(who, f"/kill-switches/{ks['id']}/release", {"reason": REASON})
    assert resp.status_code == 200, resp.text


def test_tenant_then_agent_switch_releases_in_either_order(sworld: SWorld) -> None:
    s = sworld
    agent = s.agent()
    tenant = _pull(s, "owner", "tenant")
    by_agent = _pull(s, "owner", "agent", agent)
    assert by_agent["affected_agent_ids"] == [str(agent)]  # coverage recorded, no new transition
    _release(s, tenant)
    assert s.routing(agent)["state"] == "killed"  # the agent switch still covers it
    _release(s, by_agent)
    assert s.routing(agent)["state"] == "active"
    s.admin.execute(
        "UPDATE sibyl.kill_switch SET pulled_at = now() - interval '11 minutes' WHERE id = $1",
        UUID(tenant["id"]),
    )


def test_provider_switch_survives_a_tenant_release(sworld: SWorld) -> None:
    s = sworld
    p = s.provider()
    agent = s.agent(model=s.model(p))
    other = s.agent()
    tenant = _pull(s, "owner2", "tenant")
    provider = _pull(s, "owner2", "provider", p)
    _release(s, tenant, who="owner2")
    assert s.routing(agent)["state"] == "killed"
    assert s.routing(other)["state"] == "active"
    _release(s, provider, who="owner2")
    assert s.routing(agent)["state"] == "active"
    s.admin.execute(
        "UPDATE sibyl.kill_switch SET pulled_at = now() - interval '11 minutes' WHERE id = $1",
        UUID(tenant["id"]),
    )


def test_kill_action_on_a_killed_agent_is_refused(sworld: SWorld) -> None:
    s = sworld
    agent = s.agent()
    ks = _pull(s, "owner", "agent", agent)
    resp = s.post(
        "owner", "/incidents", {"agent_id": str(agent), "action": "kill", "reason": REASON}
    )
    assert resp.status_code == 409
    _release(s, ks)


def test_release_restores_a_prior_quarantine(sworld: SWorld) -> None:
    s = sworld
    agent = s.agent()
    q = s.post(
        "owner", "/incidents", {"agent_id": str(agent), "action": "quarantine", "reason": REASON}
    )
    assert q.status_code == 201
    ks = _pull(s, "owner", "agent", agent)
    _release(s, ks)
    assert s.routing(agent)["state"] == "quarantined"


def test_failback_saga_cannot_be_cancelled(sworld: SWorld) -> None:
    s = sworld
    p, p2 = s.provider(), s.provider()
    agent = s.agent(model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent)
    fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
    fb = s.post("owner", f"/incidents/{fid}/actions", {"action": "fail_back", "reason": REASON})
    assert fb.status_code == 200, fb.text
    failback = next(x for x in s.sagas(agent) if x["kind"] == "failback")
    view = s.get("owner", f"/incidents/{failback['id']}").json()
    assert "cancel" not in view["available_actions"]
    resp = s.post(
        "owner", f"/incidents/{failback['id']}/actions", {"action": "cancel", "reason": REASON}
    )
    assert resp.status_code == 409


def test_unexpected_step_error_takes_the_retry_path(
    sworld: SWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = sworld
    p, p2 = s.provider(), s.provider()
    agent = s.agent(model=s.model(p))
    s.plan(agent)
    s.chain(agent, [{"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)}])
    s.alert(agent)
    fid = s.run(runner.detect_tenant(s.worker_db, s.env(), s.a.id))[0]

    async def boom(conn: Any, env: Any, tenant: Any, row: Any) -> Any:
        await conn.execute("SELECT 1/0")  # a raw database error, not a SagaError

    monkeypatch.setitem(engine.STEP_FUNCTIONS, "validate", boom)
    progress = s.run(runner.run_saga(s.worker_db, s.env(), s.a.id, fid))
    assert progress[-1].status == "retry"
    row = s.saga(fid)
    assert row["attempt"] == 1 and row["error"] == "internal_error"


def _waiting_backup(s: SWorld, *, policy: str = "hold") -> dict[str, Any]:
    backup = s.agent(tier=2)
    agent = s.agent(tier=1, model=s.model(s.provider()))
    s.plan(agent, approval_timeout_policy=policy)
    s.chain(agent, [{"kind": "backup_agent", "backup_agent_id": backup}])
    s.alert(agent)
    fid = s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id)).detected[0]
    assert s.routing(agent)["state"] == "awaiting_approval"
    return {"agent": agent, "backup": backup, "fid": fid}


def test_approved_target_is_rechecked_and_refused_when_no_longer_viable(sworld: SWorld) -> None:
    s = sworld
    w = _waiting_backup(s)
    s.in_tenant(
        s.a,
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'quarantined', NULL, 'operator',"
        " 'human', $3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'backup broke', $4,"
        ' \'quarantine.applied\', \'{"cause": "test", "policy_violation_ids": []}\'::jsonb,'
        " NULL, NULL, NULL)",
        s.a.id,
        w["backup"],
        s.a.users["owner"],
        f"q:{w['backup']}",
    )
    resp = s.post(
        "approver", f"/incidents/{w['fid']}/actions", {"action": "approve", "reason": REASON}
    )
    assert resp.status_code == 409 and resp.json()["type"].endswith("/target_not_viable")
    assert s.routing(w["agent"])["state"] == "awaiting_approval"  # nothing moved


def test_fail_safe_to_a_dead_target_does_not_strand_awaiting_approval(sworld: SWorld) -> None:
    s = sworld
    w = _waiting_backup(s, policy="fail_safe")
    s.in_tenant(
        s.a,
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'killed', NULL, 'operator',"
        " 'human', $3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'backup killed', $4,"
        " 'override.by_human', NULL, NULL, NULL, NULL)",
        s.a.id,
        w["backup"],
        s.a.users["owner"],
        f"k:{w['backup']}",
    )
    saga = s.saga(w["fid"])
    s.admin.execute(
        "UPDATE sibyl.approval SET expires_at = now() - interval '1 s' WHERE id = $1",
        saga["approval_id"],
    )
    out = s.run(timeouts.run_tenant(s.worker_db, s.env("approvals:t"), s.a.id))
    assert [e.policy_applied for e in out] == ["fail_safe"]
    assert s.saga(w["fid"])["state"] == "failed"
    assert s.routing(w["agent"])["state"] == "degraded"


def test_break_glass_anchor_payload_names_the_reason(sworld: SWorld) -> None:
    s = sworld
    s.key("bg-anchor", s.a, ["killswitch:pull"])
    ks = _pull(s, "bg-anchor", "agent", s.agent())
    raw = s.val(
        "SELECT payload FROM sibyl.outbox WHERE tenant_id = $1 AND event_type = 'audit.anchor_now'"
        " AND aggregate_id = $2",
        s.a.id,
        UUID(ks["id"]),
    )
    payload = json.loads(raw) if isinstance(raw, str) else dict(raw)
    assert payload == {"reason": "break_glass", "kill_switch_id": ks["id"]}
    _release(s, ks)
