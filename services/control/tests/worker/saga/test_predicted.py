"""Lane P's entry ``open_predicted`` on PG17: tier gating, D39, D36, breaker, D21 hold."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.settings import Settings
from sibyl_control.worker.saga import PredictedTrigger, open_predicted, runner
from sibyl_lane_s_world import SWorld

STRONG = {
    "band": "0.90",
    "confidence": "medium",
    "contributing_rules": ("error_trend", "latency_trend"),
}


def _agent(s: SWorld, tier: int) -> dict[str, Any]:
    p, p2 = s.provider(), s.provider()
    agent = s.agent(tier=tier, model=s.model(p))
    s.plan(agent)
    s.chain(
        agent,
        [
            {"kind": "alt_provider", "provider_id": p2, "model_id": s.model(p2)},
            {"kind": "human_queue"},
        ],
    )
    return {"agent": agent, "p2": p2}


def _predict(s: SWorld, agent: UUID, *, band_gate: str = "0.90", **kw: Any) -> Any:
    trig = PredictedTrigger(agent_id=agent, prediction_id=uuid4(), **{**STRONG, **kw})

    async def go() -> Any:
        async with s.worker_db.tenant_tx(s.a.id) as conn:
            await conn.execute("SELECT sibyl.audit_lock($1)", s.a.id)
            return await open_predicted(conn, s.a.id, trig, env=s.env(automation_band=band_gate))

    return s.run(go())


def _prediction(s: SWorld, agent: UUID, band: str) -> None:
    s.admin.execute(
        "INSERT INTO sibyl.prediction (tenant_id, predicted_at, agent_id, health_snapshot_id,"
        " scoring_config_id, horizon_s, source, probability_band, confidence)"
        " VALUES ($1, now(), $2, $3, $4, 900, 'rules/v1', $5, 'medium')",
        s.a.id,
        agent,
        uuid4(),
        uuid4(),
        band,
    )


def _drive(s: SWorld) -> None:
    s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id))


def test_tier3_strong_prediction_fails_over_automatically(sworld: SWorld) -> None:
    s = sworld
    a = _agent(s, 3)
    out = _predict(s, a["agent"])
    assert out.action == "saga" and out.failover_id is not None
    _drive(s)
    saga = s.saga(out.failover_id)
    assert saga["kind"] == "preemptive" and saga["state"] == "done"
    assert s.routing(a["agent"])["target_provider_id"] == a["p2"]


def test_tier1_prediction_requests_approval_with_rule_requester(sworld: SWorld) -> None:
    s = sworld
    a = _agent(s, 1)
    out = _predict(s, a["agent"], band="0.60")
    assert out.action == "approval"
    _drive(s)
    saga = s.saga(out.failover_id)
    assert saga["state"] == "waiting_approval"
    approval = s.one("SELECT * FROM sibyl.approval WHERE id = $1", saga["approval_id"])
    assert approval["requested_by_kind"] == "rule"
    assert approval["requested_action"] == "alt_provider_failover"
    assert s.routing(a["agent"])["state"] == "awaiting_approval"


def test_tier2_degrade_then_auto_degrades_now_and_fails_over_after_persistence(
    sworld: SWorld,
) -> None:
    s = sworld
    a = _agent(s, 2)
    out = _predict(s, a["agent"])
    assert out.action == "degrade_then_auto"
    assert s.routing(a["agent"])["state"] == "degraded"
    saga = s.saga(out.failover_id)
    assert saga["state"] == "pending"
    _drive(s)  # still inside the 20 s pause: nothing runs
    assert s.saga(out.failover_id)["state"] == "pending"
    for _ in range(2):
        _prediction(s, a["agent"], "0.90")
    s.admin.execute(
        "UPDATE sibyl.failover SET next_action_at = now(), created_at = created_at - interval '1"
        " min'"
        " WHERE id = $1",
        out.failover_id,
    )
    _drive(s)
    assert s.saga(out.failover_id)["state"] == "done"
    assert s.routing(a["agent"])["state"] == "failed_over"


def test_tier2_prediction_that_does_not_persist_reverts_the_degrade(sworld: SWorld) -> None:
    s = sworld
    a = _agent(s, 2)
    out = _predict(s, a["agent"])
    s.admin.execute(
        "UPDATE sibyl.failover SET next_action_at = now() WHERE id = $1", out.failover_id
    )
    _drive(s)
    saga = s.saga(out.failover_id)
    assert saga["state"] == "cancelled" and saga["error"] == "prediction_not_persisted"
    assert s.routing(a["agent"])["state"] == "active"


@pytest.mark.parametrize("tier", [2, 3])
def test_d36_gate_keeps_060_at_degrade_only(
    sworld: SWorld, tier: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = sworld
    # The gate comes from Settings via the Env, never from a raw environment read.
    monkeypatch.setenv("SIBYL_PREDICTED_AUTOMATION_BAND", "0.60")
    a = _agent(s, tier)
    out = _predict(s, a["agent"], band="0.60")
    assert out.action == "degrade"
    assert s.saga(out.failover_id)["state"] == "done"
    assert s.routing(a["agent"])["state"] == "degraded"
    b = _agent(s, tier)
    out = _predict(s, b["agent"], band="0.60", band_gate="0.60")
    assert out.action == ("saga" if tier == 3 else "degrade_then_auto")
    assert s.results(out.failover_id)["open"]["prediction"]["persist_band"] == "0.60"


def test_worker_env_takes_the_band_and_ramp_from_settings() -> None:
    default = runner.worker_env(Settings(), wid="saga:t")
    assert (default.automation_band, default.failback_ramp) == ("0.90", False)
    tuned = runner.worker_env(
        Settings(predicted_automation_band="0.60", failback_ramp=True, demo=True), wid="saga:t"
    )
    assert (tuned.automation_band, tuned.failback_ramp, tuned.demo_mode) == ("0.60", True, True)
    assert tuned.worker_id == "saga:t"


def test_hold_suppresses_and_saga_in_flight_is_a_noop(sworld: SWorld) -> None:
    s = sworld
    a = _agent(s, 3)
    first = _predict(s, a["agent"])
    assert _predict(s, a["agent"]).reason == "saga_in_flight"
    _drive(s)
    assert s.saga(first.failover_id)["state"] == "done"
    b = _agent(s, 3)
    s.in_tenant(
        s.a,
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'active', NULL, 'operator',"
        " 'human', $3, NULL, NULL, NULL, NULL, NULL, NULL, now() + interval '30 minutes', NULL,"
        " 'hold', $4, 'override.by_human', NULL, NULL, NULL, NULL)",
        s.a.id,
        b["agent"],
        s.a.users["owner"],
        f"hold:{b['agent']}",
    )
    assert _predict(s, b["agent"]).action == "suppressed"


def test_weak_or_long_horizon_predictions_do_nothing(sworld: SWorld) -> None:
    s = sworld
    a = _agent(s, 3)
    assert _predict(s, a["agent"], horizon_s=3600).action == "none"
    assert _predict(s, a["agent"], band="0.25").action == "watch"
    assert s.routing(a["agent"])["state"] == "active"


def test_breaker_forces_approval_after_two_undone_automated_transitions(sworld: SWorld) -> None:
    s = sworld
    a = _agent(s, 3)
    for i in range(2):
        out = _predict(s, a["agent"])
        _drive(s)
        saga = s.saga(out.failover_id)
        t = saga["routing_transition_id"]
        s.in_tenant(
            s.a,
            "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'failed_over', 'active', NULL, 'undo',"
            " 'human', $3, NULL, NULL, NULL, NULL, NULL, $4, now() - interval '1 s', NULL,"
            " 'undo for test', $5,"
            " 'failover.undone', '{}'::jsonb, NULL, NULL, NULL)",
            s.a.id,
            a["agent"],
            s.a.users["owner"],
            t,
            f"undo:{t}:{i}",
        )
    out = _predict(s, a["agent"])
    assert out.action == "approval"
