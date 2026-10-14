"""The drift tick on PG17 as ``sibyl_worker``: discovery, freeze, evaluation, reports,
hysteresis, ``silent_drift`` / ``model_change`` alerts (leading, never a saga), retention, and
the ``drift_cusum`` feed."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from sibyl_control.worker import loops
from sibyl_control.worker.drift import factor
from sibyl_control.worker.scoring.config import EngineConfig
from sibyl_control.worker.scoring.extensions import registered
from sibyl_drift_kit import NORMAL, Profile, Traffic, make_traffic
from sibyl_lane_s_world import SWorld

H = timedelta(hours=1)


@pytest.fixture(scope="module")
def traffic(sworld: SWorld) -> Traffic:
    return make_traffic(sworld)


def _baseline_traffic(t: Traffic, agent: UUID, end: datetime) -> None:
    t.period(agent, end - H, end, 400, seed=1, tasks=60)


def _codes(alerts: list[Any], state: str | None = None) -> list[str]:
    return [a["code"] for a in alerts if state is None or a["state"] == state]


def test_lifecycle_freeze_drift_alert_and_recovery(traffic: Traffic, sworld: SWorld) -> None:
    t = traffic
    agent = t.agent()
    now = t.now()
    t0 = now - 5 * H
    _baseline_traffic(t, agent, t0)
    drifted = Profile(out_mu=700, refusal=0.15, served="gpt-4o-mini-2024-07-18", fingerprint="fp_z")
    t.period(agent, t0, t0 + H, 200, drifted, seed=2)
    t.period(agent, t0 + H, t0 + 2 * H, 200, drifted, seed=3)
    t.period(agent, t0 + 2 * H, t0 + 3 * H, 200, NORMAL, seed=4)
    t.period(agent, t0 + 3 * H, t0 + 4 * H, 200, NORMAL, seed=5)

    first = t.run(t0)
    [baseline] = t.baselines(agent)
    assert baseline["id"] in first.created and baseline["id"] in first.frozen
    assert baseline["state"] == "frozen" and baseline["sample_count"] == 400
    assert list(baseline["served_models"]) == ["gpt-4o-2024-08-06"]
    assert list(baseline["fingerprints"]) == ["fp_a"]
    features = json.loads(baseline["features"])
    assert features["output_tokens"]["kind"] == "numeric"
    assert features["tool_bigram"]["probs"] == {"fetch>answer": 0.5, "search>fetch": 0.5}
    assert t.reports(agent) == []  # frozen this tick, evaluated from the next

    second = t.run(t0 + H)
    [report] = t.reports(agent)
    assert report["id"] in second.reports
    assert report["verdict"] == "drift" and report["behaviour_evaluated"]
    by_feature = {f["feature"]: f for f in json.loads(report["features"])}
    assert by_feature["output_tokens"]["statistic"] == "psi"
    assert by_feature["output_tokens"]["verdict"] == "drift"
    assert by_feature["refusal"]["statistic"] == "js"
    assert by_feature["input_tokens"]["verdict"] == "none"
    identity = {(i["kind"], i["value"]) for i in json.loads(report["identity"])}
    assert identity == {
        ("served_model_mismatch", "gpt-4o-mini-2024-07-18"),
        ("new_fingerprint", "fp_z"),
    }
    # identity raises at once; behaviour waits for a second drift verdict (raise_after = 2)
    alerts = t.alerts(agent)
    assert _codes(alerts, "open") == ["model_change"]
    assert alerts[0]["kind"] == "leading" and alerts[0]["severity"] == "warning"
    evidence = json.loads(alerts[0]["evidence"])
    assert evidence["watch_only"] and evidence["report_id"] == str(report["id"])

    head = sworld.head(sworld.a)
    t.run(t0 + 2 * H)
    assert sorted(_codes(t.alerts(agent), "open")) == ["model_change", "silent_drift"]
    assert sworld.audit_actions(sworld.a, head) == ["alert.fired"]
    drift_alert = next(a for a in t.alerts(agent) if a["code"] == "silent_drift")
    assert "output_tokens" in drift_alert["summary"]
    assert json.loads(drift_alert["evidence"])["link"].startswith("/api/v1/drift/reports/")
    # never a saga: drift alerts are leading and cap 0
    assert sworld.val("SELECT count(*) FROM sibyl.failover WHERE agent_id = $1", agent) == 0

    t.run(t0 + 3 * H)
    assert sorted(_codes(t.alerts(agent), "open")) == ["model_change", "silent_drift"]
    t.run(t0 + 4 * H)
    assert _codes(t.alerts(agent), "open") == []
    assert sorted(_codes(t.alerts(agent), "resolved")) == ["model_change", "silent_drift"]
    events = sworld.rows(
        "SELECT event_type FROM sibyl.outbox WHERE tenant_id = $1 AND topic = 'alert'"
        " AND payload->>'agent_id' = $2 ORDER BY created_at",
        sworld.a.id,
        str(agent),
    )
    assert [e["event_type"] for e in events] == [
        "alert.fired",
        "alert.fired",
        "alert.resolved",
        "alert.resolved",
    ]
    verdicts = [r["verdict"] for r in t.reports(agent)]
    assert verdicts[:2] == ["drift", "drift"] and "drift" not in verdicts[2:]
    # every feature row shows its numbers: statistic, value, noise floor, thresholds, samples
    sample = json.loads(t.reports(agent)[-1]["features"])[0]
    assert {"value", "noise_floor", "excess", "watch", "drift", "n_baseline", "n_window"} <= set(
        sample
    )


def test_not_due_and_quiet_agents(traffic: Traffic) -> None:
    t = traffic
    agent = t.agent()
    now = t.now()
    t0 = now - 3 * H
    _baseline_traffic(t, agent, t0)
    t.run(t0)
    assert t.baselines(agent)[0]["state"] == "frozen"
    t.run(t0 + H)  # no calls after the freeze: nothing to compare, streaks untouched
    assert t.reports(agent) == []
    assert t.baselines(agent)[0]["last_evaluated_at"] is not None
    t.period(agent, t0 + H, t0 + 2 * H, 200, NORMAL, seed=9)
    t.run(t0 + 2 * H)
    t.run(t0 + 2 * H + timedelta(minutes=1))  # inside eval_every: not evaluated again
    [report] = t.reports(agent)
    assert report["verdict"] == "none"


def test_collecting_until_enough_samples(traffic: Traffic) -> None:
    t = traffic
    agent = t.agent()
    now = t.now()
    t.period(agent, now - H, now, 100, seed=11, tasks=0)
    result = t.run(now)
    [baseline] = t.baselines(agent)
    assert baseline["state"] == "collecting" and baseline["id"] in result.created
    assert not result.frozen
    t.run(now)  # discovery is idempotent: still one current baseline
    assert len(t.baselines(agent)) == 1


def test_disabled_rule_raises_nothing(traffic: Traffic, sworld: SWorld) -> None:
    t = traffic
    agent = t.agent()
    now = t.now()
    t0 = now - 2 * H
    _baseline_traffic(t, agent, t0)
    t.period(agent, t0, t0 + H, 200, Profile(served="o3-2025-04-16"), seed=12)
    t.run(t0)
    sworld.admin.execute(
        "UPDATE sibyl.alert_rule SET enabled = false WHERE tenant_id = $1"
        " AND code = 'model_change'",
        sworld.a.id,
    )
    try:
        t.run(t0 + H)
    finally:
        sworld.admin.execute(
            "UPDATE sibyl.alert_rule SET enabled = true WHERE tenant_id = $1"
            " AND code = 'model_change'",
            sworld.a.id,
        )
    assert t.reports(agent)[0]["identity_changed"]
    assert t.alerts(agent) == []


def test_rules_are_seeded_once_as_watch_only(traffic: Traffic, sworld: SWorld) -> None:
    traffic.run(traffic.now())
    traffic.run(traffic.now())
    rows = sworld.rows(
        "SELECT code, kind, penalty, thresholds FROM sibyl.alert_rule WHERE tenant_id = $1"
        " AND code IN ('silent_drift', 'model_change') ORDER BY code",
        sworld.a.id,
    )
    assert [(r["code"], r["kind"], r["penalty"]) for r in rows] == [
        ("model_change", "leading", 0),
        ("silent_drift", "leading", 0),
    ]
    for r in rows:
        thresholds = json.loads(r["thresholds"])
        assert thresholds["watch_only"] is True
        assert {t["cap"] for t in thresholds["tiers"].values()} == {0}


def test_retention_purges_old_reports(traffic: Traffic, sworld: SWorld) -> None:
    t = traffic
    agent = t.agent()
    now = t.now()
    _baseline_traffic(t, agent, now)
    t.run(now)
    [baseline] = t.baselines(agent)
    sworld.admin.execute(
        "INSERT INTO sibyl.drift_report (tenant_id, baseline_id, agent_id, provider, model,"
        " evaluated_at, window_start, window_end, sample_count, verdict, behaviour_evaluated,"
        " features) VALUES ($1, $2, $3, 'openai', 'gpt-4o', now() - interval '40 days',"
        " now() - interval '41 days', now() - interval '40 days', 1, 'none', false, '[]')",
        sworld.a.id,
        baseline["id"],
        agent,
    )
    assert t.run(now).purged >= 1
    assert all(r["evaluated_at"] > now - timedelta(days=30) for r in t.reports(agent))


def test_drift_cusum_feed(traffic: Traffic, sworld: SWorld) -> None:
    t = traffic
    agent = t.agent()
    now = t.now()
    t0 = now - 2 * H
    _baseline_traffic(t, agent, t0)
    t.period(agent, t0, t0 + H, 200, Profile(out_mu=800), seed=21)
    t.run(t0)
    t.run(t0 + H)

    async def feed() -> factor.DriftFeed:
        async with sworld.worker_db.tenant_tx(sworld.a.id) as conn:
            return await factor.load_feed(conn, sworld.a.id, t0 + H)

    loaded = sworld.run(feed())
    drift = loaded.agents[agent]
    assert (drift.verdict, drift.severity) == ("drift", 0.5)
    assert drift.ratio > 1.0 and drift.model == "gpt-4o"


def test_the_loop_is_registered_and_composes_with_lane_p() -> None:
    spec = next(s for s in loops.LOOPS if s.name == "drift")
    assert loops.resolve_tick(spec) is not None and spec.interval_s == 60
    factor.install()
    ext = registered()
    assert getattr(ext.leading, "_sibyl_drift_composed", False)
    assert getattr(ext.prepare, "_sibyl_drift_composed", False)
    assert ext.horizons is not None  # lane P's predictor is untouched
    factor.install()  # idempotent
    assert registered().leading is ext.leading


def test_compose_appends_drift_cusum_watch_only() -> None:
    from sibyl_control.migrate.rules_seed import load

    cfg = EngineConfig.from_seed(load())
    assert cfg.rule("drift_cusum").cap(1) == 0  # watch-only by the seed
    now = datetime(2026, 10, 12, 12, 0, 0).astimezone()
    agent = UUID(int=7)
    drift = factor.AgentDrift("watch", 0.25, 0.6, "openai", "gpt-4o", now)
    out = factor.outcome(drift, cfg)
    assert out is not None and out.alert_only and out.kind == "leading"
    assert factor.outcome(None, cfg) is None
    assert factor.outcome(factor.AgentDrift("none", 0.0, 0, "", "m", now), cfg) is None

    calls: list[str] = []

    async def prev_prepare(conn: Any, tenant: UUID, now_: datetime) -> str:
        calls.append("prepare")
        return "p"

    def prev_leading(inputs: Any, config: Any, now_: datetime) -> list[Any]:
        return []

    leading, _prepare = factor.compose(prev_leading, prev_prepare)
    token = factor._CURRENT.set(
        factor.DriftFeed(UUID(int=1), now, {agent: drift})  # type: ignore[arg-type]
    )
    try:
        inputs = type("I", (), {"agent_id": agent})()
        [got] = leading(inputs, cfg, now)
        assert got.code == "drift_cusum" and got.severity == 0.25
        assert leading(type("I", (), {"agent_id": UUID(int=8)})(), cfg, now) == []
        assert factor.current(agent, now + timedelta(minutes=5)) is None  # stale feed
    finally:
        factor._CURRENT.reset(token)
    assert (
        factor.worst(
            [
                {
                    "agent_id": agent,
                    "verdict": "watch",
                    "max_ratio": 0.5,
                    "provider": "p",
                    "model": "a",
                    "evaluated_at": now,
                },
                {
                    "agent_id": agent,
                    "verdict": "drift",
                    "max_ratio": 1.2,
                    "provider": "p",
                    "model": "b",
                    "evaluated_at": now,
                },
            ]
        )[agent].model
        == "b"
    )


def test_tick_runs_every_active_tenant(traffic: Traffic, sworld: SWorld) -> None:
    import logging

    from sibyl_control.worker import drift
    from sibyl_control.worker.loops import LoopContext

    agent = traffic.agent()
    now = traffic.now()
    traffic.period(agent, now - H, now, 50, NORMAL, seed=51, tasks=0)
    ctx = LoopContext("drift", sworld.worker_db, None, logging.getLogger("drift-test"))
    sworld.run(drift.tick(ctx))
    assert [b["state"] for b in traffic.baselines(agent)] == ["collecting"]
