"""Deterministic scenarios against PG17: synthetic events -> rollup -> scoring (as sibyl_worker).

Each scenario warms an agent with healthy traffic, injects a failure, and asserts the score,
factors, band timeline, alert fire/resolve timing and outbox messages tick by tick.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.core.canonical import thaw
from sibyl_schemas.models._event_parts import HealthTransitionAttrs
from sibyl_schemas.models.health import Factor

from .h_sim import TICK, Sim
from .h_testkit import Kit, calls, tool_calls

PER_TICK = 6  # requests per agent per 10 s: 180 per 5 min, well above min_samples


def healthy(*agents: UUID, n: int = PER_TICK, **kw: Any) -> Callable[[datetime], list[dict]]:
    return lambda ts: [e for a in agents for e in calls(a, ts, n, spread_s=9.5, **kw)]


def failing(*agents: UUID, n: int = PER_TICK) -> Callable[[datetime], list[dict]]:
    return lambda ts: [e for a in agents for e in calls(a, ts, n, errors=n, spread_s=9.5)]


def warm(sim: Sim, traffic: Callable[[datetime], list[dict]], ticks: int = 12) -> None:
    sim.run(ticks, traffic)


def snapshots(kit: Kit, tenant: UUID, agent: UUID) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in kit.q(
            "SELECT * FROM sibyl.health_snapshot WHERE tenant_id = $1 AND agent_id = $2 "
            "ORDER BY evaluated_at",
            tenant,
            agent,
        )
    ]


def test_hard_outage_tier1_fails_fast_alerts_and_recovers(kit: Kit) -> None:
    t = kit.tenant()
    kit.provider(t)
    a = kit.agent(t, tier=1)
    sim = Sim(kit, t)
    warm(sim, healthy(a))
    assert sim.results[-1].evaluations[a].band == "healthy"
    assert sim.results[-1].evaluations[a].score == 100
    assert not sim.results[-1].evaluations[a].provisional

    outage = sim.run(4, failing(a))
    bands = sim.bands(a, outage)
    assert bands[0] == "healthy" and bands[1] == "failed", "tier 1 worsens after 2 ticks"
    ev = outage[1].evaluations[a]
    rules = {f["rule"] for f in ev.factors if f["penalty"] > 0}
    assert "consecutive_failures" in rules
    assert ev.recommended_action == "reroute_to_fallback"
    assert outage[2].evaluations[a].very_fast

    fired = {x["code"]: x for x in sim.alerts(a)}
    assert set(fired) >= {"consecutive_failures", "error_rate"}
    assert fired["consecutive_failures"]["first_fired_at"] == sim.now - 4 * TICK, "h_in = 1"
    assert fired["error_rate"]["severity"] == "critical", "failed band = very-fast pair"
    assert all(x["state"] == "open" and x["verdict"] is None for x in fired.values())

    transitions = sim.outbox.of("health.transition")
    to_failed = [m for m in transitions if m.payload["to_status"] == "failed"]
    assert len(to_failed) == 1
    attrs = thaw(to_failed[0].payload)  # G0: outbox payloads are frozen (tuples)
    attrs.pop("agent_id")
    HealthTransitionAttrs.model_validate(attrs)

    recovery = sim.run(60, healthy(a))
    rb = sim.bands(a, recovery)
    assert rb[-1] == "healthy"
    first_healthy = rb.index("healthy")
    assert first_healthy >= 18, "tier 1 improves only after 18 clean ticks"
    alerts = sim.alerts(a)
    assert {x["state"] for x in alerts} == {"resolved"}
    assert all(x["verdict"] is None and x["outcome_observed"] == "recovered" for x in alerts)
    assert all(not x["verdict_wanted"] for x in alerts), "no routing transition while open"
    assert len(sim.outbox.of("alert.resolved")) == len(alerts)
    audit = kit.q(
        "SELECT count(*) AS n FROM sibyl.audit_events WHERE tenant_id = $1 AND action = "
        "'alert.fired'",
        t,
    )
    assert audit[0]["n"] == len(alerts)


def test_latency_creep_tier2_degrades_on_p95(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=2)
    sim = Sim(kit, t)
    warm(sim, healthy(a))
    for latency in (12000, 18000, 26000, 34000, 60000, 60000):
        sim.run(6, healthy(a, latency_ms=latency))
    ev = sim.results[-1].evaluations[a]
    p95 = next(f for f in ev.factors if f["rule"] == "p95_latency")
    assert p95["threshold"] == 20000 and p95["penalty"] == 25, "saturates at 2t for tier 2"
    assert ev.score == 75 and ev.band == "watch"
    assert "large-model threshold" in p95["explanation"]
    assert any(x["code"] == "p95_latency" for x in sim.alerts(a))


def test_refusal_spike_tier1_scores_through_quality_proxy_and_alerts_r6(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=1)
    sim = Sim(kit, t)
    warm(sim, healthy(a))

    def refusing(ts: datetime) -> list[dict]:
        return calls(a, ts, PER_TICK, spread_s=9.5, attrs={"finish_reasons": ["content_filter"]})

    spike = sim.run(40, refusing)
    ev = spike[-1].evaluations[a]
    pens = {f["rule"]: f["penalty"] for f in ev.factors}
    assert pens["quality_proxy"] == 25 and pens["refusal_share"] == 0
    assert ev.score == 75 and ev.band == "watch"
    assert ev.recommended_action == "handoff", "tier 1 quality -> handoff"
    r6 = [x for x in sim.alerts(a) if x["code"] == "refusal_share"]
    assert len(r6) == 1 and r6[0]["severity"] == "warning"
    assert not [x for x in sim.alerts(a) if x["code"] == "quality_proxy"], "score-only"
    fired_tick = next(
        i for i, r in enumerate(spike) if "refusal_share" in r.evaluations[a].newly_fired
    )
    first_breach = next(
        i for i, r in enumerate(spike) if r.evaluations[a].outcomes["refusal_share"].severity > 0
    )
    assert fired_tick - first_breach == 5, "R6 hysteresis_in is 6 ticks"


def test_snapshots_are_written_on_change_plus_60s_heartbeat(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=3)
    sim = Sim(kit, t)
    warm(sim, healthy(a), ticks=12)
    start = sim.now
    sim.run(12, healthy(a))
    rows = [r for r in snapshots(kit, t, a) if r["evaluated_at"] >= start]
    assert [r["write_reason"] for r in rows] == ["heartbeat", "heartbeat"]
    gap = rows[1]["evaluated_at"] - rows[0]["evaluated_at"]
    assert gap == timedelta(seconds=60)


def test_every_health_snapshot_references_a_recent_frozen_feature_snapshot(kit: Kit) -> None:
    """B-04 (sibyl-health/1 requires ``feature_snapshot_ref``): every health snapshot carries
    the agent's latest frozen feature snapshot, at most one sample interval (30 ticks, R49's
    1-in-30) old; quiet agents get a ``sample`` snapshot every 300 s and no more."""
    t = kit.tenant()
    a = kit.agent(t, tier=3)
    sim = Sim(kit, t)
    warm(sim, healthy(a), ticks=12)
    sim.run(48, healthy(a))  # 600 s in all
    fs = {
        r["id"]: r
        for r in kit.q(
            "SELECT id, as_of, reason FROM sibyl.feature_snapshot WHERE tenant_id = $1"
            " AND agent_id = $2",
            t,
            a,
        )
    }
    rows = snapshots(kit, t, a)
    assert len(rows) >= 10
    for row in rows:
        ref = fs[row["feature_snapshot_id"]]  # never null, never dangling
        age = row["evaluated_at"] - ref["as_of"]
        assert timedelta(0) <= age < timedelta(seconds=300), (row["evaluated_at"], ref)
    samples = [r for r in fs.values() if r["reason"] == "sample"]
    assert 1 <= len(samples) <= 3, len(samples)


def test_every_written_snapshot_explains_its_score(kit: Kit) -> None:
    t = kit.tenant()
    a, b = kit.agent(t, tier=1), kit.agent(t, tier=3)
    sim = Sim(kit, t)
    warm(sim, healthy(a, b))
    sim.run(6, failing(a, b))
    sim.run(4, healthy(a, b))
    rows = snapshots(kit, t, a) + snapshots(kit, t, b)
    assert len(rows) > 4
    for row in rows:
        api = [f for f in row["factors"] if not f["rule"].startswith("_")]
        clamp = sum(f["penalty"] for f in row["factors"] if f["rule"] == "_clamp")
        assert 100 - sum(f["penalty"] for f in api) + clamp == row["score"]
        for f in api:
            Factor.model_validate(f)
        assert any(f["rule"] == "_hysteresis" for f in row["factors"])
        assert row["scoring_config_id"] is not None


def test_cooldown_reopens_the_same_alert_row(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=3)
    sim = Sim(kit, t)
    warm(sim, healthy(a))
    burst = lambda ts: calls(a, ts, PER_TICK, errors=PER_TICK, spread_s=9.5)  # noqa: E731
    sim.run(1, burst)  # R3 tier 3: t=5, 6 errors in a row -> fires (h_in 1)
    sim.run(7, healthy(a))  # out 6 -> resolves
    r3 = [x for x in sim.alerts(a) if x["code"] == "consecutive_failures"]
    assert len(r3) == 1 and r3[0]["state"] == "resolved"
    sim.run(1, burst)
    r3 = [x for x in sim.alerts(a) if x["code"] == "consecutive_failures"]
    assert len(r3) == 1, "inside the 900 s cooldown the row re-opens"
    assert r3[0]["state"] == "open" and r3[0]["fired_count"] == 2
    assert r3[0]["severity"] == "warning" and r3[0]["escalation_level"] == 0
    sim.run(7, healthy(a))
    sim.run(1, burst)  # third fire inside escalate_window_s: one step up (sre §2.2)
    r3 = [x for x in sim.alerts(a) if x["code"] == "consecutive_failures"]
    assert len(r3) == 1 and r3[0]["fired_count"] == 3
    assert r3[0]["escalation_level"] == 1 and r3[0]["severity"] == "critical"
    assert len(sim.outbox.of("alert.fired")) >= 3


def test_provider_collapse_opens_one_incident_and_resolves_with_members(kit: Kit) -> None:
    t = kit.tenant()
    kit.provider(t)
    agents = [kit.agent(t, tier=3) for _ in range(4)]
    sim = Sim(kit, t)
    warm(sim, healthy(*agents))
    sim.run(8, failing(*agents))
    incidents = kit.q("SELECT * FROM sibyl.provider_incident WHERE tenant_id = $1", t)
    assert len(incidents) == 1 and incidents[0]["state"] == "open"
    assert set(incidents[0]["affected_agent_ids"]) == set(agents)
    members = [x for x in sim.alerts() if x["provider_incident_id"] == incidents[0]["id"]]
    assert members and all(x["suppressed_by_incident"] for x in members)
    assert len(sim.outbox.of("provider_incident.opened")) == 1
    sim.run(45, healthy(*agents))
    incident = kit.q("SELECT state FROM sibyl.provider_incident WHERE tenant_id = $1", t)[0]
    assert incident["state"] == "resolved"
    assert {x["state"] for x in sim.alerts()} == {"resolved"}
    assert len(sim.outbox.of("provider_incident.resolved")) == 1


def test_small_toolset_across_many_tasks_is_not_a_loop(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=2)
    sim = Sim(kit, t)
    warm(sim, healthy(a))

    def busy(ts: datetime) -> list[dict]:
        return healthy(a)(ts) + [
            e for _ in range(5) for e in tool_calls(a, ts, ["lookup", "search"])
        ]

    sim.run(12, busy)
    ev = sim.results[-1].evaluations[a]
    assert ev.outcomes["tool_loop"].severity == 0 and ev.band == "healthy"


def test_lone_agent_does_not_collapse(kit: Kit) -> None:
    t = kit.tenant()
    kit.provider(t)
    agents = [kit.agent(t, tier=3) for _ in range(5)]
    sim = Sim(kit, t)
    warm(sim, healthy(*agents))
    sim.run(6, lambda ts: failing(agents[0])(ts) + healthy(*agents[1:])(ts))
    assert kit.q("SELECT * FROM sibyl.provider_incident WHERE tenant_id = $1", t) == []


def test_provider_major_outage_r4_is_one_provider_alert_and_incident(kit: Kit) -> None:
    t = kit.tenant()
    p = kit.provider(t)
    agents = [kit.agent(t, tier=2) for _ in range(2)]
    sim = Sim(kit, t)
    warm(sim, healthy(*agents))
    kit.in_tenant(
        t,
        "INSERT INTO sibyl.provider_status (tenant_id, provider_id, source, status, "
        "observed_at) VALUES ($1, $2, 'status_feed', 'major_outage', $3)",
        t,
        p,
        sim.now,
    )
    sim.run(3, healthy(*agents))
    r4 = [x for x in sim.alerts() if x["code"] == "provider_status"]
    assert len(r4) == 1 and r4[0]["scope"] == "provider" and r4[0]["provider_id"] == p
    ev = sim.results[-1].evaluations[agents[0]]
    r4f = [f for f in ev.factors if f["rule"] == "provider_status"]
    # S-16 (ML §8.2): the agents' own traffic is clean, so the page is status-only evidence:
    # a leading-facet penalty (partial_outage ordinal), no floor, band watch on tier 2
    assert [(f["penalty"], f["kind"]) for f in r4f] == [(35, "leading")]
    assert ev.score == 65 and ev.target_band == "watch" and ev.floor is None
    assert ev.band in ("healthy", "watch"), "band hysteresis may still be entering watch"
    incident = kit.q("SELECT * FROM sibyl.provider_incident WHERE tenant_id = $1", t)
    assert len(incident) == 1 and incident[0]["provider_status_id"] is not None
    kit.in_tenant(
        t,
        "INSERT INTO sibyl.provider_status (tenant_id, provider_id, source, status, "
        "observed_at) VALUES ($1, $2, 'status_feed', 'operational', $3)",
        t,
        p,
        sim.now,
    )
    sim.run(8, healthy(*agents))
    assert (
        kit.q("SELECT state FROM sibyl.provider_incident WHERE tenant_id = $1", t)[0]["state"]
        == "resolved"
    )
    assert [x["state"] for x in sim.alerts() if x["code"] == "provider_status"] == ["resolved"]


def test_killed_agent_resolves_its_alerts_as_unknown(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=2)
    sim = Sim(kit, t)
    warm(sim, healthy(a))
    sim.run(4, failing(a))
    assert any(x["state"] == "open" for x in sim.alerts(a))
    kit.exe(
        "UPDATE sibyl.routing_state SET state = 'killed' WHERE tenant_id = $1 AND agent_id = $2",
        t,
        a,
    )
    sim.run(1, failing(a))
    alerts = sim.alerts(a)
    assert alerts and all(
        x["state"] == "resolved" and x["outcome_observed"] == "unknown" for x in alerts
    )


def test_tool_loop_and_schema_failures(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=2)
    sim = Sim(kit, t)
    warm(sim, healthy(a))

    task = uuid4()  # one task stuck calling the same tool

    def looping(ts: datetime) -> list[dict]:
        return healthy(a)(ts) + tool_calls(a, ts, ["search"] * 10, bad=6, task=task)

    sim.run(20, looping)
    ev = sim.results[-1].evaluations[a]
    pens = {f["rule"]: f["penalty"] for f in ev.factors}
    assert pens["tool_loop"] >= 24 and pens["quality_proxy"] == 20, "repeat ratio ~0.98"
    assert ev.recommended_action == "quarantine"
    codes = {x["code"] for x in sim.alerts(a)}
    assert {"tool_loop", "schema_fail_share"} <= codes


def test_new_agent_without_plan_is_provisional_and_capped(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=1, plan=False)
    sim = Sim(kit, t)
    warm(sim, healthy(a), ticks=6)
    sim.run(5, failing(a))
    ev = sim.results[-1].evaluations[a]
    assert ev.provisional and ev.band == "watch" and ev.score < 45
    assert all(x["severity"] != "critical" for x in sim.alerts(a))


def test_heartbeat_missing_r9_with_declared_cadence(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=2)
    kit.exe("UPDATE sibyl.continuity_plan SET expected_cadence_s = 30 WHERE agent_id = $1", a)
    sim = Sim(kit, t)
    warm(sim, healthy(a))
    sim.run(12)  # silence: no traffic for two minutes
    ev = sim.results[-1].evaluations[a]
    assert ev.outcomes["heartbeat_missing"].severity == 1
    assert {f["rule"]: f["penalty"] for f in ev.factors}["heartbeat_missing"] == 20
    assert any(x["code"] == "heartbeat_missing" for x in sim.alerts(a))


def test_alert_that_saw_an_automated_degrade_resolves_with_verdict_wanted(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=3)
    sim = Sim(kit, t)
    warm(sim, healthy(a))
    sim.run(4, failing(a))
    rule = kit.q("SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = 'error_rate'", t)[
        0
    ]["id"]
    kit.in_tenant(
        t,
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'degraded', NULL, 'rule', "
        "'rule', NULL, $3, ARRAY['error_rate'], NULL, NULL, NULL, NULL, NULL, NULL, NULL, $4, "
        "'route.changed', NULL, NULL, NULL, NULL)",
        t,
        a,
        rule,
        f"degrade:{a}",
    )
    sim.run(45, healthy(a))
    alerts = sim.alerts(a)
    assert alerts and all(x["state"] == "resolved" for x in alerts)
    assert all(x["verdict_wanted"] and x["verdict"] is None for x in alerts)


def test_burst_just_before_a_minute_boundary_is_seen(kit: Kit) -> None:
    """Regression: the last-minute gate must include the bucket containing now - 60 s."""
    t = kit.tenant()
    a = kit.agent(t, tier=3)
    start = datetime.now(UTC).replace(second=3, microsecond=0) - timedelta(minutes=40)
    sim = Sim(kit, t, now=start)
    warm(sim, healthy(a))
    assert sim.now.second == 3
    sim.run(1, lambda ts: calls(a, ts, PER_TICK, errors=PER_TICK, spread_s=6.5))
    ev = sim.results[-1].evaluations[a]
    assert ev.outcomes["consecutive_failures"].value == PER_TICK
    assert "consecutive_failures" in ev.newly_fired
