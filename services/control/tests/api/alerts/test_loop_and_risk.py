"""Cross-checks with the worker side: a silence set through the API expires through the alert
loop, and lane V's risk read serves the horizons lane P writes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from sibyl_control.core.outbox import InMemoryOutboxWriter
from sibyl_control.core.risk import RiskDocument
from sibyl_control.worker.alerts import run_tenant
from sibyl_control.worker.predict.horizons import predict_horizons
from sibyl_control.worker.predict.leading import evaluate_leading

from .test_alerts import NOW, act, alert, get, tok


def _p_inputs() -> Any:
    import importlib.util
    import sys
    from pathlib import Path

    name = "sibyl_lane_p_inputs"
    if name not in sys.modules:
        path = Path(__file__).resolve().parents[2] / "worker" / "predict" / "p_inputs.py"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


_P = _p_inputs()
feed, headroom_ramp, inputs, run_ticks, seed_config = (
    _P.feed,
    _P.headroom_ramp,
    _P.inputs,
    _P.run_ticks,
    _P.seed_config,
)


def test_silence_expires_through_the_alert_loop(lane: Any, world: Any) -> None:
    w = world
    aid = alert(lane.db, w, agent=w.agents["in_g1"])
    owner = tok(lane, w, "owner")
    until = (datetime.now(UTC) + timedelta(minutes=5)).replace(microsecond=0)
    assert (
        act(lane, owner, aid, {"action": "silence", "until": until.isoformat()}).status_code == 200
    )

    async def loop(now: datetime) -> Any:
        conn = lane.db.admin.raw
        async with conn.transaction():
            await conn.execute("SELECT sibyl.set_tenant($1)", w.tenant)
            return await run_tenant(conn, w.tenant, now, InMemoryOutboxWriter())

    assert lane.db.admin.run(loop(until - timedelta(seconds=1))).reopened == []
    assert lane.db.admin.run(loop(until + timedelta(seconds=1))).reopened == [aid]
    body = get(lane, owner, f"/alerts/{aid}").json()
    assert (body["state"], body["silenced_until"], body["fired_count"]) == ("open", None, 2)


def _risk_snapshot(lane: Any, w: Any, agent: UUID) -> None:
    cfg = seed_config()
    f = feed(headroom=headroom_ramp(0.10, 0.06))
    inp = inputs(tier=1, headroom=0.10)
    ev = run_ticks(inp, cfg, lambda i, c, n: evaluate_leading(i, f, c, n), 13)
    doc, mode = predict_horizons(inp, ev, cfg, NOW, f)
    with lane.db.admin.tx(w.tenant):
        config = lane.db.admin.fetchval(
            "SELECT id FROM sibyl.scoring_config WHERE tenant_id = $1 LIMIT 1", w.tenant
        )
        lane.db.admin.execute(
            "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, agent_id, score, band,"
            " provisional, events_seen, observation_coverage, factors, horizons,"
            " predicted_failure_mode, recommended_action, scoring_config_id, policy_version,"
            " routing_state_at, window_start, window_end, grain_s)"
            " VALUES ($1, now(), $2, 80, 'watch', false, 300, 1, '[]', $3::jsonb, $4, 'throttle',"
            " $5, 1, 'active', now() - interval '5 minutes', now(), 300)",
            w.tenant,
            agent,
            doc,
            mode,
            config,
        )


def test_risk_read_serves_lane_p_horizons(lane: Any, world: Any) -> None:
    w = world
    _risk_snapshot(lane, w, w.agents["in_g1"])
    body = get(lane, tok(lane, w, "owner"), f"/agents/{w.agents['in_g1']}/risk").json()
    assert body["horizons"]["15m"]["probability_band"] == "0.25"
    assert body["horizons"]["15m"]["horizon_s"] == 900
    assert body["leading_rules_firing"] == ["ratelimit_proximity"]
    assert body["predicted_failure_mode"] == "provider_outage"
    assert body["rules_source"] == "rules/v1"


@pytest.mark.xfail(
    strict=False,
    raises=Exception,
    reason="CR (lane V / INT-1): getAgentRisk copies sibyl-health/1 keys (source, "
    "predicted_failure_mode) into RiskHorizon, whose frozen type forbids extras",
)
def test_risk_read_validates_against_the_frozen_risk_document(lane: Any, world: Any) -> None:
    w = world
    _risk_snapshot(lane, w, w.agents["in_g1"])
    body = get(lane, tok(lane, w, "owner"), f"/agents/{w.agents['in_g1']}/risk").json()
    RiskDocument.model_validate(body)
