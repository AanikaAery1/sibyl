"""The live detection gap against PG17 (events -> rollup -> scoring, as sibyl_worker).

1. Cold start: a tier-3 agent a few minutes old that served healthy traffic and then hit a hard
   outage only reached ``watch`` on the demo stack (provisional cap). With a proven baseline the
   failure floor must reach ``failed`` with a critical alert; an agent failing since its first
   call stays capped.
2. Inline fallback: calls the gateway rescued on the fallback step are stored under the fallback
   provider. They must still be attributed to the agent's primary, or a primary outage declared
   on the status page (R4) never reaches the agents it hides behind the fallback.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.worker.scoring.store import load_tenant

from .h_sim import Sim
from .h_testkit import Kit, calls

PER_TICK = 6
FALLBACK = "fallback-two"
RESCUED = {"retry": {"attempt": 3, "inline_fallback_used": True}}


def healthy(agent: UUID, **kw: Any) -> Callable[[datetime], list[dict]]:
    return lambda ts: calls(agent, ts, PER_TICK, spread_s=9.5, **kw)


def failing(agent: UUID) -> Callable[[datetime], list[dict]]:
    return lambda ts: calls(agent, ts, PER_TICK, errors=PER_TICK, spread_s=9.5)


def rescued(agent: UUID) -> Callable[[datetime], list[dict]]:
    def gen(ts: datetime) -> list[dict]:
        rows = calls(agent, ts, PER_TICK, spread_s=9.5, provider=FALLBACK, attrs=RESCUED)
        return [{**r, "route_decision": "inline_fallback", "model": "small-2"} for r in rows]

    return gen


def young_agent(kit: Kit, tenant: UUID, sim: Sim, minutes: int = 3) -> UUID:
    """An agent created ``minutes`` before the simulation's clock (which runs 40 min behind)."""
    age = datetime.now(sim.now.tzinfo) - sim.now + timedelta(minutes=minutes)
    return kit.agent(tenant, tier=3, age=age)


def test_young_agent_with_proven_traffic_reaches_failed_on_a_hard_outage(kit: Kit) -> None:
    t = kit.tenant()
    kit.provider(t)
    sim = Sim(kit, t)
    a = young_agent(kit, t, sim)
    sim.run(12, healthy(a))  # 72 healthy calls over two minutes
    assert sim.results[-1].evaluations[a].provisional, "still in cold start while healthy"

    outage = sim.run(12, failing(a))
    bands = sim.bands(a, outage)
    assert "failed" in bands[:5], f"tier 3 reaches failed within its detected hysteresis: {bands}"
    ev = outage[-1].evaluations[a]
    assert ev.band == "failed" and not ev.provisional
    assert any("cold-start cap lifted" in f["explanation"] for f in ev.factors)
    severities = {x["code"]: x["severity"] for x in sim.alerts(a)}
    assert severities.get("error_rate") == "critical", severities
    snap = kit.q(
        "SELECT band, provisional FROM sibyl.health_snapshot WHERE tenant_id = $1 AND agent_id = "
        "$2 ORDER BY evaluated_at DESC LIMIT 1",
        t,
        a,
    )[0]
    assert snap["band"] == "failed" and not snap["provisional"], "what the saga reads"


def test_new_agent_failing_since_its_first_call_stays_provisional(kit: Kit) -> None:
    t = kit.tenant()
    kit.provider(t)
    sim = Sim(kit, t)
    a = young_agent(kit, t, sim)
    sim.run(8, failing(a))
    ev = sim.results[-1].evaluations[a]
    assert ev.provisional and ev.band == "watch" and ev.floor == "failed"
    assert all(x["severity"] != "critical" for x in sim.alerts(a))


def _primary(kit: Kit, tenant: UUID, agent: UUID, provider: UUID) -> None:
    model, version = uuid4(), uuid4()
    kit.in_tenant(
        tenant,
        "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name) VALUES ($1, $2, $3, "
        "'large-1')",
        tenant,
        model,
        provider,
    )
    kit.in_tenant(
        tenant,
        "INSERT INTO sibyl.agent_version (tenant_id, id, agent_id, version_no, primary_model_id, "
        "source) VALUES ($1, $2, $3, 1, $4, 'api')",
        tenant,
        version,
        agent,
        model,
    )
    kit.in_tenant(
        tenant,
        "UPDATE sibyl.agent SET current_version_id = $2 WHERE tenant_id = $1 AND id = $3",
        tenant,
        version,
        agent,
    )


def _inputs(kit: Kit, sim: Sim, tenant: UUID, agent: UUID) -> Any:
    async def go() -> Any:
        async with kit.worker.tenant_tx(tenant) as conn:
            return await load_tenant(conn, tenant, sim.now)

    return kit.run(go()).inputs[agent]


def test_inline_fallback_calls_count_for_the_primary_provider(kit: Kit) -> None:
    t = kit.tenant()
    primary = kit.provider(t)
    kit.provider(t, FALLBACK)
    a = kit.agent(t, tier=2)
    _primary(kit, t, a, primary)
    sim = Sim(kit, t)
    sim.run(12, healthy(a))
    sim.run(40, rescued(a))  # 6+ minutes: the 5-minute window holds only rescued calls
    inp = _inputs(kit, sim, t, a)
    assert inp.provider == "provider-one" and inp.provider_id == primary
    assert inp.w5.inline_fallback_count == inp.w5.request_count > 0
    assert inp.error_count_1h == 0 and inp.request_count_1h > 0

    kit.in_tenant(
        t,
        "INSERT INTO sibyl.provider_status (tenant_id, provider_id, source, status, "
        "observed_at) VALUES ($1, $2, 'status_feed', 'major_outage', $3)",
        t,
        primary,
        sim.now,
    )
    sim.run(4, rescued(a))
    ev = sim.results[-1].evaluations[a]
    assert "provider_status" in {f["rule"] for f in ev.factors if f["penalty"] > 0}
    assert ev.band in ("degraded", "failed") and ev.recommended_action == "reroute_to_fallback"


def test_mixed_traffic_keeps_the_volume_rule_without_a_version(kit: Kit) -> None:
    # no agent_version: the dominant provider by volume, rescued calls not counted for the
    # fallback provider
    t = kit.tenant()
    kit.provider(t)
    kit.provider(t, FALLBACK)
    a = kit.agent(t, tier=2)
    sim = Sim(kit, t)

    def mixed(ts: datetime) -> list[dict]:
        return healthy(a)(ts)[:2] + rescued(a)(ts)

    sim.run(6, mixed)
    assert _inputs(kit, sim, t, a).provider == "provider-one"
    sim.run(40, rescued(a))
    inp = _inputs(kit, sim, t, a)
    assert inp.provider == FALLBACK, "nothing else to go on: the serving provider"
