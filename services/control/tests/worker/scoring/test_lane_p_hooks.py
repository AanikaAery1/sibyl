"""Lane P change requests on the health engine (INT-1, wave 2).

* ``Extensions.prepare`` runs once per tenant tick right after ``load_tenant``, on the tick's
  connection with the same ``now``, before any leading evaluator reads its feed;
* the ``degraded`` floor is keyed on the OUTCOME's kind: a leading outcome sharing R4's code
  (the provider-status facet on ``maintenance``) never trips it; a detected R4 still does;
* re-firing never clobbers an active silence: an ``acked`` alert with ``silenced_until`` in the
  future stays ``acked``; once the silence has passed it re-opens.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sibyl_control.migrate.rules_seed import load
from sibyl_control.worker.scoring.alerts import _REFIRE_SQL, Live
from sibyl_control.worker.scoring.config import EngineConfig
from sibyl_control.worker.scoring.engine import evaluate
from sibyl_control.worker.scoring.extensions import Extensions, register, registered, reset
from sibyl_control.worker.scoring.rules import RuleOutcome

from .h_inputs import NOW, inputs
from .h_sim import Sim
from .h_testkit import Kit, calls

CFG = EngineConfig.from_seed(load(Path(__file__).resolve().parents[5] / "rules/v1/defaults.yaml"))
TICK = timedelta(seconds=10)


def test_register_accepts_and_keeps_a_prepare_hook() -> None:
    async def prepare(conn: Any, tenant: UUID, now: datetime) -> None:
        return None

    try:
        register(prepare=prepare)
        register(leading=lambda *_: [])
        assert registered().prepare is prepare and registered().leading is not None
    finally:
        reset()


def test_prepare_runs_after_load_tenant_with_the_ticks_now(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t, tier=3)
    sim = Sim(kit, t)
    seen: list[tuple[UUID, datetime, bool]] = []
    feed: dict[str, datetime] = {}

    async def prepare(conn: Any, tenant: UUID, now: datetime) -> None:
        feed["now"] = now
        same_tx = await conn.fetchval("SELECT current_setting('app.tenant_id', true)")
        seen.append((tenant, now, same_tx == str(tenant)))

    def leading(inputs: Any, config: Any, now: datetime) -> list[RuleOutcome]:
        assert feed.get("now") == now, "prepare ran first, with the same now"
        return []

    sim.extensions = Extensions(leading=leading, prepare=prepare)
    start = sim.now
    sim.run(3, lambda ts: calls(a, ts, 6, spread_s=9.5))
    assert [s[0] for s in seen] == [t, t, t]
    assert [s[1] for s in seen] == [start + i * TICK for i in range(3)]
    assert all(s[2] for s in seen), "prepare runs on the tick's tenant transaction"


def _provider(kind: str) -> RuleOutcome:
    return RuleOutcome(
        "provider_status",
        kind,
        True,
        1.0,
        "maintenance" if kind == "leading" else "major_outage",
        "major_outage",
        direction="equals",
        explanation="provider status",
        evidence="/api/v1/providers",
    )


def _floors(kind: str) -> list[str | None]:
    inp = inputs(tier=2, req=100)
    state = None
    out = []
    for i in range(12):
        ev = evaluate(inp, state, CFG, NOW + i * TICK, leading=[_provider(kind)])
        out.append(ev.floor)
        state = ev.state
    return out


def test_a_leading_outcome_under_r4s_code_never_trips_the_degraded_floor() -> None:
    assert CFG.rule("provider_status").severity == "critical"
    assert CFG.rule("provider_status").kind == "detected"
    assert set(_floors("leading")) == {None}
    assert "degraded" in _floors("detected"), "a detected R4 still floors at degraded"


def _alert(kit: Kit, tenant: UUID, agent: UUID, *, silenced_for: timedelta | None) -> UUID:
    rule = kit.val(
        "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = 'error_rate'", tenant
    )
    owner = kit.val("SELECT id FROM sibyl.app_user WHERE tenant_id = $1 LIMIT 1", tenant)
    rows = kit.in_tenant(
        tenant,
        "INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity, state, dedupe_key,"
        " what_to_do, summary, acked_at, acked_by_user_id, silenced_until, silenced_by_user_id)"
        " VALUES ($1, $2, 'agent', $3, 'warning', 'acked', $4, 'check', 'errors', now(), $5,"
        " now() + $6::interval, CASE WHEN $6::interval IS NULL THEN NULL ELSE $5::uuid END)"
        " RETURNING id",
        tenant,
        rule,
        agent,
        f"error_rate:agent:{agent}",
        owner,
        silenced_for,
    )
    return UUID(str(rows[0]["id"]))


def _refire(kit: Kit, tenant: UUID, alert: UUID) -> str:
    kit.in_tenant(
        tenant,
        _REFIRE_SQL,
        tenant,
        alert,
        datetime.now().astimezone(),
        "warning",
        0,
        json.dumps({"rule": "error_rate"}),
        None,
    )
    return str(kit.val("SELECT state FROM sibyl.alert WHERE id = $1", alert))


def test_refire_keeps_an_active_silence_and_reopens_after_it(kit: Kit) -> None:
    t = kit.tenant()
    silenced = _alert(kit, t, kit.agent(t), silenced_for=timedelta(hours=1))
    assert _refire(kit, t, silenced) == "acked"
    assert kit.val("SELECT silenced_until FROM sibyl.alert WHERE id = $1", silenced) is not None
    expired = _alert(kit, t, kit.agent(t), silenced_for=timedelta(hours=-1))
    assert _refire(kit, t, expired) == "open"
    plain = _alert(kit, t, kit.agent(t), silenced_for=None)
    assert _refire(kit, t, plain) == "open"


def test_live_alert_knows_its_silence() -> None:
    base = Live(
        UUID(int=1),
        UUID(int=2),
        "agent",
        UUID(int=3),
        None,
        "warning",
        "acked",
        "k",
        None,
        NOW,
        NOW,
        1,
        None,
        0,
        None,
        "error_rate",
    )
    assert replace(base, silenced_until=NOW + TICK).silenced(NOW)
    assert not replace(base, silenced_until=NOW - TICK).silenced(NOW)
    assert not replace(base, state="open", silenced_until=NOW + TICK).silenced(NOW)
    assert not base.silenced(NOW)
