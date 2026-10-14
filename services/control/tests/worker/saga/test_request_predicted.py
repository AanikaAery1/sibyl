"""Lane P's agreed entry ``request_predicted_failover`` on PG17.

P gates (tier, D36 release gate, breaker) and passes ``mode``; S owns D21, saga_in_flight
(joined), viability, D22 at timeout and the 20 s ``degrade_then_auto`` timer.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.settings import Settings
from sibyl_control.worker.saga import request_predicted_failover, runner
from sibyl_lane_s_world import SWorld


def _agent(s: SWorld, tier: int) -> UUID:
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
    return agent


def _prediction_row(s: SWorld, agent: UUID, band: str = "0.90") -> UUID:
    pid: UUID = s.val("SELECT sibyl.uuidv7()")
    s.admin.execute(
        "INSERT INTO sibyl.prediction (tenant_id, predicted_at, id, agent_id, health_snapshot_id,"
        " scoring_config_id, horizon_s, source, probability_band, confidence, contributions,"
        " predicted_failure_mode) VALUES ($1, now(), $2, $3, $4, $5, 900, 'rules/v1', $6,"
        ' \'medium\', \'[{"rule": "ratelimit_proximity"}, {"rule": "error_trend"}]\'::jsonb,'
        " 'provider_outage')",
        s.a.id,
        pid,
        agent,
        uuid4(),
        uuid4(),
        band,
    )
    return pid


class _Recording:
    """An asyncpg connection that records every statement, in order (CR-P2 lock ordering)."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn
        self.sql: list[str] = []

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._conn, name)
        if name not in ("execute", "fetch", "fetchrow", "fetchval", "executemany"):
            return target

        async def call(sql: str, *args: Any, **kw: Any) -> Any:
            self.sql.append(sql)
            return await target(sql, *args, **kw)

        return call


def _request(
    s: SWorld,
    agent: UUID,
    mode: str,
    *,
    horizon: str = "15m",
    band: str = "0.90",
    gate: str = "0.90",
    record: list[str] | None = None,
) -> Any:
    """P's call as the predict loop makes it: no audit lock taken yet, the worker's Settings."""
    pid = _prediction_row(s, agent, band)

    async def go() -> Any:
        async with s.worker_db.tenant_tx(s.a.id) as raw:
            conn = _Recording(raw)
            out = await request_predicted_failover(
                conn,
                s.a.id,
                agent,
                pid,
                horizon,
                band,
                "medium",
                mode=mode,
                settings=Settings(predicted_automation_band=gate),
            )
            if record is not None:
                record.extend(conn.sql)
            return out

    return s.run(go())


def _drive(s: SWorld) -> None:
    s.run(runner.run_tenant(s.worker_db, s.env(), s.a.id))


def _routing_apply(s: SWorld, agent: UUID, to: str, hold: bool, key: str) -> None:
    s.in_tenant(
        s.a,
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', $3, NULL, 'operator',"
        " 'human', $4, NULL, NULL, NULL, NULL, NULL, NULL,"
        " CASE WHEN $5 THEN now() + interval '30 minutes' END, NULL, 'test operator', $6,"
        " 'override.by_human', NULL, NULL, NULL, NULL)",
        s.a.id,
        agent,
        to,
        s.a.users["owner"],
        hold,
        key,
    )


def test_auto_opens_then_joins_the_live_saga(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s, 3)
    fid = _request(s, agent, "auto")
    assert fid is not None
    saga = s.saga(fid)
    assert saga["kind"] == "preemptive" and saga["actor_kind"] == "rule"
    assert saga["rule_codes"] == ["ratelimit_proximity", "error_trend"]
    assert s.results(fid)["open"]["failure_mode"] == "provider_outage"
    assert _request(s, agent, "auto") == fid  # joined while live
    _drive(s)
    assert s.saga(fid)["state"] == "done"
    assert s.routing(agent)["state"] == "failed_over"


def test_approval_mode_is_honoured_even_on_tier3(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s, 3)
    fid = _request(s, agent, "approval")
    _drive(s)
    assert s.saga(fid)["state"] == "waiting_approval"
    assert s.routing(agent)["state"] == "awaiting_approval"


def test_degrade_then_auto_owns_the_20s_timer(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s, 2)
    fid = _request(s, agent, "degrade_then_auto", band="0.60", gate="0.60")
    assert s.routing(agent)["state"] == "degraded"
    saga = s.saga(fid)
    assert saga["state"] == "pending" and saga["next_action_at"] > saga["created_at"]
    _drive(s)  # inside the pause: nothing runs
    assert s.saga(fid)["state"] == "pending"
    s.admin.execute("UPDATE sibyl.failover SET next_action_at = now() WHERE id = $1", fid)
    _drive(s)  # the triggering prediction is still the latest (sparse rows): persisted
    assert s.saga(fid)["state"] == "done"
    assert s.routing(agent)["state"] == "failed_over"


def test_degrade_then_auto_cancels_and_reverts_when_the_band_drops(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s, 2)
    fid = _request(s, agent, "degrade_then_auto", band="0.60", gate="0.60")
    _prediction_row(s, agent, "0.25")
    s.admin.execute("UPDATE sibyl.failover SET next_action_at = now() WHERE id = $1", fid)
    _drive(s)
    assert s.saga(fid)["error"] == "prediction_not_persisted"
    assert s.routing(agent)["state"] == "active"


def test_declined_on_long_horizon_hold_or_kill(sworld: SWorld) -> None:
    s = sworld
    agent = _agent(s, 3)
    assert _request(s, agent, "auto", horizon="1h") is None
    _routing_apply(s, agent, "active", True, f"hold:{agent}")
    assert _request(s, agent, "auto") is None
    killed = _agent(s, 3)
    _routing_apply(s, killed, "killed", False, f"kill:{killed}")
    assert _request(s, killed, "auto") is None
    assert s.sagas(agent) == [] and s.sagas(killed) == []


@pytest.mark.parametrize("gate", ["0.90", "0.60"])
def test_the_persist_band_and_env_come_from_settings(sworld: SWorld, gate: str) -> None:
    """B20: no bare ``Env()`` and no hard-coded ``"0.60"``: the band P gated with is the band
    the 20 s persistence check holds the prediction to."""
    s = sworld
    agent = _agent(s, 2)
    fid = _request(s, agent, "degrade_then_auto", band=gate, gate=gate)
    assert s.results(fid)["open"]["prediction"]["persist_band"] == gate


@pytest.mark.parametrize("mode", ["auto", "degrade_then_auto"])
def test_a_090_gate_never_automates_a_060_prediction(sworld: SWorld, mode: str) -> None:
    """B20 fail closed: whatever band the caller gated with, an automated mode below the
    deployment's D36 band is declined (nothing opened, routing untouched)."""
    s = sworld
    agent = _agent(s, 2)
    assert _request(s, agent, mode, band="0.60", gate="0.90") is None
    assert s.sagas(agent) == []
    assert s.routing(agent)["state"] == "active"


def test_approval_mode_is_still_offered_below_the_band(sworld: SWorld) -> None:
    """Tier-1 style approval (a human decides) is not automation: the 0.90 gate does not stop it."""
    s = sworld
    agent = _agent(s, 1)
    assert _request(s, agent, "approval", band="0.60", gate="0.90") is not None


def test_settings_are_required(sworld: SWorld) -> None:
    """B20: the entry has no implicit ``Settings()``; the predict loop passes its own."""
    s = sworld
    agent = _agent(s, 3)

    async def go() -> Any:
        async with s.worker_db.tenant_tx(s.a.id) as conn:
            call: Any = request_predicted_failover
            return await call(conn, s.a.id, agent, uuid4(), "15m", "0.90", "medium", mode="auto")

    with pytest.raises(TypeError):
        s.run(go())


@pytest.mark.parametrize("mode", ["auto", "degrade_then_auto", "approval"])
def test_audit_lock_is_taken_before_any_write(sworld: SWorld, mode: str) -> None:
    """CR-P2: the entry takes ``sibyl.audit_lock`` itself before it locks or writes a row."""
    s = sworld
    agent = _agent(s, 3)
    sql: list[str] = []
    assert _request(s, agent, mode, record=sql) is not None
    first_write = next(
        i
        for i, q in enumerate(sql)
        if q.lstrip().upper().startswith(("INSERT", "UPDATE"))
        or "routing_apply" in q
        or "FOR UPDATE" in q.upper()
    )
    locks = [i for i, q in enumerate(sql) if "audit_lock" in q]
    assert locks and locks[0] < first_write, sql[: first_write + 1]
