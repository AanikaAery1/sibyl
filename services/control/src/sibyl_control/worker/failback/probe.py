"""Failback: probe the primary, then return the agent to it (API.md §6.1; sre §2.3 item 3).

Probe: an agent ``failed_over`` for at least 5 minutes, with no live saga, whose primary provider
has had no non-operational status and no open provider incident in the last 5 minutes and whose
health has not been ``degraded``/``failed`` in that window. A pass opens a ``failback`` saga and
moves the agent ``failed_over → failing_back`` (trigger ``failback_probe``, canary 10 %).

Phase 1 (Tier-A cut A4): the ramp is off and the next step goes straight to ``active`` (trigger
``canary``). With ``Settings.failback_ramp`` (``env.failback_ramp``) the canary ramps
10 → 25 → 50 → 100, each step held green for 5 minutes; a breach reverts to ``failed_over`` and
doubles the probe wait for that incident (5 → 10 → 20 min, cap 60); two reverts suspend
automated failback until a human runs ``fail_back``. An operator ``fail_back`` opens the same
saga; this loop completes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord
from ..saga import engine, entry, routing
from ..saga.model import SYSTEM, Env, SagaError, SagaOpen

PRIMARY_HEALTHY_FOR = timedelta(minutes=5)
STEP_GREEN_FOR = timedelta(minutes=5)
PROBE_BACKOFF_BASE = timedelta(minutes=5)
PROBE_BACKOFF_CAP = timedelta(minutes=60)
MAX_REVERTS = 2
RAMP: tuple[int, ...] = (10, 25, 50, 100)

_CANDIDATES_SQL = """
SELECT rs.agent_id, inc.id AS incident_id, inc.step_results -> 'failback' AS fb,
       (SELECT m.provider_id FROM sibyl.agent a JOIN sibyl.agent_version v
           ON v.tenant_id = a.tenant_id AND v.id = a.current_version_id
         JOIN sibyl.model m ON m.tenant_id = v.tenant_id AND m.id = v.primary_model_id
        WHERE a.tenant_id = rs.tenant_id AND a.id = rs.agent_id) AS primary_provider_id
  FROM sibyl.routing_state rs
  JOIN LATERAL (SELECT f.id, f.step_results FROM sibyl.failover f
                 WHERE f.tenant_id = rs.tenant_id AND f.agent_id = rs.agent_id
                   AND f.kind IN ('failover', 'preemptive') AND f.state = 'done'
                   AND f.to_state = 'failed_over'
                 ORDER BY f.finished_at DESC LIMIT 1) inc ON true
 WHERE rs.tenant_id = $1 AND rs.state = 'failed_over' AND rs.state_since <= now() - $2::interval
   AND NOT EXISTS (SELECT 1 FROM sibyl.failover f WHERE f.tenant_id = rs.tenant_id
                     AND f.agent_id = rs.agent_id
                     AND f.state IN ('pending', 'running', 'waiting_approval'))
 LIMIT $3
"""
_UNHEALTHY_SQL = """
SELECT EXISTS (SELECT 1 FROM sibyl.provider_status WHERE tenant_id = $1 AND provider_id = $2
                 AND status NOT IN ('operational', 'unknown') AND observed_at > now() -
                   $3::interval)
    OR EXISTS (SELECT 1 FROM sibyl.provider_incident WHERE tenant_id = $1 AND provider_id = $2
                 AND (state = 'open' OR resolved_at > now() - $3::interval))
"""
_SICK_SQL = """
SELECT EXISTS (SELECT 1 FROM sibyl.health_snapshot WHERE tenant_id = $1 AND agent_id = $2
                 AND evaluated_at > $3 AND band IN ('degraded', 'failed'))
"""
_RUNNING_SQL = """
SELECT id FROM sibyl.failover WHERE tenant_id = $1 AND kind = 'failback' AND state = 'running'
 ORDER BY created_at LIMIT $2
"""


@dataclass
class FailbackRun:
    probed: list[UUID] = field(default_factory=list)
    completed: list[UUID] = field(default_factory=list)
    reverted: list[UUID] = field(default_factory=list)


def probe_backoff(reverts: int) -> timedelta:
    wait: timedelta = min(PROBE_BACKOFF_CAP, PROBE_BACKOFF_BASE * 2**reverts)
    return wait


async def primary_healthy(
    conn: Any, tenant: UUID, agent_id: UUID, provider_id: UUID | None, since: Any
) -> bool:
    if provider_id is not None and await conn.fetchval(
        _UNHEALTHY_SQL, tenant, provider_id, PRIMARY_HEALTHY_FOR
    ):
        return False
    return not await conn.fetchval(_SICK_SQL, tenant, agent_id, since)


async def _now(conn: Any) -> Any:
    return await conn.fetchval("SELECT now()")


async def _incident_failback(
    conn: Any, env: Env, tenant: UUID, incident_id: UUID, **changes: Any
) -> dict[str, Any]:
    incident = await engine.load(conn, tenant, incident_id)
    assert incident is not None
    state = dict(engine.results(incident).get("failback") or {})
    state.update(changes)
    await engine.save(
        conn, env, tenant, incident, step_results=engine.with_result(incident, "failback", state)
    )
    return state


async def start(conn: Any, env: Env, tenant: UUID, candidate: Any) -> UUID | None:
    """Probe passed: open the failback saga and move to ``failing_back`` at 10 %."""
    fb = dict(candidate["fb"] or {})
    attempt = int(fb.get("attempts") or 0) + 1
    try:
        row, created = await entry.open_saga(
            conn,
            tenant,
            SagaOpen(
                agent_id=candidate["agent_id"],
                actor=SYSTEM,
                trigger="failback_probe",
                kind="failback",
                idempotency_key=f"failback:{candidate['incident_id']}:{attempt}",
                reason="primary healthy for 5 minutes",
            ),
            inline=True,
            extra_results={"incident_id": str(candidate["incident_id"])},
            env=env,
        )
    except SagaError:
        return None
    if not created:
        return None
    applied = await routing.apply(
        conn,
        tenant,
        candidate["agent_id"],
        expected_from="failed_over",
        to_state="failing_back",
        trigger="failback_probe",
        actor=SYSTEM,
        idempotency_key=f"failover:{row['id']}:failing_back",
        audit_action="route.changed",
        failover_id=row["id"],
        canary_pct=RAMP[0],
        reason="failback probe passed",
    )
    await _incident_failback(conn, env, tenant, candidate["incident_id"], attempts=attempt)
    await engine.save(
        conn,
        env,
        tenant,
        row,
        step="write_routing",
        routing_transition_id=applied.transition_id,
        step_results=engine.with_result(
            row,
            "ramp",
            {"pct": RAMP[0], "since": (await _now(conn)).isoformat(), "probe": True},
        ),
    )
    started: UUID = row["id"]
    return started


async def _label(conn: Any, tenant: UUID, row: dict[str, Any], transition_id: UUID) -> None:
    incident_id = engine.results(row).get("incident_id")
    ttr = None
    if incident_id:
        ttr = await conn.fetchval(
            "SELECT extract(epoch FROM now() - created_at)::int FROM sibyl.failover"
            " WHERE tenant_id = $1 AND id = $2",
            tenant,
            UUID(incident_id),
        )
    await conn.execute(
        "INSERT INTO sibyl.label (tenant_id, agent_id, kind, label_strength, judges_kind,"
        " judges_id, judged_as_of, labeller_kind, labeller_ref, value, reason)"
        " VALUES ($1, $2, 'failover_outcome', 'outcome', 'transition', $3, now(), 'worker',"
        " 'failback', $4::jsonb, 'failback verified')",
        tenant,
        row["agent_id"],
        str(transition_id),
        {
            "fallback_succeeded": True,
            "failback_verified": True,
            "undone_by_operator": False,
            "time_to_recover_s": ttr,
            "incident_id": incident_id,
        },
    )


async def _complete(conn: Any, env: Env, tenant: UUID, row: dict[str, Any]) -> None:
    applied = await routing.apply(
        conn,
        tenant,
        row["agent_id"],
        expected_from="failing_back",
        to_state="active",
        trigger="canary",
        actor=SYSTEM,
        idempotency_key=f"failover:{row['id']}:active",
        audit_action="route.changed",
        failover_id=row["id"],
        canary_pct=100,
        reason="failback complete",
    )
    await env.audit.append(
        conn,
        tenant,
        AuditRecord(
            action="failback.completed",
            actor_type="system",
            resource_type="agent",
            resource_id=row["agent_id"],
            detail={
                "transition_id": str(applied.transition_id),
                "canary_pct": 100,
                "incident_id": engine.results(row).get("incident_id"),
            },
        ),
    )
    await _label(conn, tenant, row, applied.transition_id)
    row = await engine.save(
        conn,
        env,
        tenant,
        row,
        to_state="active",
        routing_transition_id=applied.transition_id,
        step_results=engine.with_result(row, "ramp", {"pct": 100, "completed": True}),
    )
    await engine.finish(conn, env, tenant, row, "done")


async def _revert(conn: Any, env: Env, tenant: UUID, row: dict[str, Any], pct: int) -> None:
    await routing.apply(
        conn,
        tenant,
        row["agent_id"],
        expected_from="failing_back",
        to_state="failed_over",
        trigger="canary",
        actor=SYSTEM,
        idempotency_key=f"failover:{row['id']}:revert",
        audit_action="route.changed",
        failover_id=row["id"],
        reason=f"canary breach at {pct} %",
    )
    incident_id = engine.results(row).get("incident_id")
    if incident_id:
        incident = await engine.load(conn, tenant, UUID(incident_id), lock=False)
        prior = dict(engine.results(incident or {}).get("failback") or {})
        reverts = int(prior.get("reverts") or 0) + 1
        wait = probe_backoff(reverts)
        await _incident_failback(
            conn,
            env,
            tenant,
            UUID(incident_id),
            reverts=reverts,
            next_probe_at=(await conn.fetchval("SELECT now() + $1::interval", wait)).isoformat(),
            suspended=reverts >= MAX_REVERTS,
        )
    await engine.finish(conn, env, tenant, row, "failed", "canary_breach")


async def step_running(conn: Any, env: Env, tenant: UUID, failover_id: UUID) -> str:
    """Advance one running failback saga: complete, ramp a step, revert, or wait."""
    row = await engine.load(conn, tenant, failover_id)
    if row is None or row["state"] != "running":
        return "gone"
    state = await routing.state_of(conn, tenant, row["agent_id"])
    if state is None or state["state"] != "failing_back":
        await engine.finish(conn, env, tenant, row, "cancelled", "routing_moved")
        return "cancelled"
    ramp = dict(engine.results(row).get("ramp") or {})
    pct = int(ramp.get("pct") or state["canary_pct"] or RAMP[0])
    if not env.failback_ramp:
        await _complete(conn, env, tenant, row)
        return "completed"
    provider = await conn.fetchval(
        "SELECT m.provider_id FROM sibyl.agent a JOIN sibyl.agent_version v"
        " ON v.tenant_id = a.tenant_id AND v.id = a.current_version_id JOIN sibyl.model m"
        " ON m.tenant_id = v.tenant_id AND m.id = v.primary_model_id"
        " WHERE a.tenant_id = $1 AND a.id = $2",
        tenant,
        row["agent_id"],
    )
    since = ramp.get("since")
    since_ts = datetime.fromisoformat(str(since)) if since else state["state_since"]
    if not await primary_healthy(conn, tenant, row["agent_id"], provider, since_ts):
        await _revert(conn, env, tenant, row, pct)
        return "reverted"
    if await conn.fetchval(
        "SELECT now() - $1::timestamptz < $2::interval", since_ts, STEP_GREEN_FOR
    ):
        return "waiting"
    nxt = next((p for p in RAMP if p > pct), 100)
    if nxt >= 100:
        await _complete(conn, env, tenant, row)
        return "completed"
    await routing.apply(
        conn,
        tenant,
        row["agent_id"],
        expected_from="failing_back",
        to_state="failing_back",
        trigger="canary",
        actor=SYSTEM,
        idempotency_key=f"failover:{row['id']}:ramp:{nxt}",
        audit_action="route.changed",
        failover_id=row["id"],
        canary_pct=nxt,
        reason=f"canary green at {pct} %",
    )
    await engine.save(
        conn,
        env,
        tenant,
        row,
        step_results=engine.with_result(
            row, "ramp", {"pct": nxt, "since": (await _now(conn)).isoformat()}
        ),
    )
    return "ramped"


def _due(fb: dict[str, Any], now: datetime) -> bool:
    if fb.get("suspended"):
        return False
    nxt = fb.get("next_probe_at")
    return nxt is None or now >= datetime.fromisoformat(str(nxt))


async def run_tenant(db: Any, env: Env, tenant: UUID, *, limit: int = 50) -> FailbackRun:
    run = FailbackRun()
    async with db.tenant_tx(tenant, readonly=True) as conn:
        running = [r["id"] for r in await conn.fetch(_RUNNING_SQL, tenant, limit)]
    for failover_id in running:
        async with db.tenant_tx(tenant) as conn:
            await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
            outcome = await step_running(conn, env, tenant, failover_id)
        if outcome == "completed":
            run.completed.append(failover_id)
        elif outcome == "reverted":
            run.reverted.append(failover_id)
    async with db.tenant_tx(tenant, readonly=True) as conn:
        candidates = list(await conn.fetch(_CANDIDATES_SQL, tenant, PRIMARY_HEALTHY_FOR, limit))
    for cand in candidates:
        started: UUID | None = None
        async with db.tenant_tx(tenant) as conn:
            await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
            now = await _now(conn)
            if not _due(dict(cand["fb"] or {}), now):
                continue
            since = await conn.fetchval("SELECT now() - $1::interval", PRIMARY_HEALTHY_FOR)
            if not await primary_healthy(
                conn, tenant, cand["agent_id"], cand["primary_provider_id"], since
            ):
                continue
            started = await start(conn, env, tenant, cand)
            if started is not None and not env.failback_ramp:
                await step_running(conn, env, tenant, started)
        if started is not None:
            run.probed.append(started)
    return run
