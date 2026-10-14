"""One scoring tick for one tenant (ML.md §7.4 "evaluate" loop, wave-1 scope).

load inputs -> evaluate every agent (pure) -> feature_snapshot rows for transitions and fires
-> health_snapshot rows on change + 60 s heartbeat -> alerts and provider incidents ->
``health.transition`` outbox messages. Everything commits in the caller's ``tenant_tx``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ...core.audit import AuditWriter, PgAuditWriter
from ...core.outbox import OutboxMessage, OutboxWriter, PgOutboxWriter
from .alerts import AlertManager, AlertStats
from .engine import Evaluation, evaluate, should_write, with_horizons
from .extensions import Extensions, registered
from .store import TenantData, load_tenant

GRAIN_S = 300
MAX_FACTORS_BYTES = 8000
MAX_SUMMARY_BYTES = 2000
SAMPLE_TICKS = 30  # R49: a `sample` feature snapshot 1-in-30 ticks (300 s at the 10 s tick)

_FEATURE_SQL = """
INSERT INTO sibyl.feature_snapshot (tenant_id, agent_id, as_of, feature_set, reason,
  observation_coverage, summary)
SELECT $1, u.agent_id, $2, $3, u.reason, u.coverage, u.summary::jsonb
  FROM unnest($4::uuid[], $5::text[], $6::numeric[], $7::text[]) AS u(agent_id, reason, coverage,
                                                                     summary)
RETURNING id, agent_id
"""
_SNAPSHOT_SQL = """
INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, agent_id, score, band, provisional,
  events_seen, observation_coverage, factors, horizons, predicted_failure_mode,
  recommended_action, feature_snapshot_id, scoring_config_id, policy_version, routing_state_at,
  window_start, window_end, grain_s, rules_source, write_reason)
SELECT $1, $2, u.agent_id, u.score, u.band, u.provisional, u.events_seen, u.coverage,
       u.factors::jsonb, u.horizons::jsonb, u.mode, u.action, u.fs, $3, u.pv, u.rs, $4, $2, $5,
       $6, u.reason
  FROM unnest($7::uuid[], $8::int[], $9::text[], $10::bool[], $11::int[], $12::numeric[],
              $13::text[], $14::text[], $15::text[], $16::text[], $17::uuid[], $18::int8[],
              $19::text[], $20::text[])
       AS u(agent_id, score, band, provisional, events_seen, coverage, factors, horizons, mode,
            action, fs, pv, rs, reason)
RETURNING id, agent_id
"""


@dataclass
class ScoreResult:
    agents: int = 0
    written: int = 0
    heartbeats: int = 0
    transitions: int = 0
    feature_snapshots: int = 0
    alerts: AlertStats = field(default_factory=AlertStats)
    evaluations: dict[UUID, Evaluation] = field(default_factory=dict)
    snapshot_ids: dict[UUID, UUID] = field(default_factory=dict)


def _factors_json(ev: Evaluation) -> str:
    factors = [dict(f) for f in ev.factors]
    doc = json.dumps(factors + ev.bookkeeping(), separators=(",", ":"), default=str)
    while len(doc.encode()) > MAX_FACTORS_BYTES and any(
        len(f["explanation"]) > 60 for f in factors
    ):
        for f in factors:
            f["explanation"] = f["explanation"][: max(60, len(f["explanation"]) // 2)]
        doc = json.dumps(factors + ev.bookkeeping(), separators=(",", ":"), default=str)
    return doc


def _summary_json(data: TenantData, agent: UUID, ev: Evaluation) -> str:
    grains = {
        k: (round(v, 6) if isinstance(v, float) else v)
        for k, v in data.summaries.get(agent, {}).items()
    }
    doc = json.dumps(
        {"grains": {"5m": grains}, "score": ev.score, "band": ev.band}, separators=(",", ":")
    )
    if len(doc.encode()) > MAX_SUMMARY_BYTES:
        doc = json.dumps({"score": ev.score, "band": ev.band})
    return doc


def evaluate_all(data: TenantData, ext: Extensions) -> dict[UUID, Evaluation]:
    out: dict[UUID, Evaluation] = {}
    cfg, now = data.config, data.now
    for agent, inp in data.inputs.items():
        leading = ext.leading(inp, cfg, now) if ext.leading else ()
        ev = evaluate(inp, data.priors.get(agent), cfg, now, leading=leading)
        if ext.horizons:
            horizons, mode = ext.horizons(inp, ev, cfg, now)
            ev = with_horizons(ev, horizons, mode)
        out[agent] = ev
    return out


@dataclass(frozen=True)
class Frozen:
    """This tick's feature snapshots; ``decisive`` froze on a transition or an alert."""

    ids: Mapping[UUID, UUID] = field(default_factory=dict)
    decisive: frozenset[UUID] = frozenset()

    def ref(self, data: TenantData, agent: UUID) -> UUID | None:
        """This tick's snapshot, else the agent's latest frozen one (carried forward)."""
        latest = data.latest_fs.get(agent)
        return self.ids.get(agent) or (latest[0] if latest else None)


async def _feature_snapshots(
    conn: Any, data: TenantData, evals: Mapping[UUID, Evaluation]
) -> Frozen:
    """Freeze features on a transition or an alert, and otherwise sample them once per
    ``SAMPLE_TICKS`` ticks per agent, deterministically by age rather than at random, so that
    every health snapshot can reference features at most one sample interval old (B-04)."""
    reasons: list[tuple[UUID, str]] = []
    interval = timedelta(seconds=SAMPLE_TICKS * float(data.config.scoring.get("tick_s", 10)))
    for agent, ev in evals.items():
        alertable = any(data.config.rule(c).scope == "agent" for c in ev.newly_fired)
        latest = data.latest_fs.get(agent)
        if ev.band_changed:
            reasons.append((agent, "transition"))
        elif alertable or ev.flapping_started:
            reasons.append((agent, "alert"))
        elif latest is None or data.now - latest[1] >= interval:
            reasons.append((agent, "sample"))
    if not reasons:
        return Frozen()
    rows = await conn.fetch(
        _FEATURE_SQL,
        data.tenant_id,
        data.now,
        str(data.config.scoring.get("feature_set", "features/v1")),
        [a for a, _ in reasons],
        [r for _, r in reasons],
        [round(data.inputs[a].coverage, 3) for a, _ in reasons],
        [_summary_json(data, a, evals[a]) for a, _ in reasons],
    )
    by_agent = {r["agent_id"]: r["id"] for r in rows}
    return Frozen(by_agent, frozenset(a for a, why in reasons if why != "sample"))


async def _health_snapshots(
    conn: Any, data: TenantData, evals: Mapping[UUID, Evaluation], fs: Frozen
) -> tuple[dict[UUID, UUID], int]:
    rows: list[tuple[UUID, Evaluation, str]] = []
    for agent, ev in evals.items():
        reason = should_write(data.priors.get(agent), ev, data.now)
        if reason is not None or agent in fs.decisive:
            rows.append((agent, ev, reason or "change"))
    if not rows:
        return {}, 0
    inputs = data.inputs
    result = await conn.fetch(
        _SNAPSHOT_SQL,
        data.tenant_id,
        data.now,
        data.config.scoring_config_id,
        data.now - timedelta(seconds=GRAIN_S),
        GRAIN_S,
        str(data.config.scoring.get("rules_source", "rules/v1")),
        [a for a, _, _ in rows],
        [ev.score for _, ev, _ in rows],
        [ev.band for _, ev, _ in rows],
        [ev.provisional for _, ev, _ in rows],
        [inputs[a].request_count_1h for a, _, _ in rows],
        [round(inputs[a].coverage, 3) for a, _, _ in rows],
        [_factors_json(ev) for _, ev, _ in rows],
        [json.dumps(ev.horizons, default=str) for _, ev, _ in rows],
        [ev.predicted_failure_mode for _, ev, _ in rows],
        [ev.recommended_action for _, ev, _ in rows],
        [fs.ref(data, a) for a, _, _ in rows],
        [inputs[a].policy_version for a, _, _ in rows],
        [inputs[a].routing_state for a, _, _ in rows],
        [reason for _, _, reason in rows],
    )
    heartbeats = sum(1 for _, _, reason in rows if reason == "heartbeat")
    return {r["agent_id"]: r["id"] for r in result}, heartbeats


async def _transitions(
    conn: Any,
    data: TenantData,
    evals: Mapping[UUID, Evaluation],
    snapshots: Mapping[UUID, UUID],
    fs: Frozen,
    outbox: OutboxWriter,
) -> int:
    n = 0
    for agent, ev in sorted(evals.items(), key=lambda kv: str(kv[0])):
        if not ev.band_changed or agent not in snapshots or agent not in fs.ids:
            continue
        payload = {
            "agent_id": str(agent),
            "health_snapshot_id": str(snapshots[agent]),
            "from_status": ev.from_band or "unknown",
            "to_status": ev.band,
            "score": ev.score,
            "feature_snapshot_ref": f"fs_{fs.ids[agent]}",
            "rules_fired": ev.rules_fired,
            "recommended_action": ev.recommended_action,
        }
        await outbox.emit(
            conn,
            data.tenant_id,
            OutboxMessage(
                "health",
                "health.transition",
                "agent",
                agent,
                payload,
                f"health.transition:{snapshots[agent]}",
            ),
        )
        n += 1
    return n


async def score_tenant(
    conn: Any,
    tenant: UUID,
    *,
    now: datetime | None = None,
    extensions: Extensions | None = None,
    outbox: OutboxWriter | None = None,
    audit: AuditWriter | None = None,
) -> ScoreResult:
    """Score every non-retired agent of ``tenant`` on a connection inside its ``tenant_tx``."""
    now = now or await conn.fetchval("SELECT now()")
    data = await load_tenant(conn, tenant, now)
    if data is None:
        return ScoreResult()
    ext = extensions or registered()
    if ext.prepare is not None:
        await ext.prepare(conn, tenant, now)
    outbox = outbox or PgOutboxWriter()
    evals = evaluate_all(data, ext)
    fs = await _feature_snapshots(conn, data, evals)
    snapshots, heartbeats = await _health_snapshots(conn, data, evals, fs)
    stats = await AlertManager(conn, data, outbox, audit or PgAuditWriter()).process(
        evals, snapshots
    )
    transitions = await _transitions(conn, data, evals, snapshots, fs, outbox)
    return ScoreResult(
        agents=len(evals),
        written=len(snapshots),
        heartbeats=heartbeats,
        transitions=transitions,
        feature_snapshots=len(fs.ids),
        alerts=stats,
        evaluations=evals,
        snapshot_ids=snapshots,
    )
