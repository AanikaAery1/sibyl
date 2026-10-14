"""Sparse ``prediction`` rows from health snapshots, and the gate into lane S (ML.md §7.3, R49).

The scoring tick writes ``health_snapshot.horizons`` (on change, including a horizon band
change, plus a 60 s heartbeat). This loop turns those snapshots into ``prediction`` rows under
the sparse rule: a row per (snapshot, horizon) when the band changed since the agent's last
row for that horizon, when the band is ``>= "0.25"``, when the snapshot froze a feature
snapshot, or as an hourly heartbeat. Lead time is measured from the first band rise, which the
rule captures exactly.

The scan uses a per-tenant watermark held in memory and lagging ``now`` by ``SAFETY_LAG`` (a
scoring transaction may commit a few seconds after its ``evaluated_at``); rows already written
for a (snapshot, horizon) are skipped, so overlap and restarts are idempotent. A restart resumes
from the newest prediction within ``LOOKBACK``.

Each scan first trips the persisted per-agent breakers that are due (``breaker``), before any
other write of the transaction. A newly written 15-minute row that crosses the tier gate while
the previous 15-minute row did not is a rising edge: lane S's ``request_predicted_failover`` is
called once, in this transaction, with the effective mode (``approval`` while the agent's
breaker is tripped). Snapshots in band ``failed`` belong to the detected path
and are not offered as predictions; provisional snapshots never are (no rule actor may act).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from .bands import BAND_RANK
from .breaker import trip_breakers
from .catalog import HORIZON_KEYS, HORIZON_S, family
from .gate import (
    GateConfig,
    PredictedFailoverRequester,
    effective_mode,
    failover_requester,
    gate_config,
    qualifies,
)

if TYPE_CHECKING:
    from ...core.settings import Settings

log = logging.getLogger("sibyl.worker.predict")

SAFETY_LAG = timedelta(seconds=30)
LOOKBACK = timedelta(minutes=15)
HEARTBEAT = timedelta(hours=1)
PREV_WINDOW = timedelta(minutes=65)
BATCH = 5000
SILENT_STATES = frozenset({"killed", "quarantined", "failed_over", "failing_back"})
WRITE_FLOOR_BAND = "0.25"

_CURSORS: dict[UUID, datetime] = {}

_CONFIG_SQL = (
    "SELECT id, config FROM sibyl.scoring_config WHERE tenant_id = $1 "
    "AND activated_at IS NOT NULL AND superseded_at IS NULL"
)
_RESUME_SQL = (
    "SELECT max(predicted_at) FROM sibyl.prediction WHERE tenant_id = $1 AND predicted_at > $2"
)
_SNAPSHOTS_SQL = """
SELECT id, agent_id, evaluated_at, band, provisional, horizons, predicted_failure_mode,
       feature_snapshot_id, scoring_config_id, factors
  FROM sibyl.health_snapshot
 WHERE tenant_id = $1 AND evaluated_at > $2 AND evaluated_at <= $3 AND horizons <> '{}'::jsonb
 ORDER BY evaluated_at, id
 LIMIT $4
"""
_PREV_SQL = """
SELECT DISTINCT ON (agent_id, horizon_s) agent_id, horizon_s, predicted_at, probability_band,
       confidence, contributions
  FROM sibyl.prediction
 WHERE tenant_id = $1 AND predicted_at > $2 AND predicted_at <= $3
 ORDER BY agent_id, horizon_s, predicted_at DESC, id DESC
"""
_EXISTING_SQL = """
SELECT id, health_snapshot_id, horizon_s, predicted_at, probability_band, confidence, contributions
  FROM sibyl.prediction WHERE tenant_id = $1 AND predicted_at > $2 AND predicted_at <= $3
"""
_INSERT_SQL = """
INSERT INTO sibyl.prediction (tenant_id, predicted_at, agent_id, health_snapshot_id,
  feature_snapshot_id, scoring_config_id, horizon_s, source, probability_band, confidence,
  predicted_failure_mode, contributions)
SELECT $1, u.at, u.agent, u.hs, u.fs, u.sc, u.h, u.src, u.band, u.conf, u.mode, u.contrib::jsonb
  FROM unnest($2::timestamptz[], $3::uuid[], $4::uuid[], $5::uuid[], $6::uuid[], $7::int[],
              $8::text[], $9::text[], $10::text[], $11::text[], $12::text[])
       AS u(at, agent, hs, fs, sc, h, src, band, conf, mode, contrib)
RETURNING id, agent_id, health_snapshot_id, horizon_s
"""
_AGENTS_SQL = """
SELECT a.id, a.tier, coalesce(rs.state, 'active') AS state, rs.operator_hold_until,
       cp.preemptive_mode, a.preemptive_breaker_tripped_at IS NOT NULL AS breaker_tripped,
       EXISTS (SELECT 1 FROM sibyl.failover f WHERE f.tenant_id = a.tenant_id
         AND f.agent_id = a.id AND f.state IN ('pending', 'running', 'waiting_approval')) AS live
  FROM sibyl.agent a
  LEFT JOIN sibyl.routing_state rs ON rs.tenant_id = a.tenant_id AND rs.agent_id = a.id
  LEFT JOIN sibyl.continuity_plan cp ON cp.tenant_id = a.tenant_id AND cp.agent_id = a.id
 WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])
"""
# D21, once per evaluation (as ``saga.engine.suppress_for_hold``): count a suppression only when
# the alert was evaluated again since the last one, and stamp when it happened.
_HOLD_SQL = (
    "UPDATE sibyl.alert a SET hold_suppressed_count = hold_suppressed_count + 1,"
    " hold_suppressed_at = now() FROM sibyl.alert_rule r WHERE a.tenant_id = $1"
    " AND a.agent_id = $2 AND a.state <> 'resolved' AND r.tenant_id = a.tenant_id"
    " AND r.id = a.rule_id AND r.kind = 'leading'"
    " AND (a.hold_suppressed_at IS NULL OR a.hold_suppressed_at < a.last_evaluated_at)"
)


@dataclass(frozen=True)
class Prev:
    at: datetime
    band: str
    confidence: str
    rules: tuple[str, ...]


@dataclass(frozen=True)
class GateCall:
    agent_id: UUID
    prediction_id: UUID
    band: str
    confidence: str
    mode: str
    failover_id: UUID | None


@dataclass
class PredictResult:
    scanned: int = 0
    written: int = 0
    skipped_existing: int = 0
    gate_calls: list[GateCall] = field(default_factory=list)
    gate_blocked: list[tuple[UUID, str]] = field(default_factory=list)
    cursor: datetime | None = None


@dataclass
class _Row:
    snapshot: Mapping[str, Any]
    key: str
    entry: Mapping[str, Any]
    prev: Prev | None


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _rules_of(contributions: Any) -> tuple[str, ...]:
    return tuple(str(c.get("rule")) for c in _json(contributions) or () if c.get("rule"))


def _should_write(entry: Mapping[str, Any], prev: Prev | None, snap: Mapping[str, Any]) -> bool:
    band = str(entry.get("probability_band", "0.05"))
    if prev is None or band != prev.band:
        return True
    if BAND_RANK.get(band, 0) >= BAND_RANK[WRITE_FLOOR_BAND]:
        return True
    if snap["feature_snapshot_id"] is not None:
        return True
    return bool(snap["evaluated_at"] - prev.at >= HEARTBEAT)


def _contributions(entry: Mapping[str, Any], factors: Any, scoring: Any) -> str:
    penalties = {
        f.get("rule"): f.get("penalty")
        for f in _json(factors) or ()
        if isinstance(f, Mapping) and not str(f.get("rule", "")).startswith("_")
    }
    items = [
        {"rule": r, "family": family(r), "penalty": penalties.get(r)}
        for r in entry.get("contributing_rules") or ()
    ]
    return json.dumps(items, separators=(",", ":"))


async def _cursor(conn: Any, tenant: UUID, now: datetime, since: datetime | None) -> datetime:
    if since is not None:
        return since
    held = _CURSORS.get(tenant)
    if held is not None:
        return held
    floor = now - LOOKBACK
    resumed = await conn.fetchval(_RESUME_SQL, tenant, floor)
    return min(resumed or floor, now - SAFETY_LAG)


async def write_predictions(
    conn: Any,
    tenant: UUID,
    now: datetime,
    *,
    settings: Settings,
    since: datetime | None = None,
    requester: PredictedFailoverRequester | None = None,
) -> PredictResult:
    """Write sparse prediction rows for snapshots in ``(cursor, now]`` and run the gate.

    ``settings`` is the worker's ``Settings``: the D36 band comes from it (B20), never from the
    tenant's scoring config, and it is handed on to lane S's entry.
    """
    config = await conn.fetchrow(_CONFIG_SQL, tenant)
    if config is None:
        return PredictResult()
    scoring = _json(config["config"]) or {}
    gc = gate_config(scoring, settings)
    await trip_breakers(conn, tenant, now)  # first lock-taking statement: audit_lock first
    start = await _cursor(conn, tenant, now, since)
    snaps = list(await conn.fetch(_SNAPSHOTS_SQL, tenant, start, now, BATCH))
    result = PredictResult(scanned=len(snaps))
    prev = {
        (r["agent_id"], r["horizon_s"]): Prev(
            r["predicted_at"], r["probability_band"], r["confidence"], _rules_of(r["contributions"])
        )
        for r in await conn.fetch(_PREV_SQL, tenant, start - PREV_WINDOW, start)
    }
    existing: dict[tuple[UUID, int], Mapping[str, Any]] = {}
    if snaps:
        for r in await conn.fetch(_EXISTING_SQL, tenant, start, snaps[-1]["evaluated_at"]):
            existing[(r["health_snapshot_id"], r["horizon_s"])] = r

    to_write: list[_Row] = []
    for snap in snaps:
        horizons = _json(snap["horizons"]) or {}
        for key in HORIZON_KEYS:
            entry = horizons.get(key)
            if not isinstance(entry, Mapping):
                continue
            seconds = HORIZON_S[key]
            slot = (snap["agent_id"], seconds)
            before = prev.get(slot)
            done = existing.get((snap["id"], seconds))
            if done is not None:
                result.skipped_existing += 1
                prev[slot] = Prev(
                    done["predicted_at"],
                    done["probability_band"],
                    done["confidence"],
                    _rules_of(done["contributions"]),
                )
                continue
            if not _should_write(entry, before, snap):
                continue
            to_write.append(_Row(snap, key, entry, before))
            prev[slot] = Prev(
                snap["evaluated_at"],
                str(entry.get("probability_band")),
                str(entry.get("confidence")),
                tuple(entry.get("contributing_rules") or ()),
            )

    ids = await _insert(conn, tenant, to_write, scoring)
    result.written = len(ids)
    await _gate(conn, tenant, now, to_write, ids, _Gate(gc, settings, requester), result)

    if len(snaps) >= BATCH:
        cursor = snaps[-1]["evaluated_at"]
    else:
        cursor = max(start, now - SAFETY_LAG)
    result.cursor = cursor
    if since is None:
        _CURSORS[tenant] = cursor
    return result


async def _insert(
    conn: Any, tenant: UUID, rows: Sequence[_Row], scoring: Mapping[str, Any]
) -> dict[tuple[UUID, int], UUID]:
    if not rows:
        return {}
    source = str(scoring.get("rules_source", "rules/v1"))
    written = await conn.fetch(
        _INSERT_SQL,
        tenant,
        [r.snapshot["evaluated_at"] for r in rows],
        [r.snapshot["agent_id"] for r in rows],
        [r.snapshot["id"] for r in rows],
        [r.snapshot["feature_snapshot_id"] for r in rows],
        [r.snapshot["scoring_config_id"] for r in rows],
        [HORIZON_S[r.key] for r in rows],
        [str(r.entry.get("source") or source) for r in rows],
        [str(r.entry.get("probability_band", "0.05")) for r in rows],
        [str(r.entry.get("confidence", "low")) for r in rows],
        [
            r.entry.get("predicted_failure_mode") or r.snapshot["predicted_failure_mode"]
            for r in rows
        ],
        [_contributions(r.entry, r.snapshot["factors"], scoring) for r in rows],
    )
    return {(w["health_snapshot_id"], w["horizon_s"]): w["id"] for w in written}


@dataclass(frozen=True)
class _Gate:
    config: GateConfig
    settings: Settings
    requester: PredictedFailoverRequester | None


def _crosses(tier: int, band: str, confidence: str, rules: Sequence[str], gc: GateConfig) -> bool:
    return qualifies(tier, band, confidence, len({family(r) for r in rules}), gc)


async def _gate(
    conn: Any,
    tenant: UUID,
    now: datetime,
    rows: Sequence[_Row],
    ids: Mapping[tuple[UUID, int], UUID],
    gate: _Gate,
    result: PredictResult,
) -> None:
    gc = gate.config
    candidates = [
        r
        for r in rows
        if r.key == "15m"
        and r.snapshot["band"] != "failed"
        and not r.snapshot["provisional"]
        and (r.snapshot["id"], HORIZON_S["15m"]) in ids
    ]
    if not candidates:
        return
    agents = {
        a["id"]: a
        for a in await conn.fetch(
            _AGENTS_SQL, tenant, sorted({r.snapshot["agent_id"] for r in candidates}, key=str)
        )
    }
    for row in candidates:
        agent = agents.get(row.snapshot["agent_id"])
        if agent is None:
            continue
        tier = int(agent["tier"])
        band = str(row.entry.get("probability_band"))
        confidence = str(row.entry.get("confidence"))
        rules = tuple(row.entry.get("contributing_rules") or ())
        if not _crosses(tier, band, confidence, rules, gc):
            continue
        before = row.prev
        if before is not None and _crosses(tier, before.band, before.confidence, before.rules, gc):
            continue  # not a rising edge: S already has this episode
        await _offer(conn, tenant, now, row, ids, agent, band, confidence, gate, result)


async def _offer(
    conn: Any,
    tenant: UUID,
    now: datetime,
    row: _Row,
    ids: Mapping[tuple[UUID, int], UUID],
    agent: Mapping[str, Any],
    band: str,
    confidence: str,
    gate: _Gate,
    result: PredictResult,
) -> None:
    agent_id = row.snapshot["agent_id"]
    if agent["state"] in SILENT_STATES or agent["live"]:
        result.gate_blocked.append((agent_id, f"routing:{agent['state']}"))
        return
    hold = agent["operator_hold_until"]
    if hold is not None and hold > now:
        await conn.execute(_HOLD_SQL, tenant, agent_id)
        result.gate_blocked.append((agent_id, "operator_hold"))
        return
    tier = int(agent["tier"])
    mode = effective_mode(tier, agent["preemptive_mode"], bool(agent["breaker_tripped"]))
    prediction_id = ids[(row.snapshot["id"], HORIZON_S["15m"])]
    entry = gate.requester or failover_requester()
    failover_id = None
    if entry is not None:
        failover_id = await entry(
            conn,
            tenant,
            agent_id,
            prediction_id,
            "15m",
            band,
            confidence,
            mode=mode,
            settings=gate.settings,
        )
    else:
        log.info(
            "gate crossed for agent %s (band %s, %s, mode %s): no saga entry",
            agent_id,
            band,
            confidence,
            mode,
        )
    result.gate_calls.append(GateCall(agent_id, prediction_id, band, confidence, mode, failover_id))


def reset_cursors() -> None:
    _CURSORS.clear()
