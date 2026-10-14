"""Alert fire / re-fire / resolve and provider-incident collapse (ML.md §3.7; sre §2.2-§2.4).

Decisions come from the engine's per-rule hysteresis (``Evaluation.newly_fired`` /
``newly_cleared``); this module only turns them into rows:

* **Fire**: one live row per ``dedupe_key`` (``<rule>:agent:<id>`` / ``<rule>:provider:<id>``).
  Within ``cooldown_s`` of the last fire a resolved, unverdicted row is re-opened
  (``fired_count + 1``) instead of a new row. ``escalate_after_fires`` fires inside
  ``escalate_window_s`` bump severity one step. Audit ``alert.fired`` (actor ``rule``).
* **Resolve** (D33): on ``out`` hysteresis, ``state=resolved``, ``verdict`` stays NULL,
  ``outcome_observed='recovered'``, ``verdict_wanted`` when an automated routing transition
  happened while it was open. Killed/quarantined agents resolve with ``outcome='unknown'``.
* **Provider collapse**: when at least ``max(2, min(3, ⌈30 % of the provider's agents⌉))``
  agents on one provider fire the same collapsible rule within 120 s, or the provider reports
  ``major_outage`` (R4), one ``provider_incident`` collects the member alerts
  (``suppressed_by_incident``). It resolves when ≥ 80 % of members are clear, and resolves
  its members with it.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord, AuditWriter
from ...core.outbox import OutboxMessage, OutboxWriter
from .config import EngineConfig, RuleSpec
from .engine import Evaluation
from .rules import RuleOutcome
from .store import TenantData

SEVERITIES = ("info", "warning", "critical")
COLLAPSIBLE = frozenset({"error_rate", "p95_latency", "consecutive_failures"})
COLLAPSE_WINDOW = timedelta(seconds=120)
INCIDENT_CLEAR_SHARE = 0.8
TOUCH_EVERY = timedelta(seconds=60)
SILENT_STATES = frozenset({"killed", "quarantined"})
PROVIDER_RULE = "provider_status"
FLAP_RULE = "flapping"

_LIVE_SQL = """
SELECT DISTINCT ON (dedupe_key) id, rule_id, scope, agent_id, provider_id, severity, state,
       dedupe_key, provider_incident_id, suppressed_by_incident, first_fired_at,
       last_evaluated_at, resolved_at, fired_count, cooldown_until, escalation_level, verdict,
       silenced_until
  FROM sibyl.alert
 WHERE tenant_id = $1 AND (state <> 'resolved' OR cooldown_until > $2)
 ORDER BY dedupe_key, (state <> 'resolved') DESC, first_fired_at DESC
"""
_INSERT_SQL = """
INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, provider_id, severity, dedupe_key,
  first_fired_at, last_evaluated_at, cooldown_until, what_to_do, evidence, health_snapshot_id,
  summary)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10, $11::jsonb, $12, $13)
RETURNING id
"""
# An acked alert under an active silence stays acked (lane P CR): re-firing refreshes the
# evidence and counters but never clobbers the silence.
_REFIRE_SQL = """
UPDATE sibyl.alert
   SET state = CASE WHEN state = 'acked' AND silenced_until > $3 THEN 'acked' ELSE 'open' END,
  resolved_at = NULL, outcome_observed = NULL,
  outcome_at = NULL, fired_count = fired_count + 1, last_evaluated_at = $3, severity = $4,
  escalation_level = $5, evidence = $6::jsonb, health_snapshot_id = coalesce($7, health_snapshot_id)
 WHERE tenant_id = $1 AND id = $2
"""
_RESOLVE_SQL = """
UPDATE sibyl.alert SET state = 'resolved', resolved_at = $3, outcome_observed = $4,
  outcome_at = $3, verdict_wanted = $5, last_evaluated_at = $3
 WHERE tenant_id = $1 AND id = $2 AND state <> 'resolved'
"""
_TOUCH_SQL = "UPDATE sibyl.alert SET last_evaluated_at = $2 WHERE tenant_id = $1 AND id = ANY($3)"
_AUTOMATED_SQL = (
    "SELECT EXISTS (SELECT 1 FROM sibyl.routing_transition WHERE tenant_id = $1 AND agent_id = $2 "
    "AND actor_kind IN ('rule', 'policy') AND created_at >= $3)"
)
_INCIDENTS_SQL = (
    "SELECT id, provider_id, severity, rule_codes, affected_agent_ids FROM sibyl.provider_incident "
    "WHERE tenant_id = $1 AND state = 'open'"
)
_OPEN_INCIDENT_SQL = """
INSERT INTO sibyl.provider_incident (tenant_id, provider_id, severity, started_at, rule_codes,
  affected_agent_ids, affected_process_count, provider_status_id, summary)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id
"""
_UPDATE_INCIDENT_SQL = """
UPDATE sibyl.provider_incident SET severity = $3, rule_codes = $4, affected_agent_ids = $5,
  affected_process_count = $6 WHERE tenant_id = $1 AND id = $2
"""
_RESOLVE_INCIDENT_SQL = (
    "UPDATE sibyl.provider_incident SET state = 'resolved', resolved_at = $3 "
    "WHERE tenant_id = $1 AND id = $2"
)
_ATTACH_SQL = (
    "UPDATE sibyl.alert SET provider_incident_id = $2, suppressed_by_incident = true "
    "WHERE tenant_id = $1 AND id = ANY($3)"
)


@dataclass
class Live:
    id: UUID
    rule_id: UUID
    scope: str
    agent_id: UUID | None
    provider_id: UUID | None
    severity: str
    state: str
    dedupe_key: str
    provider_incident_id: UUID | None
    first_fired_at: datetime
    last_evaluated_at: datetime
    fired_count: int
    cooldown_until: datetime | None
    escalation_level: int
    verdict: str | None
    rule_code: str = ""
    silenced_until: datetime | None = None

    @property
    def live(self) -> bool:
        return self.state != "resolved"

    def silenced(self, now: datetime) -> bool:
        return (
            self.state == "acked" and self.silenced_until is not None and self.silenced_until > now
        )


@dataclass
class AlertStats:
    fired: list[UUID] = field(default_factory=list)
    refired: list[UUID] = field(default_factory=list)
    resolved: list[UUID] = field(default_factory=list)
    incidents_opened: list[UUID] = field(default_factory=list)
    incidents_resolved: list[UUID] = field(default_factory=list)


def dedupe_key(code: str, scope: str, target: UUID) -> str:
    return f"{code}:{scope}:{target}"


def bump(severity: str) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, SEVERITIES.index(severity) + 1)]


def collapse_threshold(agents_on_provider: int) -> int:
    return max(2, min(3, math.ceil(0.3 * agents_on_provider)))


def render(template: str, out: RuleOutcome | None, window_s: int) -> str:
    def fmt(value: Any) -> str:
        if isinstance(value, float) and 0 <= value <= 1:
            return f"{value * 100:.0f}%"
        if isinstance(value, float):
            return f"{value:.0f}"
        return str(value)

    values = {
        "value": fmt(out.value) if out and out.value is not None else "?",
        "threshold": fmt(out.threshold) if out and out.threshold is not None else "?",
        "window": f"{window_s // 60} min" if window_s >= 60 else f"{window_s} s",
    }
    try:
        return template.format(**values)[:1000]
    except (KeyError, IndexError, ValueError):
        return template[:1000]


class AlertManager:
    def __init__(
        self,
        conn: Any,
        data: TenantData,
        outbox: OutboxWriter,
        audit: AuditWriter,
    ) -> None:
        self.conn = conn
        self.data = data
        self.cfg: EngineConfig = data.config
        self.tenant = data.tenant_id
        self.now = data.now
        self.outbox = outbox
        self.audit = audit
        self.stats = AlertStats()
        self.live: dict[str, Live] = {}
        self.by_rule_id: dict[UUID, str] = {
            r.rule_id: code for code, r in self.cfg.rules.items() if r.rule_id
        }

    async def load(self) -> None:
        for r in await self.conn.fetch(_LIVE_SQL, self.tenant, self.now):
            live = Live(
                **{k: r[k] for k in Live.__dataclass_fields__ if k != "rule_code"},
                rule_code=self.by_rule_id.get(r["rule_id"], ""),
            )
            self.live[live.dedupe_key] = live

    # --------------------------------------------------------------------------- agent

    async def process(
        self, evals: Mapping[UUID, Evaluation], snapshots: Mapping[UUID, UUID]
    ) -> AlertStats:
        await self.load()
        touch: list[UUID] = []
        for agent, ev in evals.items():
            inp = self.data.inputs[agent]
            snap = snapshots.get(agent)
            if inp.routing_state in SILENT_STATES:
                for live in self._agent_live(agent):
                    await self._resolve(live, outcome="unknown")
                continue
            for code in sorted(ev.newly_fired):
                rule = self.cfg.rule(code)
                if rule.scope != "agent":
                    continue
                await self._fire(rule, "agent", agent, ev, ev.outcomes.get(code), snap)
            if ev.flapping_started and self.cfg.has_rule(FLAP_RULE):
                await self._fire(self.cfg.rule(FLAP_RULE), "agent", agent, ev, None, snap)
            for code in sorted(ev.newly_cleared):
                cleared = self.live.get(dedupe_key(code, "agent", agent))
                if cleared and cleared.live and cleared.provider_incident_id is None:
                    await self._resolve(cleared, outcome="recovered")
            for code in ev.fired:
                held = self.live.get(dedupe_key(code, "agent", agent))
                if held and held.live and self.now - held.last_evaluated_at >= TOUCH_EVERY:
                    touch.append(held.id)
        if touch:
            await self.conn.execute(_TOUCH_SQL, self.tenant, self.now, touch)
        await self._providers(evals)
        await self._collapse(evals)
        await self._resolve_incidents(evals)
        return self.stats

    def _agent_live(self, agent: UUID) -> list[Live]:
        return [v for v in self.live.values() if v.agent_id == agent and v.live]

    def _severity(
        self, rule: RuleSpec, ev: Evaluation | None, live: Live | None
    ) -> tuple[str, int]:
        severity = rule.severity
        if ev is not None and rule.kind == "detected" and ev.band == "failed":
            severity = "critical"  # the very-fast condition (ML.md §3.5)
        level = live.escalation_level if live else 0
        if (
            live
            and live.fired_count + 1 >= rule.escalate_after_fires
            and (self.now - live.first_fired_at).total_seconds() <= rule.escalate_window_s
        ):
            level += 1
            severity = bump(severity)
        if ev is not None and ev.provisional and severity == "critical":
            severity = "warning"
        if ev is not None and rule.kind == "leading" and ev.tier == 1 and severity == "critical":
            severity = "warning"
        return severity, level

    def _evidence(
        self, rule: RuleSpec, out: RuleOutcome | None, ev: Evaluation | None, snapshot: UUID | None
    ) -> dict[str, Any]:
        doc: dict[str, Any] = {"rule": rule.code, "window_s": rule.window_s}
        if out is not None:
            doc |= {"value": out.value, "threshold": out.threshold, "link": out.evidence}
        if ev is not None:
            doc |= {"score": ev.score, "band": ev.band}
            if rule.code == FLAP_RULE:
                doc["transitions"] = [list(x) for x in ev.state.transitions]
        if snapshot is not None:
            doc["health_snapshot_id"] = str(snapshot)
        return doc

    async def _fire(
        self,
        rule: RuleSpec,
        scope: str,
        target: UUID,
        ev: Evaluation | None,
        out: RuleOutcome | None,
        snapshot: UUID | None,
        summary: str | None = None,
    ) -> Live | None:
        if rule.rule_id is None:
            return None
        key = dedupe_key(rule.code, scope, target)
        live = self.live.get(key)
        evidence = self._evidence(rule, out, ev, snapshot)
        tier = ev.tier if ev else 2
        if live is not None and (live.live or live.verdict is None):
            severity, level = self._severity(rule, ev, live)
            await self.conn.execute(
                _REFIRE_SQL, self.tenant, live.id, self.now, severity, level, evidence, snapshot
            )
            reopened = not live.live
            state = "acked" if live.silenced(self.now) else "open"
            live.state, live.fired_count, live.severity = state, live.fired_count + 1, severity
            live.escalation_level, live.last_evaluated_at = level, self.now
            self.stats.refired.append(live.id)
            await self._emit_alert("alert.fired" if reopened else "alert.updated", live)
            if reopened:
                await self._audit_fired(live, rule)
            return live
        severity, level = self._severity(rule, ev, None)
        text = render(rule.what_to_do, out, rule.window_s)
        alert_id = await self.conn.fetchval(
            _INSERT_SQL,
            self.tenant,
            rule.rule_id,
            scope,
            target if scope == "agent" else None,
            target if scope == "provider" else None,
            severity,
            key,
            self.now,
            self.now + timedelta(seconds=rule.cooldown(tier)),
            text,
            evidence,
            snapshot,
            (summary or (out.explanation if out else rule.code))[:500],
        )
        live = Live(
            alert_id,
            rule.rule_id,
            scope,
            target if scope == "agent" else None,
            target if scope == "provider" else None,
            severity,
            "open",
            key,
            None,
            self.now,
            self.now,
            1,
            None,
            level,
            None,
            rule.code,
        )
        self.live[key] = live
        self.stats.fired.append(alert_id)
        await self._emit_alert("alert.fired", live)
        await self._audit_fired(live, rule)
        return live

    async def _resolve(self, live: Live, *, outcome: str) -> None:
        if not live.live:
            return
        wanted = False
        if live.agent_id is not None:
            wanted = bool(
                await self.conn.fetchval(
                    _AUTOMATED_SQL, self.tenant, live.agent_id, live.first_fired_at
                )
            )
        await self.conn.execute(_RESOLVE_SQL, self.tenant, live.id, self.now, outcome, wanted)
        live.state = "resolved"
        self.stats.resolved.append(live.id)
        await self._emit_alert("alert.resolved", live)

    async def _emit_alert(self, event: str, live: Live) -> None:
        payload: dict[str, Any] = {
            "alert_id": str(live.id),
            "rule": live.rule_code,
            "severity": live.severity,
            "scope": live.scope,
            "state": live.state,
        }
        if live.agent_id:
            payload["agent_id"] = str(live.agent_id)
        if live.provider_id:
            payload["provider_id"] = str(live.provider_id)
        if live.provider_incident_id:
            payload["provider_incident_id"] = str(live.provider_incident_id)
        await self.outbox.emit(
            self.conn, self.tenant, OutboxMessage("alert", event, "alert", live.id, payload)
        )

    async def _audit_fired(self, live: Live, rule: RuleSpec) -> None:
        await self.audit.append(
            self.conn,
            self.tenant,
            AuditRecord(
                action="alert.fired",
                actor_type="rule",
                actor_id=rule.rule_id,
                resource_type="alert",
                resource_id=live.id,
                resource_ref=live.dedupe_key,
                detail={
                    "alert_id": str(live.id),
                    "rules": [rule.code],
                    "severity": live.severity,
                    "scope": live.scope,
                },
                occurred_at=self.now,
            ),
        )

    # ------------------------------------------------------------------------ providers

    def _status_major(self, provider: UUID) -> bool:
        status = self.data.provider_status.get(provider)
        return bool(status and status["status"] == "major_outage")

    async def _providers(self, evals: Mapping[UUID, Evaluation]) -> None:
        """R4 is provider-scoped: one alert per provider on ``major_outage`` (in 1 / out 6)."""
        if not self.cfg.has_rule(PROVIDER_RULE):
            return
        rule = self.cfg.rule(PROVIDER_RULE)
        for pid, slug in sorted(self.data.provider_slugs.items(), key=lambda kv: kv[1]):
            key = dedupe_key(PROVIDER_RULE, "provider", pid)
            live = self.live.get(key)
            status = self.data.provider_status.get(pid)
            if self._status_major(pid):
                if live is None or not live.live:
                    fired = await self._fire(
                        rule,
                        "provider",
                        pid,
                        None,
                        None,
                        None,
                        summary=f"Provider {slug} reports major_outage",
                    )
                    if fired is not None:
                        await self._attach(pid, [fired], status_id=status["id"] if status else None)
            elif live and live.live and self._provider_quiet(pid):
                if live.provider_incident_id is None:
                    await self._resolve(live, outcome="recovered")

    def _provider_quiet(self, pid: UUID) -> bool:
        """Status off ``major_outage`` for the rule's out-hysteresis (6 ticks = 60 s)."""
        status = self.data.provider_status.get(pid)
        if status is None or status["status"] == "major_outage":
            return False
        out_ticks = self.cfg.rule(PROVIDER_RULE).h_out(2) if self.cfg.has_rule(PROVIDER_RULE) else 6
        quiet = (self.now - status["observed_at"]).total_seconds()
        return bool(quiet >= out_ticks * self.cfg.tick_s)

    def _slug(self, pid: UUID) -> str | None:
        return self.data.provider_slugs.get(pid)

    async def _collapse(self, evals: Mapping[UUID, Evaluation]) -> None:
        on_provider: dict[UUID, list[UUID]] = defaultdict(list)
        for agent, inp in self.data.inputs.items():
            if inp.provider_id:
                on_provider[inp.provider_id].append(agent)
        open_incidents = {
            r["provider_id"]: r for r in await self.conn.fetch(_INCIDENTS_SQL, self.tenant)
        }
        for pid, agents in on_provider.items():
            for code in sorted(COLLAPSIBLE):
                members = [
                    live
                    for a in agents
                    if (live := self.live.get(dedupe_key(code, "agent", a))) is not None
                    and live.live
                    and live.provider_incident_id is None
                ]
                if not members:
                    continue
                recent = [m for m in members if self.now - m.first_fired_at <= COLLAPSE_WINDOW]
                if pid in open_incidents or len(recent) >= collapse_threshold(len(agents)):
                    await self._attach(pid, members, status_id=None)
                    open_incidents.setdefault(pid, {"id": None})

    async def _attach(self, pid: UUID, members: Iterable[Live], *, status_id: UUID | None) -> None:
        members = list(members)
        row = next(
            (
                r
                for r in await self.conn.fetch(_INCIDENTS_SQL, self.tenant)
                if r["provider_id"] == pid
            ),
            None,
        )
        severity = max((m.severity for m in members), key=SEVERITIES.index, default="warning")
        codes = sorted({m.rule_code for m in members})
        agents = sorted({m.agent_id for m in members if m.agent_id}, key=str)
        if row is None:
            slug = self._slug(pid) or str(pid)
            incident = await self.conn.fetchval(
                _OPEN_INCIDENT_SQL,
                self.tenant,
                pid,
                severity,
                self.now,
                codes,
                agents,
                self._processes(agents),
                status_id,
                f"Provider {slug}: {len(agents) or 'all'} agents affected ({', '.join(codes)})",
            )
            self.stats.incidents_opened.append(incident)
            await self.outbox.emit(
                self.conn,
                self.tenant,
                OutboxMessage(
                    "provider_incident",
                    "provider_incident.opened",
                    "provider_incident",
                    incident,
                    {
                        "provider_incident_id": str(incident),
                        "provider_id": str(pid),
                        "severity": severity,
                        "rule_codes": codes,
                    },
                ),
            )
        else:
            incident = row["id"]
            severity = max([severity, row["severity"]], key=SEVERITIES.index)
            codes = sorted({*codes, *row["rule_codes"]})
            agents = sorted({*agents, *row["affected_agent_ids"]}, key=str)
            await self.conn.execute(
                _UPDATE_INCIDENT_SQL,
                self.tenant,
                incident,
                severity,
                codes,
                agents,
                self._processes(agents),
            )
        await self.conn.execute(_ATTACH_SQL, self.tenant, incident, [m.id for m in members])
        for m in members:
            m.provider_incident_id = incident
            await self._emit_alert("alert.updated", m)

    def _processes(self, agents: Iterable[UUID]) -> int:
        return len(
            {
                self.data.inputs[a].business_process_id
                for a in agents
                if a in self.data.inputs and self.data.inputs[a].business_process_id
            }
        )

    async def _resolve_incidents(self, evals: Mapping[UUID, Evaluation]) -> None:
        for row in await self.conn.fetch(_INCIDENTS_SQL, self.tenant):
            incident, pid = row["id"], row["provider_id"]
            members = [
                m for m in self.live.values() if m.provider_incident_id == incident and m.live
            ]
            if self._status_major(pid):
                continue

            def clear(m: Live, pid: UUID = pid) -> bool:
                if m.scope == "provider":
                    return self._provider_quiet(pid)
                ev = evals.get(m.agent_id) if m.agent_id else None
                return ev is None or m.rule_code not in ev.fired

            if members and sum(clear(m) for m in members) / len(members) < INCIDENT_CLEAR_SHARE:
                continue
            await self.conn.execute(_RESOLVE_INCIDENT_SQL, self.tenant, incident, self.now)
            self.stats.incidents_resolved.append(incident)
            for m in members:
                await self._resolve(m, outcome="recovered")
            await self.outbox.emit(
                self.conn,
                self.tenant,
                OutboxMessage(
                    "provider_incident",
                    "provider_incident.resolved",
                    "provider_incident",
                    incident,
                    {"provider_incident_id": str(incident), "provider_id": str(pid)},
                ),
            )
