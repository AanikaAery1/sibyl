"""Drift alerts through the existing alert lifecycle (D51): rules ``silent_drift`` (behaviour)
and ``model_change`` (identity), one live alert per agent+provider+model.

Both rules are ``kind = 'leading'`` with cap 0 in every tier and ``watch_only``: the saga's
detected-failure trigger only reads ``detected`` alerts, so a drift alert can never start a
failover, and the health score never moves because of it. The loop keeps the two rule rows
present per tenant (``ensure_rules``), so a tenant created after 0018 gets them on its first
tick; an admin can disable either through the alert-rule API (a disabled rule raises nothing).

Firing mirrors ``worker.scoring.alerts``: a live row is refreshed in place; a resolved,
unverdicted row inside its cooldown re-opens (``fired_count + 1``); otherwise a new row.
Fire and re-open emit ``alert.fired`` (outbox topic ``alert``) and audit ``alert.fired``
(actor ``rule``); resolve emits ``alert.resolved``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from ...core.audit import AuditRecord, AuditWriter
from ...core.outbox import OutboxMessage, OutboxWriter

SILENT_DRIFT = "silent_drift"
MODEL_CHANGE = "model_change"
SEED_VERSION = "drift/1"
_TIERS_CAP0 = {
    str(t): {"cap": 0, "cooldown_s": 3600, "hysteresis_in": 2, "hysteresis_out": 3}
    for t in (1, 2, 3)
}

RULES: Mapping[str, Mapping[str, Any]] = {
    SILENT_DRIFT: {
        "metric": "drift_psi_js",
        "comparator": "composite",
        "window_s": 3600,
        "min_samples": 200,
        "hysteresis_in": 2,
        "hysteresis_out": 3,
        "thresholds": {
            "watch_only": True,
            "sli_family": "output_quality",
            "statistics": {"psi": [0.10, 0.25], "js_share": [0.005, 0.02], "js_mix": [0.05, 0.10]},
            "tiers": _TIERS_CAP0,
        },
        "what_to_do": (
            "Behaviour drifted from the frozen baseline (see the drift report for every feature's"
            " PSI / Jensen-Shannon value). Watch only: check whether the model, prompt, tools or"
            " traffic changed. If the change is intended, reset the drift baseline."
        ),
    },
    MODEL_CHANGE: {
        "metric": "model_identity",
        "comparator": "boolean",
        "window_s": 3600,
        "min_samples": 3,
        "hysteresis_in": 1,
        "hysteresis_out": 3,
        "thresholds": {
            "watch_only": True,
            "sli_family": "output_quality",
            "tiers": {
                str(t): {"cap": 0, "cooldown_s": 3600, "hysteresis_in": 1, "hysteresis_out": 3}
                for t in (1, 2, 3)
            },
        },
        "what_to_do": (
            "The provider served a different model or fingerprint than the agent asked for or was"
            " served in its baseline. Watch only: confirm the change with the provider's release"
            " notes; if it is intended, reset the drift baseline."
        ),
    },
}

_ENSURE_SQL = """
INSERT INTO sibyl.alert_rule (tenant_id, code, kind, scope, metric, comparator, thresholds,
  window_s, min_samples, hysteresis_in, hysteresis_out, cooldown_s, severity, penalty, horizon_s,
  tier_applicability, what_to_do_template, origin, seed_version)
VALUES ($1, $2, 'leading', 'agent', $3, $4, $5::jsonb, $6, $7, $8, $9, 3600, 'warning', 0, 3600,
        '{1,2,3}', $10, 'seed', $11)
ON CONFLICT (tenant_id, code) DO NOTHING
"""
_RULES_SQL = (
    "SELECT id, code, enabled, severity, cooldown_s, what_to_do_template FROM sibyl.alert_rule"
    " WHERE tenant_id = $1 AND code = ANY($2::text[])"
)
_LATEST_SQL = """
SELECT id, state, verdict, fired_count, cooldown_until, severity
  FROM sibyl.alert
 WHERE tenant_id = $1 AND dedupe_key = $2
 ORDER BY (state <> 'resolved') DESC, first_fired_at DESC
 LIMIT 1
"""
_INSERT_SQL = """
INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity, dedupe_key, first_fired_at,
  last_evaluated_at, cooldown_until, what_to_do, evidence, summary)
VALUES ($1, $2, 'agent', $3, $4, $5, $6, $6, $7, $8, $9::jsonb, $10)
RETURNING id
"""
_REFRESH_SQL = (
    "UPDATE sibyl.alert SET evidence = $3::jsonb, last_evaluated_at = $4, summary = $5"
    " WHERE tenant_id = $1 AND id = $2"
)
_REOPEN_SQL = """
UPDATE sibyl.alert SET state = 'open', resolved_at = NULL, outcome_observed = NULL,
  outcome_at = NULL, fired_count = fired_count + 1, last_evaluated_at = $3, evidence = $4::jsonb,
  summary = $5
 WHERE tenant_id = $1 AND id = $2
"""
_RESOLVE_SQL = """
UPDATE sibyl.alert SET state = 'resolved', resolved_at = $3, outcome_observed = $4, outcome_at = $3,
  last_evaluated_at = $3
 WHERE tenant_id = $1 AND id = $2 AND state <> 'resolved'
RETURNING id, severity, agent_id
"""


@dataclass(frozen=True)
class DriftRule:
    id: UUID
    code: str
    enabled: bool
    severity: str
    cooldown_s: int
    what_to_do: str


@dataclass(frozen=True)
class LiveAlert:
    id: UUID
    state: str
    severity: str

    @property
    def live(self) -> bool:
        return self.state != "resolved"


def dedupe_key(code: str, agent_id: UUID, provider: str, model: str) -> str:
    return f"{code}:agent:{agent_id}:{provider}/{model}"


async def ensure_rules(conn: Any, tenant: UUID) -> dict[str, DriftRule]:
    """Insert the two drift rules when missing; return the tenant's rows by code."""
    for code, spec in RULES.items():
        await conn.execute(
            _ENSURE_SQL,
            tenant,
            code,
            spec["metric"],
            spec["comparator"],
            dict(spec["thresholds"]),
            spec["window_s"],
            spec["min_samples"],
            spec["hysteresis_in"],
            spec["hysteresis_out"],
            spec["what_to_do"],
            SEED_VERSION,
        )
    rows = await conn.fetch(_RULES_SQL, tenant, list(RULES))
    return {
        r["code"]: DriftRule(
            r["id"],
            r["code"],
            bool(r["enabled"]),
            r["severity"],
            int(r["cooldown_s"]),
            r["what_to_do_template"],
        )
        for r in rows
    }


async def live_alert(conn: Any, tenant: UUID, key: str) -> LiveAlert | None:
    """The live alert for ``key`` (None when there is none or only resolved ones)."""
    row = await conn.fetchrow(_LATEST_SQL, tenant, key)
    if row is None or row["state"] == "resolved":
        return None
    return LiveAlert(row["id"], row["state"], row["severity"])


class AlertWriter:
    """Fire / refresh / resolve drift alerts on the tick's connection."""

    def __init__(
        self, conn: Any, tenant: UUID, now: datetime, outbox: OutboxWriter, audit: AuditWriter
    ) -> None:
        self.conn = conn
        self.tenant = tenant
        self.now = now
        self.outbox = outbox
        self.audit = audit
        self.fired: list[UUID] = []
        self.resolved: list[UUID] = []

    async def fire(
        self,
        rule: DriftRule,
        agent_id: UUID,
        key: str,
        evidence: Mapping[str, Any],
        summary: str,
    ) -> UUID | None:
        if not rule.enabled:
            return None
        doc = dict(evidence)
        latest = await self.conn.fetchrow(_LATEST_SQL, self.tenant, key)
        if latest is not None and latest["state"] != "resolved":
            await self.conn.execute(
                _REFRESH_SQL, self.tenant, latest["id"], doc, self.now, summary[:500]
            )
            return UUID(str(latest["id"]))
        reopen = (
            latest is not None
            and latest["verdict"] is None
            and latest["cooldown_until"] is not None
            and latest["cooldown_until"] > self.now
        )
        if reopen:
            assert latest is not None
            alert_id = UUID(str(latest["id"]))
            await self.conn.execute(
                _REOPEN_SQL, self.tenant, alert_id, self.now, doc, summary[:500]
            )
            severity = str(latest["severity"])
        else:
            severity = rule.severity
            alert_id = await self.conn.fetchval(
                _INSERT_SQL,
                self.tenant,
                rule.id,
                agent_id,
                severity,
                key,
                self.now,
                self.now + timedelta(seconds=rule.cooldown_s),
                rule.what_to_do[:1000],
                doc,
                summary[:500],
            )
        await self._emit("alert.fired", alert_id, rule.code, severity, agent_id, "open")
        await self.audit.append(
            self.conn,
            self.tenant,
            AuditRecord(
                action="alert.fired",
                actor_type="rule",
                actor_id=rule.id,
                resource_type="alert",
                resource_id=alert_id,
                resource_ref=key,
                detail={
                    "alert_id": str(alert_id),
                    "rules": [rule.code],
                    "severity": severity,
                    "scope": "agent",
                },
                occurred_at=self.now,
            ),
        )
        self.fired.append(alert_id)
        return alert_id

    async def resolve(self, code: str, alert_id: UUID, *, outcome: str = "recovered") -> bool:
        row = await self.conn.fetchrow(_RESOLVE_SQL, self.tenant, alert_id, self.now, outcome)
        if row is None:
            return False
        await self._emit(
            "alert.resolved", alert_id, code, row["severity"], row["agent_id"], "resolved"
        )
        self.resolved.append(alert_id)
        return True

    async def _emit(
        self, event: str, alert_id: UUID, code: str, severity: str, agent_id: UUID, state: str
    ) -> None:
        payload = {
            "alert_id": str(alert_id),
            "rule": code,
            "severity": severity,
            "scope": "agent",
            "state": state,
            "agent_id": str(agent_id),
        }
        await self.outbox.emit(
            self.conn, self.tenant, OutboxMessage("alert", event, "alert", alert_id, payload)
        )
