"""Sentinel's only write path: a finding row, its ``sentinel.finding_created`` audit, and (from
the worker, for flagged drift and critical held-action reviews) a watch-only
``sentinel_finding`` alert.

The alert rule is a tenant ``alert_rule`` of kind ``leading`` that is not in the rules seed:
the scoring engine only evaluates seeded rules and the failover saga only starts from
``detected`` alerts, so a Sentinel alert can never trigger automation. It is created when an
admin turns Sentinel on (``ensure_alert_rule``); if an admin deletes or disables it, Sentinel
writes findings only.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final
from uuid import UUID

from sibyl_schemas.values import SentinelTask

from ...core.audit import AuditActor, AuditRecord, AuditWriter
from ...core.outbox import OutboxMessage, OutboxWriter

ALERT_RULE_CODE: Final = "sentinel_finding"
ALERT_WHAT_TO_DO: Final = (
    "Sibyl Sentinel flagged this agent (advisory, watch only). Read the finding and decide;"
    " Sentinel never acts."
)
_ENSURE_RULE_SQL = """
INSERT INTO sibyl.alert_rule (tenant_id, code, kind, scope, metric, comparator, thresholds,
  window_s, min_samples, severity, penalty, what_to_do_template, origin)
VALUES ($1, 'sentinel_finding', 'leading', 'agent', 'sentinel', 'boolean',
  '{"watch_only": true, "source": "sentinel", "tiers": {}}'::jsonb, 86400, 0, 'info', 0, $2,
  'custom')
ON CONFLICT (tenant_id, code) DO NOTHING
"""
_INSERT_SQL = """
INSERT INTO sibyl.sentinel_finding (tenant_id, kind, subject_kind, subject_id, agent_id, severity,
  summary, body, recommendation, provider, model, prompt_sha256, tokens_in, tokens_out, cost_usd,
  cost_estimated, calls, trigger, requested_by_user_id, dedupe_key)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
  $20)
ON CONFLICT (tenant_id, dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING
RETURNING *
"""
_RULE_SQL = (
    "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = $2 AND enabled"
    " AND kind = 'leading'"
)
_LIVE_ALERT_SQL = (
    "SELECT id FROM sibyl.alert WHERE tenant_id = $1 AND dedupe_key = $2 AND state <> 'resolved'"
    " FOR UPDATE"
)
_ALERT_INSERT_SQL = """
INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity, dedupe_key, what_to_do,
  evidence, summary)
VALUES ($1, $2, 'agent', $3, $4, $5, $6, $7::jsonb, $8)
RETURNING id
"""
_ALERT_REFIRE_SQL = """
UPDATE sibyl.alert SET fired_count = fired_count + 1, last_evaluated_at = now(), summary = $3,
       evidence = $4::jsonb,
       severity = CASE WHEN severity = 'critical' OR $5 = 'critical' THEN 'critical' ELSE $5 END
 WHERE tenant_id = $1 AND id = $2
"""
_LINK_SQL = "UPDATE sibyl.sentinel_finding SET alert_id = $3 WHERE tenant_id = $1 AND id = $2"
SUMMARY_FIELDS: Final = ("summary",)


@dataclass(frozen=True)
class Subject:
    kind: SentinelTask
    subject_kind: str
    subject_id: UUID | None
    agent_id: UUID | None
    dedupe_key: str | None


@dataclass(frozen=True)
class FindingDraft:
    subject: Subject
    output: Mapping[str, Any]
    provider: str
    model: str
    prompt_sha256: bytes
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    cost_estimated: bool
    calls: int
    trigger: str  # scheduled | on_demand
    requested_by: UUID | None = None
    data_meta: Mapping[str, Any] | None = None


def recommendation_of(kind: SentinelTask, out: Mapping[str, Any]) -> str | None:
    if kind is SentinelTask.INCIDENT_EXPLANATION:
        steps = [str(s) for s in out.get("what_to_check") or ()]
        return "; ".join(steps)[:2000] or None
    if kind is SentinelTask.HELD_ACTION_REVIEW:
        return f"Advisory: {out.get('advice')}. {out.get('reasoning', '')}"[:2000]
    value = out.get("recommendation")
    return str(value)[:2000] if value else None


def should_alert(kind: SentinelTask, out: Mapping[str, Any]) -> bool:
    if kind is SentinelTask.SEMANTIC_DRIFT:
        flagged = bool(out.get("purpose_drift") or out.get("injection_like"))
        return flagged and out.get("severity") in ("warning", "critical")
    if kind is SentinelTask.HELD_ACTION_REVIEW:
        return out.get("severity") == "critical"
    return False


async def ensure_alert_rule(conn: Any, tenant: UUID) -> None:
    await conn.execute(_ENSURE_RULE_SQL, tenant, ALERT_WHAT_TO_DO)


async def insert_finding(conn: Any, tenant: UUID, d: FindingDraft) -> dict[str, Any] | None:
    """The new row, or ``None`` when a scheduled finding for this subject already exists."""
    out = dict(d.output)
    body = {"output": out, "input": dict(d.data_meta or {})}
    row = await conn.fetchrow(
        _INSERT_SQL,
        tenant,
        d.subject.kind.value,
        d.subject.subject_kind,
        d.subject.subject_id,
        d.subject.agent_id,
        str(out.get("severity", "info")),
        str(out.get("summary") or "(no summary)")[:2000],
        json.loads(json.dumps(body, default=str)),
        recommendation_of(d.subject.kind, out),
        d.provider,
        d.model[:128],
        d.prompt_sha256,
        d.tokens_in,
        d.tokens_out,
        d.cost_usd,
        d.cost_estimated,
        max(1, min(d.calls, 10)),
        d.trigger,
        d.requested_by,
        d.subject.dedupe_key,
    )
    return None if row is None else dict(row)


def finding_record(
    row: Mapping[str, Any], actor: AuditActor, request_id: UUID | None = None
) -> AuditRecord:
    detail: dict[str, Any] = {
        "finding_id": str(row["id"]),
        "kind": row["kind"],
        "subject_kind": row["subject_kind"],
        "provider": row["provider"],
        "model": row["model"],
        "prompt_sha256": bytes(row["prompt_sha256"]).hex(),
        "tokens_in": int(row["tokens_in"]),
        "tokens_out": int(row["tokens_out"]),
        "cost_usd": str(row["cost_usd"]),
        "trigger": row["trigger"],
        "severity": row["severity"],
    }
    if row["subject_id"] is not None:
        detail["subject_id"] = str(row["subject_id"])
    if row["agent_id"] is not None:
        detail["agent_id"] = str(row["agent_id"])
    return AuditRecord(
        action="sentinel.finding_created",
        resource_type="sentinel_finding",
        resource_id=row["id"],
        detail=detail,
        request_id=request_id,
        **actor.fields(),
    )


async def audit_finding(
    conn: Any, audit: AuditWriter, tenant: UUID, row: Mapping[str, Any], actor: AuditActor
) -> Any:
    return await audit.append(conn, tenant, finding_record(row, actor))


async def raise_alert(
    conn: Any, outbox: OutboxWriter, tenant: UUID, row: Mapping[str, Any]
) -> UUID | None:
    """A watch-only alert for a flagged finding (worker only; one live alert per agent)."""
    agent = row["agent_id"]
    if agent is None:
        return None
    rule = await conn.fetchval(_RULE_SQL, tenant, ALERT_RULE_CODE)
    if rule is None:
        return None
    key = f"{ALERT_RULE_CODE}:agent:{agent}"
    evidence = {"finding_id": str(row["id"]), "kind": row["kind"], "watch_only": True}
    summary = f"Sentinel: {row['summary']}"[:500]
    live = await conn.fetchval(_LIVE_ALERT_SQL, tenant, key)
    if live is not None:
        await conn.execute(_ALERT_REFIRE_SQL, tenant, live, summary, evidence, row["severity"])
        alert_id: UUID = live
        event = "alert.updated"
    else:
        alert_id = await conn.fetchval(
            _ALERT_INSERT_SQL,
            tenant,
            rule,
            agent,
            row["severity"],
            key,
            ALERT_WHAT_TO_DO,
            evidence,
            summary,
        )
        event = "alert.fired"
    await conn.execute(_LINK_SQL, tenant, row["id"], alert_id)
    await outbox.emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            event,
            "alert",
            alert_id,
            {
                "alert_id": str(alert_id),
                "rule": ALERT_RULE_CODE,
                "severity": row["severity"],
                "scope": "agent",
                "state": "open",
                "agent_id": str(agent),
            },
        ),
    )
    return alert_id
