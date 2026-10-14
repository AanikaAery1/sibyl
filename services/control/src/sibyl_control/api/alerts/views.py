"""Read models for alerts and provider incidents (OpenAPI ``Alert``, ``ProviderIncident``).

Both objects are open to additive fields (API.md §2.7); the extra alert fields are the ones the
console's alert card and the D33 unverdicted queue need (``scope``, ``fired_count``,
``escalation_level``, ``verdict_wanted``, ``outcome_observed``, ``what_to_do``, ``evidence``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..registry._kit import JSON, jsonable

ALERT_SELECT = """
SELECT * FROM (
  SELECT a.*, r.code AS rule_code, g.agent_group_id, l.reason AS verdict_note,
         a.verdict_wanted::int AS vw
    FROM sibyl.alert a
    JOIN sibyl.alert_rule r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id
    LEFT JOIN sibyl.agent g ON g.tenant_id = a.tenant_id AND g.id = a.agent_id
    LEFT JOIN sibyl.label l ON l.tenant_id = a.tenant_id AND l.id = a.verdict_label_id
   WHERE a.tenant_id = $1 {where}
) q WHERE true
"""

INCIDENT_SELECT = """
SELECT * FROM (
  SELECT i.*, (SELECT h.id FROM sibyl.legal_hold h WHERE h.tenant_id = i.tenant_id
                 AND h.provider_incident_id = i.id ORDER BY h.placed_at DESC LIMIT 1)
              AS legal_hold_id
    FROM sibyl.provider_incident i WHERE i.tenant_id = $1
) q WHERE true
"""


def alert_view(row: Mapping[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "agent_id": jsonable(row["agent_id"]),
        "provider_id": jsonable(row["provider_id"]),
        "rule_code": row["rule_code"],
        "scope": row["scope"],
        "severity": row["severity"],
        "state": row["state"],
        "fired_at": jsonable(row["first_fired_at"]),
        "last_evaluated_at": jsonable(row["last_evaluated_at"]),
        "acked_at": jsonable(row["acked_at"]),
        "acked_by_user_id": jsonable(row["acked_by_user_id"]),
        "resolved_at": jsonable(row["resolved_at"]),
        "silenced_until": jsonable(row.get("silenced_until")),
        "verdict": row["verdict"],
        "verdict_note": row.get("verdict_note"),
        "verdict_wanted": row["verdict_wanted"],
        "outcome_observed": row["outcome_observed"],
        "fired_count": row["fired_count"],
        "escalation_level": row["escalation_level"],
        "hold_suppressed_count": row["hold_suppressed_count"],
        "health_snapshot_id": jsonable(row["health_snapshot_id"]),
        "provider_incident_id": jsonable(row["provider_incident_id"]),
        "suppressed_by_incident": row["suppressed_by_incident"],
        "incident_id": jsonable(row["failover_id"]),
        "what_to_do": row["what_to_do"],
        "summary": row["summary"],
        "evidence": jsonable(row["evidence"] or {}),
    }


def incident_view(row: Mapping[str, Any]) -> JSON:
    return {
        "id": str(row["id"]),
        "provider_id": str(row["provider_id"]),
        "state": row["state"],
        "severity": row["severity"],
        "opened_at": jsonable(row["started_at"]),
        "resolved_at": jsonable(row["resolved_at"]),
        "affected_agent_ids": [str(a) for a in row["affected_agent_ids"] or ()],
        "affected_process_count": row["affected_process_count"],
        "rule_codes": list(row["rule_codes"] or ()),
        "summary": row["summary"],
        "legal_hold_id": jsonable(row.get("legal_hold_id")),
    }
