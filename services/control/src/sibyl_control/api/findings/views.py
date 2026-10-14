"""One view over findings from every source (OpenAPI ``Finding``).

Sentinel findings (``sentinel_finding``) and external monitor findings (``external_finding``)
are read through one ``UNION ALL`` so the list pages by ``(created_at, id)`` across both.
Source-specific fields are null on the other source. ``advisory`` is always true.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Final

from ..registry._kit import JSON, jsonable

_SENTINEL = """
SELECT f.id, 'sentinel'::text AS source, NULL::uuid AS monitor_id, NULL::text AS monitor_name,
       f.kind, f.subject_kind, f.subject_id, f.agent_id, f.severity, f.summary, f.body,
       f.recommendation,
       CASE WHEN f.kind = 'held_action_review' THEN f.body->'output'->>'advice' END AS advice,
       f.body->'output'->>'confidence' AS confidence, f.provider, f.model, f.trigger,
       f.tokens_in, f.tokens_out, f.cost_usd, f.alert_id, f.feedback, f.feedback_by_user_id,
       f.feedback_at, f.created_at, a.agent_group_id
  FROM sibyl.sentinel_finding f
  LEFT JOIN sibyl.agent a ON a.tenant_id = f.tenant_id AND a.id = f.agent_id
 WHERE f.tenant_id = $1
"""
_EXTERNAL = """
SELECT e.id, 'external'::text AS source, e.monitor_id, m.name AS monitor_name, e.kind,
       e.subject_kind, e.subject_id, e.agent_id, e.severity, e.summary, e.body, e.recommendation,
       e.advice, e.confidence, e.provider, e.model, 'external'::text AS trigger,
       NULL::integer AS tokens_in, NULL::integer AS tokens_out, NULL::numeric AS cost_usd,
       e.alert_id, e.feedback, e.feedback_by_user_id, e.feedback_at, e.created_at,
       a.agent_group_id
  FROM sibyl.external_finding e
  JOIN sibyl.monitor m ON m.tenant_id = e.tenant_id AND m.id = e.monitor_id
  LEFT JOIN sibyl.agent a ON a.tenant_id = e.tenant_id AND a.id = e.agent_id
 WHERE e.tenant_id = $1
"""
# Constant fragments only: no input reaches the SQL text.
UNION_SQL: Final = f"SELECT * FROM ({_SENTINEL} UNION ALL {_EXTERNAL}) x WHERE true"  # noqa: S608
EXTERNAL_ONE_SQL: Final = f"SELECT * FROM ({_EXTERNAL}) x WHERE x.id = $2"  # noqa: S608

FIELDS: Final = (
    "id",
    "source",
    "monitor_id",
    "monitor_name",
    "kind",
    "subject_kind",
    "subject_id",
    "agent_id",
    "severity",
    "summary",
    "recommendation",
    "advice",
    "confidence",
    "provider",
    "model",
    "trigger",
    "tokens_in",
    "tokens_out",
    "alert_id",
    "feedback",
    "feedback_by_user_id",
    "feedback_at",
    "created_at",
)


def finding_view(row: Mapping[str, Any]) -> JSON:
    out: JSON = {name: jsonable(row[name]) for name in FIELDS}
    body = row["body"]
    out["body"] = body if isinstance(body, dict) else {}
    cost = row["cost_usd"]
    out["cost_usd"] = None if cost is None else str(Decimal(cost).quantize(Decimal("0.000001")))
    out["advisory"] = True
    return out
