"""``GET /fleet/health``: the roll-up the console's fleet page renders (API.md §5.10).

Group-scoped callers count only agents in their groups (ungrouped agents excluded) and see only
the provider incidents that affect one of those agents.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response

from ..auth.common import iso, json_response, tenant_tx
from ..contract import API_PREFIX
from ..deps import AuthContext, get_services, guard
from .common import group_scope

router = APIRouter()
BANDS = ("healthy", "watch", "degraded", "failed")

_SCOPE = """
WITH scope AS (
  SELECT a.id FROM sibyl.agent a
   WHERE a.tenant_id = $1 AND a.lifecycle <> 'retired'
     AND ($2::uuid[] IS NULL OR a.agent_group_id = ANY ($2::uuid[]))
     AND ($3::uuid IS NULL OR a.agent_group_id = $3)
     AND ($4::smallint IS NULL OR a.tier = $4)
), latest AS (
  SELECT DISTINCT ON (h.agent_id) h.agent_id, h.band FROM sibyl.health_snapshot h
   WHERE h.tenant_id = $1 AND h.agent_id IN (SELECT id FROM scope)
     AND h.evaluated_at > now() - interval '3 days'
   ORDER BY h.agent_id, h.evaluated_at DESC, h.id DESC
), banded AS (
  SELECT s.id FROM scope s LEFT JOIN latest l ON l.agent_id = s.id
   WHERE $5::text IS NULL OR l.band = $5
)
"""


@router.get(API_PREFIX + "/fleet/health")
async def get_fleet_health(
    request: Request,
    ctx: Annotated[AuthContext, Depends(guard("getFleetHealth"))],
    group_id: Annotated[UUID | None, Query()] = None,
    tier: Annotated[int | None, Query(ge=1, le=3)] = None,
    band: Annotated[Literal["healthy", "watch", "degraded", "failed"] | None, Query()] = None,
) -> Response:
    groups = group_scope(ctx)
    args = (ctx.tenant_id, groups, group_id, tier, band)
    async with tenant_tx(get_services(request), ctx.tenant_id, readonly=True) as conn:
        bands = await conn.fetch(
            _SCOPE + "SELECT coalesce(l.band, 'unscored') AS band, count(*) AS n FROM banded b"  # noqa: S608 (constant SQL fragments, no input)
            " LEFT JOIN latest l ON l.agent_id = b.id GROUP BY 1",
            *args,
        )
        states = await conn.fetch(
            _SCOPE + "SELECT r.state, count(*) AS n FROM banded b JOIN sibyl.routing_state r"  # noqa: S608 (constant SQL fragments, no input)
            " ON r.tenant_id = $1 AND r.agent_id = b.id GROUP BY 1",
            *args,
        )
        counts = await conn.fetchrow(
            _SCOPE + "SELECT"  # noqa: S608 (constant SQL fragments, no input)
            " (SELECT count(*) FROM sibyl.alert x WHERE x.tenant_id = $1 AND x.state IN ('open',"
            " 'acked')"
            "   AND x.agent_id IN (SELECT id FROM banded)) AS open_alerts,"
            " (SELECT count(*) FROM sibyl.failover x WHERE x.tenant_id = $1"
            "   AND x.state IN ('pending', 'running', 'waiting_approval')"
            "   AND x.agent_id IN (SELECT id FROM banded)) AS open_incidents,"
            " (SELECT count(*) FROM sibyl.approval x WHERE x.tenant_id = $1 AND x.state = 'pending'"
            "   AND x.agent_id IN (SELECT id FROM banded)) AS pending_approvals,"
            " (SELECT count(*) FROM sibyl.handoff_task x WHERE x.tenant_id = $1"
            "   AND x.state IN ('queued', 'claimed') AND x.agent_id IN (SELECT id FROM banded)) AS"
            " queue_depth",
            *args,
        )
        incidents = await conn.fetch(
            _SCOPE + "SELECT p.id, p.provider_id, p.state, p.started_at, p.resolved_at,"  # noqa: S608 (constant SQL fragments, no input)
            " ARRAY(SELECT x FROM unnest(p.affected_agent_ids) x"
            "       WHERE x IN (SELECT id FROM banded)) AS visible_agent_ids"
            " FROM sibyl.provider_incident p WHERE p.tenant_id = $1 AND p.state = 'open'"
            " AND ($2::uuid[] IS NULL AND $3::uuid IS NULL AND $4::smallint IS NULL AND $5::text"
            " IS NULL"
            "      OR p.affected_agent_ids && ARRAY(SELECT id FROM banded))"
            " ORDER BY p.started_at DESC LIMIT 50",
            *args,
        )
    by_band: dict[str, int] = {b: 0 for b in BANDS} | {r["band"]: int(r["n"]) for r in bands}
    return json_response(
        {
            "counts_by_band": by_band,
            "counts_by_routing_state": {r["state"]: int(r["n"]) for r in states},
            "open_alerts": int(counts["open_alerts"]),
            "open_incidents": int(counts["open_incidents"]),
            "pending_approvals": int(counts["pending_approvals"]),
            "queue_depth": int(counts["queue_depth"]),
            "provider_incidents": [_incident(r) for r in incidents],
        }
    )


def _incident(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "provider_id": str(row["provider_id"]),
        "state": row["state"],
        "opened_at": iso(row["started_at"]),
        "resolved_at": iso(row["resolved_at"]),
        # Only the affected agents inside the caller's scope (no leak across groups).
        "affected_agent_ids": [str(a) for a in row["visible_agent_ids"]],
        "legal_hold_id": None,
        "alerts": [],
    }
