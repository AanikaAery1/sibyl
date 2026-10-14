"""One request builder per monitor operation (the sync and async clients send the same ``Req``).

Every list route takes ``limit`` / ``cursor`` plus the route's filters as keyword arguments,
exactly as named in the OpenAPI contract (``openapi/sibyl-api.v1.yaml``); ``None`` filters are
dropped and list values repeat the parameter.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from ._http import Req, listing, query, seg


def list_agents(limit: int | None, cursor: str | None, filters: dict[str, Any]) -> Req:
    """Filters: lifecycle, tier, risk_class, group_id, routing_state, band, q."""
    return listing("/agents", limit, cursor, filters)


def get_agent(agent_id: UUID | str) -> Req:
    return Req("GET", f"/agents/{seg(agent_id)}")


def get_fleet_health(filters: dict[str, Any]) -> Req:
    """Filters: group_id, tier, band."""
    return Req("GET", "/fleet/health", query(filters))


def get_health(agent_id: UUID | str, verbose: bool | None) -> Req:
    return Req("GET", f"/agents/{seg(agent_id)}/health", query({"verbose": verbose}))


def list_runs(limit: int | None, cursor: str | None, filters: dict[str, Any]) -> Req:
    """Filters: agent_id, root_only, since, until, status."""
    return listing("/runs", limit, cursor, filters)


def get_run(run_id: UUID | str) -> Req:
    return Req("GET", f"/runs/{seg(run_id)}")


def get_drift(agent_id: UUID | str, since: Any, limit: int | None) -> Req:
    return Req("GET", f"/agents/{seg(agent_id)}/drift", query({"since": since, "limit": limit}))


def list_alerts(limit: int | None, cursor: str | None, filters: dict[str, Any]) -> Req:
    """Filters: state, severity, agent_id, provider_id, rule_code, include_suppressed,
    unverdicted, since."""
    return listing("/alerts", limit, cursor, filters)


def get_alert(alert_id: UUID | str) -> Req:
    return Req("GET", f"/alerts/{seg(alert_id)}")


def list_incidents(limit: int | None, cursor: str | None, filters: dict[str, Any]) -> Req:
    """Filters: agent_id, state, kind, since, open."""
    return listing("/incidents", limit, cursor, filters)


def get_incident(incident_id: UUID | str) -> Req:
    return Req("GET", f"/incidents/{seg(incident_id)}")


def list_held_actions(limit: int | None, cursor: str | None, filters: dict[str, Any]) -> Req:
    """Filters: state (one or a list), agent_id, tool. Monitor keys never see arguments."""
    return listing("/held-actions", limit, cursor, filters)


def get_held_action(held_action_id: UUID | str) -> Req:
    return Req("GET", f"/held-actions/{seg(held_action_id)}")


def list_findings(limit: int | None, cursor: str | None, filters: dict[str, Any]) -> Req:
    """Filters: source, monitor_id, kind, subject_kind, subject_id, agent_id, severity, since."""
    return listing("/findings", limit, cursor, filters)


def get_monitor_self() -> Req:
    """The monitor this key is bound to: its watched groups, state and rate limit."""
    return Req("GET", "/monitors/self")


def get_finding(finding_id: UUID | str) -> Req:
    return Req("GET", f"/findings/{seg(finding_id)}")
