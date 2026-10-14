"""Provider status feed parsing -> ``provider_status.status`` (ML.md §2.3, R4).

Two shapes are understood:

* Atlassian Statuspage v2 (``/api/v2/status.json`` or ``summary.json``), which most hosted
  model providers publish: ``status.indicator`` none / minor / major / critical / maintenance,
  plus open ``incidents`` and in-progress ``scheduled_maintenances``.
* A Sibyl-native document ``{"status": "<provider_status>", "incident_id": "…"}`` (the shape of
  the ``provider.status`` event attrs), which the ``sibyl-sim`` status-feed double serves.

Only identifiers, names and states are kept in ``raw`` (≤ 8 KB); incident bodies never are.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

STATUSES = frozenset(
    {
        "operational",
        "degraded_performance",
        "partial_outage",
        "major_outage",
        "maintenance",
        "unknown",
    }
)
INDICATOR = {
    "none": "operational",
    "minor": "degraded_performance",
    "major": "partial_outage",
    "critical": "major_outage",
    "maintenance": "maintenance",
}
OPEN_INCIDENT = frozenset({"investigating", "identified", "monitoring"})
MAX_ITEMS = 5
MAX_TEXT = 120


@dataclass(frozen=True)
class FeedStatus:
    status: str
    incident_ref: str | None
    raw: Mapping[str, Any]


def _text(value: Any) -> str | None:
    return None if value is None else str(value)[:MAX_TEXT]


def _items(doc: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    value = doc.get(key)
    return [i for i in value if isinstance(i, Mapping)] if isinstance(value, list) else []


def parse_feed(doc: Any) -> FeedStatus:
    if not isinstance(doc, Mapping):
        return FeedStatus("unknown", None, {"error": "not an object"})
    status = doc.get("status")
    if isinstance(status, str):
        parsed = status if status in STATUSES else "unknown"
        return FeedStatus(parsed, _text(doc.get("incident_id")), {"status": parsed})
    if isinstance(status, Mapping):
        indicator = str(status.get("indicator", ""))
        parsed = INDICATOR.get(indicator, "unknown")
        incidents = [
            {
                "id": _text(i.get("id")),
                "name": _text(i.get("name")),
                "status": _text(i.get("status")),
            }
            for i in _items(doc, "incidents")
            if i.get("status") in OPEN_INCIDENT or "status" not in i
        ][:MAX_ITEMS]
        maintenance = [
            {"id": _text(m.get("id")), "status": _text(m.get("status"))}
            for m in _items(doc, "scheduled_maintenances")
            if m.get("status") == "in_progress"
        ][:MAX_ITEMS]
        if parsed == "operational" and maintenance:
            parsed = "maintenance"
        raw = {
            "indicator": _text(indicator),
            "description": _text(status.get("description")),
            "incidents": incidents,
            "maintenance": maintenance,
        }
        ref = incidents[0]["id"] if incidents else (maintenance[0]["id"] if maintenance else None)
        return FeedStatus(parsed, ref, raw)
    return FeedStatus("unknown", None, {"error": "no status field"})
