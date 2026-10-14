"""Response bodies of the Sentinel routes (OpenAPI ``SentinelConfig`` / ``SentinelFinding``).

The API key never appears: a config view says only whether one is vaulted and its last four
characters (``key_hint``).
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from ..registry._kit import JSON, jsonable


def money(value: Any, places: str = "0.000001") -> str | None:
    if value is None:
        return None
    return str(Decimal(value).quantize(Decimal(places)))


def usage_view(row: Mapping[str, Any] | None) -> JSON | None:
    if row is None:
        return None
    return {
        "day": row["day"].isoformat(),
        "spent_usd": money(row["spent_usd"]),
        "calls": int(row["calls"]),
        "findings": int(row["findings"]),
        "failures": int(row["failures"]),
        "skipped_budget": int(row["skipped_budget"]),
        "skipped_sampling": int(row["skipped_sampling"]),
        "exhausted": row["exhausted_at"] is not None,
    }


def config_view(row: Mapping[str, Any] | None, usage: Mapping[str, Any] | None) -> JSON:
    if row is None:
        return {
            "configured": False,
            "enabled": False,
            "provider": None,
            "model": None,
            "base_url": None,
            "has_key": False,
            "key_hint": None,
            "key_updated_at": None,
            "daily_budget_usd": None,
            "sampling_rate": None,
            "tasks": [],
            "price_in_usd_per_mtok": None,
            "price_out_usd_per_mtok": None,
            "version": 0,
            "updated_at": None,
            "usage_today": usage_view(usage),
            "advisory": True,
        }
    return {
        "configured": True,
        "enabled": bool(row["enabled"]),
        "provider": row["provider"],
        "model": row["model"],
        "base_url": row["base_url"],
        "has_key": row["key_version"] is not None,
        "key_hint": row["key_hint"],
        "key_updated_at": jsonable(row["key_updated_at"]),
        "daily_budget_usd": money(row["daily_budget_usd"], "0.0001"),
        "sampling_rate": float(row["sampling_rate"]),
        "tasks": list(row["tasks"] or ()),
        "price_in_usd_per_mtok": money(row["price_in_usd_per_mtok"], "0.0001"),
        "price_out_usd_per_mtok": money(row["price_out_usd_per_mtok"], "0.0001"),
        "version": int(row["version"]),
        "updated_at": jsonable(row["updated_at"]),
        "usage_today": usage_view(usage),
        "advisory": True,
    }


FINDING_FIELDS = (
    "id",
    "kind",
    "subject_kind",
    "subject_id",
    "agent_id",
    "severity",
    "summary",
    "recommendation",
    "provider",
    "model",
    "tokens_in",
    "tokens_out",
    "cost_estimated",
    "calls",
    "trigger",
    "requested_by_user_id",
    "alert_id",
    "feedback",
    "feedback_by_user_id",
    "feedback_at",
    "created_at",
)


def finding_view(row: Mapping[str, Any]) -> JSON:
    out: JSON = {name: jsonable(row[name]) for name in FINDING_FIELDS}
    body = row["body"]
    out["body"] = body if isinstance(body, dict) else {}
    out["prompt_sha256"] = bytes(row["prompt_sha256"]).hex()
    out["cost_usd"] = money(row["cost_usd"])
    out["advisory"] = True
    return out
