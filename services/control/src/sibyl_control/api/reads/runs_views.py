"""Run tree projections (``RunSummary``, ``RunStep``, ``RunHandoff``, ``RunNode``)."""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import UUID

from ...worker.drift.identity import served_matches
from ..auth.common import iso
from .common import s, trace_hex

JSON = dict[str, Any]
ACTION_KEYS = ("action_effect", "action_rule_id", "held_action_id")


def _attrs(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _num(value: Any) -> float | None:
    if value is None:
        return None
    return float(value) if isinstance(value, Decimal | int | float) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def run_summary(row: Any) -> JSON:
    end = _attrs(row["end_attrs"])
    first = _attrs(row["first_attrs"])
    started, ended = row["started_at"], row["end_ts"]
    duration = _num(end.get("duration_ms"))
    if duration is None and started is not None and ended is not None:
        duration = (ended - started).total_seconds() * 1000
    status = row["run_status"]
    return {
        "run_id": str(row["run_id"]),
        "agent_id": s(row["agent_id"]),
        "agent_name": end.get("agent_name") or first.get("agent_name"),
        "parent_run_id": row["parent_run_id"],
        "step_index": row["step_index"],
        "status": status,
        "error_type": end.get("error_type") if status != "ok" else None,
        "started_at": iso(started),
        "ended_at": iso(ended),
        "duration_ms": duration,
        "trace_id": trace_hex(row["trace_id"]),
        "handoff_to_agent": row["handoff_to_agent"],
        "step_count": _int(end.get("steps")),
        "tool_calls": _int(end.get("tool_calls")),
        "model_calls": _int(end.get("model_calls")),
        "cost_usd": _num(end.get("cost_usd")),
    }


def _model_call(row: Any, attrs: dict[str, Any]) -> JSON:
    requested = attrs.get("request_model") or row["model"]
    served = row["response_model"] or attrs.get("response_model")
    mismatch = None
    if isinstance(requested, str) and isinstance(served, str):
        mismatch = not served_matches(requested, served)
    return {
        "call_id": s(row["call_id"]),
        "provider": row["provider"] or attrs.get("provider"),
        "requested_model": requested,
        "served_model": served,
        "model_mismatch": mismatch,
        "system_fingerprint": attrs.get("system_fingerprint"),
        "tokens_in": row["tokens_in"],
        "tokens_out": row["tokens_out"],
        "cost_usd": _num(row["cost_usd"]),
        "finish_reasons": attrs.get("finish_reasons"),
    }


def action_gate(attrs: dict[str, Any]) -> JSON | None:
    """The Action Gate outcome on a tool call, or None when the gate recorded nothing."""
    if not any(k in attrs for k in ACTION_KEYS):
        return None
    return {
        "effect": attrs.get("action_effect"),
        "rule_id": attrs.get("action_rule_id"),
        "held_action_id": attrs.get("held_action_id"),
    }


def _tool_call(attrs: dict[str, Any]) -> JSON:
    return {
        "tool_name": attrs.get("tool_name"),
        "tool_type": attrs.get("tool_type"),
        "tool_call_id": attrs.get("tool_call_id"),
        "side_effect_class": attrs.get("side_effect_class"),
        "handoff_to_agent": attrs.get("handoff_to_agent"),
        "action_gate": action_gate(attrs),
    }


def event_step(row: Any) -> JSON:
    attrs = _attrs(row["attrs"])
    is_model = row["event_type"] == "gen_ai.request"
    latency = row["latency_ms"]
    return {
        "kind": "model_call" if is_model else "tool_call",
        "step_index": _int(attrs.get("step_index")),
        "ts": iso(row["ts"]),
        "event_id": str(row["event_id"]),
        "status": row["status"],
        "error_type": row["error_type"],
        "latency_ms": latency if latency is not None else _num(attrs.get("latency_ms")),
        "model_call": _model_call(row, attrs) if is_model else None,
        "tool_call": None if is_model else _tool_call(attrs),
        "child_run_id": None,
    }


def child_step(child: JSON) -> JSON:
    return {
        "kind": "child_run",
        "step_index": child["step_index"],
        "ts": child["started_at"],
        "event_id": None,
        "status": child["status"],
        "error_type": child["error_type"],
        "latency_ms": child["duration_ms"],
        "model_call": None,
        "tool_call": None,
        "child_run_id": child["run_id"],
    }


def step_order(step: JSON) -> tuple[int, int, str]:
    index = step["step_index"]
    return (0 if index is not None else 1, index or 0, step["ts"] or "")


def handoff(
    from_run: str, ref: str, via: str, ts: str | None, event_id: str | None, agents: dict[str, UUID]
) -> JSON:
    to = agents.get(ref)
    return {
        "from_run_id": from_run,
        "to_agent": ref,
        "to_agent_id": str(to) if to else None,
        "via": via,
        "ts": ts,
        "event_id": event_id,
    }
