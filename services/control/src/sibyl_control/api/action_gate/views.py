"""Response bodies of the Action Gate routes (OpenAPI ``ActionPolicy``, ``HeldAction``)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any
from uuid import UUID

from ...core.etag import etag_for_row
from ..registry._kit import jsonable

JSON = dict[str, Any]


TENANT_LABEL = "All agents"


def scope_id(row: Mapping[str, Any]) -> UUID | None:
    value: UUID | None = row["agent_id"] or row["agent_group_id"]
    return value


def scope_view(row: Mapping[str, Any], label: str | None) -> JSON:
    """``{kind, id, label}``: the agent or agent-group name, ``All agents`` for the tenant."""
    kind = row["scope_kind"]
    text = TENANT_LABEL if kind == "tenant" else (label or str(scope_id(row)))
    return {"kind": kind, "id": scope_id(row), "label": text}


def rule_view(row: Mapping[str, Any]) -> JSON:
    return {
        "position": int(row["position"]),
        "rule_id": row["rule_id"],
        "tool": row["tool"],
        "effect": row["effect"],
        "reason": row["reason"],
        "when": row["when_expr"],
        "cumulative": row["cumulative"],
        "data_class": row["data_class"],
    }


def policy_view(row: Mapping[str, Any], rules: Sequence[Mapping[str, Any]]) -> JSON:
    out = {
        "id": row["id"],
        "policy_id": row["policy_id"],
        "name": row["name"],
        "scope": scope_view(row, row.get("scope_label")),
        "scope_kind": row["scope_kind"],
        "scope_id": scope_id(row),
        "version_no": int(row["version_no"]),
        "state": row["state"],
        "document": row["document"],
        "document_sha256": bytes(row["document_sha256"]).hex(),
        "default_effect": row["default_effect"],
        "hold_timeout_s": int(row["hold_timeout_s"]),
        "four_eyes": bool(row["four_eyes"]),
        "approval_four_eyes": bool(row["approval_four_eyes"]),
        "rules": [rule_view(r) for r in rules],
        "change_note": row["change_note"],
        "approvals": list(row["approvals"] or []),
        "created_by": row["created_by_user_id"],
        "approved_by": row["approved_by_user_id"],
        "approved_at": row["approved_at"],
        "retired_by": row["retired_by_user_id"],
        "retired_at": row["retired_at"],
        "superseded_by": row["superseded_by"],
        "superseded_at": row["superseded_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    body: JSON = jsonable(out)
    return body


def policy_etag(row: Mapping[str, Any]) -> str:
    return etag_for_row(row["updated_at"], row["id"])


def on_behalf_of_view(row: Mapping[str, Any]) -> JSON | None:
    kind = row["on_behalf_of_kind"]
    if kind == "user":
        return {"kind": "user", "id": row["on_behalf_of_user_id"]}
    if kind == "external":
        return {"kind": "external", "ref": row["on_behalf_of_ref"]}
    return None


def _number(value: Decimal) -> str:
    text = format(Decimal(value).normalize(), "f")
    return "0" if text in ("-0", "") else text


def counter_view(row: Mapping[str, Any]) -> JSON | None:
    if row["counter_key"] is None:
        return None
    return {
        "key": row["counter_key"],
        "amount": _number(row["counter_amount"]),
        "max": _number(row["counter_max"]),
        "window_s": int(row["counter_window_s"]),
        "applied_at": row["counter_applied_at"],
    }


def held_view(row: Mapping[str, Any], *, args: Any = None, history: bool = False) -> JSON:
    """The held action; ``history`` (the decision trail) on single-object reads only."""
    out = {
        "held_action_id": row["id"],
        "id": row["id"],
        "agent_id": row["agent_id"],
        "policy_id": row["policy_id"],
        "policy_version": row["policy_version"],
        "rule_id": row["rule_id"],
        "call_id": row["call_id"],
        "tool": row["tool"],
        "source": row["source"],
        "args_sha256": bytes(row["args_sha256"]).hex(),
        "args_payload_ref": row["args_payload_ref"],
        "args": args,
        "server_effect": row["server_effect"],
        "reason": row["reason"],
        "sensitive": bool(row["sensitive"]),
        "approvals_required": int(row["approvals_required"]),
        "approvals": list(row["approvals"] or []),
        "state": row["state"],
        "decision": row["decision"],
        "decided_by": row["decided_by_user_id"],
        "decided_at": row["decided_at"],
        "decision_reason": row["decision_reason"],
        "resolved_by_timeout": bool(row["resolved_by_timeout"]),
        "hold_timeout_s": int(row["hold_timeout_s"]),
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "on_behalf_of": on_behalf_of_view(row),
        "matched_paths": list(row["matched_paths"] or []),
        "four_eyes": int(row["approvals_required"]) >= 2,
        "counter": counter_view(row),
    }
    if history:
        out["history"] = list(row["history"] or [])
    body: JSON = jsonable(out)
    return body


def held_etag(row: Mapping[str, Any]) -> str:
    return etag_for_row(row["updated_at"], row["id"])
