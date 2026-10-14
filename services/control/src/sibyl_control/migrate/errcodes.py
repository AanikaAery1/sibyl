"""SQLSTATE map for errors raised by Sibyl database functions and triggers.

Every ``RAISE`` in ``services/control/migrations`` uses a custom SQLSTATE in class ``SB``
(W0-8) and a message that starts with ``sibyl:<code>`` (the W0-KER kernel contract), so a
caller can match either. ``test_invariants`` greps the migrations and fails on any raise
whose SQLSTATE is missing here or whose message prefix disagrees with this table.
"""

from __future__ import annotations

from typing import Final

SQLSTATE_TO_CODE: Final[dict[str, str]] = {
    "SB001": "tenant_not_set",
    "SB002": "tenant_mismatch",
    "SB010": "invalid_transition",
    "SB011": "stale_precondition",
    "SB012": "operator_hold",
    "SB013": "reason_required",
    "SB014": "routing_arguments",
    "SB015": "idempotency_key_reuse",
    "SB020": "audit_action_unknown",
    "SB021": "audit_actor_not_allowed",
    "SB022": "audit_field_missing",
    "SB023": "audit_detail_invalid",
    "SB024": "audit_canonical_mismatch",
    "SB025": "audit_chain_genesis",
    "SB030": "immutable_row",
    "SB031": "erasure_refused",
    "SB032": "legal_hold_active",
    "SB033": "tenant_erasing",
    "SB034": "erasure_blocked_by_chain",
    "SB035": "erasure_not_approved",
    "SB040": "fallback_chain_invalid",
    "SB041": "self_approval",
    "SB042": "owner_required",
    "SB043": "capture_policy_looser",
    "SB044": "key_field_immutable",
    "SB045": "graph_node_missing",
    "SB046": "fail_mode_required",
    "SB047": "breakglass_limit",
    "SB048": "continuity_plan_invalid",
    "SB049": "tenant_create_invalid",
    "SB050": "partition_policy_unknown",
    "SB051": "agent_unconfirmed",  # 0020 PLUG: discovered agents are never routed
    # SB060 (pre-G0 unsigned-ledger code) is retired; the signed ledger raises SB061.
    "SB061": "ledger_invalid",
}

CODE_TO_SQLSTATE: Final[dict[str, str]] = {v: k for k, v in SQLSTATE_TO_CODE.items()}


def code_for(sqlstate: str) -> str | None:
    """Return the Sibyl error code for a SQLSTATE, or None when it is not a Sibyl error."""
    return SQLSTATE_TO_CODE.get(sqlstate)
