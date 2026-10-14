"""D48 Action Gate schemas (ACTION-GATE.md §3): action policies, held actions, decisions.

Enumerations render the ``sibyl_schemas`` value sets inline (single source); the policy
document itself is ``sibyl-action-policy/1``, owned by ``sibyl_schemas.action_gate`` and
validated server-side with ``parse_policy``, so the API carries it as an open object.
"""

from __future__ import annotations

from enum import Enum

from sibyl_schemas import values as sv

from .dsl import (
    N_TS,
    N_UUID,
    REASON,
    TS,
    UUID,
    Schema,
    array,
    body_obj,
    boolean,
    enum,
    free_object,
    integer,
    nullable,
    obj,
    ref,
    string,
)

CALL_ID = string(pattern=r"^[A-Za-z0-9._:-]{1,160}$")
TOOL = string(minLength=1, maxLength=256)
NUMERIC = string(pattern=r"^-?[0-9]+(\.[0-9]+)?$", description="decimal as a string")
SHA256 = string(pattern=r"^[0-9a-f]{64}$")
UNSIGNED = string(pattern=r"^[0-9]{1,30}(\.[0-9]{1,18})?$")


def _enum(values: type[Enum]) -> Schema:
    return enum(*(str(m.value) for m in values))


EFFECT = _enum(sv.ActionEffect)
HISTORY_KINDS = (
    "requested",
    "blocked",
    "approval",
    "refused",
    "approved",
    "denied",
    "expired",
    "cancelled",
)


def _policies() -> dict[str, Schema]:
    return {
        "ActionPolicyCreate": body_obj(
            {
                "name": string(minLength=1, maxLength=200),
                "scope_kind": _enum(sv.ActionScopeKind),
                "scope_id": N_UUID,
                "document": free_object(
                    "sibyl-action-policy/1 document (rules, default_effect, hold_timeout_s,"
                    " sensitive_tools …); policy_id and version are assigned, omitted"
                    " tool lists and limits take their defaults"
                ),
                "four_eyes": boolean(description="held actions need two distinct approvers"),
                "reason": REASON,
                "change_note": string(
                    minLength=1, maxLength=2000, description="what this version changes (kept)"
                ),
                "based_on_id": nullable(
                    {
                        **UUID,
                        "description": "the version this one revises; must be a version of the"
                        " same scope (the same policy_id), else 422",
                    }
                ),
            },
            ("name", "scope_kind", "document"),
        ),
        "ActionPolicyScope": obj(
            {
                "kind": _enum(sv.ActionScopeKind),
                "id": N_UUID,
                "label": string(description="agent name, agent-group name or 'All agents'"),
            },
            ("kind", "id", "label"),
        ),
        "ActionPolicyApproval": obj(
            {"user_id": UUID, "at": TS, "reason": nullable(string())},
            ("user_id", "at", "reason"),
        ),
        "ActionRuleView": obj(
            {
                "position": integer(minimum=1),
                "rule_id": string(),
                "tool": TOOL,
                "effect": EFFECT,
                "reason": string(),
                "when": nullable(free_object("argument predicate AST")),
                "cumulative": nullable(free_object("cumulative cap")),
                "data_class": nullable(free_object("data-classification rule")),
            },
            ("position", "rule_id", "tool", "effect", "reason"),
        ),
        "ActionPolicy": obj(
            {
                "id": {
                    **UUID,
                    "description": "the version id (the snapshot key, document.policy_id)",
                },
                "policy_id": {
                    **UUID,
                    "description": "stable across every version of one scope (the first version's"
                    " id); cumulative counters are kept per policy_id",
                },
                "name": string(),
                "scope": ref("ActionPolicyScope"),
                "scope_kind": _enum(sv.ActionScopeKind),
                "scope_id": N_UUID,
                "version_no": integer(minimum=1),
                "state": _enum(sv.ActionPolicyState),
                "document": free_object("normalised sibyl-action-policy/1 document"),
                "document_sha256": SHA256,
                "default_effect": EFFECT,
                "hold_timeout_s": integer(minimum=10, maximum=86400),
                "four_eyes": boolean(description="held actions need two distinct approvers"),
                "approval_four_eyes": boolean(
                    description="a tier-1 agent is in scope: the author cannot approve"
                ),
                "rules": array(ref("ActionRuleView")),
                "change_note": nullable(string()),
                "approvals": array(ref("ActionPolicyApproval")),
                "created_by": UUID,
                "approved_by": N_UUID,
                "approved_at": N_TS,
                "retired_by": N_UUID,
                "retired_at": N_TS,
                "superseded_by": N_UUID,
                "superseded_at": N_TS,
                "created_at": TS,
                "updated_at": TS,
            },
            (
                "id",
                "policy_id",
                "name",
                "scope",
                "scope_kind",
                "version_no",
                "state",
                "document",
                "rules",
            ),
        ),
        "ActionSimulate": body_obj(
            {
                "tool": TOOL,
                "args": free_object("the proposed tool arguments"),
                "agent_id": UUID,
                "counters": free_object("counter key -> current window total (numbers)"),
            },
            ("tool", "args"),
        ),
        "ActionPolicyDraftSimulate": body_obj(
            {
                "document": free_object(
                    "an unsaved sibyl-action-policy/1 document (defaults as on create)"
                ),
                "scope_kind": _enum(sv.ActionScopeKind),
                "scope_id": N_UUID,
                "tool": TOOL,
                "args": free_object("the proposed tool arguments"),
                "agent_id": UUID,
                "counters": free_object("counter key -> current window total (numbers)"),
            },
            ("document", "tool", "args"),
            description="with agent_id the draft takes its scope's place (scope_kind defaults to"
            " agent) beside the agent's other approved policies",
        ),
    }


def _decisions() -> dict[str, Schema]:
    counter = obj(
        {
            "key": string(),
            "amount": NUMERIC,
            "max": NUMERIC,
            "window_s": integer(minimum=1),
            "value": nullable(NUMERIC),
            "window_start": N_TS,
        },
        ("key", "amount", "max", "window_s"),
    )
    return {
        "ActionCounter": counter,
        "ActionDecision": obj(
            {
                "effect": EFFECT,
                "rule_id": nullable(string()),
                "reason": string(),
                "matched_paths": array(string()),
                "policy_id": N_UUID,
                "policy_version": nullable(integer(minimum=1)),
                "counter": nullable(ref("ActionCounter")),
                "sensitive": boolean(),
                "hold_timeout_s": nullable(integer(minimum=1)),
                "policy_state": nullable(
                    {**_enum(sv.ActionPolicyState), "description": "null for an unsaved draft"}
                ),
                "evaluated_at": TS,
            },
            ("effect", "rule_id", "reason", "policy_id"),
        ),
        "ActionDecisionRequest": body_obj(
            {
                "call_id": CALL_ID,
                "agent_id": UUID,
                "source": _enum(sv.ActionSource),
                "policy_id": UUID,
                "policy_version": integer(minimum=1),
                "rule_id": string(maxLength=64),
                "tool": TOOL,
                "counter_key": string(minLength=1, maxLength=200),
                "increment": UNSIGNED,
                "max": UNSIGNED,
                "window_s": integer(minimum=1),
                "args_sha256": SHA256,
            },
            (
                "call_id",
                "agent_id",
                "source",
                "policy_id",
                "policy_version",
                "rule_id",
                "tool",
                "counter_key",
                "increment",
                "max",
                "window_s",
                "args_sha256",
            ),
            description="sibyl_schemas.action_gate.ActionDecisionRequest; max and window_s are"
            " re-read from the control plane's copy of the rule",
        ),
        "ActionDecisionResult": obj(
            {
                "call_id": CALL_ID,
                "within_cap": boolean(description="the counter was incremented only when true"),
                "counter_value": nullable(NUMERIC),
                "agent_id": UUID,
                "effect": EFFECT,
                "policy_id": UUID,
                "policy_version": integer(minimum=1),
                "rule_id": string(),
                "counter_key": string(),
                "max": nullable(NUMERIC),
                "window_s": integer(minimum=1),
                "window_start": N_TS,
                "replayed": boolean(description="a stored decision for this call_id"),
            },
            ("call_id", "within_cap"),
        ),
    }


def _holds() -> dict[str, Schema]:
    approval = obj({"user_id": UUID, "session_id": N_UUID, "at": TS}, ("user_id", "at"))
    history = obj(
        {
            "at": TS,
            "kind": enum(*HISTORY_KINDS),
            "user_id": N_UUID,
            "key_id": N_UUID,
            "reason": nullable(string()),
            "step_up": boolean(description="the decision needed (and had) a fresh step-up"),
            "code": nullable(string(description="refused: the problem code (self_approval …)")),
            "approvals": nullable(integer(minimum=0, maximum=2)),
        },
        ("at", "kind", "user_id", "key_id", "reason", "step_up", "code", "approvals"),
    )
    return {
        "OnBehalfOfUser": body_obj(
            {"kind": enum("user"), "id": UUID},
            ("kind", "id"),
            description="an app_user of this tenant; never approves the hold",
        ),
        "OnBehalfOfExternal": body_obj(
            {
                "kind": enum("external"),
                "ref": string(minLength=1, maxLength=128, pattern=r"^[^\x00-\x1f\x7f]+$"),
            },
            ("kind", "ref"),
        ),
        "OnBehalfOf": {
            "oneOf": [ref("OnBehalfOfUser"), ref("OnBehalfOfExternal")],
            "discriminator": {"propertyName": "kind"},
            "description": "frozen (WAVE3.md); gateway header X-Sibyl-On-Behalf-Of:"
            " user:<uuid> | external:<ref>",
        },
        "HeldActionHistoryEntry": history,
        "HeldActionCounter": obj(
            {
                "key": string(),
                "amount": NUMERIC,
                "max": NUMERIC,
                "window_s": integer(minimum=1),
                "applied_at": nullable(
                    {**TS, "description": "set when an approval added amount to the window"}
                ),
            },
            ("key", "amount", "max", "window_s", "applied_at"),
        ),
        "HeldActionRequest": body_obj(
            {
                "call_id": CALL_ID,
                "agent_id": UUID,
                "source": _enum(sv.ActionSource),
                "tool": TOOL,
                "args": free_object("secrets-scrubbed arguments (scrubbed again and sealed)"),
                "args_sha256": SHA256,
                "policy_id": N_UUID,
                "policy_version": nullable(integer(minimum=1)),
                "rule_id": nullable(string(maxLength=64)),
                "reason": string(maxLength=500),
                "hold_timeout_s": integer(minimum=1, maximum=86400),
                "task_id": string(),
                "on_behalf_of": nullable(ref("OnBehalfOf")),
            },
            (
                "call_id",
                "agent_id",
                "source",
                "tool",
                "args",
                "args_sha256",
                "policy_id",
                "policy_version",
                "rule_id",
                "reason",
                "hold_timeout_s",
            ),
            description="sibyl_schemas.action_gate.HeldActionRequest",
        ),
        "HeldActionApproval": approval,
        "HeldAction": obj(
            {
                "held_action_id": UUID,
                "id": UUID,
                "agent_id": UUID,
                "policy_id": UUID,
                "policy_version": integer(minimum=1),
                "rule_id": nullable(string()),
                "call_id": CALL_ID,
                "tool": TOOL,
                "source": _enum(sv.ActionSource),
                "args_sha256": SHA256,
                "args_payload_ref": N_UUID,
                "args": nullable(
                    free_object("scrubbed arguments (single-object reads by humans only)")
                ),
                "server_effect": EFFECT,
                "reason": string(),
                "sensitive": boolean(),
                "approvals_required": integer(minimum=1, maximum=2),
                "approvals": array(ref("HeldActionApproval")),
                "state": _enum(sv.HeldActionState),
                "decision": nullable(enum("allow", "deny")),
                "decided_by": N_UUID,
                "decided_at": N_TS,
                "decision_reason": nullable(string()),
                "resolved_by_timeout": boolean(),
                "hold_timeout_s": integer(minimum=1, maximum=86400),
                "expires_at": TS,
                "created_at": TS,
                "on_behalf_of": nullable(ref("OnBehalfOf")),
                "matched_paths": array(string()),
                "four_eyes": boolean(description="two distinct approvers (approvals_required 2)"),
                "counter": nullable(ref("HeldActionCounter")),
                "history": array(
                    ref("HeldActionHistoryEntry"),
                    description="single-object reads only (GET by id, the decision response)",
                ),
            },
            ("held_action_id", "state", "agent_id", "call_id", "tool", "decision", "expires_at"),
            description="a superset of sibyl_schemas.action_gate.HeldActionStatus",
        ),
        "HeldActionAction": body_obj(
            {"action": enum("approve", "deny"), "reason": REASON}, ("action", "reason")
        ),
    }


def _summary() -> dict[str, Schema]:
    names = ("blocked", "escalated", "approved", "denied", "expired")

    def counts() -> dict[str, Schema]:
        return {name: integer(minimum=0) for name in names}

    return {
        "ActionSummaryRow": obj({"agent_id": UUID, **counts()}, ("agent_id", *names)),
        "ActionSummary": obj(
            {
                "from": TS,
                "to": TS,
                "data": array(ref("ActionSummaryRow")),
                "total": obj(counts(), names),
            },
            ("from", "to", "data", "total"),
            description="distinct calls per agent from the audit chain: blocked / escalated"
            " (action.blocked / action.escalated by call_id), approved (final approvals),"
            " denied, expired (by held action)",
        ),
    }


def action_gate_schemas() -> dict[str, Schema]:
    return {**_policies(), **_decisions(), **_holds(), **_summary()}
