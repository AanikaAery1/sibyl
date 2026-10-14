"""D48 Action Gate routes (ACTION-GATE.md §3): action policies, held actions, decisions.

Humans read with ``actions:read``, write policies with ``action_policies:write`` and decide held
actions with ``actions:decide`` (four-eyes per policy, no self-approval, step-up for sensitive
tools). Enforcement points (gateway, SDK) act through API keys holding ``actions:hold``.
"""

from __future__ import annotations

from sibyl_schemas import values as sv

from .dsl import UUID, ActionRule, Op, Q, array, boolean, enum
from .params import AGENT_ID_Q, FROM_Q, TO_Q
from .schemas_action_gate import TOOL

READ = "actions:read"
DECIDE = "actions:decide"
WRITE = "action_policies:write"
HOLD = "actions:hold"


def _enum(values: type) -> dict[str, object]:
    return enum(*(str(m.value) for m in values))


HELD_ACTION_ACTIONS = {
    "approve": ActionRule(
        DECIDE,
        ("action.approved",),
        step_up="conditional",
        rules=("four_eyes",),
        note="step-up when the tool is sensitive; four-eyes holds need two distinct approvers",
    ),
    "deny": ActionRule(
        DECIDE,
        ("action.denied",),
        step_up="conditional",
        rules=("four_eyes",),
        note="step-up when the tool is sensitive; one deny ends the hold",
    ),
}

POLICIES: tuple[Op, ...] = (
    Op(
        "get",
        "/action-policies",
        "listActionPolicies",
        "action_gate",
        "Action policies (every version)",
        scope=READ,
        paged=True,
        query=(
            Q("state", _enum(sv.ActionPolicyState)),
            Q("scope_kind", _enum(sv.ActionScopeKind)),
            AGENT_ID_Q,
            Q("policy_id", UUID, description="every version of one policy (stable id)"),
            Q(
                "include_history",
                boolean(default=False),
                description="list superseded versions too (default: only with state=superseded)",
            ),
        ),
        ok=((200, "ActionPolicy", "Page of action policies"),),
        description="agent_id is the agent of an agent-scoped policy (not every policy that"
        " applies to the agent).",
    ),
    Op(
        "post",
        "/action-policies",
        "createActionPolicy",
        "action_gate",
        "Create a draft action policy version for a scope",
        scope=WRITE,
        idem=True,
        audit=("action_policy.created",),
        body="ActionPolicyCreate",
        ok=((201, "ActionPolicy", "Draft created"),),
        etag_out=True,
        problems={404: ("not_found",), 422: ("validation_failed",)},
        description="The document is validated with sibyl_schemas.action_gate.parse_policy. A"
        " version of an existing scope keeps that scope's policy_id; based_on_id, when given,"
        " must be a version of the same scope.",
    ),
    Op(
        "post",
        "/action-policies/simulate",
        "simulateActionPolicyDraft",
        "action_gate",
        "Dry-run an unsaved policy document against sample arguments; writes nothing",
        scope=READ,
        idem=True,
        body="ActionPolicyDraftSimulate",
        ok=((200, "ActionDecision", "Decision"),),
        problems={404: ("not_found",), 422: ("validation_failed",)},
        description="With agent_id the draft replaces the approved policy of its own scope and"
        " is combined with the agent's other approved policies (most restrictive wins).",
    ),
    Op(
        "get",
        "/action-policies/{policy_id}",
        "getActionPolicy",
        "action_gate",
        "One action policy version with its rules",
        scope=READ,
        ok=((200, "ActionPolicy", "Action policy"),),
        etag_out=True,
    ),
    Op(
        "post",
        "/action-policies/{policy_id}/approve",
        "approveActionPolicy",
        "action_gate",
        "Approve a draft; it supersedes the scope's approved version and enters the snapshot",
        scope=WRITE,
        rules=("four_eyes_tier1",),
        idem=True,
        audit=("action_policy.approved",),
        body="ReasonBody",
        ok=((200, "ActionPolicy", "Approved"),),
        problems={409: ("invalid_transition", "self_approval")},
    ),
    Op(
        "post",
        "/action-policies/{policy_id}/retire",
        "retireActionPolicy",
        "action_gate",
        "Retire a draft or the approved version (leaves the snapshot)",
        scope=WRITE,
        idem=True,
        audit=("action_policy.retired",),
        body="ReasonBody",
        ok=((200, "ActionPolicy", "Retired"),),
        problems={409: ("invalid_transition",)},
    ),
    Op(
        "post",
        "/action-policies/{policy_id}/simulate",
        "simulateActionPolicy",
        "action_gate",
        "Dry-run the policy against sample arguments; writes nothing",
        scope=READ,
        idem=True,
        body="ActionSimulate",
        ok=((200, "ActionDecision", "Decision"),),
    ),
)

HOLDS: tuple[Op, ...] = (
    Op(
        "post",
        "/held-actions",
        "createHeldAction",
        "action_gate",
        "Hold an escalated action for a human (gateway, SDK); idempotent per (agent, call_id)",
        scope=HOLD,
        key_scopes=(HOLD,),
        key_only=True,
        rules=("bound_agent",),
        idem=True,
        audit=("action.escalated", "action.blocked"),
        audit_note="action.blocked when the control plane's own evaluation blocks the call",
        body="HeldActionRequest",
        ok=((201, "HeldAction", "Held"), (200, "HeldAction", "Existing hold for this call_id")),
        problems={404: ("not_found",), 413: ("payload_too_large",), 503: ("service_unavailable",)},
    ),
    Op(
        "get",
        "/held-actions",
        "listHeldActions",
        "action_gate",
        "Held actions (the approval queue)",
        scope=READ,
        paged=True,
        query=(
            Q(
                "state",
                array(_enum(sv.HeldActionState), uniqueItems=True),
                description="repeat for any of several states (state=pending&state=approved)",
            ),
            AGENT_ID_Q,
            Q("tool", TOOL),
            Q(
                "include",
                enum("args"),
                description="args: add the scrubbed arguments for human callers holding"
                " actions:decide over the agent's group; others get args null",
            ),
        ),
        ok=((200, "HeldAction", "Page of held actions"),),
    ),
    Op(
        "get",
        "/held-actions/{held_action_id}",
        "getHeldAction",
        "action_gate",
        "One held action; enforcement points poll it for the decision",
        scope=READ,
        scope_any=(HOLD,),
        key_scopes=(HOLD,),
        rules=("bound_agent",),
        ok=((200, "HeldAction", "Held action"),),
        etag_out=True,
    ),
    Op(
        "post",
        "/held-actions/{held_action_id}/actions",
        "actOnHeldAction",
        "action_gate",
        "Approve or deny a held action (four-eyes per policy; the requester never decides)",
        scope=DECIDE,
        idem=True,
        audit=("action.approved", "action.denied"),
        audit_note="per action; see x-sibyl-actions",
        per_action=HELD_ACTION_ACTIONS,
        body="HeldActionAction",
        ok=((200, "HeldAction", "Decision recorded"),),
        problems={
            403: ("step_up_required",),
            409: ("action_not_pending", "self_approval", "duplicate_approver"),
        },
    ),
)

DECISIONS: tuple[Op, ...] = (
    Op(
        "post",
        "/action-decisions",
        "decideAction",
        "action_gate",
        "Authoritative cumulative check-and-increment; idempotent per (agent, call_id)",
        scope=HOLD,
        key_scopes=(HOLD,),
        key_only=True,
        rules=("bound_agent",),
        idem=True,
        audit=("action.allowed", "action.blocked", "action.escalated"),
        audit_when="conditional",
        audit_note="action.allowed is sampled (always for sensitive tools)",
        body="ActionDecisionRequest",
        ok=((200, "ActionDecisionResult", "Decision"),),
        problems={404: ("not_found",), 413: ("payload_too_large",)},
    ),
)

SUMMARY: tuple[Op, ...] = (
    Op(
        "get",
        "/action-summary",
        "getActionSummary",
        "action_gate",
        "Blocked, escalated and decided actions per agent over a window (fleet view)",
        scope=READ,
        query=(FROM_Q, TO_Q, AGENT_ID_Q),
        ok=((200, "ActionSummary", "Counts per agent"),),
        problems={422: ("validation_failed",)},
        description="Default window: the last 24 hours; at most 31 days. Counted from the audit"
        " chain, so it covers what reached the control plane (holds and cumulative decisions).",
    ),
)

ACTION_GATE_OPS: tuple[Op, ...] = POLICIES + HOLDS + DECISIONS + SUMMARY
