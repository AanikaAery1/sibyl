"""Action Gate value sets (D48, ACTION-GATE.md §1/§3): the control-plane vocabulary of action
policies and held actions. `sibyl.action_policy`, `sibyl.held_action` and
`sibyl.action_decision` CHECK constraints enumerate exactly these (drift-tested); the policy
document model and the pure evaluator live in `sibyl_schemas.action_gate`.
"""

from __future__ import annotations

from enum import StrEnum


class ActionEffect(StrEnum):
    """Outcome of evaluating a proposed tool call; ordered by restrictiveness."""

    ALLOW = "allow"
    ESCALATE = "escalate"
    BLOCK = "block"


class ActionPolicyState(StrEnum):
    """`draft -> approved -> superseded | retired`; only `approved` is enforced (snapshot)."""

    DRAFT = "draft"
    APPROVED = "approved"
    SUPERSEDED = "superseded"
    RETIRED = "retired"


class ActionScopeKind(StrEnum):
    """What an action policy applies to; the most specific approved policy wins
    (agent > agent_group > tenant)."""

    TENANT = "tenant"
    AGENT_GROUP = "agent_group"
    AGENT = "agent"


class HeldActionState(StrEnum):
    """`pending -> approved | denied | expired | cancelled` (state machine `held_action`)."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ToolActionEffect(StrEnum):
    """Action Gate outcome recorded on a `tool.call` event (`attrs.action_effect`): what the
    enforcement point did with the call, not the policy effect alone (`escalate` resolves to
    `held`, then `approved` or `denied`)."""

    ALLOW = "allow"
    BLOCK = "block"
    HELD = "held"
    APPROVED = "approved"
    DENIED = "denied"


class ActionSource(StrEnum):
    """The enforcement point that proposed the action."""

    SDK = "sdk"
    GATEWAY = "gateway"
