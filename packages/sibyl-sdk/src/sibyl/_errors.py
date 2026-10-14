"""The only exceptions the SDK ever raises into application code (API §8.1)."""

from __future__ import annotations

from uuid import UUID


class SibylError(Exception):
    """Base class for every Sibyl SDK exception."""


class SibylConfigError(SibylError):
    """Raised by `init()` for a missing or malformed configuration value."""


class SibylKilled(SibylError):
    """Raised by wrapped clients when policy state is `killed` (kill beats fail-open)."""

    def __init__(self, agent_id: UUID | None, policy_version: int, reason: str) -> None:
        super().__init__(f"agent {agent_id} is killed (policy version {policy_version}): {reason}")
        self.agent_id = agent_id
        self.policy_version = policy_version
        self.reason = reason


class SibylPolicyUnavailable(SibylError):
    """Raised only for fail-closed agents when no snapshot is fresh within `max_stale`."""

    def __init__(self, agent_id: UUID | str | None, freshness: str) -> None:
        super().__init__(
            f"no usable policy snapshot for fail-closed agent {agent_id} ({freshness})"
        )
        self.agent_id = agent_id
        self.freshness = freshness


class SibylActionBlocked(SibylError):
    """The Action Gate blocked a tool call before it ran (the function was not executed)."""

    def __init__(self, tool: str, rule_id: str | None, reason: str) -> None:
        super().__init__(f"tool {tool!r} blocked by {rule_id or 'policy default'}: {reason}")
        self.tool = tool
        self.rule_id = rule_id
        self.reason = reason


class SibylActionHeld(SibylError):
    """`mode="async"`: the call was escalated and is held for a human decision."""

    def __init__(
        self, tool: str, held_action_id: str, reason: str, *, rule_id: str | None = None
    ) -> None:
        super().__init__(f"tool {tool!r} held for approval ({held_action_id}): {reason}")
        self.tool = tool
        self.held_action_id = held_action_id
        self.reason = reason
        self.rule_id = rule_id


class SibylActionDenied(SibylError):
    """An escalated call was denied, expired, cancelled, or not decided in time."""

    def __init__(
        self,
        tool: str,
        held_action_id: str | None,
        state: str,
        reason: str,
        *,
        rule_id: str | None = None,
    ) -> None:
        super().__init__(f"tool {tool!r} not approved ({state}): {reason}")
        self.tool = tool
        self.held_action_id = held_action_id
        self.state = state
        self.reason = reason
        self.rule_id = rule_id
