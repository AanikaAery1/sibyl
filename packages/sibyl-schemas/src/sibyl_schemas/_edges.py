"""State-machine edges for the twelve machines (W0-11, API §6.1; chair ruling G0-3; B14 ``job``;
D48 ``held_action`` and ``action_policy``).

`(machine, from_state, to_state, trigger)`; `""` is the creation pseudo-state. Routing edges
carry the exact trigger `routing_apply()` passes; the other machines use `"*"` (any trigger)
except the tenant-key shred and the R63 erasure `restore` edges. `services/control` seeds
`sibyl.state_edge` with the same set and a DB test diffs the migrated table against
`STATE_EDGES`.

G0-3: `undo` is the inverse of every automated (`rule`/`policy`) routing edge; operator
self-edges on `active`, `degraded` and `quarantined` implement `clear_hold`; the
`failed_over -> failed_over` (`rule`, `operator`) and `failing_back -> failing_back`
(`canary`) self-edges move between fallback steps and canary percentages.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, NamedTuple


class StateMachine(StrEnum):
    ROUTING = "routing"
    FAILOVER = "failover"
    APPROVAL = "approval"
    HANDOFF = "handoff"
    ALERT = "alert"
    ERASURE = "erasure"
    TENANT_KEY = "tenant_key"
    KILL_SWITCH = "kill_switch"
    LIFECYCLE = "lifecycle"
    JOB = "job"
    HELD_ACTION = "held_action"
    ACTION_POLICY = "action_policy"


class StateEdge(NamedTuple):
    machine: str
    from_state: str
    to_state: str
    trigger: str


ANY_TRIGGER: Final = "*"

# fmt: off
ROUTING_AUTOMATED_EDGES: Final = (
    ("active", "degraded", "rule"),
    ("degraded", "active", "rule"),
    ("degraded", "awaiting_approval", "rule"),
    ("active", "awaiting_approval", "rule"),
    ("degraded", "failed_over", "rule"),
    ("active", "failed_over", "rule"),
    ("active", "quarantined", "policy"),
    ("degraded", "quarantined", "policy"),
    ("failed_over", "quarantined", "policy"),
)
"""Edges a rule or policy actor takes on its own; each has an `undo` inverse."""

_ROUTING_OTHER: Final = (
    ("", "active", "register"),
    ("active", "degraded", "operator"),
    ("degraded", "active", "operator"),
    ("degraded", "failed_over", "approval"),
    ("degraded", "failed_over", "operator"),
    ("active", "failed_over", "operator"),
    ("awaiting_approval", "failed_over", "approval"),
    ("awaiting_approval", "failed_over", "approval_timeout"),
    ("awaiting_approval", "degraded", "approval"),
    ("awaiting_approval", "degraded", "approval_timeout"),
    ("failed_over", "failed_over", "rule"),
    ("failed_over", "failed_over", "operator"),
    ("failed_over", "failing_back", "failback_probe"),
    ("failed_over", "failing_back", "operator"),
    ("failing_back", "failing_back", "canary"),
    ("failing_back", "active", "canary"),
    ("failing_back", "failed_over", "canary"),
    ("active", "quarantined", "operator"),
    ("degraded", "quarantined", "operator"),
    ("failed_over", "quarantined", "operator"),
    ("quarantined", "active", "operator"),
    ("active", "killed", "operator"),
    ("degraded", "killed", "operator"),
    ("failed_over", "killed", "operator"),
    ("failing_back", "killed", "operator"),
    ("awaiting_approval", "killed", "operator"),
    ("quarantined", "killed", "operator"),
    ("killed", "active", "operator"),
    ("active", "active", "operator"),
    ("degraded", "degraded", "operator"),
    ("quarantined", "quarantined", "operator"),
)

_ANY: Final = {
    StateMachine.FAILOVER: (
        ("", "pending"), ("", "running"), ("pending", "running"), ("pending", "cancelled"),
        ("running", "waiting_approval"), ("waiting_approval", "running"),
        ("waiting_approval", "cancelled"), ("running", "done"), ("running", "failed"),
        ("running", "cancelled"),
    ),
    StateMachine.APPROVAL: (
        ("", "pending"), ("pending", "approved"), ("pending", "denied"), ("pending", "expired"),
        ("pending", "cancelled"),
    ),
    StateMachine.HANDOFF: (
        ("", "queued"), ("queued", "claimed"), ("claimed", "queued"), ("claimed", "completed"),
        ("queued", "returned"), ("queued", "expired"), ("expired", "claimed"),
    ),
    StateMachine.ALERT: (
        ("", "open"), ("open", "acked"), ("open", "resolved"), ("acked", "resolved"),
        ("acked", "open"), ("resolved", "open"),
    ),
    StateMachine.ERASURE: (
        ("", "requested"), ("requested", "hold_blocked"), ("hold_blocked", "requested"),
        ("requested", "approved"), ("approved", "hold_blocked"), ("approved", "executing"),
        ("executing", "keys_shredded"), ("executing", "objects_deleted"),
        ("keys_shredded", "objects_deleted"), ("objects_deleted", "derived_purged"),
        ("objects_deleted", "verified"), ("derived_purged", "verified"),
        ("verified", "completed"), ("requested", "rejected"), ("hold_blocked", "rejected"),
        ("requested", "cancelled"), ("hold_blocked", "cancelled"), ("approved", "cancelled"),
    ),
    StateMachine.TENANT_KEY: (("", "active"), ("active", "retired")),
    # B14: claim, finish, retry with back-off, a lease that expired is re-claimed (same state,
    # no edge needed), and a queued job may be failed (cancelled or past its deadline).
    StateMachine.JOB: (
        ("", "queued"), ("queued", "running"), ("running", "done"), ("running", "failed"),
        ("running", "queued"), ("queued", "failed"),
    ),
    StateMachine.KILL_SWITCH: (("", "pulled"), ("pulled", "released")),
    # D48 Action Gate: a hold is created pending (or denied at once when the control plane's
    # own evaluation blocks it); a pending hold is decided, expires (deny) or is cancelled.
    StateMachine.HELD_ACTION: (
        ("", "pending"), ("", "denied"), ("pending", "approved"), ("pending", "denied"),
        ("pending", "expired"), ("pending", "cancelled"),
    ),
    StateMachine.ACTION_POLICY: (
        ("", "draft"), ("draft", "approved"), ("draft", "retired"), ("approved", "superseded"),
        ("approved", "retired"),
    ),
    StateMachine.LIFECYCLE: (
        ("", "discovered"), ("", "proposed"), ("discovered", "proposed"),
        ("discovered", "retired"), ("proposed", "approved"), ("proposed", "discovered"),
        ("proposed", "retired"), ("approved", "deployed"), ("approved", "retired"),
        ("deployed", "monitored"), ("deployed", "retired"), ("monitored", "deployed"),
        ("monitored", "retired"),
    ),
}

_RESTORE_FROM: Final = (
    "requested", "hold_blocked", "approved", "keys_shredded", "objects_deleted",
    "derived_purged", "verified", "completed", "rejected", "cancelled",
)
"""R63: restore re-application may reopen any erasure request (sibyl_audit definers only)."""

_TRIGGERED: Final = (
    StateEdge("tenant_key", "active", "shredded", "shred"),
    StateEdge("tenant_key", "retired", "shredded", "shred"),
    *(StateEdge("erasure", s, "executing", "restore") for s in _RESTORE_FROM),
    StateEdge("erasure", "executing", "completed", "restore"),
)
# fmt: on


def _build() -> frozenset[StateEdge]:
    routing = [*ROUTING_AUTOMATED_EDGES, *_ROUTING_OTHER]
    routing += [(to, frm, "undo") for frm, to, _ in ROUTING_AUTOMATED_EDGES]
    edges = {StateEdge(StateMachine.ROUTING.value, *edge) for edge in routing}
    for machine, pairs in _ANY.items():
        edges |= {StateEdge(machine.value, frm, to, ANY_TRIGGER) for frm, to in pairs}
    return frozenset(edges | set(_TRIGGERED))


STATE_EDGES: Final = _build()
"""Every legal `(machine, from_state, to_state, trigger)`; `""` = creation."""
