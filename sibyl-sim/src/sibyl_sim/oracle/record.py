"""What one run observed, read only through the control-plane API and the actors' own view.

The oracle never queries the database (ML §8.1): every field here came from an HTTP response
(SSE frames as Operator/Admin/Auditor, health reads, listings, event reads) or from what an
actor saw on the wire (status codes, `X-Sibyl-*` headers). Times are sim seconds from the
scenario start.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ..harness.world import World
from ..scenarios.model import AgentRef
from .timing import Timing


@dataclass(frozen=True)
class SseEvent:
    t: float
    tenant: str
    event: str
    data: dict[str, Any]

    @property
    def agent_id(self) -> str | None:
        value = self.data.get("agent_id")
        return str(value) if value else None


@dataclass(frozen=True)
class HealthRead:
    t: float
    agent: AgentRef
    score: int
    status: str
    factors: tuple[dict[str, Any], ...] = ()
    recommended_action: str | None = None
    predicted_failure_mode: str | None = None
    provisional: bool = False
    events_seen: int = 0
    schema_errors: tuple[str, ...] = ()

    @classmethod
    def from_doc(cls, t: float, agent: AgentRef, doc: dict[str, Any]) -> HealthRead:
        prov = doc.get("provisional") or {}
        return cls(
            t,
            agent,
            int(doc.get("score", 0)),
            str(doc.get("status", "unknown")),
            tuple(doc.get("factors") or ()),
            doc.get("recommended_action"),
            doc.get("predicted_failure_mode"),
            bool(prov.get("flag", False)),
            int(prov.get("events_seen") or 0),
        )


@dataclass
class ActorStats:
    agent: AgentRef
    via: str = "gateway"
    requests: int = 0
    statuses: Counter[int] = field(default_factory=Counter)
    routes: Counter[str] = field(default_factory=Counter)
    errors: Counter[str] = field(default_factory=Counter)
    first_seen: dict[str, float] = field(default_factory=dict)  # "status:503" / "route:x" -> t
    tool_calls: int = 0
    tasks: int = 0
    # B38: (planned t, seconds late) for every arrival the actor sent
    late: list[tuple[float, float]] = field(default_factory=list)
    # A-5 ground truth: every proposed side-effecting call and what happened to it on the
    # agent's side: executed (the tool body ran), blocked, held, denied (incl. timeout)
    actions: list[dict[str, Any]] = field(default_factory=list)

    def note(self, key: str, t: float) -> None:
        self.first_seen.setdefault(key, t)

    def action(
        self,
        t: float,
        tool: str,
        args: Any,
        outcome: str,
        held_action_id: str | None = None,
        state: str | None = None,
    ) -> None:
        self.actions.append(
            {"t": round(t, 3), "tool": tool, "args": args, "outcome": outcome}
            | ({"held_action_id": held_action_id} if held_action_id else {})
            | ({"state": state} if state else {})
        )


@dataclass(frozen=True)
class CrossRead:
    """A deliberate cross-tenant read: `tenant`'s persona asking for `foreign`'s agent."""

    tenant: str
    persona: str
    foreign: AgentRef
    status: int


@dataclass
class RunRecord:
    scenario: str
    seed: int
    started_at: str
    duration_s: float
    world: World
    sse: list[SseEvent] = field(default_factory=list)
    health: dict[AgentRef, list[HealthRead]] = field(default_factory=dict)
    listed_agents: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    events: dict[AgentRef, list[dict[str, Any]]] = field(default_factory=dict)
    transitions: dict[AgentRef, list[dict[str, Any]]] = field(default_factory=dict)
    actors: dict[AgentRef, ActorStats] = field(default_factory=dict)
    cross_reads: list[CrossRead] = field(default_factory=list)
    lanes: dict[str, bool] = field(default_factory=dict)
    lane_reads: dict[str, Any] = field(default_factory=dict)
    persona_log: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    timing: Timing = field(default_factory=Timing)  # B38: measured tick lag

    # ------------------------------------------------------------------ lookups

    def agent_id(self, ref: AgentRef) -> str:
        return str(self.world.tenant(ref.tenant).agent(ref.slug).id)

    def ref_of(self, agent_id: str | None) -> AgentRef | None:
        if not agent_id:
            return None
        found = self.world.owner_of(agent_id)
        return AgentRef(found[0].slug, found[1].slug) if found else None

    def tier(self, ref: AgentRef) -> int:
        return self.world.tenant(ref.tenant).agent(ref.slug).tier

    def events_of(self, tenant: str, *names: str) -> list[SseEvent]:
        return [e for e in self.sse if e.tenant == tenant and (not names or e.event in names)]

    def alerts_fired(self, tenant: str) -> list[SseEvent]:
        return self.events_of(tenant, "alert.fired")

    def final_health(self, ref: AgentRef) -> HealthRead | None:
        series = self.health.get(ref) or []
        return series[-1] if series else None
