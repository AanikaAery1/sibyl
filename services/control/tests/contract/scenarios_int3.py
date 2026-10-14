"""Lane INT-3 scenarios: B19's deliberate pre-emptive breaker clear on a tripped tenant-A agent."""

from __future__ import annotations

from uuid import UUID

from ._world_kit import REASON, Req, Scenario
from .pg_world import ContractWorld
from .scenarios_lane_s import s_agent


def tripped_agent(w: ContractWorld, *, group: UUID | None = None) -> UUID:
    """A lane S agent whose pre-emptive breaker the worker has tripped (direct SQL)."""
    agent = s_agent(w, group=group)
    w.admin.execute(
        "UPDATE sibyl.agent SET preemptive_breaker_tripped_at = now() - interval '1 hour'"
        " WHERE tenant_id = $1 AND id = $2",
        w.a.id,
        agent,
    )
    return agent


def clear_req(agent: UUID) -> Req:
    return Req(f"/agents/{agent}/preemptive-breaker/clear", {"reason": REASON}, agent_id=str(agent))


INT3: dict[str, Scenario] = {
    "clearPreemptiveBreaker": lambda w: clear_req(tripped_agent(w)),
}
