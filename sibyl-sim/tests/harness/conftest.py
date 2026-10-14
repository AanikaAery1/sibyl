"""A small hand-built world and run record for the oracle, metrics and report unit tests."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from sibyl_sim.harness.world import AgentInfo, PersonaInfo, TenantInfo, World
from sibyl_sim.oracle.record import ActorStats, HealthRead, RunRecord, SseEvent
from sibyl_sim.scenarios.model import AgentRef

M = "meridian"
N = "northstar"
KB = AgentRef(M, "kb-summarizer")
BILL = AgentRef(M, "billing-agent")
FAQ = AgentRef(M, "faq-bot")
CLAIMS = AgentRef(N, "claims-coder")
IDS = {
    KB: UUID("00000000-0000-7000-8000-00000000000a"),
    BILL: UUID("00000000-0000-7000-8000-00000000000b"),
    FAQ: UUID("00000000-0000-7000-8000-00000000000c"),
    CLAIMS: UUID("00000000-0000-7000-8000-00000000000d"),
}
OPENAI_M = UUID("00000000-0000-7000-8000-0000000000e1")


def _agent(ref: AgentRef, tier: int, provider: str = "openai-stub") -> AgentInfo:
    return AgentInfo(ref.slug, IDS[ref], tier, provider, "gpt-5.4", "sbl_live_x")


def _persona(name: str) -> PersonaInfo:
    return PersonaInfo(name, UUID(int=hash(name) & ((1 << 64) - 1)), ("operator",), f"tok-{name}")


@pytest.fixture
def world() -> World:
    meridian = TenantInfo(
        M,
        UUID("00000000-0000-7000-8000-0000000000f1"),
        {
            KB.slug: _agent(KB, 3),
            BILL.slug: _agent(BILL, 1),
            FAQ.slug: _agent(FAQ, 3, "ollama-stub"),
        },
        {"openai-stub": OPENAI_M},
        {n: _persona(n) for n in ("admin", "operator", "auditor")},
    )
    northstar = TenantInfo(
        N,
        UUID("00000000-0000-7000-8000-0000000000f2"),
        {CLAIMS.slug: _agent(CLAIMS, 3)},
        {"openai-stub": UUID("00000000-0000-7000-8000-0000000000e2")},
        {n: _persona(n) for n in ("admin", "operator", "auditor")},
    )
    return World({M: meridian, N: northstar}, 18390, "tpl")


def fired(t: float, tenant: str, ref: AgentRef | None, rule: str, **extra: Any) -> SseEvent:
    data: dict[str, Any] = {"alert_id": f"a-{rule}-{t}", "rule": rule, "severity": "warning"}
    data |= {"scope": "agent", "state": "open"}
    if ref is not None:
        data["agent_id"] = str(IDS[ref])
    data.update(extra)
    return SseEvent(t, tenant, "alert.fired", data)


def transition(t: float, ref: AgentRef, frm: str, to: str, action: str = "none") -> SseEvent:
    return SseEvent(
        t,
        ref.tenant,
        "health.transition",
        {
            "agent_id": str(IDS[ref]),
            "from_status": frm,
            "to_status": to,
            "score": 50,
            "recommended_action": action,
        },
    )


def factor(rule: str, penalty: int, **extra: Any) -> dict[str, Any]:
    return {
        "rule": rule,
        "penalty": penalty,
        "value": 0.5,
        "threshold": 0.2,
        "kind": "detected",
        "explanation": f"{rule} breached",
    } | extra


def health(
    t: float, ref: AgentRef, score: int, status: str, *factors: dict[str, Any]
) -> HealthRead:
    return HealthRead(t, ref, score, status, tuple(factors), events_seen=40)


@pytest.fixture
def record(world: World) -> RunRecord:
    rec = RunRecord("S-99", 7, "2026-10-11T00:00:00Z", 120, world)
    rec.listed_agents = {
        M: [{"id": str(IDS[r]), "slug": r.slug} for r in (KB, BILL, FAQ)],
        N: [{"id": str(IDS[CLAIMS]), "slug": CLAIMS.slug}],
    }
    for ref in (KB, BILL, FAQ, CLAIMS):
        rec.health[ref] = [health(115, ref, 100, "healthy")]
        rec.actors[ref] = ActorStats(ref, requests=30)
    return rec
