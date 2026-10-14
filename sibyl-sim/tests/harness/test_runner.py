"""Runner pieces that need no stack: lane availability, deterministic plans, self-checks."""

from __future__ import annotations

import uuid
from pathlib import Path

from sibyl_control.cli import seed
from sibyl_sim.harness.labels import write_ground_truth
from sibyl_sim.harness.runner import _sanity, available_lanes, plans_for
from sibyl_sim.harness.world import AgentInfo, TenantInfo, World
from sibyl_sim.oracle.record import ActorStats, RunRecord
from sibyl_sim.scenarios.load import load
from sibyl_sim.scenarios.model import AgentRef


def seeded_world() -> World:
    tenants = {}
    for spec in seed.WORLD:
        agents = {
            a.slug: AgentInfo(
                a.slug,
                uuid.uuid5(uuid.NAMESPACE_DNS, f"{spec.slug}.{a.slug}"),
                a.tier,
                a.provider,
                "m",
                "k",
            )
            for a in spec.agents
        }
        tenants[spec.slug] = TenantInfo(
            spec.slug, uuid.uuid5(uuid.NAMESPACE_DNS, spec.slug), agents
        )
    return World(tenants, 18390)


def test_lane_needs_api_and_loops() -> None:
    probed = {"S": True, "P": True, "U": False}
    loops = {
        "saga": {"implemented": True},
        "approvals": {"implemented": True},
        "failback": {"implemented": False},
        "handoff": {"implemented": True},
        "predict": {"implemented": True},
        "alerts": {"implemented": True},
    }
    assert available_lanes(probed, loops) == {"S": False, "P": True, "U": False}
    assert available_lanes(probed, {}) == {"S": True, "P": True, "U": False}  # compose: API only


def test_plans_cover_every_agent_and_are_deterministic(tmp_path: Path) -> None:
    world = seeded_world()
    s = load("S-01")
    a, b = plans_for(s, world, 7), plans_for(s, world, 7)
    assert a == b
    assert len(a) == 23 and not any(r.tenant == "sandbox" for r in a)
    busy = a[AgentRef("meridian", "kb-summarizer")]
    steady = a[AgentRef("meridian", "faq-bot")]
    assert len(busy) > 3 * len(steady)
    first = write_ground_truth(tmp_path / "one", s, 7, a)
    second = write_ground_truth(tmp_path / "two", s, 7, b)
    assert first.read_bytes() == second.read_bytes()
    assert plans_for(s, world, 8) != a


def test_sanity_rejects_runs_without_traffic_or_streams(world: World) -> None:
    rec = RunRecord("S-99", 1, "x", 10, world)
    assert _sanity(load("S-09"), rec) == ["no actor sent traffic"]
    rec.actors[AgentRef("meridian", "kb-summarizer")] = ActorStats(
        AgentRef("meridian", "kb-summarizer"), requests=3
    )
    rec.notes.append("SSE: not every tenant stream connected: [...]")
    assert _sanity(load("S-09"), rec) == ["SSE: not every tenant stream connected: [...]"]


def test_persona_calls_are_judged() -> None:
    from sibyl_sim.harness.runner import persona_verdicts

    log = [
        {
            "t": 120.0,
            "persona": "admin",
            "verb": "self_approve",
            "status": 409,
            "expect_status": 409,
            "code": "self_approval",
        },
        {
            "t": 150.0,
            "persona": "operator",
            "verb": "deny",
            "status": 409,
            "expect_status": None,
            "code": "approval_not_pending",
        },
        {
            "t": 160.0,
            "persona": "admin",
            "verb": "self_approve",
            "status": 200,
            "expect_status": 409,
            "code": None,
        },
    ]
    ok, deny, four_eyes = persona_verdicts(log)
    assert ok.status == "pass" and ok.severity == "CRITICAL"
    assert (
        deny.status == "fail" and deny.severity == "HIGH" and "approval_not_pending" in deny.detail
    )
    assert four_eyes.status == "fail" and "want 409" in four_eyes.detail
