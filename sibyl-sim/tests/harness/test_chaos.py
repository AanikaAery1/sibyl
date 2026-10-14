"""Chaos driver: timeline steps become admin calls on the real sim control app."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sibyl_sim.doubles import build_state, control_app
from sibyl_sim.harness.chaos import ChaosDriver, agent_credential
from sibyl_sim.scenarios.model import AgentRef, ChaosStep

KB = AgentRef("meridian", "kb-summarizer")
FAQ = AgentRef("meridian", "faq-bot")
CLAIMS = AgentRef("northstar", "claims-coder")


class Hooks:
    def __init__(self) -> None:
        self.paused: list[tuple[str, float]] = []
        self.actor: list[tuple[AgentRef, dict[str, Any]]] = []

    def pause_ingest(self, tenant: str, seconds: float) -> None:
        self.paused.append((tenant, seconds))

    def actor_set(self, ref: AgentRef, patch: dict[str, Any]) -> None:
        self.actor.append((ref, patch))

    def agents_of(self, tenant: str) -> list[AgentRef]:
        return [KB, FAQ] if tenant == "meridian" else [CLAIMS]


@pytest.fixture
async def driver() -> Any:
    state = build_state(seed=3, admin_token="")
    transport = httpx.ASGITransport(app=control_app(state))
    async with httpx.AsyncClient(transport=transport, base_url="http://sim") as client:
        hooks = Hooks()
        yield ChaosDriver(client, hooks), state, hooks


def test_agent_credentials_are_stable_and_distinct() -> None:
    assert agent_credential(KB) == "sk-sim-meridian-kb-summarizer"
    assert agent_credential(KB) != agent_credential(FAQ)


async def test_unscoped_set_patches_base_knobs(driver: Any) -> None:
    d, state, _ = driver
    row = await d.apply(ChaosStep(10, "double", "openai-stub", {"outage": True}))
    assert state.doubles["openai-stub"].knobs.outage is True
    assert row["ok"] and row["target"] == "double:openai-stub"


async def test_agent_scoped_set_becomes_credential_overrides(driver: Any) -> None:
    d, state, _ = driver
    await d.apply(ChaosStep(5, "double", "openai-stub", {"truncation_rate": 0.5}, agents=(KB,)))
    await d.apply(ChaosStep(6, "double", "openai-stub", {"refusal_rate": 0.4}, agents=(KB,)))
    await d.apply(ChaosStep(7, "double", "openai-stub", {"outage": True}, tenants=("northstar",)))
    knobs = state.doubles["openai-stub"].knobs
    assert knobs.truncation_rate == 0 and not knobs.outage  # base untouched
    kb = knobs.for_request(agent_credential(KB), "gpt-5.4")
    assert kb.truncation_rate == 0.5 and kb.refusal_rate == 0.4  # patches accumulate
    assert knobs.for_request(agent_credential(CLAIMS), "gpt-5.4").outage
    assert not knobs.for_request(agent_credential(FAQ), "gpt-5.4").outage


async def test_reset_clears_overrides(driver: Any) -> None:
    d, state, _ = driver
    await d.apply(ChaosStep(5, "double", "openai-stub", {"outage": True}, agents=(KB,)))
    await d.apply(ChaosStep(9, "double", "openai-stub", reset=True))
    assert state.doubles["openai-stub"].knobs.overrides == ()
    await d.apply(ChaosStep(10, "double", "openai-stub", {"refusal_rate": 0.1}, agents=(FAQ,)))
    assert len(state.doubles["openai-stub"].knobs.overrides) == 1


async def test_status_feed_and_hooks(driver: Any) -> None:
    d, state, hooks = driver
    await d.apply(ChaosStep(1, "status", "openai", {"mode": "lies", "lie_status": "major_outage"}))
    assert state.feeds["openai"].status()[0] == "major_outage"
    await d.apply(ChaosStep(2, "status", "openai", reset=True))
    assert state.feeds["openai"].status()[0] == "operational"
    await d.apply(ChaosStep(3, "ingest", "meridian", pause_s=90))
    await d.apply(ChaosStep(4, "actor", "meridian/kb-summarizer", {"silent_s": 240}))
    assert hooks.paused == [("meridian", 90)]
    assert hooks.actor == [(KB, {"silent_s": 240})]


async def test_rejected_knob_is_reported_not_raised(driver: Any) -> None:
    d, _, _ = driver
    row = await d.apply(ChaosStep(1, "double", "openai-stub", {"error_rate": 7}))
    assert row["ok"] is False and "error_rate" in row["error"]
