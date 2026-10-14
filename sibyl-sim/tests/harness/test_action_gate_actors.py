"""A-5 actor plumbing against fakes: the persona verbs (policy draft/approval, held-action
decisions) over a mock API, and the SDK actor's gated execution against a fake enforcer."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from sibyl import SibylActionBlocked, SibylActionDenied
from sibyl_sim.actors.agents import SdkActor
from sibyl_sim.actors.personas import PersonaRunner
from sibyl_sim.harness.clock import RunClock
from sibyl_sim.harness.world import World
from sibyl_sim.oracle.record import ActorStats
from sibyl_sim.scenarios.model import PersonaStep

from .conftest import BILL, IDS, M

API = "http://api"


def persona_runner(world: World, handler: Any) -> PersonaRunner:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return PersonaRunner(client, API, world, RunClock())


def step(persona: str, verb: str, **args: Any) -> PersonaStep:
    return PersonaStep(1.0, persona, verb, M, {"agent": BILL.slug, **args})


async def test_policy_is_drafted_by_one_person_and_approved_by_another(world: World) -> None:
    seen: list[tuple[str, str, Any, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path, body, request.headers["authorization"]))
        if request.url.path.endswith("/action-policies"):
            return httpx.Response(201, json={"id": "p-1"})
        return httpx.Response(200, json={"id": "p-1", "status": "approved"})

    runner = persona_runner(world, handler)
    doc = {"default_effect": "allow", "rules": []}
    approve_first = await runner.run(step("operator", "approve_action_policy"))
    assert approve_first["status"] == 404, "nothing drafted yet"
    drafted = await runner.run(step("admin", "install_action_policy", document=doc))
    approved = await runner.run(step("operator", "approve_action_policy"))
    assert drafted["status"] == 201 and approved["status"] == 200
    create, approve = seen
    assert create[2]["scope_id"] == str(IDS[BILL]) and create[2]["document"] == doc
    assert approve[1] == "/api/v1/action-policies/p-1/approve"
    assert create[3] != approve[3], "four eyes: two different people"


async def test_decide_held_approves_every_pending_hold_and_logs_the_ids(world: World) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "GET":
            assert request.url.params["state"] == "pending"
            return httpx.Response(200, json={"data": [{"id": "h-1"}, {"id": "h-2"}]})
        if request.url.path.endswith("h-2/actions"):
            return httpx.Response(409, json={"type": "x/action_not_pending"})
        assert request.headers["authorization"].endswith(".stepup")
        return httpx.Response(200, json={"id": "h-1", "state": "approved"})

    row = await persona_runner(world, handler).run(step("operator", "decide_held"))
    assert row["decided"] == ["h-1"] and row["decision"] == "approve"
    assert row["status"] == 409, "a refused decision is visible in the persona verdict"
    assert len(calls) == 3


async def test_a_lost_answer_is_logged_not_raised(world: World) -> None:
    """S-29 (2026-10-14): an approve whose answer timed out was still applied by the server; the
    step raised, its ids were lost and the persona schedule died, so the oracle saw an execution
    "no person approved". A lost answer is now an attempted approval, logged as ambiguous, and
    the step fails visibly (status 0) without raising."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "h-1"}, {"id": "h-2"}]})
        if request.url.path.endswith("h-1/actions"):
            raise httpx.ReadTimeout("the api answered too late", request=request)
        return httpx.Response(200, json={"id": "h-2", "state": "approved"})

    row = await persona_runner(world, handler).run(step("operator", "decide_held"))
    assert row["status"] == 0 and row["code"] == "transport:ReadTimeout"
    assert row["decided"] == ["h-1", "h-2"] and row["ambiguous"] == ["h-1"]


async def test_a_transport_failure_never_ends_the_schedule(world: World) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    doc = {"default_effect": "allow", "rules": []}
    runner = persona_runner(world, handler)
    row = await runner.run(step("admin", "install_action_policy", document=doc))
    assert row["status"] == 0 and row["code"] == "transport:ConnectError"
    again = await runner.run(step("operator", "decide_held"))  # the next step still runs
    assert again["status"] == 0 and len(runner.log) == 2


async def test_decide_held_with_nothing_pending(world: World) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": []})

    runner = persona_runner(world, handler)
    assert (await runner.run(step("operator", "decide_held")))["status"] == 404
    quiet = await runner.run(step("operator", "decide_held", allow_none=True))
    assert quiet["status"] == 200 and quiet["decided"] == []


class FakeActions:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.seen: list[tuple[str, Any, str]] = []

    async def acheck(self, tool: str, args: Any, *, mode: str) -> Any:
        self.seen.append((tool, args, mode))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return SimpleNamespace(held_action_id=self.outcome)


def bare_actor() -> SdkActor:
    actor = SdkActor.__new__(SdkActor)  # no SDK client: _gated only needs stats and a clock
    actor.stats = ActorStats(BILL, via="sdk")
    actor.clock = RunClock()
    return actor


CALL = {"id": "c", "function": {"name": "payments.transfer", "arguments": '{"amount": 5}'}}


@pytest.mark.parametrize(
    ("outcome", "want", "held", "state"),
    [
        (None, "executed", None, None),
        ("h-9", "executed", "h-9", None),
        (SibylActionBlocked("payments.transfer", "over-limit", "too much"), "blocked", None, None),
        (
            SibylActionDenied("payments.transfer", "h-3", "expired", "late"),
            "denied",
            "h-3",
            "expired",
        ),
    ],
)
async def test_sdk_actor_runs_the_tool_only_when_the_gate_returns(
    outcome: Any, want: str, held: str | None, state: str | None
) -> None:
    actor = bare_actor()
    fake = FakeActions(outcome)
    result = await actor._gated(SimpleNamespace(actions=fake), CALL)
    assert fake.seen == [("payments.transfer", {"amount": 5}, "wait")]
    [act] = actor.stats.actions
    assert act["outcome"] == want and act.get("held_action_id") == held
    assert act.get("state") == state
    assert ("ok" in result) == (want == "executed")
