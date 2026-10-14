"""Pure viability rules (ML §4.6 guard rail 3): one candidate per chain step, with its reason."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.worker.saga.model import Target
from sibyl_control.worker.saga.viability import Candidate, Context, _ad_hoc_step, evaluate_step

P, P2, M, CRED, BACKUP = (uuid4() for _ in range(5))


def _ctx(**kw: Any) -> Context:
    base: dict[str, Any] = {
        "tenant": uuid4(),
        "agent_id": uuid4(),
        "tier": 2,
        "plan": {"credential_mode": "passthrough"},
        "identity": None,
        "routing_state": "active",
        "failure_mode": "provider_outage",
        "unhealthy": frozenset(),
        "excluded": frozenset(),
        "demo_mode": False,
    }
    base.update(kw)
    ctx = Context(**base)
    ctx.models[M] = {"provider_id": P2, "model_name": "gpt-x", "is_allowed": True}
    ctx.providers[P] = {"is_enabled": True}
    ctx.providers[P2] = {"is_enabled": True}
    ctx.credentials[CRED] = "active"
    ctx.agents[BACKUP] = {"lifecycle": "deployed", "state": "active"}
    return ctx


def _alt(**kw: Any) -> dict[str, Any]:
    return {"id": uuid4(), "kind": "alt_provider", "provider_id": P2, "model_id": M, **kw}


def test_viable_alt_provider_and_routing_kind() -> None:
    c = evaluate_step(_ctx(), _alt())
    assert c.viable and c.reason == "ok" and c.routing_kind == "model"


@pytest.mark.parametrize(
    ("ctx_kw", "step_kw", "reason"),
    [
        ({"failure_mode": "infinite_loop"}, {}, "failure_mode_not_provider"),
        ({"unhealthy": frozenset({P2})}, {}, "provider_unhealthy"),
        ({"excluded": frozenset({P2})}, {}, "provider_incident_batch"),
        ({"plan": {"credential_mode": "vaulted_fallback"}}, {}, "credential_missing"),
        ({}, {"credential_id": uuid4()}, "credential_not_active"),
        ({"demo_mode": True}, {"credential_id": CRED}, "demo_mode"),
        ({}, {"model_id": uuid4()}, "model_unknown"),
        ({}, {"provider_id": uuid4(), "model_id": None}, "provider_unknown"),
        (
            {"identity": {"enforcement": "block", "allowed_providers": [P], "allowed_models": []}},
            {},
            "identity_provider",
        ),
        (
            {
                "identity": {
                    "enforcement": "block",
                    "allowed_providers": [],
                    "allowed_models": ["x"],
                }
            },
            {},
            "identity_model",
        ),
    ],
)
def test_model_step_refusals(ctx_kw: dict[str, Any], step_kw: dict[str, Any], reason: str) -> None:
    c = evaluate_step(_ctx(**ctx_kw), _alt(**step_kw))
    assert not c.viable and c.reason == reason


def test_identity_in_observe_mode_does_not_block() -> None:
    ident = {"enforcement": "observe", "allowed_providers": [P], "allowed_models": ["x"]}
    assert evaluate_step(_ctx(identity=ident), _alt()).viable


def test_disabled_provider_and_disallowed_model() -> None:
    ctx = _ctx()
    ctx.providers[P2] = {"is_enabled": False}
    assert evaluate_step(ctx, _alt()).reason == "provider_disabled"
    ctx = _ctx()
    ctx.models[M] = {"provider_id": P2, "model_name": "gpt-x", "is_allowed": False}
    assert evaluate_step(ctx, _alt()).reason == "model_not_allowed"


@pytest.mark.parametrize(
    ("info", "backup", "reason"),
    [
        ({"lifecycle": "deployed", "state": "active"}, BACKUP, "ok"),
        ({"lifecycle": "retired", "state": "active"}, BACKUP, "backup_agent_not_serving"),
        ({"lifecycle": "deployed", "state": "killed"}, BACKUP, "backup_agent_not_serving"),
        (None, uuid4(), "backup_agent_unknown"),
        (None, None, "backup_agent_erased"),
    ],
)
def test_backup_agent_rules(info: Any, backup: UUID | None, reason: str) -> None:
    ctx = _ctx()
    if info is not None:
        ctx.agents[BACKUP] = info
    c = evaluate_step(ctx, {"id": uuid4(), "kind": "backup_agent", "backup_agent_id": backup})
    assert c.reason == reason and c.viable == (reason == "ok")
    if c.viable:
        assert c.routing_kind == "agent"


def test_retry_safe_mode_and_human_queue() -> None:
    assert evaluate_step(_ctx(), {"id": None, "kind": "retry"}).reason == "retry_is_gateway_local"
    assert evaluate_step(_ctx(), {"id": None, "kind": "degraded_safe_mode"}).viable
    degraded = _ctx(routing_state="degraded")
    assert evaluate_step(degraded, {"id": None, "kind": "degraded_safe_mode"}).reason == (
        "already_degraded"
    )
    human = evaluate_step(_ctx(failure_mode="infinite_loop"), {"id": None, "kind": "human_queue"})
    assert human.viable and human.routing_kind == "human_queue"


def test_ad_hoc_targets_map_to_steps() -> None:
    assert _ad_hoc_step(Target(kind="agent", agent_id=BACKUP))["kind"] == "backup_agent"
    assert _ad_hoc_step(Target(kind="human_queue"))["kind"] == "human_queue"
    step = _ad_hoc_step(Target(kind="model", provider_id=P2, model_id=M))
    assert step["kind"] == "alt_provider" and step["model_id"] == M
    assert Candidate(None, "human_queue", True, "ok").as_json()["step_id"] is None
