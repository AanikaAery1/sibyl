"""Lane AG-CORE scenarios (D48 Action Gate): action policies, held actions and the cumulative
decision, built through the api on tenant-A agents (lane S's ``s_agent``). Policies are
created and approved by the owner (tier-2 agents: no four-eyes on approval); holds are created by
the ``keys`` enforcement key and decided by the owner."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sibyl_schemas import action_gate as ag

from ._world_kit import REASON, Req, Scenario, _api
from .pg_world import ContractWorld
from .scenarios_lane_s import s_agent

POLICY: dict[str, Any] = {
    "schema": "sibyl-action-policy/1",
    "default_effect": "allow",
    "rules": [
        {
            "rule_id": "over_limit",
            "tool": "payments.transfer",
            "when": {"gt": ["/amount", 10000]},
            "effect": "block",
            "reason": "transfers above 10,000 are blocked",
        },
        {
            "rule_id": "review",
            "tool": "payments.transfer",
            "when": {"gt": ["/amount", 5000]},
            "effect": "escalate",
            "reason": "transfers above 5,000 need a human",
        },
        {
            "rule_id": "daily_cap",
            "tool": "payments.transfer",
            "cumulative": {"sum": "/amount", "max": 100000, "window_s": 86400},
            "effect": "allow",
            "reason": "daily cap",
        },
    ],
}


def _create_body(agent: UUID) -> dict[str, Any]:
    return {
        "name": "contract payments guard",
        "scope_kind": "agent",
        "scope_id": str(agent),
        "document": POLICY,
        "reason": REASON,
    }


def _draft(w: ContractWorld, agent: UUID | None = None) -> str:
    resp = _api(w, "POST", "/action-policies", _create_body(agent or s_agent(w)))
    return str(resp.json()["id"])


def _approved(w: ContractWorld) -> tuple[UUID, str]:
    agent = s_agent(w)
    policy = _draft(w, agent)
    _api(w, "POST", f"/action-policies/{policy}/approve", {"reason": REASON})
    return agent, policy


def _hold_body(agent: UUID) -> dict[str, Any]:
    args = {"amount": 6000, "currency": "INR"}
    return {
        "call_id": f"contract-{uuid4().hex[:12]}",
        "agent_id": str(agent),
        "source": "gateway",
        "tool": "payments.transfer",
        "args": args,
        "args_sha256": ag.args_digest(args),
        "policy_id": None,
        "policy_version": None,
        "rule_id": None,
        "reason": "escalated by the gateway",
        "hold_timeout_s": 600,
    }


def _held(w: ContractWorld) -> tuple[UUID, str]:
    agent, _ = _approved(w)
    resp = w.client.post("/api/v1/held-actions", json=_hold_body(agent), headers=w.idem("keys"))
    assert resp.status_code == 201, resp.text
    return agent, str(resp.json()["held_action_id"])


def _create_hold(w: ContractWorld) -> Req:
    agent, _ = _approved(w)
    return Req("/held-actions", _hold_body(agent), agent_id=str(agent), who="keys")


def _get_hold(w: ContractWorld) -> Req:
    agent, held = _held(w)
    return Req(f"/held-actions/{held}", agent_id=str(agent))


def _act_hold(w: ContractWorld) -> Req:
    agent, held = _held(w)
    return Req(
        f"/held-actions/{held}/actions",
        {"action": "approve", "reason": REASON},
        agent_id=str(agent),
    )


def _decide(w: ContractWorld) -> Req:
    """An enforcement point's check-and-increment, built from its own local evaluation."""
    agent, policy_id = _approved(w)
    document = w.client.get(f"/api/v1/action-policies/{policy_id}", headers=w.headers("owner"))
    policy = ag.parse_policy(document.json()["document"])
    args = {"amount": 100}
    need = ag.evaluate(policy, "payments.transfer", args).needs_counter
    assert need is not None
    body = {
        "call_id": f"contract-{uuid4().hex[:12]}",
        "agent_id": str(agent),
        "source": "gateway",
        "policy_id": policy_id,
        "policy_version": policy.version,
        "rule_id": need.rule_id,
        "tool": "payments.transfer",
        "counter_key": need.counter_key,
        "increment": need.increment,
        "max": need.max,
        "window_s": need.window_s,
        "args_sha256": ag.args_digest(args),
    }
    return Req("/action-decisions", body, agent_id=str(agent), who="keys")


ACTION_GATE: dict[str, Scenario] = {
    "listActionPolicies": lambda w: Req("/action-policies"),
    "createActionPolicy": lambda w: (
        lambda a: Req("/action-policies", _create_body(a), agent_id=str(a))
    )(s_agent(w)),
    "getActionPolicy": lambda w: Req(f"/action-policies/{_draft(w)}"),
    "approveActionPolicy": lambda w: Req(
        f"/action-policies/{_draft(w)}/approve", {"reason": REASON}
    ),
    "retireActionPolicy": lambda w: Req(f"/action-policies/{_draft(w)}/retire", {"reason": REASON}),
    "simulateActionPolicy": lambda w: Req(
        f"/action-policies/{_draft(w)}/simulate",
        {"tool": "payments.transfer", "args": {"amount": 20000}},
    ),
    "createHeldAction": _create_hold,
    "listHeldActions": lambda w: Req("/held-actions"),
    "getHeldAction": _get_hold,
    "actOnHeldAction": _act_hold,
    "decideAction": _decide,
    # lane AG-LIVE
    "simulateActionPolicyDraft": lambda w: Req(
        "/action-policies/simulate",
        {"document": POLICY, "tool": "payments.transfer", "args": {"amount": 20000}},
    ),
    "getActionSummary": lambda w: (lambda a: Req("/action-summary", params={"agent_id": a}))(
        str(_held(w)[0])
    ),
}
