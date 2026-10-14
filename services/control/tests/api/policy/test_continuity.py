"""Continuity plans and fallback chains against a migrated PG17 (API.md §5.6, R34, D13, D22)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sibyl_lane_r_harness import World
from sibyl_lane_r_policy_setup import (
    add_agent,
    add_credential,
    add_model,
    add_pii_source,
    add_provider,
    outbox_count,
    receipt_ok,
)

PLAN = "/api/v1/agents/{}/continuity-plan"
CHAINS = "/api/v1/agents/{}/fallback-chains"
CHAIN = "/api/v1/fallback-chains/{}"
ACTIONS = "/api/v1/fallback-chains/{}/actions"
BASE = {"degraded_mode": "safe_no_tools", "approval_timeout_policy": "hold"}


def _type(resp: Any) -> str:
    return str(resp.json().get("type", "")).rsplit("/", 1)[-1]


def _put_plan(
    world: World, agent: UUID, body: dict[str, Any], if_match: str | None, who: str = "owner"
) -> Any:
    headers = world.headers(who)
    if if_match is not None:
        headers["If-Match"] = if_match
    return world.client.put(PLAN.format(agent), json=body, headers=headers)


def _chain(world: World, agent: UUID, steps: list[dict[str, Any]], who: str = "owner") -> Any:
    return world.client.post(CHAINS.format(agent), json={"steps": steps}, headers=world.idem(who))


def _act(world: World, chain: str, action: str, who: str) -> Any:
    return world.client.post(
        ACTIONS.format(chain),
        json={"action": action, "reason": f"{action} for the continuity drill"},
        headers=world.idem(who),
    )


HUMAN = {"kind": "human_queue", "risk": "low"}


def test_plan_create_replace_and_etags(world: World) -> None:
    agent = add_agent(world, world.a, tier=2)
    missing = world.client.get(PLAN.format(agent), headers=world.headers("viewer"))
    assert missing.status_code == 404 and _type(missing) == "plan_missing"
    assert _put_plan(world, agent, BASE, None).status_code == 428

    made = _put_plan(world, agent, BASE, "*")
    assert made.status_code == 201, made.text
    plan = made.json()
    assert (plan["rto_s"], plan["rpo_s"], plan["preemptive_mode"]) == (
        3600,
        300,
        "degrade_then_auto",
    )
    assert plan["inline_fallback"] is True
    assert made.headers["etag"] == '"1"'
    assert receipt_ok(made, world.a)
    plan_id = world.admin.fetchval(
        "SELECT id FROM sibyl.continuity_plan WHERE agent_id = $1", agent
    )
    assert outbox_count(world, world.a, "policy_changed", plan_id) == 1

    assert _put_plan(world, agent, BASE, "*").status_code == 412
    replaced = _put_plan(
        world, agent, {**BASE, "rto_s": 120, "reason": "tighter RTO for Q4"}, '"1"'
    )
    assert replaced.status_code == 200 and replaced.json()["row_version"] == 2
    assert replaced.json()["rto_s"] == 120
    stale = _put_plan(world, agent, BASE, '"1"')
    assert stale.status_code == 412 and stale.json()["current"]["row_version"] == 2

    got = world.client.get(PLAN.format(agent), headers=world.headers("viewer"))
    assert got.headers["etag"] == '"2"'
    cached = world.client.get(
        PLAN.format(agent), headers=world.headers("viewer", **{"If-None-Match": '"2"'})
    )
    assert cached.status_code == 304
    assert "config.changed" in world.audit.actions(world.a.id)


def test_plan_expected_cadence_round_trips_and_is_audited(world: World) -> None:
    agent = add_agent(world, world.a, tier=2)
    made = _put_plan(world, agent, {**BASE, "expected_cadence_s": 60}, "*")
    assert made.status_code == 201, made.text
    assert made.json()["expected_cadence_s"] == 60
    stored = world.admin.fetchval(
        "SELECT expected_cadence_s FROM sibyl.continuity_plan WHERE agent_id = $1", agent
    )
    assert stored == 60

    world.audit.clear()
    changed = _put_plan(
        world, agent, {**BASE, "expected_cadence_s": 30, "reason": "heartbeat every 30 s"}, '"1"'
    )
    assert changed.status_code == 200 and changed.json()["expected_cadence_s"] == 30
    assert changed.headers["etag"] == '"2"'
    (record,) = [r for r in world.audit.rows[world.a.id] if r.action == "config.changed"]
    assert record.detail["before"]["expected_cadence_s"] == 60
    assert record.detail["after"]["expected_cadence_s"] == 30
    got = world.client.get(PLAN.format(agent), headers=world.headers("viewer"))
    assert got.json()["expected_cadence_s"] == 30

    cleared = _put_plan(world, agent, BASE, '"2"')  # PUT replaces: omitted means none
    assert cleared.status_code == 200 and cleared.json()["expected_cadence_s"] is None
    nulled = _put_plan(world, agent, {**BASE, "expected_cadence_s": None}, '"3"')
    assert nulled.status_code == 200 and nulled.json()["expected_cadence_s"] is None
    for bad in (0, -5, 1.5, "60"):
        refused = _put_plan(world, agent, {**BASE, "expected_cadence_s": bad}, '"4"')
        assert refused.status_code == 422, (bad, refused.text)


def test_plan_tier1_rules(world: World) -> None:
    agent = add_agent(world, world.a, tier=1, group=world.a.group_id)
    tier1 = _put_plan(world, agent, BASE, "*", who="engineer")
    assert tier1.status_code == 201
    assert tier1.json()["inline_fallback"] is False
    assert tier1.json()["preemptive_mode"] == "approval"

    needs = _put_plan(world, agent, {**BASE, "inline_fallback": True}, '"1"', who="engineer")
    assert needs.status_code == 403 and _type(needs) == "tier1_inline_fallback_needs_approver"
    assert world.audit.actions(world.a.id)[-1] == "access.denied"
    approved = _put_plan(world, agent, {**BASE, "inline_fallback": True}, '"1"', who="owner")
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved_by_user_id"] == str(world.a.users["owner"])
    kept = _put_plan(
        world, agent, {**BASE, "inline_fallback": True, "rto_s": 60}, '"2"', who="engineer"
    )
    assert kept.status_code == 200, kept.text
    assert kept.json()["approved_by_user_id"] == str(world.a.users["owner"])

    exposed = add_agent(world, world.a, tier=1)
    add_pii_source(world, world.a, exposed)
    refused = _put_plan(world, exposed, {**BASE, "approval_timeout_policy": "fail_safe"}, "*")
    assert refused.status_code == 422 and _type(refused) == "fail_safe_forbidden"
    clean = add_agent(world, world.a, tier=1)
    ok = _put_plan(world, clean, {**BASE, "approval_timeout_policy": "fail_safe"}, "*")
    assert ok.status_code == 201


def test_plan_object_rules(world: World) -> None:
    outside = add_agent(world, world.a, group=world.a.other_group_id)
    assert _put_plan(world, outside, BASE, "*", who="engineer").status_code == 404
    assert (
        world.client.get(PLAN.format(outside), headers=world.headers("engineer")).status_code == 404
    )
    assert _put_plan(world, outside, BASE, "*", who="owner-b").status_code == 404
    assert (
        world.client.get(PLAN.format(outside), headers=world.headers("owner-b")).status_code == 404
    )
    assert _put_plan(world, outside, BASE, "*", who="viewer").status_code == 403


def test_chain_shape_validation(world: World) -> None:
    agent = add_agent(world, world.a)
    provider = add_provider(world, world.a)
    other = add_provider(world, world.a)
    cred_other = add_credential(world, world.a, other)
    revoked = add_credential(world, world.a, provider, status="revoked")

    cases = [
        ([HUMAN, {"kind": "retry", "risk": "low"}], "step_after_human_queue"),
        (
            [
                {"kind": "alt_provider", "provider_id": str(provider), "risk": "low"},
                {"kind": "retry", "risk": "low"},
            ],
            "step_rank_order",
        ),
        (
            [{"kind": "backup_agent", "backup_agent_id": str(agent), "risk": "low"}],
            "backup_is_self",
        ),
        (
            [
                {
                    "kind": "alt_provider",
                    "provider_id": str(provider),
                    "credential_id": str(cred_other),
                    "risk": "low",
                }
            ],
            "validation_failed",
        ),
        (
            [
                {
                    "kind": "alt_provider",
                    "provider_id": str(provider),
                    "credential_id": str(revoked),
                    "risk": "low",
                }
            ],
            "validation_failed",
        ),
        ([{"kind": "alt_model_same_provider", "risk": "low"}], "validation_failed"),
    ]
    for steps, code in cases:
        resp = _chain(world, agent, steps)
        assert resp.status_code == 422, (code, resp.text)
        assert _type(resp) == code

    assert (
        _put_plan(world, agent, {**BASE, "credential_mode": "vaulted_fallback"}, "*").status_code
        == 201
    )
    vaulted = _chain(
        world, agent, [{"kind": "alt_provider", "provider_id": str(provider), "risk": "low"}]
    )
    assert vaulted.status_code == 422 and _type(vaulted) == "alt_provider_requires_credential"


def test_chain_draft_approve_retire(world: World) -> None:
    agent = add_agent(world, world.a, tier=1, group=world.a.group_id)
    backup = add_agent(world, world.a)
    provider = add_provider(world, world.a)
    model = add_model(world, world.a, provider)
    cred = add_credential(world, world.a, provider)
    steps = [
        {"kind": "retry", "risk": "low", "max_attempts": 2},
        {"kind": "alt_model_same_provider", "model_id": str(model), "risk": "low"},
        {
            "kind": "alt_provider",
            "provider_id": str(provider),
            "credential_id": str(cred),
            "risk": "medium",
        },
        {"kind": "backup_agent", "backup_agent_id": str(backup), "risk": "high"},
        HUMAN,
    ]
    made = _chain(world, agent, steps, who="engineer")
    assert made.status_code == 201, made.text
    chain = made.json()
    assert chain["status"] == "draft" and chain["version_no"] == 1
    assert [s["kind"] for s in chain["steps"]] == [s["kind"] for s in steps]
    assert all(s["viable"] for s in chain["steps"])
    etag = made.headers["etag"]

    assert (
        world.client.put(
            CHAIN.format(chain["id"]), json={"steps": steps}, headers=world.headers("owner")
        ).status_code
        == 428
    )
    wrong = world.client.put(
        CHAIN.format(chain["id"]),
        json={"steps": steps},
        headers=world.headers("owner", **{"If-Match": '"nope"'}),
    )
    assert wrong.status_code == 412
    edited = world.client.put(
        CHAIN.format(chain["id"]),
        json={"steps": [steps[0], steps[3], HUMAN], "note": "shorter"},
        headers=world.headers("engineer", **{"If-Match": etag}),
    )
    assert edited.status_code == 200, edited.text
    assert [s["position"] for s in edited.json()["steps"]] == [0, 1, 2]

    assert _act(world, chain["id"], "approve", "viewer").status_code == 403
    forbidden = _act(world, chain["id"], "approve", "engineer")
    assert forbidden.status_code == 403 and _type(forbidden) == "forbidden"
    assert _put_plan(world, agent, BASE, "*").status_code == 201

    self_approved = _act(world, chain["id"], "approve", "owner")  # requester was the engineer
    assert self_approved.status_code == 200, self_approved.text
    assert self_approved.json()["status"] == "approved"
    plan = world.client.get(PLAN.format(agent), headers=world.headers("owner")).json()
    assert plan["fallback_chain_id"] == chain["id"]
    assert outbox_count(world, world.a, "policy_changed", UUID(chain["id"])) == 1

    again = _act(world, chain["id"], "approve", "approver")
    assert again.status_code == 409 and _type(again) == "invalid_transition"
    immutable = world.client.put(
        CHAIN.format(chain["id"]),
        json={"steps": steps},
        headers=world.headers("owner", **{"If-Match": self_approved.headers["etag"]}),
    )
    assert immutable.status_code == 409 and _type(immutable) == "chain_immutable"

    second = _chain(world, agent, [HUMAN], who="owner")
    assert second.json()["version_no"] == 2
    four_eyes = _act(world, second.json()["id"], "approve", "owner")
    assert four_eyes.status_code == 409 and _type(four_eyes) == "self_approval"
    by_other = _act(world, second.json()["id"], "approve", "approver")
    assert by_other.status_code == 200, by_other.text
    first_now = world.admin.fetchval(
        "SELECT status FROM sibyl.fallback_chain WHERE id = $1", UUID(chain["id"])
    )
    assert first_now == "retired"

    retired = _act(world, second.json()["id"], "retire", "engineer")
    assert retired.status_code == 200 and retired.json()["status"] == "retired"
    plan = world.client.get(PLAN.format(agent), headers=world.headers("owner")).json()
    assert plan["fallback_chain_id"] is None

    listed = world.client.get(
        CHAINS.format(agent), params={"status": "retired"}, headers=world.headers("viewer")
    )
    assert {c["version_no"] for c in listed.json()["data"]} == {1, 2}
    assert (
        world.client.get(CHAINS.format(agent), headers=world.headers("owner-b")).status_code == 404
    )


def test_plan_chain_pointer_rules_and_viability(world: World) -> None:
    agent = add_agent(world, world.a)
    stranger = add_agent(world, world.a)
    provider = add_provider(world, world.a)
    cred = add_credential(world, world.a, provider)
    draft = _chain(
        world,
        agent,
        [
            {
                "kind": "alt_provider",
                "provider_id": str(provider),
                "credential_id": str(cred),
                "risk": "low",
            }
        ],
    )
    assert draft.status_code == 201
    not_approved = _put_plan(world, agent, {**BASE, "fallback_chain_id": draft.json()["id"]}, "*")
    assert not_approved.status_code == 422 and _type(not_approved) == "chain_not_approved"

    theirs = _chain(world, stranger, [HUMAN])
    assert _act(world, theirs.json()["id"], "approve", "owner").status_code == 200
    mismatch = _put_plan(world, agent, {**BASE, "fallback_chain_id": theirs.json()["id"]}, "*")
    assert mismatch.status_code == 422 and _type(mismatch) == "chain_agent_mismatch"

    world.admin.execute(
        "UPDATE sibyl.provider_credential SET status = 'revoked', ciphertext = NULL, nonce = NULL"
        " WHERE id = $1",
        cred,
    )
    listed = world.client.get(CHAINS.format(agent), headers=world.headers("viewer")).json()["data"]
    assert listed[0]["steps"][0]["viable"] is False


def test_chain_replay_and_isolation(world: World) -> None:
    agent = add_agent(world, world.a)
    headers = world.idem("owner")
    one = world.client.post(
        CHAINS.format(agent),
        json={"steps": [{**HUMAN, "params": {"temperature": 0.2}}]},
        headers=headers,
    )
    two = world.client.post(
        CHAINS.format(agent),
        json={"steps": [{**HUMAN, "params": {"temperature": 0.2}}]},
        headers=headers,
    )
    assert one.status_code == two.status_code == 201
    assert two.headers.get("idempotency-replayed") == "true"
    assert one.json()["id"] == two.json()["id"]
    assert _chain(world, agent, [HUMAN], who="owner-b").status_code == 404
    outside = add_agent(world, world.a, group=world.a.other_group_id)
    assert _chain(world, outside, [HUMAN], who="engineer").status_code == 404
