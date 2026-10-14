"""Optional body ``reason`` on audited policy writes and the ``tenant_wide`` rule on alert-rule
writes (INT-1). The reason lands on the audit row; ``X-Sibyl-Reason`` is the fallback."""

from __future__ import annotations

from typing import Any

from sibyl_control.api.contract import operation
from sibyl_lane_r_harness import World
from sibyl_lane_r_policy_setup import add_agent, secrets_only, slug

RULES = "/api/v1/alert-rules"


def _reasons(world: World) -> list[str | None]:
    return [r.reason for r in world.audit.rows.get(world.a.id, [])]


def _seed_rule(world: World) -> dict[str, Any]:
    listed = world.client.get(RULES, params={"limit": 200}, headers=world.headers("viewer"))
    return dict(next(r for r in listed.json()["data"] if r["origin"] == "seed"))


def test_alert_rule_writes_declare_the_tenant_wide_rule() -> None:
    for op_id in ("createAlertRule", "updateAlertRule", "resetAlertRule"):
        assert "tenant_wide" in operation(op_id).object_rules


def test_a_group_limited_engineer_cannot_reset_a_rule(world: World) -> None:
    rule = _seed_rule(world)
    resp = world.client.post(f"{RULES}/{rule['id']}/reset", headers=world.idem("engineer"))
    assert resp.status_code == 403, resp.text
    assert resp.json()["type"].endswith("/forbidden")


def test_alert_rule_create_patch_and_reset_carry_the_reason(world: World) -> None:
    world.audit.clear()
    created = world.client.post(
        RULES,
        json={
            "code": slug("r").replace("-", "_"),
            "scope": "agent",
            "severity": "warning",
            "window_s": 60,
            "reason": "custom latency guard for claims",
        },
        headers=world.idem("owner"),
    )
    assert created.status_code == 201, created.text
    rule = _seed_rule(world)
    etag = world.client.get(f"{RULES}/{rule['id']}", headers=world.headers("owner")).headers["etag"]
    patched = world.client.patch(
        f"{RULES}/{rule['id']}",
        json={"cooldown_s": 900, "reason": "too noisy during the batch window"},
        headers=world.headers("owner", **{"If-Match": etag}),
    )
    assert patched.status_code == 200, patched.text
    reset = world.client.post(
        f"{RULES}/{rule['id']}/reset",
        json={"reason": "batch window moved, back to defaults"},
        headers=world.idem("owner"),
    )
    assert reset.status_code == 200, reset.text
    bare = world.client.post(
        f"{RULES}/{rule['id']}/reset",
        headers=world.idem("owner", **{"X-Sibyl-Reason": "reset again from the runbook"}),
    )
    assert bare.status_code == 200, bare.text
    assert _reasons(world) == [
        "custom latency guard for claims",
        "too noisy during the batch window",
        "batch window moved, back to defaults",
        "reset again from the runbook",
    ]


def test_an_alert_rule_patch_with_only_a_reason_is_422(world: World) -> None:
    rule = _seed_rule(world)
    etag = world.client.get(f"{RULES}/{rule['id']}", headers=world.headers("owner")).headers["etag"]
    resp = world.client.patch(
        f"{RULES}/{rule['id']}",
        json={"reason": "nothing else changes here"},
        headers=world.headers("owner", **{"If-Match": etag}),
    )
    assert resp.status_code == 422, resp.text


def test_fallback_chain_create_carries_the_reason(world: World) -> None:
    agent = add_agent(world, world.a)
    world.audit.clear()
    resp = world.client.post(
        f"/api/v1/agents/{agent}/fallback-chains",
        json={
            "steps": [{"kind": "human_queue", "risk": "low"}],
            "reason": "human queue until the backup model is approved",
        },
        headers=world.idem("owner"),
    )
    assert resp.status_code == 201, resp.text
    assert _reasons(world) == ["human queue until the backup model is approved"]


def test_capture_policy_carries_the_reason(world: World) -> None:
    profile = str(secrets_only(world, world.a))
    tenant = world.client.get(
        "/api/v1/capture-policies?scope_kind=tenant", headers=world.headers("owner")
    ).json()["data"]
    if not tenant:
        made = world.client.post(
            "/api/v1/capture-policies",
            json={
                "scope_kind": "tenant",
                "capture_mode": "redacted",
                "redaction_profile_id": profile,
                "payload_retention_days": 30,
                "consequences_version": "c1",
                "acknowledged": True,
            },
            headers=world.idem("owner", **{"If-Match": "*"}),
        )
        assert made.status_code == 201, made.text
    agent = add_agent(world, world.a)
    world.audit.clear()
    resp = world.client.post(
        "/api/v1/capture-policies",
        json={
            "scope_kind": "agent",
            "agent_id": str(agent),
            "capture_mode": "metadata",
            "redaction_profile_id": profile,
            "payload_retention_days": 7,
            "consequences_version": "c1",
            "acknowledged": True,
            "reason": "agent handles health data: metadata only",
        },
        headers=world.idem("owner", **{"If-Match": "*"}),
    )
    assert resp.status_code == 201, resp.text
    assert _reasons(world) == ["agent handles health data: metadata only"]
