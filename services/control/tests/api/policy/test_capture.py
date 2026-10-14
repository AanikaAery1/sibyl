"""Capture policies and redaction profiles against a migrated PG17 (API.md §5.6, D12)."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from sibyl_lane_r_harness import World
from sibyl_lane_r_policy_setup import add_agent, outbox_count, receipt_ok, secrets_only

CAPTURE = "/api/v1/capture-policies"
EFFECTIVE = "/api/v1/capture-policies/effective"
PROFILES = "/api/v1/redaction-profiles"


def _policy(world: World, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "scope_kind": "tenant",
        "capture_mode": "redacted",
        "redaction_profile_id": str(secrets_only(world, world.a)),
        "payload_retention_days": 30,
        "consequences_version": "c1",
        "acknowledged": True,
    }
    body.update(overrides)
    return body


def _type(resp: Any) -> str:
    return str(resp.json().get("type", "")).rsplit("/", 1)[-1]


def _set(world: World, body: dict[str, Any], if_match: str | None, who: str = "owner") -> Any:
    headers = world.idem(who)
    if if_match is not None:
        headers["If-Match"] = if_match
    return world.client.post(CAPTURE, json=body, headers=headers)


def test_tenant_policy_lifecycle_supersedes_and_audits(world: World) -> None:
    assert _set(world, _policy(world), None).status_code == 428

    first = _set(world, _policy(world), "*")
    assert first.status_code == 201, first.text
    assert first.headers["etag"] == '"1"'
    assert first.json()["version_no"] == 1
    assert receipt_ok(first, world.a)
    first_id = UUID(first.json()["id"])
    assert "capture.policy_set" in world.audit.actions(world.a.id)
    assert outbox_count(world, world.a, "policy_changed", first_id) == 1

    stale_star = _set(world, _policy(world), "*")
    assert stale_star.status_code == 412
    assert stale_star.json()["current"]["version_no"] == 1
    assert _set(world, _policy(world), '"7"').status_code == 412

    second = _set(world, _policy(world, payload_retention_days=14), '"1"')
    assert second.status_code == 201, second.text
    assert second.json()["version_no"] == 2
    row = world.admin.fetchrow(
        "SELECT superseded_by, chosen_by FROM sibyl.capture_policy WHERE id = $1", first_id
    )
    assert row["superseded_by"] == UUID(second.json()["id"])
    assert row["chosen_by"] == world.a.users["owner"]

    active = world.client.get(CAPTURE, headers=world.headers("viewer"))
    assert [p["version_no"] for p in active.json()["data"]] == [2]
    every = world.client.get(
        CAPTURE, params={"include_superseded": "true"}, headers=world.headers("viewer")
    )
    assert [p["version_no"] for p in every.json()["data"]] == [1, 2]


def test_replay_returns_the_stored_response(world: World) -> None:
    current = world.client.get(
        CAPTURE, params={"scope_kind": "tenant"}, headers=world.headers("owner")
    )
    version = current.json()["data"][0]["version_no"]
    headers = world.idem("owner", **{"If-Match": f'"{version}"'})
    body = _policy(world, payload_retention_days=10)
    one = world.client.post(CAPTURE, json=body, headers=headers)
    two = world.client.post(CAPTURE, json=body, headers=headers)
    assert one.status_code == two.status_code == 201
    assert two.headers.get("idempotency-replayed") == "true"
    assert two.json()["id"] == one.json()["id"]
    assert two.headers["x-sibyl-audit-receipt"] == one.headers["x-sibyl-audit-receipt"]
    reused = world.client.post(
        CAPTURE, json=_policy(world, payload_retention_days=9), headers=headers
    )
    assert reused.status_code == 422
    assert _type(reused) == "idempotency_key_reuse"


def test_validation_codes(world: World) -> None:
    no_mode = _policy(world)
    del no_mode["capture_mode"]
    resp = _set(world, no_mode, "*")
    assert resp.status_code == 422 and _type(resp) == "capture_mode_required"

    resp = _set(world, _policy(world, header_allowlist=["X-Trace", "Authorization"]), "*")
    assert resp.status_code == 422 and _type(resp) == "header_forbidden"

    resp = _set(world, _policy(world, acknowledged=False), "*")
    assert resp.status_code == 422 and _type(resp) == "validation_failed"

    resp = _set(world, _policy(world, scope_kind="agent"), "*")
    assert resp.status_code == 422


def test_agent_policy_may_be_stricter_never_looser(world: World) -> None:
    if not world.client.get(
        CAPTURE, params={"scope_kind": "tenant"}, headers=world.headers("owner")
    ).json()["data"]:
        assert _set(world, _policy(world), "*").status_code == 201
    agent = add_agent(world, world.a)
    looser = _set(
        world, _policy(world, scope_kind="agent", agent_id=str(agent), capture_mode="full"), "*"
    )
    assert looser.status_code == 422 and _type(looser) == "agent_policy_looser_than_tenant"

    strict = _set(
        world,
        _policy(
            world,
            scope_kind="agent",
            agent_id=str(agent),
            capture_mode="metadata",
            payload_retention_days=1,
        ),
        "*",
    )
    assert strict.status_code == 201, strict.text

    effective = world.client.get(
        EFFECTIVE, params={"agent_id": str(agent)}, headers=world.headers("viewer")
    )
    assert effective.status_code == 200
    assert effective.json()["source"] == "agent"
    assert effective.json()["policy"]["capture_mode"] == "metadata"
    assert effective.json()["redaction_profile"]["name"] == "secrets_only"

    other = add_agent(world, world.a)
    fallback = world.client.get(
        EFFECTIVE, params={"agent_id": str(other)}, headers=world.headers("viewer")
    )
    assert fallback.json()["source"] == "tenant"


def test_effective_policy_missing_and_isolation(world: World) -> None:
    missing = world.client.get(EFFECTIVE, headers=world.headers("owner-b"))
    assert missing.status_code == 404 and _type(missing) == "capture_policy_missing"
    assert world.client.get(CAPTURE, headers=world.headers("owner-b")).json()["data"] == []
    foreign = add_agent(world, world.a)
    resp = world.client.get(
        EFFECTIVE, params={"agent_id": str(foreign)}, headers=world.headers("owner-b")
    )
    assert resp.status_code == 404


def test_roles(world: World) -> None:
    assert world.client.get(CAPTURE, headers=world.headers("auditor")).status_code == 200
    denied = _set(world, _policy(world), "*", who="viewer")
    assert denied.status_code == 403
    assert _set(world, _policy(world), "*", who="engineer").status_code == 403


def test_redaction_profiles(world: World) -> None:
    listed = world.client.get(PROFILES, headers=world.headers("viewer"))
    assert {p["name"] for p in listed.json()["data"] if p["is_system"]} == {
        "secrets_only",
        "pii_standard",
    }

    baseline = [r for r in world.admin.fetchval("SELECT sibyl.secrets_baseline_detector_ids()")]
    short = world.client.post(
        PROFILES, json={"name": "lean", "detectors": baseline[1:]}, headers=world.idem("owner")
    )
    assert short.status_code == 422 and _type(short) == "below_secrets_baseline"
    assert baseline[0] in short.json()["missing"]

    made = world.client.post(
        PROFILES,
        json={"name": "strict", "detectors": [*baseline, "email"]},
        headers=world.idem("owner"),
    )
    assert made.status_code == 201, made.text
    assert made.json()["version_no"] == 1 and made.json()["is_system"] is False
    assert receipt_ok(made, world.a)
    row = world.admin.fetchrow(
        "SELECT content_canonical, content_hash FROM sibyl.redaction_profile WHERE id = $1",
        UUID(made.json()["id"]),
    )
    assert (
        hashlib.sha256(row["content_canonical"].encode()).hexdigest() == made.json()["content_hash"]
    )
    assert "redaction.profile_created" in world.audit.actions(world.a.id)

    again = world.client.post(
        PROFILES,
        json={
            "name": "strict",
            "detectors": [*baseline, "email", "phone"],
            "replacement_format": "[x]",
        },
        headers=world.idem("owner"),
    )
    assert again.status_code == 201 and again.json()["version_no"] == 2
    assert (
        world.client.post(
            PROFILES, json={"name": "x", "detectors": baseline}, headers=world.idem("viewer")
        ).status_code
        == 403
    )
