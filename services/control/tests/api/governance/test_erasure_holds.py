"""Erasure requests and legal holds on PG17 (lane U), including the agent-scope end to end:
hold blocks → release → four-eyes approval → worker completes → certificate, zero residue,
signed ledger entry verified by the migrate CLI."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import sibyl_lane_u_helpers as h
from sibyl_control.core.canonical import canonicalize
from sibyl_control.migrate.__main__ import main as migrate_cli
from sibyl_control.worker.housekeeping import erasure_exec, erasure_ledger, ledger_store

RECEIPT = "X-Sibyl-Audit-Receipt"
LEGAL = {"legal_basis": "gdpr_art17", "reason": "data subject request #4711 (DPA ticket)"}
NOW = datetime.now(UTC)


def _hold(world: Any, who: str = "security_admin", **body: Any) -> Any:
    payload = {
        "window_from": (NOW - timedelta(days=30)).isoformat(),
        "expires_at": (NOW + timedelta(days=30)).isoformat(),
        "reason": "litigation hold: matter 2026-17",
        **body,
    }
    return world.post(who, "/legal-holds", payload)


def _request(world: Any, who: str = "owner", **body: Any) -> Any:
    return world.post(who, "/erasure-requests", {**LEGAL, **body})


def _act(world: Any, request_id: str, action: str, token: str) -> Any:
    return world.post(
        token,
        f"/erasure-requests/{request_id}/actions",
        {"action": action, "reason": f"{action}: reviewed with legal"},
    )


def _state(world: Any, request_id: str) -> str:
    return world.get("owner", f"/erasure-requests/{request_id}").json()["state"]


# --- legal holds ---------------------------------------------------------------------------


def test_hold_placement_rules(world: Any) -> None:
    agent = world.add_agent(world.a, "hold-rules")
    stale = _hold(world, "secadmin-stale", scope_kind="agent", scope_ref=str(agent))
    assert stale.status_code == 403 and stale.json()["type"].endswith("/step_up_required")
    assert _hold(world, "auditor", scope_kind="tenant").status_code == 403
    assert _hold(world, scope_kind="tenant", scope_ref="x").status_code == 422
    assert _hold(world, scope_kind="agent").status_code == 422
    assert _hold(world, scope_kind="agent", scope_ref=str(UUID(int=7))).status_code == 422
    assert _hold(world, scope_kind="subject", scope_ref="bob@example.com").status_code == 422
    assert _hold(world, scope_kind="incident").status_code == 422
    too_long = (NOW + timedelta(days=800)).isoformat()
    assert _hold(world, scope_kind="tenant", expires_at=too_long).status_code == 422
    no_expiry = world.post(
        "security_admin",
        "/legal-holds",
        {
            "scope_kind": "agent",
            "scope_ref": str(agent),
            "window_from": NOW.isoformat(),
            "reason": "litigation hold: matter 2026-17",
        },
    )
    assert no_expiry.status_code == 422
    placed = _hold(world, scope_kind="agent", scope_ref=str(agent))
    assert placed.status_code == 201, placed.text
    assert placed.json()["agent_ids"] == [str(agent)]
    assert placed.headers[RECEIPT].startswith(f"{world.a.id}:")
    row = world.fetchrow(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = $2",
        world.a.id,
        int(placed.headers[RECEIPT].split(":")[1]),
    )
    assert row["action"] == "hold.placed" and row["reason"].startswith("litigation hold")
    hold_id = placed.json()["id"]
    listed = world.get("auditor", "/legal-holds", params={"state": "active"}).json()["data"]
    assert hold_id in {x["id"] for x in listed}
    assert world.get("viewer", "/legal-holds").status_code == 403
    assert (
        world.post(
            "owner-b", f"/legal-holds/{hold_id}/release", {"reason": "not my tenant hold"}
        ).status_code
        == 404
    )
    released = world.post(
        "owner", f"/legal-holds/{hold_id}/release", {"reason": "matter settled, released"}
    )
    assert released.status_code == 200 and released.json()["state"] == "released"
    again = world.post(
        "owner", f"/legal-holds/{hold_id}/release", {"reason": "matter settled, released"}
    )
    assert again.status_code == 409 and again.json()["type"].endswith("/not_active")


# --- erasure request rules -----------------------------------------------------------------


def test_request_validation(world: Any) -> None:
    assert _request(world, scope_kind="agent").status_code == 422  # scope_ref_required
    assert _request(world, scope_kind="agent", scope_ref="nope").status_code == 422
    assert _request(world, scope_kind="agent", scope_ref=str(UUID(int=9))).status_code == 404
    assert (
        _request(
            world, scope_kind="agent", scope_ref=str(UUID(int=9)), legal_basis="whim"
        ).status_code
        == 422
    )
    assert _request(world, "security_admin", scope_kind="tenant").status_code == 403
    assert _request(world, "viewer", scope_kind="tenant").status_code == 403
    agent = world.add_agent(world.a, "dup-erasure")
    first = _request(world, scope_kind="agent", scope_ref=str(agent))
    assert first.status_code == 201
    dup = _request(world, "admin", scope_kind="agent", scope_ref=str(agent))
    assert dup.status_code == 409 and dup.json()["type"].endswith("/erasure_in_progress")
    rid = first.json()["id"]
    assert world.get("owner-b", f"/erasure-requests/{rid}").status_code == 404
    assert _act(world, rid, "cancel", "owner-b").status_code == 404
    assert world.get("owner-b", f"/erasure-requests/{rid}/certificate").status_code == 404
    pending = world.get("owner", f"/erasure-requests/{rid}/certificate")
    assert pending.status_code == 409 and pending.json()["type"].endswith("/not_completed")


def test_second_owner_is_required_for_tenant_scope(world: Any) -> None:
    world.in_tenant(
        world.b.id,
        "UPDATE sibyl.membership SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2",
        world.b.id,
        world.b.users["owner2"],
    )
    resp = _request(world, "owner-b", scope_kind="tenant", legal_basis="tenant_offboarding")
    assert resp.status_code == 409 and resp.json()["type"].endswith("/second_owner_required")


def test_reject_and_cancel_rules(world: Any) -> None:
    agent = world.add_agent(world.a, "cancel-me")
    rid = _request(world, "admin", scope_kind="agent", scope_ref=str(agent)).json()["id"]
    assert _act(world, rid, "reject", "owner-stale").json()["type"].endswith("/step_up_required")
    assert _act(world, rid, "approve", "admin").status_code == 403  # admin lacks erasure:approve
    assert _act(world, rid, "cancel", "security_admin").status_code == 403  # not requester/owner
    cancelled = _act(world, rid, "cancel", "admin")
    assert cancelled.status_code == 200 and cancelled.json()["state"] == "cancelled"
    assert _act(world, rid, "cancel", "admin").json()["type"].endswith("/invalid_transition")
    rid2 = _request(world, "security_admin", scope_kind="agent", scope_ref=str(agent)).json()["id"]
    assert _act(world, rid2, "reject", "security_admin").json()["type"].endswith("/self_approval")
    rejected = _act(world, rid2, "reject", "owner")
    assert rejected.status_code == 200 and rejected.json()["state"] == "rejected"
    actions = world.actions(world.a.id, 0)
    assert {"erasure.cancelled", "erasure.rejected"} <= set(actions)


def test_a_new_hold_blocks_an_approved_request_before_execution(world: Any) -> None:
    agent = world.add_agent(world.a, "late-hold")
    rid = _request(world, scope_kind="agent", scope_ref=str(agent)).json()["id"]
    assert _act(world, rid, "approve", "approver").json()["state"] == "approved"
    hold = _hold(world, scope_kind="agent", scope_ref=str(agent)).json()
    assert _state(world, rid) == "hold_blocked"
    world.tick(erasure_exec)
    assert _state(world, rid) == "hold_blocked"
    world.post(
        "security_admin", f"/legal-holds/{hold['id']}/release", {"reason": "hold no longer needed"}
    )
    assert _state(world, rid) == "requested"  # fresh four-eyes approval needed
    _act(world, rid, "cancel", "owner")


# --- agent-scope end to end ----------------------------------------------------------------


@pytest.fixture(scope="module")
def agent_erasure(world: Any) -> dict[str, Any]:
    target = world.add_agent(world.a, "erase-me")
    bystander = world.add_agent(world.a, "keep-me")
    target_refs = [h.add_payload(world, world.a.id, agent=target) for _ in range(2)]
    kept_ref = h.add_payload(world, world.a.id, agent=bystander)
    h.append_rows(world, world.a.id, 1, agent=target)
    hold = _hold(world, scope_kind="agent", scope_ref=str(target))
    assert hold.status_code == 201
    created = _request(world, scope_kind="agent", scope_ref=str(target))
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["state"] == "hold_blocked" and body["blocking_hold_ids"] == [hold.json()["id"]]
    assert "audit_events" in body["retained_tables"]
    blocked = _act(world, body["id"], "approve", "approver")
    assert blocked.status_code == 409 and blocked.json()["type"].endswith("/hold_blocked")
    world.tick(erasure_exec)
    assert _state(world, body["id"]) == "hold_blocked"
    released = world.post(
        "security_admin",
        f"/legal-holds/{hold.json()['id']}/release",
        {"reason": "matter closed by counsel"},
    )
    assert released.json()["reopened_erasure_ids"] == [body["id"]]
    assert _act(world, body["id"], "approve", "owner").json()["type"].endswith("/self_approval")
    stale = _act(world, body["id"], "approve", "secadmin-stale")
    assert stale.json()["type"].endswith("/step_up_required")
    approved = _act(world, body["id"], "approve", "approver")
    assert approved.status_code == 200 and approved.json()["state"] == "approved"
    world.tick(erasure_exec)
    return {
        "id": body["id"],
        "target": target,
        "bystander": bystander,
        "target_refs": target_refs,
        "kept_ref": kept_ref,
    }


def test_agent_erasure_completes_with_zero_residue(
    world: Any, agent_erasure: dict[str, Any]
) -> None:
    rid = agent_erasure["id"]
    doc = world.get("auditor", f"/erasure-requests/{rid}").json()
    assert doc["state"] == "completed", doc["error"]
    steps = [e["step"] for e in doc["execution_log"]]
    assert steps == [
        "requested",
        "approved",
        "executing",
        "objects_deleted",
        "derived_purged",
        "verified",
        "completed",
    ]
    residue = world.in_tenant(world.a.id, "SELECT * FROM sibyl.erasure_residue($1)", UUID(rid))
    assert residue == []
    target = agent_erasure["target"]
    assert world.fetchval("SELECT count(*) FROM sibyl.agent WHERE id = $1", target) == 0
    assert (
        world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE agent_id = $1", target) == 0
    )
    for _, key in agent_erasure["target_refs"]:
        assert world.run(world.blob.head(key)) is None
    kept_id, kept_key = agent_erasure["kept_ref"]
    assert world.run(world.blob.head(kept_key)) is not None
    assert world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE id = $1", kept_id) == 1
    actions = world.actions(world.a.id, 0)
    for action in (
        "erasure.requested",
        "erasure.blocked_by_hold",
        "erasure.approved",
        "erasure.objects_deleted",
        "erasure.derived_purged",
        "erasure.completed",
    ):
        assert action in actions, action
    # the audit chain (which keeps the identifiers, U3) still verifies end to end
    verified = world.post("auditor", "/audit/verifications", {})
    assert verified.status_code == 200 and verified.json()["ok"] is True


def test_certificate_is_hashed_and_names_its_anchor(
    world: Any, agent_erasure: dict[str, Any]
) -> None:
    rid = agent_erasure["id"]
    resp = world.get("auditor", f"/erasure-requests/{rid}/certificate")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    cert = body["certificate"]
    assert hashlib.sha256(canonicalize(cert)).hexdigest() == body["certificate_sha256"]
    completed = datetime.fromisoformat(cert["completed_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(cert["backups_expire_at"].replace("Z", "+00:00"))
    assert expires - completed == timedelta(days=7)
    assert cert["scope_kind"] == "agent" and cert["scope_ref"] == str(agent_erasure["target"])
    assert cert["shredded_keys"] == []  # agent scope deletes; the tenant DEK is shared
    assert cert["affected_objects"]["objects_deleted"]["payload_refs"] == 2
    assert cert["affected_objects"]["objects_deleted"]["blob_objects"] == 2
    assert "audit_events" in cert["retained_tables"] and "tenant" in cert["retained_tables"]
    anchor = world.fetchrow(
        "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        UUID(body["anchor_id"]),
    )
    assert anchor["kind"] == "erasure"
    assert cert["anchor"]["id"] == body["anchor_id"]
    assert str(world.a.users["owner"]) not in json.dumps(cert)  # actors are hashed refs only
    completed_row = world.fetchrow(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND action = 'erasure.completed'"
        " AND resource_id = $2",
        world.a.id,
        UUID(rid),
    )
    assert completed_row["detail"]["certificate_sha256"] == body["certificate_sha256"]
    assert completed_row["severity"] == "critical"


def test_ledger_entry_is_signed_and_verifies_with_the_migrate_cli(
    world: Any, agent_erasure: dict[str, Any], tmp_path: Path
) -> None:
    world.tick(erasure_ledger)
    text = world.run(ledger_store.read_jsonl(world.blob))
    entries = [json.loads(line) for line in text.splitlines()]
    mine = [e for e in entries if e["erasure_request_id"] == agent_erasure["id"]]
    assert len(mine) == 1 and mine[0]["scope_kind"] == "agent"
    head = json.loads(world.run(world.blob.get(ledger_store.HEAD_KEY)))
    assert head["count"] == len(entries)
    ledger_path = tmp_path / "ledger.jsonl"
    ledger_path.write_text(text)
    head_path = tmp_path / "head.json"
    head_path.write_text(json.dumps(head))
    args = [
        "ledger-verify",
        "--ledger",
        str(ledger_path),
        "--public-key",
        str(world.ledger_public_path),
        "--expected-count",
        str(head["count"]),
        "--expected-head",
        head["head_hash"],
        "--head",
        str(head_path),
    ]
    assert migrate_cli(args) == 0
    forged = text.replace(agent_erasure["id"], str(UUID(int=1)))
    ledger_path.write_text(forged)
    assert migrate_cli(args) == 4
    # the database accepts the same ledger for a restore re-application (chain + head check)
    accepted = world.fetchval(
        "SELECT jsonb_array_length(sibyl.erasure_ledger_verify($1, $2, $3))",
        text,
        head["count"],
        head["head_hash"],
    )
    assert accepted == head["count"]


def test_ledger_backfills_a_completed_request_it_does_not_name(
    world: Any, agent_erasure: dict[str, Any]
) -> None:
    for key in world.run(world.blob.list_prefix(ledger_store.ENTRIES)):
        world.run(world.blob.delete(key))
    world.tick(erasure_ledger)
    entries = world.run(ledger_store.load(world.blob))
    assert agent_erasure["id"] in {e["erasure_request_id"] for e in entries}


# --- subject scope (agent_window) ----------------------------------------------------------


def test_subject_erasure_hashes_the_identifier_and_erases_the_window(world: Any) -> None:
    agent = world.add_agent(world.a, "subject-agent")
    inside = h.add_payload(world, world.a.id, agent=agent, created_at=NOW - timedelta(hours=2))
    outside = h.add_payload(world, world.a.id, agent=agent, created_at=NOW - timedelta(days=3))
    identifier = "alice.subject@example.com"
    window = {
        "agent_ids": [str(agent)],
        "window_from": (NOW - timedelta(days=1)).isoformat(),
    }
    hold = _hold(world, scope_kind="subject", scope_ref=identifier, agent_ids=[str(agent)])
    assert hold.status_code == 201
    assert identifier not in hold.text
    blocked = _request(world, scope_kind="subject", scope_ref=identifier, **window)
    assert blocked.status_code == 201 and blocked.json()["state"] == "hold_blocked"
    assert identifier not in blocked.text
    assert blocked.json()["scope_ref"] == hold.json()["scope_ref"]
    assert blocked.json()["resolution"] == "agent_window"
    world.post(
        "security_admin",
        f"/legal-holds/{hold.json()['id']}/release",
        {"reason": "subject hold released"},
    )
    rid = blocked.json()["id"]
    assert _act(world, rid, "approve", "approver").status_code == 200
    world.tick(erasure_exec)
    doc = world.get("owner", f"/erasure-requests/{rid}").json()
    assert doc["state"] == "completed", doc["error"]
    assert [e["step"] for e in doc["execution_log"]][-3:] == [
        "objects_deleted",
        "verified",
        "completed",
    ]
    assert world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE id = $1", inside[0]) == 0
    assert world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE id = $1", outside[0]) == 1
    assert world.fetchval("SELECT count(*) FROM sibyl.agent WHERE id = $1", agent) == 1
    stored = world.fetch("SELECT scope_ref FROM sibyl.erasure_request WHERE id = $1", UUID(rid))
    assert identifier not in json.dumps([dict(r) for r in stored])
