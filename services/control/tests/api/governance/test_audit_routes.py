"""Audit log, anchors, signing keys and verification routes on PG17 (lane U)."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import sibyl_lane_u_helpers as h
from sibyl_control.api.governance import audit as audit_routes
from sibyl_control.core.authz import (
    KEY_SCOPES,
    MONITOR_SCOPES,
    Principal,
    PrincipalKind,
    grants_for_api_key,
)
from sibyl_control.core.crypto.signing import b64url_decode
from sibyl_control.worker.housekeeping import anchors
from sibyl_control.worker.housekeeping.chain import anchor_signature_ok

RECEIPT = "X-Sibyl-Audit-Receipt"


def _anchor(world: Any) -> None:
    h.append_rows(world, world.a.id, 2)
    world.tick(anchors)


def test_owner_lists_events_by_seq_with_cursor(world: Any) -> None:
    h.append_rows(world, world.a.id, 5)
    first = world.get("owner", "/audit/events", params={"limit": 3})
    assert first.status_code == 200, first.text
    body = first.json()
    seqs = [e["seq"] for e in body["data"]]
    assert seqs == sorted(seqs) and seqs[0] == 0
    assert body["has_more"] and body["next_cursor"]
    assert set(body["data"][0]) >= {"hash", "prev_hash", "detail", "envelope_sha256", "recorded_at"}
    second = world.get("owner", "/audit/events", params={"limit": 3, "cursor": body["next_cursor"]})
    assert second.json()["data"][0]["seq"] == seqs[-1] + 1
    # a cursor replayed under other filters is refused
    other = world.get(
        "owner", "/audit/events", params={"limit": 3, "cursor": body["next_cursor"], "action": "x"}
    )
    assert other.status_code == 400


def test_filters_and_reads_write_no_audit(world: Any) -> None:
    before = world.head(world.a.id)
    resp = world.get(
        "auditor", "/audit/events", params={"action": "audit.genesis", "actor_type": "system"}
    )
    assert resp.status_code == 200
    assert [e["action"] for e in resp.json()["data"]] == ["audit.genesis"]
    assert world.head(world.a.id) == before
    assert RECEIPT not in resp.headers
    assert world.get("owner", "/audit/events", params={"actor_type": "robot"}).status_code == 422


def test_viewer_has_no_audit_read(world: Any) -> None:
    assert world.get("viewer", "/audit/events").status_code == 403
    assert world.get("viewer", "/audit/events/0").status_code == 403


def test_engineer_sees_only_rows_about_agents_in_its_group(world: Any) -> None:
    mine = world.add_agent(world.a, "eng-agent-in")
    theirs = world.add_agent(world.a, "eng-agent-out", group=world.a.other_group_id)
    h.append_rows(world, world.a.id, 1, agent=mine)
    h.append_rows(world, world.a.id, 1, agent=theirs)
    rows = world.get("engineer", "/audit/events", params={"limit": 200}).json()["data"]
    assert rows and {r["resource_id"] for r in rows} == {str(mine)}
    own_seq = rows[-1]["seq"]
    assert world.get("engineer", f"/audit/events/{own_seq}").status_code == 200
    other_seq = world.fetchval(
        "SELECT max(seq) FROM sibyl.audit_events WHERE tenant_id = $1 AND resource_id = $2",
        world.a.id,
        theirs,
    )
    assert world.get("engineer", f"/audit/events/{other_seq}").status_code == 404
    assert world.get("engineer", "/audit/events/0").status_code == 404  # not about an agent


def test_get_event_and_foreign_or_unknown_seq_is_404(world: Any) -> None:
    resp = world.get("owner", "/audit/events/0")
    assert resp.status_code == 200 and resp.json()["action"] == "audit.genesis"
    high = world.head(world.a.id) + 1000
    assert world.get("owner", f"/audit/events/{high}").status_code == 404
    assert world.get("owner", "/audit/events/not-a-seq").status_code == 404
    # tenant b has far fewer rows: tenant a's top seq does not exist there
    top_a = world.head(world.a.id)
    assert top_a > world.head(world.b.id)
    assert world.get("owner-b", f"/audit/events/{top_a}").status_code == 404


def test_anchors_and_signing_keys_verify_each_other(world: Any) -> None:
    _anchor(world)
    keys = world.get("auditor", "/audit/signing-keys")
    assert keys.status_code == 200
    (key,) = keys.json()["data"]
    assert key["purpose"] == "audit_anchor" and key["kid"] == "anchor-test-1"
    public = b64url_decode(key["public_key"])
    listed = world.get("auditor", "/audit/anchors", params={"kind": "hourly"})
    assert listed.status_code == 200
    data = listed.json()["data"]
    assert data
    for anchor in data:
        row = dict(anchor)
        row["head_hash"] = bytes.fromhex(anchor["head_hash"])
        row["signature"] = b64url_decode(anchor["signature"])
        assert anchor_signature_ok(row, public)
    assert world.get("owner", "/audit/anchors", params={"kind": "weekly"}).status_code == 422
    foreign = world.get("owner-b", "/audit/anchors").json()["data"]
    assert {a["tenant_id"] for a in foreign} <= {str(world.b.id)}
    assert not {a["id"] for a in foreign} & {a["id"] for a in data}


def test_sync_verification_is_audited_and_idempotent(world: Any) -> None:
    _anchor(world)
    headers = world.idem("auditor")
    resp = world.client.post("/api/v1/audit/verifications", json={}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True and body["anchors_checked"] >= 1 and body["first_break_seq"] is None
    assert resp.headers[RECEIPT].startswith(f"{world.a.id}:")
    seq = int(resp.headers[RECEIPT].split(":")[1])
    row = world.fetchrow(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = $2", world.a.id, seq
    )
    assert row["action"] == "audit.verified" and row["actor_type"] == "human"
    again = world.client.post("/api/v1/audit/verifications", json={}, headers=headers)
    assert again.status_code == 200 and again.headers.get("Idempotency-Replayed") == "true"
    assert again.json() == body
    partial = world.post("owner", "/audit/verifications", {"from_seq": 1, "to_seq": 3})
    assert partial.status_code == 200 and partial.json()["rows"] == 3


def test_verification_range_validation(world: Any) -> None:
    beyond = world.head(world.a.id) + 50
    assert world.post("owner", "/audit/verifications", {"to_seq": beyond}).status_code == 422
    assert (
        world.post("owner", "/audit/verifications", {"from_seq": 5, "to_seq": 2}).status_code == 422
    )
    assert world.post("owner", "/audit/verifications", {"extra": 1}).status_code == 422
    no_key = world.client.post(
        "/api/v1/audit/verifications", json={}, headers=world.headers("owner")
    )
    assert no_key.status_code == 428


def test_large_ranges_become_a_job_the_worker_records(world: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(audit_routes, "SYNC_ROW_LIMIT", 3)
    resp = world.post("security_admin", "/audit/verifications", {})
    assert resp.status_code == 202, resp.text
    job = resp.json()["job_id"]
    assert resp.headers["Location"] == f"/api/v1/jobs/{job}"
    assert world.run_jobs("audit_verify") == 1
    row = world.fetchrow(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND action = 'audit.verified'"
        " AND detail->>'job_id' = $2",
        world.a.id,
        job,
    )
    assert row is not None and row["actor_type"] == "system"


def test_api_keys_cannot_read_the_audit_log(world: Any) -> None:
    token = f"key-{uuid4()}"
    world.resolver.add(
        token,
        Principal(
            PrincipalKind.API_KEY,
            world.a.id,
            uuid4(),
            grants_for_api_key(KEY_SCOPES - {"killswitch:pull"} - MONITOR_SCOPES),
        ),
    )
    for path in ("/audit/signing-keys", "/audit/events", "/audit/anchors", "/legal-holds"):
        assert world.get(token, path).status_code == 403, path
