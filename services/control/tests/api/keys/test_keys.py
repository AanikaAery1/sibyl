"""API keys on PG17: create (shown once), list/get visibility, rotate with grace, revoke,
break-glass (D20), agent-bound keys for group engineers, env mismatch, outbox, idempotency."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any
from uuid import uuid4

import pytest
import sibyl_lane_a_kit as kit  # loaded by conftest

API = "/api/v1"
KEY_RE = re.compile(r"^sbl_(live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}$")


def tok(lane: Any, w: Any, role: str, **kw: Any) -> str:
    return kit.add_session(lane.db, w.tenant, w.users[role], **kw)


def create(lane: Any, token: str, body: dict[str, Any], key: dict[str, str] | None = None) -> Any:
    return lane.client.post(
        f"{API}/api-keys", json=body, headers=lane.bearer(token, **(key or kit.idem()))
    )


@pytest.fixture
def ready(lane: Any, world: Any) -> Any:
    kit.add_capture_policy(lane.db, world.tenant, world.users["owner"])
    return world


def key_row(lane: Any, w: Any, key_id: str) -> Any:
    with lane.db.admin.tx(w.tenant):
        return lane.db.admin.fetchrow(
            "SELECT * FROM sibyl.api_key WHERE tenant_id = $1 AND id = $2", w.tenant, key_id
        )


def test_create_shows_the_secret_once_and_stores_only_the_hmac(lane: Any, ready: Any) -> None:
    token = tok(lane, ready, "admin")
    idem = kit.idem()
    body = {"name": "gateway", "env": "test", "scopes": ["gateway:proxy", "routing:read"]}
    resp = create(lane, token, body, idem)
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert KEY_RE.fullmatch(out["secret"]) and out["prefix"] == out["secret"].split("_")[2]
    assert out["scopes"] == ["gateway:proxy", "routing:read"] and out["agent_id"] is None
    row = key_row(lane, ready, out["id"])
    secret = out["secret"].split("_", 3)[3]  # sbl_<env>_<prefix12>_<secret, may contain _>
    assert (
        bytes(row["secret_hash"])
        == hmac.new(bytes.fromhex(kit.PEPPER_HEX), secret.encode(), hashlib.sha256).digest()
    )
    assert row["created_by"] == ready.users["admin"]
    replay = create(lane, token, body, idem)
    assert replay.status_code == 201 and replay.headers["idempotency-replayed"] == "true"
    assert replay.json()["secret"] is None and replay.json()["id"] == out["id"]
    with lane.db.admin.tx(ready.tenant):
        stored = lane.db.admin.fetchval(
            "SELECT response_body::text FROM sibyl.idempotency_record WHERE tenant_id = $1"
            " AND idempotency_key = $2",
            ready.tenant,
            idem["Idempotency-Key"],
        )
    assert out["secret"] not in stored
    listed = lane.client.get(f"{API}/api-keys", headers=lane.bearer(token)).json()["data"]
    assert all("secret" not in k and "secret_hash" not in k for k in listed)
    audit = kit.audit_rows(lane.db, ready.tenant, "api_key.created")[-1]
    assert audit["detail"]["prefix"] == out["prefix"] and out["secret"] not in str(audit["detail"])
    events = [
        e for e in kit.outbox_events(lane.db, ready.tenant) if e["event_type"] == "policy_changed"
    ]
    assert events and events[-1]["payload"]["tenant_id"] == str(ready.tenant)


def test_create_validation(lane: Any, ready: Any) -> None:
    token = tok(lane, ready, "admin")
    cases = [
        ({"name": "x", "env": "test", "scopes": ["tenant:read"]}, 400, "invalid_scope"),
        (
            {"name": "x", "env": "test", "scopes": ["ingest:write", "ingest:write"]},
            422,
            "validation_failed",
        ),
        (
            {"name": "x", "env": "live", "scopes": ["ingest:write"]},
            422,
            "validation_failed",
        ),  # env mismatch
        (
            {
                "name": "x",
                "env": "test",
                "scopes": ["ingest:write"],
                "expires_at": "2030-01-01T00:00:00Z",
            },
            422,
            "expires_at_out_of_range",
        ),
        (
            {"name": "x", "env": "test", "scopes": ["ingest:write"], "agent_id": str(uuid4())},
            404,
            "not_found",
        ),
    ]
    for body, status, code in cases:
        resp = create(lane, token, body)
        assert resp.status_code == status and resp.json()["type"].endswith(f"/{code}"), (
            body,
            resp.text,
        )


def test_capture_policy_must_exist_first(lane: Any, world: Any) -> None:
    resp = create(
        lane, tok(lane, world, "admin"), {"name": "x", "env": "test", "scopes": ["ingest:write"]}
    )
    assert resp.status_code == 409 and resp.json()["type"].endswith("/capture_policy_missing")


def test_group_engineer_manages_only_in_group_bound_keys(lane: Any, ready: Any) -> None:
    admin = tok(lane, ready, "admin")
    eng = tok(lane, ready, "engineer")
    tenant_level = create(
        lane, admin, {"name": "t", "env": "test", "scopes": ["ingest:write"]}
    ).json()
    other = create(
        lane,
        admin,
        {
            "name": "o",
            "env": "test",
            "scopes": ["ingest:write"],
            "agent_id": str(ready.agents["other"]),
        },
    ).json()
    mine = create(
        lane,
        eng,
        {
            "name": "m",
            "env": "test",
            "scopes": ["ingest:write", "routing:read", "handoff:write"],
            "agent_id": str(ready.agents["in_g2"]),
        },
    )
    assert mine.status_code == 201, mine.text  # g2 is a child of the engineer's g1
    assert (
        create(lane, eng, {"name": "x", "env": "test", "scopes": ["ingest:write"]}).status_code
        == 403
    )
    out_of_group = create(
        lane,
        eng,
        {
            "name": "x",
            "env": "test",
            "scopes": ["ingest:write"],
            "agent_id": str(ready.agents["other"]),
        },
    )
    assert out_of_group.status_code == 404
    listed = {
        k["id"] for k in lane.client.get(f"{API}/api-keys", headers=lane.bearer(eng)).json()["data"]
    }
    assert listed == {mine.json()["id"]}
    for hidden in (tenant_level["id"], other["id"]):
        assert (
            lane.client.get(f"{API}/api-keys/{hidden}", headers=lane.bearer(eng)).status_code == 404
        )
        revoke = lane.client.post(
            f"{API}/api-keys/{hidden}/revoke",
            json={"reason": "not mine to revoke"},
            headers=lane.bearer(eng, **kit.idem()),
        )
        assert revoke.status_code == 404
    assert "access.denied" in kit.audit_actions(lane.db, ready.tenant)
    viewer = tok(lane, ready, "viewer")
    assert lane.client.get(f"{API}/api-keys", headers=lane.bearer(viewer)).status_code == 403


def test_rotate_with_grace_and_narrowing(lane: Any, ready: Any) -> None:
    admin = tok(lane, ready, "admin")
    old = create(
        lane,
        admin,
        {
            "name": "sdk",
            "env": "test",
            "scopes": ["ingest:write", "routing:read"],
            "agent_id": str(ready.agents["in_g1"]),
        },
    ).json()
    url = f"{API}/api-keys/{old['id']}/rotate"
    widen = lane.client.post(
        url,
        json={"scopes": ["ingest:write", "gateway:proxy"]},
        headers=lane.bearer(admin, **kit.idem()),
    )
    assert widen.status_code == 400 and widen.json()["type"].endswith("/invalid_scope")
    resp = lane.client.post(
        url,
        json={"grace_s": 600, "scopes": ["ingest:write"]},
        headers=lane.bearer(admin, **kit.idem()),
    )
    assert resp.status_code == 201, resp.text
    new = resp.json()
    assert new["rotated_from_id"] == old["id"] and new["scopes"] == ["ingest:write"]
    assert new["agent_id"] == old["agent_id"] and KEY_RE.fullmatch(new["secret"])
    prev = key_row(lane, ready, old["id"])
    assert prev["status"] == "rotating" and prev["rotation_grace_until"] is not None
    again = lane.client.post(url, json={}, headers=lane.bearer(admin, **kit.idem()))
    assert again.status_code == 409 and again.json()["type"].endswith("/key_not_active")
    no_body = lane.client.post(
        f"{API}/api-keys/{new['id']}/rotate", headers=lane.bearer(admin, **kit.idem())
    )
    assert no_body.status_code == 201
    assert (
        kit.audit_rows(lane.db, ready.tenant, "api_key.rotated")[-1]["detail"]["grace_until"]
        is not None
    )
    too_long = lane.client.post(
        f"{API}/api-keys/{no_body.json()['id']}/rotate",
        json={"grace_s": 90000},
        headers=lane.bearer(admin, **kit.idem()),
    )
    assert too_long.status_code == 422


def test_revoke_is_audited_and_publishes_policy_changed(lane: Any, ready: Any) -> None:
    admin = tok(lane, ready, "admin")
    made = create(lane, admin, {"name": "gw", "env": "test", "scopes": ["gateway:proxy"]}).json()
    before = len(kit.outbox_events(lane.db, ready.tenant))
    url = f"{API}/api-keys/{made['id']}/revoke"
    resp = lane.client.post(
        url, json={"reason": "leaked in a ticket"}, headers=lane.bearer(admin, **kit.idem())
    )
    assert resp.status_code == 200 and resp.json()["status"] == "revoked"
    assert len(kit.outbox_events(lane.db, ready.tenant)) == before + 1
    row = kit.audit_rows(lane.db, ready.tenant, "api_key.revoked")[-1]
    assert row["reason"] == "leaked in a ticket" and row["detail"]["previous_status"] == "active"
    twice = lane.client.post(
        url, json={"reason": "leaked in a ticket"}, headers=lane.bearer(admin, **kit.idem())
    )
    assert twice.status_code == 409 and twice.json()["type"].endswith("/already_revoked")
    short = lane.client.post(
        url, json={"reason": "short"}, headers=lane.bearer(admin, **kit.idem())
    )
    assert short.status_code == 422


def test_keys_authenticate_and_env_mismatch_is_401(lane: Any, ready: Any, lane_db: Any) -> None:
    admin = tok(lane, ready, "admin")
    made = create(
        lane,
        admin,
        {
            "name": "r",
            "env": "test",
            "scopes": ["routing:read"],
            "agent_id": str(ready.agents["in_g1"]),
        },
    ).json()
    url = f"{API}/agents/{ready.agents['in_g1']}/routing"
    ok = lane.client.get(url, headers=lane.bearer(made["secret"]))
    assert ok.status_code == 200, ok.text
    with kit.lane_app(lane_db, env="live") as live:
        refused = live.client.get(url, headers=live.bearer(made["secret"]))
        assert refused.status_code == 401
    lane.client.post(
        f"{API}/api-keys/{made['id']}/revoke",
        json={"reason": "rotation drill done"},
        headers=lane.bearer(admin, **kit.idem()),
    )
    assert lane.client.get(url, headers=lane.bearer(made["secret"])).status_code == 401


def test_rotated_key_verifies_only_within_grace(lane: Any, ready: Any) -> None:
    admin = tok(lane, ready, "admin")
    old = create(
        lane,
        admin,
        {
            "name": "r",
            "env": "test",
            "scopes": ["routing:read"],
            "agent_id": str(ready.agents["in_g1"]),
        },
    ).json()
    lane.client.post(
        f"{API}/api-keys/{old['id']}/rotate",
        json={"grace_s": 0},
        headers=lane.bearer(admin, **kit.idem()),
    )
    url = f"{API}/agents/{ready.agents['in_g1']}/routing"
    assert lane.client.get(url, headers=lane.bearer(old["secret"])).status_code == 401


# ---- break-glass (D20) -------------------------------------------------------------------------

BREAK_GLASS = {"name": "break-glass", "env": "live", "scopes": ["killswitch:pull"]}


def test_break_glass_creation_rules(lane_db: Any) -> None:
    w = kit.world(lane_db)  # no capture policy: break-glass keys never ingest
    with kit.lane_app(lane_db, env="live") as live:
        owner = kit.add_session(lane_db, w.tenant, w.users["owner"])
        stale = kit.add_session(lane_db, w.tenant, w.users["owner"], step_up_at=kit.stale())
        admin = kit.add_session(lane_db, w.tenant, w.users["admin"])
        refused = create(live, stale, BREAK_GLASS)
        assert refused.status_code == 403 and refused.json()["type"].endswith("/step_up_required")
        assert create(live, admin, BREAK_GLASS).status_code == 403  # no killswitch:pull
        mixed = create(live, owner, BREAK_GLASS | {"scopes": ["killswitch:pull", "routing:read"]})
        assert mixed.status_code == 422 and mixed.json()["type"].endswith(
            "/break_glass_scope_exclusive"
        )
        bound = create(live, owner, BREAK_GLASS | {"agent_id": str(w.agents["in_g1"])})
        assert bound.status_code == 422
        made = [create(live, owner, BREAK_GLASS) for _ in range(2)]
        assert [m.status_code for m in made] == [201, 201], made[0].text
        third = create(live, owner, BREAK_GLASS)
        assert third.status_code == 422  # at most two active per tenant (DB trigger)
        sec = kit.add_session(lane_db, w.tenant, w.users["security_admin"])
        assert (
            create(live, sec, BREAK_GLASS).status_code == 403
        )  # security_admin lacks apikeys:manage
        key = made[0].json()
        routing = live.client.get(
            f"{API}/agents/{w.agents['in_g1']}/routing", headers=live.bearer(key["secret"])
        )
        assert routing.status_code == 403 and routing.json()["type"].endswith(
            "/break_glass_key_misuse"
        )
        rot_stale = live.client.post(
            f"{API}/api-keys/{key['id']}/rotate", json={}, headers=live.bearer(stale, **kit.idem())
        )
        assert rot_stale.status_code == 403
        rot = live.client.post(
            f"{API}/api-keys/{key['id']}/rotate", json={}, headers=live.bearer(owner, **kit.idem())
        )
        assert rot.status_code == 201, rot.text
        revoke = live.client.post(
            f"{API}/api-keys/{key['id']}/revoke",
            json={"reason": "drill complete, revoke"},
            headers=live.bearer(stale, **kit.idem()),
        )
        assert revoke.status_code == 200  # revocation never waits for a step-up
