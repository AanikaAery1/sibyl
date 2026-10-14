"""Monitor routes on PG17 (D53): registration with a one-time key, validation, If-Match updates,
pause/resume, revocation (keys revoked, webhooks disabled, terminal), extra keys, webhooks
(URL vetting, one-time signing secret, signed test ping) and the key-scope rules elsewhere."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import httpx
from sibyl_schemas.webhook_signature import verify

from .conftest import REASON, Receiver, get, new_monitor, post

HOOK = "http://sibyl-sim:8400/sibyl-hook"


def _audit(world: Any, head: int) -> list[str]:
    return [a for a in world.audit_since(world.a.id, head) if a != "access.denied"]


def test_registration_issues_a_monitor_key_once(mw: Any) -> None:
    head = mw.audit_head(mw.a.id)
    body = {
        "name": f"claude-{uuid4().hex[:6]}",
        "kind": "mcp",
        "description": "Claude reviewing held actions",
        "all_groups": False,
        "group_ids": [str(mw.a.groups["g1"])],
        "rate_limit_per_min": 30,
        "key_env": "test",
        "reason": REASON,
    }
    headers = mw.idem("owner")
    resp = mw.client.post("/api/v1/monitors", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    created = resp.json()
    key = created["api_key"]
    assert key["secret"].startswith("sbl_test_") and key["monitor_id"] == created["id"]
    assert sorted(key["scopes"]) == ["findings:write", "monitor:read"]
    assert created["state"] == "active" and created["advisory"] is True
    assert created["group_ids"] == [str(mw.a.groups["g1"])] and not created["all_groups"]
    assert [k["prefix"] for k in created["keys"]] == [key["prefix"]]
    assert "secret" not in json.dumps(created["keys"])
    assert _audit(mw, head) == ["monitor.registered", "api_key.created"]
    replay = mw.client.post("/api/v1/monitors", json=body, headers=headers)
    assert replay.status_code == 201 and replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json()["api_key"]["secret"] is None
    # the key works and sees its own monitor
    mw.tokens["fresh"] = key["secret"]
    me = get(mw, "/monitors/self", "fresh")
    assert me.status_code == 200 and me.json()["id"] == created["id"]
    # the key never reaches the gateway snapshot (plain keys do)
    snap = mw.client.get("/api/v1/policy/snapshot", headers=mw.headers("keys"))
    assert snap.status_code == 200, snap.text
    assert str(mw.key_ids["keys"]) in snap.text and key["id"] not in snap.text


def test_registration_without_a_key_and_validation(mw: Any) -> None:
    bare = new_monitor(mw, issue_key=False)
    assert bare["api_key"] is None and bare["keys"] == []
    dup = post(mw, "/monitors", {"name": bare["name"].upper(), "kind": "api", "key_env": "test"})
    assert dup.status_code == 409 and dup.json()["type"].endswith("/conflict")
    unknown = post(
        mw,
        "/monitors",
        {
            "name": "x-unknown-group",
            "kind": "api",
            "all_groups": False,
            "group_ids": [str(uuid4())],
        },
    )
    assert unknown.status_code == 422
    both = post(
        mw,
        "/monitors",
        {"name": "x-both", "kind": "api", "group_ids": [str(mw.a.groups["g1"])]},
    )
    assert both.status_code == 422
    owner = post(mw, "/monitors", {"name": "x-owner", "kind": "api", "owner_user_id": str(uuid4())})
    assert owner.status_code == 422
    live = post(mw, "/monitors", {"name": "x-live", "kind": "api", "key_env": "live"})
    assert live.status_code == 422  # the contract deployment is env=test
    assert post(mw, "/monitors", {"name": "x", "kind": "robot"}).status_code == 422
    viewer = post(mw, "/monitors", {"name": "x-viewer", "kind": "api"}, who="viewer")
    assert viewer.status_code == 403


def test_list_and_get_for_readers(mw: Any) -> None:
    created = new_monitor(mw, kind="webhook")
    listed = get(mw, "/monitors", "auditor", kind="webhook", limit=200)
    assert listed.status_code == 200
    assert created["id"] in {m["id"] for m in listed.json()["data"]}
    one = get(mw, f"/monitors/{created['id']}", "operator")
    assert one.status_code == 200 and one.headers["etag"] == '"1"'
    assert get(mw, f"/monitors/{uuid4()}").status_code == 404
    assert get(mw, "/monitors", "viewer").status_code == 403
    assert get(mw, "/monitors/self").status_code == 403  # a human has no monitor


def _patch(world: Any, monitor_id: str, body: dict[str, Any], etag: str | None) -> Any:
    headers = world.headers("owner", **({"If-Match": etag} if etag else {}))
    return world.client.patch(f"/api/v1/monitors/{monitor_id}", json=body, headers=headers)


def test_update_pause_resume_and_groups_with_if_match(mw: Any) -> None:
    created = new_monitor(mw)
    mid = created["id"]
    assert _patch(mw, mid, {"state": "paused"}, None).status_code == 428
    assert _patch(mw, mid, {"state": "paused"}, '"7"').status_code == 412
    head = mw.audit_head(mw.a.id)
    paused = _patch(mw, mid, {"state": "paused", "rate_limit_per_min": 5}, '"1"')
    assert paused.status_code == 200, paused.text
    assert paused.json()["state"] == "paused" and paused.headers["etag"] == '"2"'
    row = mw.admin.fetchrow(
        "SELECT detail FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2"
        " AND action = 'monitor.updated'",
        mw.a.id,
        head,
    )
    assert row["detail"]["change"]["state"] == {"before": "active", "after": "paused"}
    groups = {"all_groups": False, "group_ids": [str(mw.a.groups["g2"])], "state": "active"}
    resumed = _patch(mw, mid, groups, '"2"')
    assert resumed.status_code == 200 and resumed.json()["group_ids"] == groups["group_ids"]
    same = _patch(mw, mid, {"state": "active"}, '"3"')
    assert same.status_code == 200 and same.headers["etag"] == '"3"'  # nothing changed
    half = _patch(mw, mid, {"all_groups": False}, '"3"')
    assert half.status_code == 422  # all_groups and group_ids change together
    assert _patch(mw, str(uuid4()), {"state": "paused"}, '"1"').status_code == 404


def test_revocation_is_terminal_and_disables_everything(mw: Any, receiver: Receiver) -> None:
    created = new_monitor(mw)
    mid = created["id"]
    hook = post(mw, f"/monitors/{mid}/webhooks", {"url": HOOK, "event_types": ["action.held"]})
    assert hook.status_code == 201, hook.text
    extra = post(mw, f"/monitors/{mid}/keys", {"name": "second", "env": "test"})
    assert extra.status_code == 201 and extra.json()["monitor_id"] == mid
    mw.tokens["second"] = extra.json()["secret"]
    assert get(mw, "/monitors/self", "second").status_code == 200
    head = mw.audit_head(mw.a.id)
    revoked = post(mw, f"/monitors/{mid}/revoke", {"reason": "the vendor contract ended"})
    assert revoked.status_code == 200, revoked.text
    view = revoked.json()
    assert view["state"] == "revoked" and view["keys"] == []
    assert view["webhooks"][0]["state"] == "disabled"
    row = mw.admin.fetchrow(
        "SELECT detail, reason FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2"
        " AND action = 'monitor.revoked'",
        mw.a.id,
        head,
    )
    assert row["detail"]["keys_revoked"] == 2 and row["detail"]["webhooks_disabled"] == 1
    assert row["reason"] == "the vendor contract ended"
    assert get(mw, "/monitors/self", "second").status_code == 401
    again = post(mw, f"/monitors/{mid}/revoke", {"reason": "the vendor contract ended"})
    assert again.status_code == 409
    assert _patch(mw, mid, {"state": "active"}, '"2"').status_code == 409
    assert post(mw, f"/monitors/{mid}/keys", {"env": "test"}).status_code == 409
    late = post(mw, f"/monitors/{mid}/webhooks", {"url": HOOK, "event_types": ["ping"]})
    assert late.status_code == 422  # ping is never subscribable
    late = post(mw, f"/monitors/{mid}/webhooks", {"url": HOOK, "event_types": ["action.held"]})
    assert late.status_code == 409
    test = post(mw, f"/monitors/{mid}/webhooks/{hook.json()['id']}/test")
    assert test.status_code == 409


def test_webhook_urls_are_vetted(mw: Any, receiver: Receiver) -> None:
    mid = new_monitor(mw)["id"]
    for url in (
        "http://hooks.example.com/sibyl",  # https only
        "https://127.0.0.1/hook",  # private literal
        "https://10.1.2.3/hook",
        "https://localhost/hook",
        "https://user:pw@hooks.example.com/hook",
    ):
        resp = post(mw, f"/monitors/{mid}/webhooks", {"url": url, "event_types": ["run.failed"]})
        assert resp.status_code == 422, (url, resp.text)
        assert resp.json()["type"].endswith("/base_url_not_allowlisted"), url
    settings = mw.lane.services.settings
    previous = settings.webhook_allowed_hosts
    settings.webhook_allowed_hosts = ".example.org"
    try:
        refused = post(mw, f"/monitors/{mid}/webhooks", {"url": HOOK, "event_types": ["ping"]})
        assert refused.status_code == 422
        refused = post(
            mw, f"/monitors/{mid}/webhooks", {"url": HOOK, "event_types": ["alert.fired"]}
        )
        assert refused.status_code == 422 and "ALLOWED_HOSTS" in refused.json()["detail"]
    finally:
        settings.webhook_allowed_hosts = previous


def test_webhook_secret_is_shown_once_and_signs_the_test_ping(mw: Any, receiver: Receiver) -> None:
    mid = new_monitor(mw)["id"]
    headers = mw.idem("owner")
    body = {"url": HOOK, "event_types": ["alert.fired", "drift.detected"], "reason": REASON}
    created = mw.client.post(f"/api/v1/monitors/{mid}/webhooks", json=body, headers=headers)
    assert created.status_code == 201, created.text
    hook = created.json()
    secret = hook["secret"]
    assert secret.startswith("whsec_") and len(secret) == 49
    replay = mw.client.post(f"/api/v1/monitors/{mid}/webhooks", json=body, headers=headers)
    assert replay.json()["secret"] is None
    stored = mw.admin.fetchrow(
        "SELECT ciphertext FROM sibyl.monitor_webhook WHERE id = $1", UUID(hook["id"])
    )
    assert secret.encode() not in bytes(stored["ciphertext"])
    head = mw.audit_head(mw.a.id)
    tested = post(mw, f"/monitors/{mid}/webhooks/{hook['id']}/test")
    assert tested.status_code == 200, tested.text
    result = tested.json()
    assert result["ok"] is True and result["http_status"] == 204
    assert _audit(mw, head) == ["webhook.tested"]
    sent = receiver.requests[-1]
    stamp = verify(secret, sent.headers["Sibyl-Signature"], sent.content)
    assert stamp > 0
    event = json.loads(sent.content)
    assert event["type"] == "ping" and event["monitor_id"] == mid and event["advisory"] is True
    assert sent.headers["Sibyl-Event-Type"] == "ping"
    assert sent.headers["Sibyl-Delivery-Id"] == result["delivery_id"]
    assert secret not in tested.text and secret not in json.dumps(dict(sent.headers))
    delivery = mw.admin.fetchrow(
        "SELECT status, attempts, response_code FROM sibyl.webhook_delivery WHERE id = $1",
        UUID(result["delivery_id"]),
    )
    assert (delivery["status"], delivery["attempts"], delivery["response_code"]) == (
        "delivered",
        1,
        204,
    )
    listed = get(mw, f"/monitors/{mid}").json()["webhooks"]
    assert [w["id"] for w in listed] == [hook["id"]] and "secret" not in listed[0]


def test_a_failing_receiver_is_a_200_with_ok_false(mw: Any, receiver: Receiver) -> None:
    mid = new_monitor(mw)["id"]
    hook = post(mw, f"/monitors/{mid}/webhooks", {"url": HOOK, "event_types": ["run.failed"]})
    receiver.status = 500
    failed = post(mw, f"/monitors/{mid}/webhooks/{hook.json()['id']}/test")
    assert failed.status_code == 200
    assert (failed.json()["ok"], failed.json()["error"]) == (False, "http_error")
    receiver.status = 204
    receiver.error = httpx.ConnectError("refused")
    broken = post(mw, f"/monitors/{mid}/webhooks/{hook.json()['id']}/test")
    assert (broken.json()["ok"], broken.json()["error"]) == (False, "transport")
    missing = post(mw, f"/monitors/{mid}/webhooks/{uuid4()}/test")
    assert missing.status_code == 404


def test_monitor_scopes_only_through_monitor_routes(mw: Any) -> None:
    body = {"name": "sneaky", "env": "test", "scopes": ["monitor:read"]}
    resp = post(mw, "/api-keys", body)
    assert resp.status_code == 400 and resp.json()["type"].endswith("/invalid_scope")
    created = new_monitor(mw)
    key_id = created["api_key"]["id"]
    rotated = post(mw, f"/api-keys/{key_id}/rotate", {"grace_s": 0})
    assert rotated.status_code == 201, rotated.text
    assert rotated.json()["monitor_id"] == created["id"]
    mw.tokens["rotated"] = rotated.json()["secret"]
    assert get(mw, "/monitors/self", "rotated").json()["id"] == created["id"]
    listed = get(mw, f"/api-keys/{key_id}").json()
    assert listed["monitor_id"] == created["id"]
