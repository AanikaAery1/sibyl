"""Tenant settings and keys, users, invitations, memberships, sessions, issuers, groups (PG17)."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import sibyl_lane_a_kit as kit  # loaded by conftest

API = "/api/v1"


def tok(lane: Any, w: Any, role: str, **kw: Any) -> str:
    return kit.add_session(lane.db, w.tenant, w.users[role], **kw)


def h(lane: Any, token: str, **extra: str) -> dict[str, str]:
    return lane.bearer(token, **extra)


# ---- tenant ------------------------------------------------------------------------------------


def test_get_tenant_with_etag_and_304(lane: Any, world: Any) -> None:
    token = tok(lane, world, "viewer")
    resp = lane.client.get(f"{API}/tenant", headers=h(lane, token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["slug"] == world.slug and body["limits"]["ingest_burst"] == 5000
    again = lane.client.get(
        f"{API}/tenant", headers=h(lane, token, **{"If-None-Match": resp.headers["etag"]})
    )
    assert again.status_code == 304


def test_patch_tenant_preconditions_and_audit(lane: Any, world: Any) -> None:
    token = tok(lane, world, "owner")
    etag = lane.client.get(f"{API}/tenant", headers=h(lane, token)).headers["etag"]
    body = {"raw_retention_days": 14, "hold_on_incident": True}
    assert lane.client.patch(f"{API}/tenant", json=body, headers=h(lane, token)).status_code == 428
    wrong = lane.client.patch(
        f"{API}/tenant", json=body, headers=h(lane, token, **{"If-Match": '"x"'})
    )
    assert wrong.status_code == 412 and wrong.json()["current"]["slug"] == world.slug
    head = kit.audit_head(lane.db, world.tenant)
    ok = lane.client.patch(
        f"{API}/tenant",
        json=body,
        headers=h(lane, token, **{"If-Match": etag, "X-Sibyl-Reason": "pilot retention policy"}),
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["raw_retention_days"] == 14 and ok.headers["etag"] != etag
    assert ok.headers["x-sibyl-audit-receipt"].startswith(f"{world.tenant}:")
    rows = kit.audit_rows(lane.db, world.tenant, "config.changed")[-2:]
    assert {r["detail"]["field"] for r in rows} == {
        "tenant.raw_retention_days",
        "tenant.hold_on_incident",
    }
    assert rows[0]["reason"] == "pilot retention policy"
    assert kit.audit_actions(lane.db, world.tenant, head) == ["config.changed", "config.changed"]


def test_patch_tenant_validates_and_needs_fresh_step_up(lane: Any, world: Any) -> None:
    token = tok(lane, world, "owner")
    etag = lane.client.get(f"{API}/tenant", headers=h(lane, token)).headers["etag"]
    for bad in ({"audit_retention_days": 300}, {}, {"name": None}, {"slug": "x"}):
        resp = lane.client.patch(
            f"{API}/tenant", json=bad, headers=h(lane, token, **{"If-Match": etag})
        )
        assert resp.status_code == 422, (bad, resp.text)
    stale = tok(lane, world, "owner", step_up_at=kit.stale())
    resp = lane.client.patch(
        f"{API}/tenant", json={"name": "x"}, headers=h(lane, stale, **{"If-Match": etag})
    )
    assert resp.status_code == 403 and resp.json()["type"].endswith("/step_up_required")
    admin = tok(lane, world, "admin")
    assert (
        lane.client.patch(f"{API}/tenant", json={"name": "x"}, headers=h(lane, admin)).status_code
        == 403
    )


# ---- tenant keys -------------------------------------------------------------------------------


def test_list_tenant_keys_is_metadata_only(lane: Any, world: Any) -> None:
    resp = lane.client.get(
        f"{API}/tenant-keys", headers=h(lane, tok(lane, world, "security_admin"))
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert {k["purpose"] for k in data} == {"payload", "credential", "config"}
    assert all("wrapped_dek" not in k for k in data)
    assert (
        lane.client.get(
            f"{API}/tenant-keys", headers=h(lane, tok(lane, world, "admin"))
        ).status_code
        == 403
    )


def test_rotate_tenant_key_wraps_a_new_dek_outside_postgres(lane: Any, world: Any) -> None:
    token = tok(lane, world, "owner")
    key = kit.idem()
    body = {"reason": "quarterly key rotation"}
    resp = lane.client.post(
        f"{API}/tenant-keys/payload/rotate", json=body, headers=h(lane, token, **key)
    )
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert (out["active"]["version"], out["retired"]["version"]) == (2, 1)
    assert out["retired"]["state"] == "retired" and out["active"]["kek_id"] == kit.KEK_ID
    with lane.db.admin.tx(world.tenant):
        wrapped = lane.db.admin.fetchval(
            "SELECT wrapped_dek FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'payload'"
            " AND version = 2",
            world.tenant,
        )
    dek = kit.TEST_KEK.unwrap(bytes(wrapped), kit.wrap_aad(world.tenant, "payload", 2))
    assert len(dek) == 32
    row = kit.audit_rows(lane.db, world.tenant, "tenant_key.rotated")[-1]
    assert row["detail"]["version"] == 2 and row["actor_session_id"] is not None
    replay = lane.client.post(
        f"{API}/tenant-keys/payload/rotate", json=body, headers=h(lane, token, **key)
    )
    assert replay.status_code == 201 and replay.headers["idempotency-replayed"] == "true"
    assert replay.json() == out
    reuse = lane.client.post(
        f"{API}/tenant-keys/payload/rotate",
        json={"reason": "a different reason"},
        headers=h(lane, token, **key),
    )
    assert reuse.status_code == 422
    missing = lane.client.post(
        f"{API}/tenant-keys/payload/rotate", json=body, headers=h(lane, token)
    )
    assert missing.status_code == 428
    assert (
        lane.client.post(
            f"{API}/tenant-keys/bogus/rotate", json=body, headers=h(lane, token, **kit.idem())
        ).status_code
        == 422
    )


# ---- users, invitations, memberships ------------------------------------------------------------


def test_list_users_is_self_only_without_users_manage(lane: Any, world: Any) -> None:
    viewer = lane.client.get(f"{API}/users", headers=h(lane, tok(lane, world, "viewer")))
    assert viewer.status_code == 200
    assert [u["id"] for u in viewer.json()["data"]] == [str(world.users["viewer"])]
    admin = lane.client.get(
        f"{API}/users", params={"limit": 3}, headers=h(lane, tok(lane, world, "admin"))
    )
    page = admin.json()
    assert len(page["data"]) == 3 and page["has_more"] and 'rel="next"' in admin.headers["link"]
    nxt = lane.client.get(
        f"{API}/users",
        params={"limit": 3, "cursor": page["next_cursor"]},
        headers=h(lane, tok(lane, world, "admin")),
    )
    assert not {u["id"] for u in nxt.json()["data"]} & {u["id"] for u in page["data"]}
    mismatch = lane.client.get(
        f"{API}/users",
        params={"cursor": page["next_cursor"], "status": "active"},
        headers=h(lane, tok(lane, world, "admin")),
    )
    assert mismatch.status_code == 400


def test_get_user_self_rule(lane: Any, world: Any) -> None:
    viewer = tok(lane, world, "viewer")
    own = lane.client.get(f"{API}/users/{world.users['viewer']}", headers=h(lane, viewer))
    assert own.status_code == 200 and own.json()["memberships"][0]["role_name"] == "viewer"
    other = lane.client.get(f"{API}/users/{world.users['owner']}", headers=h(lane, viewer))
    assert other.status_code == 404
    assert "access.denied" in kit.audit_actions(lane.db, world.tenant)
    assert lane.client.get(f"{API}/users/not-a-uuid", headers=h(lane, viewer)).status_code == 404


def test_invitation_rank_rules(lane: Any, world: Any) -> None:
    base = {"oidc_issuer_id": str(world.issuer_id), "scope_kind": "tenant"}
    admin = tok(lane, world, "admin")
    for role in ("owner", "security_admin"):
        resp = lane.client.post(
            f"{API}/users/invitations",
            json=base | {"email": f"{role}@x.test", "role_name": role},
            headers=h(lane, admin, **kit.idem()),
        )
        assert resp.status_code == 403, role
    scoped = lane.client.post(
        f"{API}/users/invitations",
        json=base
        | {
            "email": "a@x.test",
            "role_name": "auditor",
            "scope_kind": "agent_group",
            "scope_id": str(world.groups["g1"]),
        },
        headers=h(lane, admin, **kit.idem()),
    )
    assert scoped.status_code == 422 and scoped.json()["type"].endswith(
        "/role_requires_tenant_scope"
    )
    ok = lane.client.post(
        f"{API}/users/invitations",
        json=base
        | {
            "email": "eng@x.test",
            "role_name": "engineer",
            "scope_kind": "agent_group",
            "scope_id": str(world.groups["g1"]),
        },
        headers=h(lane, admin, **kit.idem()),
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["user"]["status"] == "invited"
    assert kit.audit_actions(lane.db, world.tenant)[-2:] == [
        "user.provisioned",
        "membership.granted",
    ]
    dup = lane.client.post(
        f"{API}/users/invitations",
        json=base | {"email": "eng@x.test", "role_name": "viewer"},
        headers=h(lane, admin, **kit.idem()),
    )
    assert dup.status_code == 409 and dup.json()["type"].endswith("/user_exists")
    owner = tok(lane, world, "owner")
    sec = lane.client.post(
        f"{API}/users/invitations",
        json=base | {"email": "sec@x.test", "role_name": "security_admin"},
        headers=h(lane, owner, **kit.idem()),
    )
    assert sec.status_code == 201


def test_memberships_grant_revoke_regrant_and_last_owner(lane: Any, world: Any) -> None:
    owner = tok(lane, world, "owner")
    body = {
        "user_id": str(world.users["viewer"]),
        "role_name": "operator",
        "scope_kind": "tenant",
        "reason": "on-call rotation for october",
    }
    granted = lane.client.post(
        f"{API}/memberships", json=body, headers=h(lane, owner, **kit.idem())
    )
    assert granted.status_code == 201, granted.text
    dup = lane.client.post(f"{API}/memberships", json=body, headers=h(lane, owner, **kit.idem()))
    assert dup.status_code == 409 and dup.json()["type"].endswith("/membership_exists")
    mid = granted.json()["id"]
    gone = lane.client.delete(
        f"{API}/memberships/{mid}", params={"reason": "rotation finished"}, headers=h(lane, owner)
    )
    assert gone.status_code == 204
    again = lane.client.post(f"{API}/memberships", json=body, headers=h(lane, owner, **kit.idem()))
    assert again.status_code == 201 and again.json()["id"] == mid
    with lane.db.admin.tx(world.tenant):
        owner_mid = lane.db.admin.fetchval(
            "SELECT id FROM sibyl.membership WHERE tenant_id = $1 AND user_id = $2",
            world.tenant,
            world.users["owner"],
        )
    last = lane.client.delete(
        f"{API}/memberships/{owner_mid}",
        params={"reason": "trying to remove the last owner"},
        headers=h(lane, owner),
    )
    assert last.status_code == 409 and last.json()["type"].endswith("/last_owner")
    admin = tok(lane, world, "admin")
    denied = lane.client.delete(
        f"{API}/memberships/{owner_mid}",
        params={"reason": "admin cannot remove owner"},
        headers=h(lane, admin),
    )
    assert denied.status_code == 403
    rows = kit.audit_rows(lane.db, world.tenant, "membership.revoked")
    assert rows[-1]["reason"] == "rotation finished"


def test_disable_and_deprovision_user(lane: Any, world: Any) -> None:
    owner = tok(lane, world, "owner")
    victim = tok(lane, world, "operator")
    url = f"{API}/users/{world.users['operator']}"
    etag = lane.client.get(url, headers=h(lane, owner)).headers["etag"]
    resp = lane.client.patch(
        url,
        json={"status": "disabled", "reason": "left the company"},
        headers=h(lane, owner, **{"If-Match": etag}),
    )
    assert resp.status_code == 200, resp.text
    assert lane.client.get(f"{API}/auth/me", headers=h(lane, victim)).status_code == 401
    row = kit.audit_rows(lane.db, world.tenant, "user.disabled")[-1]
    assert row["detail"]["sessions_revoked"] == 1
    etag = resp.headers["etag"]
    gone = lane.client.patch(
        url, json={"status": "deprovisioned"}, headers=h(lane, owner, **{"If-Match": etag})
    )
    assert gone.status_code == 200 and gone.json()["email"] is None
    with lane.db.admin.tx(world.tenant):
        email = lane.db.admin.fetchval(
            "SELECT email FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2",
            world.tenant,
            world.users["operator"],
        )
        live = lane.db.admin.fetchval(
            "SELECT count(*) FROM sibyl.membership WHERE tenant_id = $1 AND user_id = $2 AND"
            " revoked_at IS NULL",
            world.tenant,
            world.users["operator"],
        )
    assert "@" not in email and len(email) == 64 and live == 0
    me = f"{API}/users/{world.users['owner']}"
    etag = lane.client.get(me, headers=h(lane, owner)).headers["etag"]
    last = lane.client.patch(
        me, json={"status": "disabled"}, headers=h(lane, owner, **{"If-Match": etag})
    )
    assert last.status_code == 409 and last.json()["type"].endswith("/last_owner")


def test_sessions_self_and_admin(lane: Any, world: Any) -> None:
    viewer = tok(lane, world, "viewer")
    own = lane.client.get(f"{API}/sessions", headers=h(lane, viewer)).json()["data"]
    assert len(own) == 1 and own[0]["current"] is True
    other_session = kit.add_session(lane.db, world.tenant, world.users["operator"])
    admin = tok(lane, world, "admin")
    listed = lane.client.get(
        f"{API}/sessions", params={"user_id": str(world.users["operator"])}, headers=h(lane, admin)
    ).json()["data"]
    assert len(listed) == 1
    sid = listed[0]["id"]
    assert lane.client.delete(f"{API}/sessions/{sid}", headers=h(lane, viewer)).status_code == 404
    assert lane.client.delete(f"{API}/sessions/{sid}", headers=h(lane, admin)).status_code == 204
    assert lane.client.get(f"{API}/auth/me", headers=h(lane, other_session)).status_code == 401
    assert (
        kit.audit_rows(lane.db, world.tenant, "session.revoked")[-1]["detail"]["cause"]
        == "revoked_by_admin"
    )


# ---- issuers -----------------------------------------------------------------------------------


def test_issuer_create_seals_secret_and_login_uses_it(lane: Any, lane_db: Any) -> None:
    w = kit.world(lane_db, issuer_url="https://legacy.test/dex")
    owner = kit.add_session(lane_db, w.tenant, w.users["owner"])
    body = {
        "issuer_url": lane.issuer.issuer,
        "client_id": lane.issuer.client_id,
        "client_secret": lane.issuer.client_secret,
        "allowed_email_domains": ["Corp.Test"],
        "jit_default_role": "viewer",
    }
    resp = lane.client.post(f"{API}/oidc-issuers", json=body, headers=h(lane, owner, **kit.idem()))
    assert resp.status_code == 201, resp.text
    issuer = resp.json()
    assert "client_secret" not in issuer and issuer["allowed_email_domains"] == ["corp.test"]
    with lane_db.admin.tx(w.tenant):
        ct = lane_db.admin.fetchval(
            "SELECT client_secret_ct FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND id = $2",
            w.tenant,
            issuer["id"],
        )
    assert lane.issuer.client_secret.encode() not in bytes(ct)
    lane.services.settings  # noqa: B018
    lane.app.state.sibyl_lane_a["auth_settings"] = kit.AuthSettings(
        session_secret=kit.SESSION_SECRET
    )
    with lane_db.admin.tx(w.tenant):
        lane_db.admin.execute(
            "UPDATE sibyl.oidc_issuer SET status = 'disabled' WHERE tenant_id = $1 AND issuer_url"
            " = $2",
            w.tenant,
            "https://legacy.test/dex",
        )
    login = lane.client.get(f"{API}/auth/login", params={"tenant": w.slug}, follow_redirects=False)
    assert login.status_code == 302
    cookie = login.cookies["__Host-sibyl_oidc_state"]
    code, state = lane.issuer.authorize(
        login.headers["location"], sub="jit-user", email="a@corp.test"
    )
    lane.client.cookies.clear()
    done = lane.client.get(
        f"{API}/auth/callback",
        params={"code": code, "state": state},
        headers={"Cookie": f"__Host-sibyl_oidc_state={cookie}"},
        follow_redirects=False,
    )
    assert done.status_code == 302, done.text  # the token endpoint accepted the unsealed secret
    assert (
        kit.audit_rows(lane_db, w.tenant, "oidc_issuer.configured")[-1]["detail"]["issuer_url"]
        == body["issuer_url"]
    )


def test_issuer_rules(lane: Any, world: Any) -> None:
    owner = tok(lane, world, "owner")
    base = {"client_id": "c", "client_secret": "s", "allowed_email_domains": ["x.test"]}
    for bad, code in (
        ({"issuer_url": "https://idp.test/dex"}, "issuer_exists"),
        ({"issuer_url": "https://new.test", "jit_default_role": "owner"}, "jit_role_forbidden"),
        (
            {"issuer_url": "https://new.test", "role_claim_map": {"x": "admin"}},
            "jit_role_forbidden",
        ),
        ({"issuer_url": "https://u:p@new.test"}, "validation_failed"),
        ({"issuer_url": "http://new.test"}, "validation_failed"),
    ):
        resp = lane.client.post(
            f"{API}/oidc-issuers", json=base | bad, headers=h(lane, owner, **kit.idem())
        )
        assert resp.json()["type"].endswith(f"/{code}"), (bad, resp.text)
    url = f"{API}/oidc-issuers/{world.issuer_id}"
    got = lane.client.get(url, headers=h(lane, tok(lane, world, "viewer")))
    assert got.status_code == 200 and got.json()["is_active"] is True
    last = lane.client.patch(
        url, json={"is_active": False}, headers=h(lane, owner, **{"If-Match": got.headers["etag"]})
    )
    assert last.status_code == 409 and last.json()["type"].endswith("/last_active_issuer")
    changed = lane.client.patch(
        url,
        json={"allowed_email_domains": ["y.test"]},
        headers=h(lane, owner, **{"If-Match": got.headers["etag"]}),
    )
    assert changed.status_code == 200 and changed.json()["allowed_email_domains"] == ["y.test"]
    assert kit.audit_rows(lane.db, world.tenant, "oidc_issuer.changed")[-1]["detail"][
        "fields_changed"
    ] == ["allowed_email_domains"]


# ---- agent groups ------------------------------------------------------------------------------


def test_groups_create_list_patch_and_cycles(lane: Any, world: Any) -> None:
    admin = tok(lane, world, "admin")
    made = lane.client.post(
        f"{API}/agent-groups",
        json={"slug": "payments", "name": "Payments", "parent_group_id": str(world.groups["g2"])},
        headers=h(lane, admin, **kit.idem()),
    )
    assert made.status_code == 201, made.text
    dup = lane.client.post(
        f"{API}/agent-groups",
        json={"slug": "payments", "name": "x"},
        headers=h(lane, admin, **kit.idem()),
    )
    assert dup.status_code == 409 and dup.json()["type"].endswith("/slug_exists")
    listed = lane.client.get(
        f"{API}/agent-groups", headers=h(lane, tok(lane, world, "viewer"))
    ).json()["data"]
    assert {g["slug"] for g in listed} >= {"payments", "group-one", "group-two"}
    g1 = f"{API}/agent-groups/{world.groups['g1']}"
    etag = lane.client.get(g1, headers=h(lane, admin)).headers["etag"]
    cycle = lane.client.patch(
        g1,
        json={"parent_group_id": made.json()["id"]},
        headers=h(lane, admin, **{"If-Match": etag}),
    )
    assert cycle.status_code == 409 and cycle.json()["type"].endswith("/group_cycle")
    self_parent = lane.client.patch(
        g1,
        json={"parent_group_id": str(world.groups["g1"])},
        headers=h(lane, admin, **{"If-Match": etag}),
    )
    assert self_parent.status_code == 409
    renamed = lane.client.patch(
        g1, json={"name": "Group One"}, headers=h(lane, admin, **{"If-Match": etag})
    )
    assert renamed.status_code == 200 and renamed.json()["name"] == "Group One"
    stale = lane.client.patch(
        g1, json={"name": "again"}, headers=h(lane, admin, **{"If-Match": etag})
    )
    assert stale.status_code == 412
    assert (
        lane.client.get(f"{API}/agent-groups/{uuid4()}", headers=h(lane, admin)).status_code == 404
    )


def test_group_scoped_engineer_inherits_child_groups(lane: Any, world: Any) -> None:
    token = tok(lane, world, "engineer")
    me = lane.client.get(f"{API}/auth/me", headers=h(lane, token)).json()
    assert "agents:write" in me["scopes"] and "users:manage" not in me["scopes"]
