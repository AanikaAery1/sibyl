"""OIDC login, callback, step-up, logout, /auth/me, sessions and CLI bearer JWTs on PG17."""

from __future__ import annotations

import time
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs, urlsplit

import sibyl_lane_a_kit as kit  # loaded by conftest

API = "/api/v1"


def cookies_of(resp: Any) -> dict[str, Any]:
    jar: dict[str, Any] = {}
    for raw in resp.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(raw)
        for name, morsel in parsed.items():
            jar[name] = morsel
    return jar


def start_login(lane: Any, w: Any, return_to: str = "/console/fleet") -> tuple[str, str]:
    resp = lane.client.get(
        f"{API}/auth/login",
        params={"tenant": w.slug, "return_to": return_to},
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.text
    state_cookie = cookies_of(resp)["__Host-sibyl_oidc_state"]
    assert state_cookie["secure"] and state_cookie["httponly"] and state_cookie["path"] == "/"
    assert state_cookie["samesite"].lower() == "lax"
    return resp.headers["location"], state_cookie.value


def callback(lane: Any, code: str, state: str, cookie: str | None) -> Any:
    headers = {"Cookie": f"__Host-sibyl_oidc_state={cookie}"} if cookie else {}
    lane.client.cookies.clear()  # send exactly the cookie under test, never the jar's
    return lane.client.get(
        f"{API}/auth/callback",
        params={"code": code, "state": state},
        headers=headers,
        follow_redirects=False,
    )


def login(lane: Any, w: Any, role: str = "owner") -> str:
    location, cookie = start_login(lane, w)
    code, state = lane.issuer.authorize(location, sub=w.subjects[role], email=f"{role}@x.test")
    resp = callback(lane, code, state, cookie)
    assert resp.status_code == 302, resp.text
    return "sibyl_sess_" + cookies_of(resp)["__Host-sibyl_session"].value


def test_login_redirects_with_pkce_state_and_nonce(lane: Any, world: Any) -> None:
    location, _ = start_login(lane, world)
    q = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
    assert location.startswith("https://idp.test/dex/auth?")
    assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43
    assert q["redirect_uri"] == f"{kit.PUBLIC_URL}/api/v1/auth/callback"
    assert q["scope"] == "openid email profile" and q["state"] and q["nonce"]
    assert "prompt" not in q


def test_login_for_unknown_tenant_is_404(lane: Any) -> None:
    resp = lane.client.get(f"{API}/auth/login", params={"tenant": "no-such-tenant"})
    assert resp.status_code == 404
    assert resp.json()["type"].endswith("/tenant_unknown")


def test_full_code_flow_creates_a_session(lane: Any, world: Any) -> None:
    head = kit.audit_head(lane.db, world.tenant)
    location, cookie = start_login(lane, world, "/console/agents?x=1")
    code, state = lane.issuer.authorize(location, sub=world.subjects["owner"], email="o@x.test")
    resp = callback(lane, code, state, cookie)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/console/agents?x=1"
    jar = cookies_of(resp)
    session = jar["__Host-sibyl_session"]
    assert session["secure"] and session["httponly"] and int(session["max-age"]) == 8 * 3600
    assert jar["__Host-sibyl_oidc_state"]["max-age"] == "0"
    me = lane.client.get(f"{API}/auth/me", headers=lane.bearer("sibyl_sess_" + session.value))
    assert me.status_code == 200, me.text
    body = me.json()
    assert body["user"]["id"] == str(world.users["owner"])
    assert body["tenant"]["slug"] == world.slug
    assert "tenant:write" in body["scopes"] and [m["role_name"] for m in body["memberships"]] == [
        "owner"
    ]
    assert body["step_up_valid_until"] is None
    assert kit.audit_actions(lane.db, world.tenant, head) == ["access.login"]
    row = kit.audit_rows(lane.db, world.tenant, "access.login")[-1]
    assert row["actor_type"] == "human" and row["actor_id"] == world.users["owner"]
    assert row["detail"]["issuer_id"] == str(world.issuer_id)


def test_callback_replay_of_a_used_code_fails(lane: Any, world: Any) -> None:
    location, cookie = start_login(lane, world)
    code, state = lane.issuer.authorize(location, sub=world.subjects["owner"], email="o@x.test")
    assert callback(lane, code, state, cookie).status_code == 302
    again = callback(lane, code, state, cookie)
    assert again.status_code == 401
    assert kit.audit_rows(lane.db, world.tenant, "access.login_failed")[-1]["detail"]["cause"] == (
        "token_exchange_failed"
    )


def test_state_mismatch_is_refused_and_audited(lane: Any, world: Any) -> None:
    location, cookie = start_login(lane, world)
    code, _ = lane.issuer.authorize(location, sub=world.subjects["owner"], email="o@x.test")
    resp = callback(lane, code, "forged-state", cookie)
    assert resp.status_code == 401
    assert resp.json()["type"].endswith("/oidc_failed")
    failed = kit.audit_rows(lane.db, world.tenant, "access.login_failed")[-1]
    assert failed["actor_type"] == "system" and failed["detail"]["cause"] == "state_mismatch"
    assert failed["detail"]["ip_hash"]


def test_callback_without_state_cookie_is_refused(lane: Any, world: Any) -> None:
    location, _ = start_login(lane, world)
    code, state = lane.issuer.authorize(location, sub=world.subjects["owner"], email="o@x.test")
    assert callback(lane, code, state, None).status_code == 401
    assert callback(lane, code, state, "garbage").status_code == 401


def test_wrong_nonce_is_refused(lane: Any, world: Any) -> None:
    location, cookie = start_login(lane, world)
    code, state = lane.issuer.authorize(location, sub=world.subjects["owner"], email="o@x.test")
    lane.issuer.grants[code].claims["nonce"] = "other"
    assert callback(lane, code, state, cookie).status_code == 401
    assert kit.audit_rows(lane.db, world.tenant, "access.login_failed")[-1]["detail"]["cause"] == (
        "nonce_mismatch"
    )


def test_unknown_subject_without_jit_is_refused(lane: Any, world: Any) -> None:
    location, cookie = start_login(lane, world)
    code, state = lane.issuer.authorize(location, sub="stranger", email="s@x.test")
    assert callback(lane, code, state, cookie).status_code == 401
    assert kit.audit_rows(lane.db, world.tenant, "access.login_failed")[-1]["detail"]["cause"] == (
        "user_unknown"
    )


def test_disabled_user_cannot_log_in(lane: Any, world: Any) -> None:
    kit.add_user(
        lane.db, world.tenant, world.issuer_id, roles=("viewer",), subject="gone", status="disabled"
    )
    location, cookie = start_login(lane, world)
    code, state = lane.issuer.authorize(location, sub="gone", email="g@x.test")
    assert callback(lane, code, state, cookie).status_code == 401
    assert kit.audit_rows(lane.db, world.tenant, "access.login_failed")[-1]["detail"]["cause"] == (
        "user_disabled"
    )


def test_user_without_membership_cannot_log_in(lane: Any, world: Any) -> None:
    location, cookie = start_login(lane, world)
    code, state = lane.issuer.authorize(
        location, sub=_subject(lane, world, "nobody"), email="n@x.test"
    )
    assert callback(lane, code, state, cookie).status_code == 401


def _subject(lane: Any, w: Any, key: str) -> str:
    with lane.db.admin.tx(w.tenant):
        return lane.db.admin.fetchval(
            "SELECT subject FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2",
            w.tenant,
            w.users[key],
        )


def test_jit_provisioning_on_allowed_domain(lane: Any, lane_db: Any) -> None:
    tenant, slug = kit.make_tenant(lane_db)
    kit.add_issuer(
        lane_db,
        tenant,
        "https://idp.test/dex",
        jit_default_role="viewer",
        allowed_email_domains=["corp.test"],
    )
    w = kit.World(tenant, slug, None, "https://idp.test/dex")  # type: ignore[arg-type]
    location, cookie = start_login(lane, w)
    code, state = lane.issuer.authorize(location, sub="new-hire", email="dev@corp.test")
    resp = callback(lane, code, state, cookie)
    assert resp.status_code == 302, resp.text
    assert kit.audit_actions(lane.db, tenant)[-2:] == ["user.provisioned", "access.login"]
    location, cookie = start_login(lane, w)
    code, state = lane.issuer.authorize(location, sub="outsider", email="x@elsewhere.test")
    assert callback(lane, code, state, cookie).status_code == 401
    assert kit.audit_rows(lane.db, tenant, "access.login_failed")[-1]["detail"]["cause"] == (
        "email_domain_not_allowed"
    )


def test_invited_user_is_bound_by_verified_email(lane: Any, world: Any) -> None:
    owner = kit.add_session(lane.db, world.tenant, world.users["owner"])
    invited = lane.client.post(
        f"{API}/users/invitations",
        json={
            "email": "invitee@x.test",
            "oidc_issuer_id": str(world.issuer_id),
            "role_name": "viewer",
            "scope_kind": "tenant",
        },
        headers=lane.bearer(owner, **kit.idem()),
    )
    assert invited.status_code == 201, invited.text
    location, cookie = start_login(lane, world)
    code, state = lane.issuer.authorize(location, sub="invitee-sub", email="invitee@x.test")
    assert callback(lane, code, state, cookie).status_code == 302
    with lane.db.admin.tx(world.tenant):
        row = lane.db.admin.fetchrow(
            "SELECT subject, status FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2",
            world.tenant,
            invited.json()["user"]["id"],
        )
    assert (row["subject"], row["status"]) == ("invitee-sub", "active")


def test_step_up_round_trip(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["owner"], step_up=False)
    patch = lane.client.get(f"{API}/tenant", headers=lane.bearer(token))
    etag = patch.headers["etag"]
    refused = lane.client.patch(
        f"{API}/tenant", json={"name": "Renamed"}, headers=lane.bearer(token, **{"If-Match": etag})
    )
    assert refused.status_code == 403
    assert refused.json()["step_up_url"] == "/api/v1/auth/step-up"
    resp = lane.client.post(
        f"{API}/auth/step-up",
        params={"for_action": "updateTenant"},
        json={"return_to": "/console/settings"},
        headers=lane.bearer(token),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    q = {k: v[0] for k, v in parse_qs(urlsplit(resp.headers["location"]).query).items()}
    assert q["prompt"] == "login" and q["max_age"] == "0"
    cookie = cookies_of(resp)["__Host-sibyl_oidc_state"].value
    code, state = lane.issuer.authorize(
        resp.headers["location"], sub=world.subjects["owner"], email="o@x.test"
    )
    done = callback(lane, code, state, cookie)
    assert done.status_code == 302 and done.headers["location"] == "/console/settings"
    assert "__Host-sibyl_session" not in cookies_of(done)
    step = kit.audit_rows(lane.db, world.tenant, "access.step_up")[-1]
    assert step["detail"]["for_action"] == "updateTenant"
    me = lane.client.get(f"{API}/auth/me", headers=lane.bearer(token)).json()
    assert me["step_up_valid_until"] is not None
    ok = lane.client.patch(
        f"{API}/tenant", json={"name": "Renamed"}, headers=lane.bearer(token, **{"If-Match": etag})
    )
    assert ok.status_code == 200, ok.text


def test_step_up_needs_fresh_authentication_of_the_same_subject(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["owner"], step_up=False)
    for sub, extra, cause in (
        (world.subjects["admin"], {}, "subject_mismatch"),
        (world.subjects["owner"], {"auth_time": int(time.time()) - 3600}, "stale_authentication"),
    ):
        resp = lane.client.post(
            f"{API}/auth/step-up", headers=lane.bearer(token), follow_redirects=False
        )
        cookie = cookies_of(resp)["__Host-sibyl_oidc_state"].value
        code, state = lane.issuer.authorize(resp.headers["location"], sub=sub, email="o@x.test")
        lane.issuer.grants[code].claims.update(extra)
        assert callback(lane, code, state, cookie).status_code == 401
        assert (
            kit.audit_rows(lane.db, world.tenant, "access.login_failed")[-1]["detail"]["cause"]
            == cause
        )


def _step_up_without_auth_time(lane: Any, world: Any) -> Any:
    token = kit.add_session(lane.db, world.tenant, world.users["owner"], step_up=False)
    resp = lane.client.post(
        f"{API}/auth/step-up", headers=lane.bearer(token), follow_redirects=False
    )
    cookie = cookies_of(resp)["__Host-sibyl_oidc_state"].value
    code, state = lane.issuer.authorize(
        resp.headers["location"], sub=world.subjects["owner"], email="o@x.test"
    )
    lane.issuer.grants[code].claims.pop("auth_time")  # dex omits auth_time
    return callback(lane, code, state, cookie)


def test_step_up_without_auth_time_uses_iat_unless_strict(lane: Any, world: Any) -> None:
    assert _step_up_without_auth_time(lane, world).status_code == 302
    lane.app.state.sibyl_lane_a["auth_settings"] = kit.AuthSettings(
        session_secret=kit.SESSION_SECRET,
        oidc_client_secret=lane.issuer.client_secret,
        step_up_require_auth_time=True,
    )
    assert _step_up_without_auth_time(lane, world).status_code == 401
    rows = kit.audit_rows(lane.db, world.tenant, "access.login_failed")
    assert rows[-1]["detail"]["cause"] == "stale_authentication"


def test_logout_revokes_the_session(lane: Any, world: Any) -> None:
    token = login(lane, world)
    resp = lane.client.post(f"{API}/auth/logout", headers=lane.bearer(token))
    assert resp.status_code == 204, resp.text
    assert resp.headers["x-sibyl-audit-receipt"].startswith(f"{world.tenant}:")
    assert lane.client.get(f"{API}/auth/me", headers=lane.bearer(token)).status_code == 401
    assert kit.audit_rows(lane.db, world.tenant, "access.logout")[-1]["detail"]["cause"] == "logout"


def test_expired_and_revoked_sessions_are_401(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["viewer"])
    assert lane.client.get(f"{API}/auth/me", headers=lane.bearer(token)).status_code == 200
    with lane.db.admin.tx(world.tenant):
        lane.db.admin.execute(
            "UPDATE sibyl.session SET idle_expires_at = now() - interval '1 second'"
            " WHERE tenant_id = $1 AND user_id = $2",
            world.tenant,
            world.users["viewer"],
        )
    assert lane.client.get(f"{API}/auth/me", headers=lane.bearer(token)).status_code == 401
    assert (
        lane.client.get(f"{API}/auth/me", headers=lane.bearer("sibyl_sess_" + "x" * 43)).status_code
        == 401
    )
    assert (
        lane.client.get(f"{API}/auth/me", headers=lane.bearer("sibyl_sess_short")).status_code
        == 401
    )


def test_session_activity_slides_the_idle_window(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["viewer"])
    with lane.db.admin.tx(world.tenant):
        lane.db.admin.execute(
            "UPDATE sibyl.session SET last_seen_at = now() - interval '10 minutes',"
            " idle_expires_at = now() + interval '20 minutes' WHERE tenant_id = $1 AND user_id ="
            " $2",
            world.tenant,
            world.users["viewer"],
        )
    assert lane.client.get(f"{API}/auth/me", headers=lane.bearer(token)).status_code == 200
    with lane.db.admin.tx(world.tenant):
        left = lane.db.admin.fetchval(
            "SELECT extract(epoch FROM idle_expires_at - now()) FROM sibyl.session"
            " WHERE tenant_id = $1 AND user_id = $2",
            world.tenant,
            world.users["viewer"],
        )
    assert left > 25 * 60


def test_disabled_user_session_stops_working(lane: Any, world: Any) -> None:
    token = kit.add_session(lane.db, world.tenant, world.users["viewer"])
    with lane.db.admin.tx(world.tenant):
        lane.db.admin.execute(
            "UPDATE sibyl.app_user SET status = 'disabled' WHERE tenant_id = $1 AND id = $2",
            world.tenant,
            world.users["viewer"],
        )
    assert lane.client.get(f"{API}/auth/me", headers=lane.bearer(token)).status_code == 401


# ---- CLI bearer JWTs ---------------------------------------------------------------------------


def test_cli_bearer_jwt_resolves_tenant_first(lane: Any, world: Any) -> None:
    token = lane.issuer.access_token(world.subjects["engineer"])
    ok = lane.client.get(
        f"{API}/auth/me", headers=lane.bearer(token, **{"X-Sibyl-Tenant": world.slug})
    )
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["user"]["id"] == str(world.users["engineer"])
    assert body["step_up_valid_until"] is None
    assert lane.client.get(f"{API}/auth/me", headers=lane.bearer(token)).status_code == 401


def test_shared_issuer_cannot_cross_tenants(lane: Any, world: Any, lane_db: Any) -> None:
    other = kit.world(lane_db)  # same issuer URL, different tenant
    token = lane.issuer.access_token(world.subjects["owner"])
    resp = lane.client.get(
        f"{API}/auth/me", headers=lane.bearer(token, **{"X-Sibyl-Tenant": other.slug})
    )
    assert resp.status_code == 401
    unknown = lane.client.get(
        f"{API}/auth/me", headers=lane.bearer(token, **{"X-Sibyl-Tenant": "nope"})
    )
    assert unknown.status_code == 401


def test_bearer_jwt_claims_are_enforced(lane: Any, world: Any) -> None:
    sub = world.subjects["owner"]
    head = {"X-Sibyl-Tenant": world.slug}
    now = int(time.time())
    bad = [
        lane.issuer.access_token(sub, aud="sibyl-console"),
        lane.issuer.sign(lane.issuer.claims(sub, aud="sibyl-api") | {"exp": now + 7200}),
        lane.issuer.sign(lane.issuer.claims(sub, aud="sibyl-api") | {"exp": now - 600}),
        lane.issuer.sign(lane.issuer.claims(sub, aud="sibyl-api") | {"iss": "https://evil.test"}),
        kit.FakeIssuer().access_token(sub),  # right iss, foreign signing key
    ]
    for token in bad:
        assert (
            lane.client.get(f"{API}/auth/me", headers=lane.bearer(token, **head)).status_code == 401
        )


def test_bearer_jwt_cannot_step_up(lane: Any, world: Any) -> None:
    token = lane.issuer.access_token(world.subjects["owner"])
    resp = lane.client.post(
        f"{API}/auth/step-up", headers=lane.bearer(token, **{"X-Sibyl-Tenant": world.slug})
    )
    assert resp.status_code == 403


def test_repeated_bad_credentials_are_throttled_before_lookup(lane: Any, world: Any) -> None:
    statuses = {
        lane.client.get(f"{API}/auth/me", headers=lane.bearer("sibyl_sess_" + "y" * 43)).status_code
        for _ in range(25)
    }
    assert 429 in statuses
