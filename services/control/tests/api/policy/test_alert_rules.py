"""Alert-rule editing against a migrated PG17 (API.md §5.6, R18): seed copies and custom rules."""

from __future__ import annotations

from typing import Any

from sibyl_lane_r_harness import World
from sibyl_lane_r_policy_setup import receipt_ok, slug

RULES = "/api/v1/alert-rules"


def _type(resp: Any) -> str:
    return str(resp.json().get("type", "")).rsplit("/", 1)[-1]


def _seed_rule(world: World) -> dict[str, Any]:
    listed = world.client.get(RULES, params={"limit": 200}, headers=world.headers("viewer"))
    assert listed.status_code == 200
    return next(r for r in listed.json()["data"] if r["origin"] == "seed")


def test_lists_seed_copies_with_filters_and_paging(world: World) -> None:
    page = world.client.get(RULES, params={"limit": 3}, headers=world.headers("viewer"))
    assert page.status_code == 200
    body = page.json()
    assert len(body["data"]) == 3 and body["has_more"] is True
    assert 'rel="next"' in page.headers["link"]
    nxt = world.client.get(
        RULES, params={"limit": 3, "cursor": body["next_cursor"]}, headers=world.headers("viewer")
    )
    assert {r["id"] for r in nxt.json()["data"]}.isdisjoint({r["id"] for r in body["data"]})
    mismatch = world.client.get(
        RULES,
        params={"limit": 3, "cursor": body["next_cursor"], "scope": "agent"},
        headers=world.headers("viewer"),
    )
    assert mismatch.status_code == 400 and _type(mismatch) == "cursor_filter_mismatch"
    scoped = world.client.get(
        RULES, params={"scope": "provider", "limit": 200}, headers=world.headers("viewer")
    )
    assert scoped.json()["data"] and all(r["scope"] == "provider" for r in scoped.json()["data"])
    assert world.client.get(RULES, headers=world.headers("nobody")).status_code == 403


def test_patch_marks_overridden_and_reset_restores(world: World) -> None:
    rule = _seed_rule(world)
    got = world.client.get(f"{RULES}/{rule['id']}", headers=world.headers("viewer"))
    etag = got.headers["etag"]
    assert (
        world.client.patch(
            f"{RULES}/{rule['id']}", json={"enabled": False}, headers=world.headers("owner")
        ).status_code
        == 428
    )
    wrong = world.client.patch(
        f"{RULES}/{rule['id']}",
        json={"enabled": False},
        headers=world.headers("owner", **{"If-Match": '"x"'}),
    )
    assert wrong.status_code == 412
    patched = world.client.patch(
        f"{RULES}/{rule['id']}",
        json={"enabled": False, "window_s": 900, "hysteresis": {"in": 3}},
        headers=world.headers("owner", **{"If-Match": etag}),
    )
    assert patched.status_code == 200, patched.text
    out = patched.json()
    assert out["overridden"] is True and out["enabled"] is False and out["window_s"] == 900
    assert out["hysteresis"]["in"] == 3
    assert receipt_ok(patched, world.a)
    assert "config.changed" in world.audit.actions(world.a.id)

    reset = world.client.post(f"{RULES}/{rule['id']}/reset", headers=world.idem("owner"))
    assert reset.status_code == 200, reset.text
    back = reset.json()
    assert back["overridden"] is False and back["enabled"] is True
    assert back["window_s"] == rule["window_s"] and back["hysteresis"] == rule["hysteresis"]
    assert (
        world.client.patch(
            f"{RULES}/{rule['id']}",
            json={"enabled": False},
            headers=world.headers("viewer", **{"If-Match": etag}),
        ).status_code
        == 403
    )


def test_custom_rules(world: World) -> None:
    code = slug("cr").replace("-", "_")
    bad = world.client.post(
        RULES,
        json={"code": "Bad-Code", "scope": "agent", "severity": "warning", "window_s": 60},
        headers=world.idem("owner"),
    )
    assert bad.status_code == 422 and _type(bad) == "code_pattern"
    body = {
        "code": code,
        "kind": "custom",
        "scope": "agent",
        "severity": "warning",
        "window_s": 60,
        "thresholds": {"tiers": {"1": {"max": 3}}},
        "tier_applicability": [1, 2],
        "what_to_do_template": "Check the agent's tool calls.",
    }
    grouped = world.client.post(RULES, json=body, headers=world.idem("engineer"))
    assert grouped.status_code == 403  # tenant-wide config: group-limited grants refused
    made = world.client.post(RULES, json=body, headers=world.idem("admin"))
    assert made.status_code == 201, made.text
    rule = made.json()
    assert rule["origin"] == "custom" and rule["tier_applicability"] == [1, 2]
    dup = world.client.post(RULES, json=body, headers=world.idem("owner"))
    assert dup.status_code == 409 and _type(dup) == "code_exists"

    no_reset = world.client.post(f"{RULES}/{rule['id']}/reset", headers=world.idem("owner"))
    assert no_reset.status_code == 409 and _type(no_reset) == "custom_rule"
    patched = world.client.patch(
        f"{RULES}/{rule['id']}",
        json={"penalty": 15},
        headers=world.headers("owner", **{"If-Match": made.headers["etag"]}),
    )
    assert patched.status_code == 200 and patched.json()["overridden"] is False
    customs = world.client.get(RULES, params={"kind": "custom"}, headers=world.headers("viewer"))
    assert [r["code"] for r in customs.json()["data"]] == [code]


def test_isolation(world: World) -> None:
    rule = _seed_rule(world)
    assert (
        world.client.get(f"{RULES}/{rule['id']}", headers=world.headers("owner-b")).status_code
        == 404
    )
    assert (
        world.client.post(f"{RULES}/{rule['id']}/reset", headers=world.idem("owner-b")).status_code
        == 404
    )
