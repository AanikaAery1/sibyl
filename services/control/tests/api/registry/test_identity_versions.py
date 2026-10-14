"""Agent identity (narrow-only, conditional step-up), versions and AI-BOM reads."""

from __future__ import annotations

import hashlib
from uuid import UUID, uuid4

from sibyl_lane_r_harness import World
from sibyl_lane_r_registry import agent, model, outbox_events, provider


def _identity(world: World, agent_id: str, who: str = "owner"):  # type: ignore[no-untyped-def]
    return world.client.get(f"/api/v1/agents/{agent_id}/identity", headers=world.headers(who))


def _put(world: World, agent_id: str, body: dict, etag: str, who: str = "owner"):  # type: ignore[no-untyped-def,type-arg]
    return world.client.put(
        f"/api/v1/agents/{agent_id}/identity",
        json=body,
        headers=world.headers(who, **{"If-Match": etag}),
    )


IDENTITY = {
    "allowed_tools": ["search", "lookup"],
    "allowed_models": ["gpt-x"],
    "allowed_providers": [],
    "enforcement": "observe",
    "reason": "initial allowlist from design review",
}


class TestIdentity:
    def test_put_bumps_version_and_audits(self, world: World) -> None:
        created = agent(world)
        current = _identity(world, created["id"])
        assert current.status_code == 200 and current.headers["etag"] == '"1"'
        world.audit.clear()
        resp = _put(world, created["id"], IDENTITY, '"1"')
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["identity_version"] == 2 and resp.headers["etag"] == '"2"'
        assert body["allowed_tools"] == ["lookup", "search"]
        assert world.audit.actions(world.a.id) == ["agent_identity.changed"]
        detail = world.audit.rows[world.a.id][-1].detail
        assert detail["widened"] is True and list(detail["added"]["tools"]) == ["lookup", "search"]
        assert "policy_changed" in outbox_events(world, world.a, created["id"])
        assert _put(world, created["id"], IDENTITY, '"1"').status_code == 412
        assert (
            world.client.put(
                f"/api/v1/agents/{created['id']}/identity",
                json=IDENTITY,
                headers=world.headers("owner"),
            ).status_code
            == 428
        )

    def test_group_engineer_may_only_narrow(self, world: World) -> None:
        created = agent(world, agent_group_id=str(world.a.group_id))
        _put(world, created["id"], IDENTITY, '"1"')
        widen = {**IDENTITY, "allowed_tools": ["search", "lookup", "shell"]}
        resp = _put(world, created["id"], widen, '"2"', "engineer")
        assert resp.status_code == 403
        assert resp.json()["type"].endswith("/identity_widen_forbidden")
        narrow = {**IDENTITY, "allowed_tools": ["search"]}
        assert _put(world, created["id"], narrow, '"2"', "engineer").status_code == 200

    def test_enforcement_change_needs_fresh_step_up(self, world: World) -> None:
        created = agent(world)
        block = {**IDENTITY, "enforcement": "block"}
        stale = _put(world, created["id"], block, '"1"', "owner-stale")
        assert stale.status_code == 403
        assert stale.json()["type"].endswith("/step_up_required")
        assert _put(world, created["id"], block, '"1"').status_code == 200

    def test_unknown_provider_is_422(self, world: World) -> None:
        created = agent(world)
        resp = _put(world, created["id"], {**IDENTITY, "allowed_providers": [str(uuid4())]}, '"1"')
        assert resp.status_code == 422
        bad = _put(world, created["id"], {**IDENTITY, "allowed_providers": ["nope"]}, '"1"')
        assert bad.status_code == 422
        ok = _put(
            world,
            created["id"],
            {**IDENTITY, "allowed_providers": [str(provider(world, world.a))]},
            '"1"',
        )
        assert ok.status_code == 200

    def test_cross_tenant_404(self, world: World) -> None:
        created = agent(world)
        assert _identity(world, created["id"], "owner-b").status_code == 404


class TestVersions:
    def test_create_and_list_versions(self, world: World) -> None:
        created = agent(world)
        mid = model(world, world.a)
        url = f"/api/v1/agents/{created['id']}/versions"
        world.audit.clear()
        first = world.client.post(
            url,
            json={"primary_model_id": str(mid), "prompt": "You are billing."},
            headers=world.idem(),
        )
        assert first.status_code == 201, first.text
        assert first.json()["version_no"] == 1
        assert first.json()["prompt_sha256"] == hashlib.sha256(b"You are billing.").hexdigest()
        second = world.client.post(url, json={"primary_model_id": str(mid)}, headers=world.idem())
        assert second.json()["version_no"] == 2
        assert world.audit.actions(world.a.id) == ["asset.updated", "asset.updated"]
        listed = world.client.get(url + "?limit=1", headers=world.headers("viewer")).json()
        assert [v["version_no"] for v in listed["data"]] == [2] and listed["has_more"]
        nxt = world.client.get(
            url + f"?limit=1&cursor={listed['next_cursor']}", headers=world.headers("viewer")
        ).json()
        assert [v["version_no"] for v in nxt["data"]] == [1]
        detail = world.client.get(
            f"/api/v1/agents/{created['id']}", headers=world.headers("owner")
        ).json()
        assert detail["current_version"]["version_no"] == 2

    def test_bad_references_and_mismatched_prompt_hash(self, world: World) -> None:
        created = agent(world)
        url = f"/api/v1/agents/{created['id']}/versions"
        assert (
            world.client.post(
                url, json={"primary_model_id": str(uuid4())}, headers=world.idem()
            ).status_code
            == 422
        )
        mid = model(world, world.a)
        assert (
            world.client.post(
                url,
                json={"primary_model_id": str(mid), "prompt": "a", "prompt_sha256": "0" * 64},
                headers=world.idem(),
            ).status_code
            == 422
        )
        assert (
            world.client.post(
                url,
                json={"primary_model_id": str(mid), "declared_tool_ids": [str(uuid4())]},
                headers=world.idem(),
            ).status_code
            == 422
        )

    def test_bound_key_versions_only_its_agent(self, world: World) -> None:
        mine = agent(world)
        other = agent(world)
        mid = model(world, world.a)
        world.add_key("bound-ver", world.a, agent_id=UUID(mine["id"]))
        ok = world.client.post(
            f"/api/v1/agents/{mine['id']}/versions",
            json={"primary_model_id": str(mid)},
            headers=world.idem("bound-ver"),
        )
        assert ok.status_code == 201 and ok.json()["source"] == "sdk"
        denied = world.client.post(
            f"/api/v1/agents/{other['id']}/versions",
            json={"primary_model_id": str(mid)},
            headers=world.idem("bound-ver"),
        )
        assert denied.status_code == 404


class TestBom:
    def test_not_generated_then_generated(self, world: World) -> None:
        mid = model(world, world.a)
        created = agent(world, version={"primary_model_id": str(mid)})
        url = f"/api/v1/agents/{created['id']}/versions/1/bom"
        missing = world.client.get(url, headers=world.headers("viewer"))
        assert missing.status_code == 404
        assert missing.json()["type"].endswith("/bom_not_generated")
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
        world.admin.in_tenant(
            world.a.id,
            "INSERT INTO sibyl.ai_bom (tenant_id, agent_version_id, content, content_sha256,"
            " generator_version) VALUES ($1, $2, $3::jsonb, $4, 'test')",
            world.a.id,
            UUID(created["current_version"]["id"]),
            '{"bomFormat": "CycloneDX", "specVersion": "1.6"}',
            b"\x01" * 32,
        )
        got = world.client.get(url, headers=world.headers("viewer"))
        assert got.status_code == 200 and got.json()["document"] == doc
        assert got.json()["bom_sha256"] == "01" * 32
        raw = world.client.get(
            url, headers=world.headers("viewer", Accept="application/vnd.cyclonedx+json")
        )
        assert raw.headers["content-type"].startswith("application/vnd.cyclonedx+json")
        assert raw.json() == doc
        assert (
            world.client.get(
                f"/api/v1/agents/{created['id']}/versions/9/bom", headers=world.headers("viewer")
            ).status_code
            == 404
        )
