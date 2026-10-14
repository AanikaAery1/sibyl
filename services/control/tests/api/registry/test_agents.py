"""Agents: register, read, list, patch, claim (handlers against a migrated PG17)."""

from __future__ import annotations

from uuid import UUID, uuid4

from sibyl_control.core.audit import RECEIPT_HEADER
from sibyl_lane_r_harness import World
from sibyl_lane_r_registry import agent, bound_key_row, model, outbox_events, register, unique


def _type(resp) -> str:  # type: ignore[no-untyped-def]
    return str(resp.json().get("type", ""))


class TestRegister:
    def test_register_writes_agent_version_identity_routing_and_lifecycle(
        self, world: World
    ) -> None:
        world.audit.clear()
        model_id = model(world, world.a)
        status, body, headers = register(
            world, tier=2, version={"primary_model_id": str(model_id)}, tags=["billing"]
        )
        assert status == 201, body
        assert body["lifecycle"] == "proposed"
        assert body["tier"] == 2 and body["fail_mode"] == "closed"
        assert body["routing"]["state"] == "active"
        assert body["current_version"]["version_no"] == 1
        assert body["identity"]["identity_version"] == 1
        assert headers["etag"].startswith('"')
        assert headers[RECEIPT_HEADER.lower()].startswith(f"{world.a.id}:")
        assert world.audit.actions(world.a.id) == ["asset.created"]
        agent_id = UUID(body["id"])
        lt = world.admin.fetchrow(
            "SELECT from_stage, to_stage, audit_seq FROM sibyl.lifecycle_transition"
            " WHERE tenant_id = $1 AND agent_id = $2",
            world.a.id,
            agent_id,
        )
        assert lt is not None and lt["from_stage"] is None and lt["to_stage"] == "proposed"
        seq = int(headers[RECEIPT_HEADER.lower()].split(":")[1])
        assert lt["audit_seq"] == seq
        rs = world.admin.fetchrow(
            "SELECT state FROM sibyl.routing_state WHERE tenant_id = $1 AND agent_id = $2",
            world.a.id,
            agent_id,
        )
        assert rs is not None and rs["state"] == "active"
        assert "policy_changed" in outbox_events(world, world.a, agent_id)

    def test_replay_returns_the_stored_response(self, world: World) -> None:
        headers = world.idem("owner")
        body = {"slug": unique("replay"), "name": "R", "kind": "chatbot", "fail_mode": "open"}
        first = world.client.post("/api/v1/agents", json=body, headers=headers)
        second = world.client.post("/api/v1/agents", json=body, headers=headers)
        assert first.status_code == 201 and second.status_code == 201
        assert second.headers["idempotency-replayed"] == "true"
        assert second.json()["id"] == first.json()["id"]
        assert second.headers[RECEIPT_HEADER] == first.headers[RECEIPT_HEADER]
        changed = world.client.post(
            "/api/v1/agents", json={**body, "name": "other"}, headers=headers
        )
        assert changed.status_code == 422
        assert _type(changed).endswith("/idempotency_key_reuse")

    def test_idempotency_key_is_required(self, world: World) -> None:
        resp = world.client.post(
            "/api/v1/agents",
            json={"slug": unique("x"), "name": "x", "kind": "chatbot", "fail_mode": "open"},
            headers=world.headers("owner"),
        )
        assert resp.status_code == 428

    def test_duplicate_slug_is_409(self, world: World) -> None:
        first = agent(world)
        status, body, _ = register(world, slug=first["slug"])
        assert status == 409 and body["type"].endswith("/slug_exists")

    def test_fail_mode_is_required(self, world: World) -> None:
        resp = world.client.post(
            "/api/v1/agents",
            json={"slug": unique("x"), "name": "x", "kind": "chatbot"},
            headers=world.idem(),
        )
        assert resp.status_code == 422

    def test_unknown_model_in_version_is_422(self, world: World) -> None:
        status, _, _ = register(world, version={"primary_model_id": str(uuid4())})
        assert status == 422

    def test_group_engineer_registers_only_into_its_group(self, world: World) -> None:
        status, _, _ = register(world, "engineer", agent_group_id=str(world.a.group_id))
        assert status == 201
        status, _, _ = register(world, "engineer", agent_group_id=str(world.a.other_group_id))
        assert status == 404
        status, _, _ = register(world, "engineer")
        assert status == 404

    def test_viewer_is_forbidden_and_audited(self, world: World) -> None:
        world.audit.clear()
        status, _, _ = register(world, "viewer")
        assert status == 403
        assert "access.denied" in world.audit.actions(world.a.id)

    def test_tenant_key_registers_as_api_key_actor(self, world: World) -> None:
        key_id = world.add_key("tenant-key", world.a)
        status, body, _ = register(world, "tenant-key")
        assert status == 201, body
        row = world.admin.fetchrow(
            "SELECT actor_type, actor_key_id FROM sibyl.audit_events WHERE tenant_id = $1"
            " AND action = 'asset.created' AND resource_id = $2",
            world.a.id,
            UUID(body["id"]),
        )
        assert row is not None and row["actor_type"] == "api_key" and row["actor_key_id"] == key_id

    def test_bound_key_cannot_register_another_agent(self, world: World) -> None:
        own = agent(world)
        world.add_key("bound-reg", world.a, agent_id=UUID(own["id"]))
        status, _, _ = register(world, "bound-reg")
        assert status == 403


class TestRead:
    def test_get_and_cross_tenant_404(self, world: World) -> None:
        created = agent(world)
        resp = world.client.get(f"/api/v1/agents/{created['id']}", headers=world.headers("owner"))
        assert resp.status_code == 200 and resp.json()["slug"] == created["slug"]
        assert resp.headers["etag"]
        other = world.client.get(
            f"/api/v1/agents/{created['id']}", headers=world.headers("owner-b")
        )
        assert other.status_code == 404

    def test_if_none_match_gives_304(self, world: World) -> None:
        created = agent(world)
        url = f"/api/v1/agents/{created['id']}"
        etag = world.client.get(url, headers=world.headers("owner")).headers["etag"]
        resp = world.client.get(url, headers=world.headers("owner", **{"If-None-Match": etag}))
        assert resp.status_code == 304

    def test_engineer_reads_tenant_wide_but_writes_only_in_its_group(self, world: World) -> None:
        """agents:read is tenant-wide for engineers (API.md §2.2); agents:write is G."""
        outside = agent(world, agent_group_id=str(world.a.other_group_id))
        url = f"/api/v1/agents/{outside['id']}"
        read = world.client.get(url, headers=world.headers("engineer"))
        assert read.status_code == 200
        world.audit.clear()
        write = world.client.patch(
            url,
            json={"name": "x"},
            headers=world.headers("engineer", **{"If-Match": read.headers["etag"]}),
        )
        assert write.status_code == 404
        assert world.audit.actions(world.a.id) == ["access.denied"]

    def test_bound_key_sees_only_its_agent(self, world: World) -> None:
        mine = agent(world)
        other = agent(world)
        world.add_key("bound-read", world.a, agent_id=UUID(mine["id"]))
        listed = world.client.get("/api/v1/agents", headers=world.headers("bound-read"))
        assert [a["id"] for a in listed.json()["data"]] == [mine["id"]]
        assert (
            world.client.get(
                f"/api/v1/agents/{other['id']}", headers=world.headers("bound-read")
            ).status_code
            == 404
        )

    def test_list_filters_and_pages(self, world: World) -> None:
        tag = unique("pg")
        for i in range(3):
            agent(world, slug=f"{tag}-{i}", tier=1, fail_mode="open")
        first = world.client.get(
            f"/api/v1/agents?q={tag}&tier=1&limit=2", headers=world.headers("owner")
        )
        page = first.json()
        assert first.status_code == 200 and len(page["data"]) == 2 and page["has_more"]
        assert 'rel="next"' in first.headers["link"]
        second = world.client.get(
            f"/api/v1/agents?q={tag}&tier=1&limit=2&cursor={page['next_cursor']}",
            headers=world.headers("owner"),
        ).json()
        assert len(second["data"]) == 1 and not second["has_more"]
        mismatch = world.client.get(
            f"/api/v1/agents?q={tag}&tier=2&limit=2&cursor={page['next_cursor']}",
            headers=world.headers("owner"),
        )
        assert mismatch.status_code == 400
        assert all(a["tier"] == 1 for a in page["data"] + second["data"])

    def test_list_limit_above_max_is_rejected(self, world: World) -> None:
        resp = world.client.get("/api/v1/agents?limit=500", headers=world.headers("owner"))
        assert resp.status_code in (400, 422)


class TestPatch:
    def test_if_match_is_required_and_checked(self, world: World) -> None:
        created = agent(world)
        url = f"/api/v1/agents/{created['id']}"
        assert (
            world.client.patch(url, json={"name": "n"}, headers=world.headers("owner")).status_code
            == 428
        )
        stale = world.client.patch(
            url, json={"name": "n"}, headers=world.headers("owner", **{"If-Match": '"nope"'})
        )
        assert stale.status_code == 412 and stale.json()["current"]["id"] == created["id"]

    def test_patch_updates_audits_and_bumps_snapshot_on_fail_mode(self, world: World) -> None:
        created = agent(world)
        url = f"/api/v1/agents/{created['id']}"
        etag = world.client.get(url, headers=world.headers("owner")).headers["etag"]
        world.audit.clear()
        resp = world.client.patch(
            url,
            json={"name": "Renamed", "fail_mode": "open"},
            headers=world.headers("owner", **{"If-Match": etag}),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "Renamed" and resp.headers["etag"] != etag
        assert world.audit.actions(world.a.id) == ["asset.updated"]
        detail = world.audit.rows[world.a.id][-1].detail
        assert sorted(detail["fields_changed"]) == ["fail_mode", "name"]  # frozen tuple
        assert outbox_events(world, world.a, created["id"]).count("policy_changed") >= 2

    def test_tier_change_needs_agents_approve(self, world: World) -> None:
        created = agent(world, agent_group_id=str(world.a.group_id))
        url = f"/api/v1/agents/{created['id']}"
        etag = world.client.get(url, headers=world.headers("engineer")).headers["etag"]
        resp = world.client.patch(
            url, json={"tier": 1}, headers=world.headers("engineer", **{"If-Match": etag})
        )
        assert resp.status_code == 403
        ok = world.client.patch(
            url, json={"name": "fine"}, headers=world.headers("engineer", **{"If-Match": etag})
        )
        assert ok.status_code == 200

    def test_engineer_cannot_move_agent_out_of_its_group(self, world: World) -> None:
        created = agent(world, agent_group_id=str(world.a.group_id))
        url = f"/api/v1/agents/{created['id']}"
        etag = world.client.get(url, headers=world.headers("engineer")).headers["etag"]
        resp = world.client.patch(
            url,
            json={"agent_group_id": str(world.a.other_group_id)},
            headers=world.headers("engineer", **{"If-Match": etag}),
        )
        assert resp.status_code == 404


class TestClaim:
    def test_claim_provisional_agent(self, world: World) -> None:
        agent_id = uuid4()
        trace = uuid4()
        world.admin.execute(
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, is_provisional, lifecycle,"
            " discovered_via, first_trace_id)"
            " VALUES ($1, $2, $3, 'unclaimed', 'chatbot', true, 'discovered', 'run_tree', $4)",
            world.a.id,
            agent_id,
            "unclaimed/" + uuid4().hex[:8],
            trace,
        )
        url = f"/api/v1/agents/{agent_id}/claim"
        before = world.client.get(f"/api/v1/agents/{agent_id}", headers=world.headers("viewer"))
        assert before.json()["confirmed_at"] is None and before.json()["is_provisional"]
        resp = world.client.post(url, headers=world.idem())
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["is_provisional"] is False and body["confirmed_at"] is not None
        assert body["discovered_via"] == "run_tree" and body["first_trace_id"] == trace.hex
        listed = world.client.get("/api/v1/agents?limit=200", headers=world.headers("viewer"))
        row = next(a for a in listed.json()["data"] if a["id"] == str(agent_id))
        assert row["discovered_via"] == "run_tree" and row["confirmed_at"] == body["confirmed_at"]
        registered = agent(world)
        assert registered["discovered_via"] is None and registered["first_trace_id"] is None
        assert registered["confirmed_at"] is None
        again = world.client.post(url, headers=world.idem())
        assert again.status_code == 409 and _type(again).endswith("/not_provisional")


class TestLifecycle:
    def _move(self, world: World, agent_id: str, to: str, who: str = "owner"):  # type: ignore[no-untyped-def]
        return world.client.post(
            f"/api/v1/agents/{agent_id}/lifecycle",
            json={"to_stage": to, "reason": "change approved in review"},
            headers=world.idem(who),
        )

    def test_approve_deploy_retire_with_history(self, world: World) -> None:
        created = agent(world, tier=2)
        world.audit.clear()
        assert self._move(world, created["id"], "approved").status_code == 200
        assert self._move(world, created["id"], "deployed").status_code == 200
        assert self._move(world, created["id"], "retired").status_code == 200
        assert world.audit.actions(world.a.id) == [
            "asset.approved",
            "asset.approved",
            "asset.retired",
        ]
        view = world.client.get(
            f"/api/v1/agents/{created['id']}/lifecycle", headers=world.headers("viewer")
        ).json()
        assert view["lifecycle"] == "retired"
        assert [t["to_stage"] for t in view["transitions"]] == [
            "proposed",
            "approved",
            "deployed",
            "retired",
        ]

    def test_invalid_transition_is_409(self, world: World) -> None:
        created = agent(world)
        resp = self._move(world, created["id"], "deployed")
        assert resp.status_code == 409 and _type(resp).endswith("/invalid_transition")

    def test_tier1_needs_a_bound_key_to_leave_proposed(self, world: World) -> None:
        created = agent(world, tier=1)
        resp = self._move(world, created["id"], "approved")
        assert resp.status_code == 409 and _type(resp).endswith("/tier1_requires_bound_key")
        bound_key_row(world, world.a, UUID(created["id"]))
        assert self._move(world, created["id"], "approved").status_code == 200

    def test_engineer_cannot_approve(self, world: World) -> None:
        created = agent(world, agent_group_id=str(world.a.group_id))
        assert self._move(world, created["id"], "approved", "engineer").status_code == 403

    def test_retire_closes_open_edges(self, world: World) -> None:
        created = agent(world)
        mid = model(world, world.a)
        world.admin.in_tenant(
            world.a.id,
            "INSERT INTO sibyl.dependency_edge (tenant_id, src_kind, src_id, dst_kind, dst_id,"
            " edge_type, origin) VALUES ($1, 'agent', $2, 'model', $3, 'uses_model', 'declared')",
            world.a.id,
            UUID(created["id"]),
            mid,
        )
        self._move(world, created["id"], "retired")
        open_edges = world.admin.fetchval(
            "SELECT count(*) FROM sibyl.dependency_edge WHERE tenant_id = $1 AND src_id = $2"
            " AND valid_to IS NULL",
            world.a.id,
            UUID(created["id"]),
        )
        assert open_edges == 0
