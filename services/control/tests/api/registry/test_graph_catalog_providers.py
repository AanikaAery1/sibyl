"""Dependency edges and blast radius; tools / data sources / processes; providers and models."""

from __future__ import annotations

from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from sibyl_control.api.registry import ssrf
from sibyl_lane_r_harness import World
from sibyl_lane_r_registry import agent, model, outbox_events, provider, unique


def _post(world: World, path: str, body: dict, who: str = "owner"):  # type: ignore[no-untyped-def,type-arg]
    return world.client.post(f"/api/v1{path}", json=body, headers=world.idem(who))


def _patch(world: World, path: str, body: dict, who: str = "owner"):  # type: ignore[no-untyped-def,type-arg]
    etag = world.client.get(f"/api/v1{path}", headers=world.headers(who)).headers["etag"]
    return world.client.patch(
        f"/api/v1{path}", json=body, headers=world.headers(who, **{"If-Match": etag})
    )


class TestGraph:
    def test_edge_lifecycle_and_blast_radius(self, world: World) -> None:
        caller = agent(world, tier=2)
        callee = agent(world, tier=2)
        ds = _post(
            world,
            "/data-sources",
            {"slug": unique("ds"), "name": "CRM", "kind": "database", "classification": "pii"},
        ).json()
        world.audit.clear()
        edge = _post(
            world,
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": caller["id"],
                "dst_kind": "agent",
                "dst_id": callee["id"],
                "edge_type": "delegates_to",
            },
        )
        assert edge.status_code == 201, edge.text
        assert world.audit.actions(world.a.id) == ["asset.updated"]
        dup = _post(
            world,
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": caller["id"],
                "dst_kind": "agent",
                "dst_id": callee["id"],
                "edge_type": "delegates_to",
            },
        )
        assert dup.status_code == 409 and dup.json()["type"].endswith("/edge_exists")
        reads = _post(
            world,
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": callee["id"],
                "dst_kind": "data_source",
                "dst_id": ds["id"],
                "edge_type": "reads_data",
            },
        )
        assert reads.status_code == 201
        radius = world.client.get(
            f"/api/v1/blast-radius/data_source/{ds['id']}", headers=world.headers("viewer")
        ).json()
        assert set(radius["affected_agent_ids"]) == {caller["id"], callee["id"]}
        assert radius["by_depth"]["1"] == [callee["id"]]
        mine = world.client.get(
            f"/api/v1/agents/{callee['id']}/blast-radius", headers=world.headers("viewer")
        ).json()
        assert mine["affected_agent_ids"] == [caller["id"]]
        out = world.client.get(
            f"/api/v1/agents/{callee['id']}/dependencies?direction=out",
            headers=world.headers("viewer"),
        ).json()["data"]
        assert [e["edge_type"] for e in out] == ["reads_data"]
        both = world.client.get(
            f"/api/v1/agents/{callee['id']}/dependencies", headers=world.headers("viewer")
        ).json()["data"]
        assert {e["edge_type"] for e in both} == {"reads_data", "delegates_to"}
        closed = world.client.delete(
            f"/api/v1/dependency-edges/{reads.json()['id']}?reason=retired%20the%20CRM%20link",
            headers=world.headers("owner"),
        )
        assert closed.status_code == 200 and closed.json()["valid_to"] is not None
        assert (
            world.client.delete(
                f"/api/v1/dependency-edges/{reads.json()['id']}?reason=retired%20the%20CRM%20link",
                headers=world.headers("owner"),
            ).status_code
            == 404
        )
        as_of = both[0]["valid_from"]
        history = world.client.get(
            f"/api/v1/agents/{callee['id']}/dependencies",
            params={"as_of": as_of},
            headers=world.headers("viewer"),
        )
        assert history.status_code == 200
        graph_events = world.admin.fetchval(
            "SELECT count(*) FROM sibyl.outbox WHERE tenant_id = $1"
            " AND event_type = 'graph.changed'",
            world.a.id,
        )
        assert graph_events >= 3

    def test_unknown_nodes_and_types(self, world: World) -> None:
        a = agent(world)
        missing = _post(
            world,
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": a["id"],
                "dst_kind": "tool",
                "dst_id": str(uuid4()),
                "edge_type": "calls_tool",
            },
        )
        assert missing.status_code == 422 and missing.json()["type"].endswith("/node_unknown")
        bad = _post(
            world,
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": a["id"],
                "dst_kind": "agent",
                "dst_id": a["id"],
                "edge_type": "likes_to",
            },
        )
        assert bad.status_code == 422
        assert (
            world.client.get(
                f"/api/v1/blast-radius/tool/{uuid4()}", headers=world.headers("viewer")
            ).status_code
            == 404
        )

    def test_group_engineer_edges_only_inside_its_group(self, world: World) -> None:
        inside = agent(world, agent_group_id=str(world.a.group_id))
        outside = agent(world, agent_group_id=str(world.a.other_group_id))
        mid = model(world, world.a)
        ok = _post(
            world,
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": inside["id"],
                "dst_kind": "model",
                "dst_id": str(mid),
                "edge_type": "uses_model",
            },
            "engineer",
        )
        assert ok.status_code == 201
        denied = _post(
            world,
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": inside["id"],
                "dst_kind": "agent",
                "dst_id": outside["id"],
                "edge_type": "delegates_to",
            },
            "engineer",
        )
        assert denied.status_code == 404

    def test_cross_tenant_edge_close_is_404(self, world: World) -> None:
        a = agent(world)
        b = agent(world)
        edge = _post(
            world,
            "/dependency-edges",
            {
                "src_kind": "agent",
                "src_id": a["id"],
                "dst_kind": "agent",
                "dst_id": b["id"],
                "edge_type": "delegates_to",
            },
        ).json()
        assert (
            world.client.delete(
                f"/api/v1/dependency-edges/{edge['id']}?reason=not%20your%20tenant%20edge",
                headers=world.headers("owner-b"),
            ).status_code
            == 404
        )


class TestCatalogs:
    @pytest.mark.parametrize(
        ("path", "body", "patch"),
        [
            (
                "/tools",
                {"kind": "function", "permissions": ["read"]},
                {"endpoint": "https://t.example.com"},
            ),
            (
                "/data-sources",
                {"kind": "vector_index", "attrs": {"index": "docs"}},
                {"classification": "restricted"},
            ),
            ("/business-processes", {"criticality": "high"}, {"criticality": "critical"}),
        ],
    )
    def test_crud(self, world: World, path: str, body: dict, patch: dict) -> None:  # type: ignore[type-arg]
        slug = unique("cat")
        world.audit.clear()
        created = _post(world, path, {"slug": slug, "name": "Thing", **body})
        assert created.status_code == 201, created.text
        item = f"{path}/{created.json()['id']}"
        assert (
            world.client.get(f"/api/v1{item}", headers=world.headers("viewer")).status_code == 200
        )
        updated = _patch(world, item, patch)
        assert updated.status_code == 200, updated.text
        for key, value in patch.items():
            assert updated.json()[key] == value
        assert world.audit.actions(world.a.id) == ["config.changed", "config.changed"]
        dup = _post(world, path, {"slug": slug, "name": "Thing", **body})
        assert dup.status_code == 409 and dup.json()["type"].endswith("/slug_exists")
        listed = world.client.get(f"/api/v1{path}?q={slug}", headers=world.headers("viewer"))
        assert [i["slug"] for i in listed.json()["data"]] == [slug]
        assert (
            world.client.get(f"/api/v1{item}", headers=world.headers("owner-b")).status_code == 404
        )
        assert (
            _post(world, path, {"slug": unique("x"), "name": "x", **body}, "engineer").status_code
            == 403
        )

    def test_audit_detail_never_carries_free_form_json(self, world: World) -> None:
        world.audit.clear()
        _post(
            world,
            "/data-sources",
            {
                "slug": unique("ds"),
                "name": "Docs",
                "kind": "api",
                "attrs": {"content": "should never be audited"},
            },
        )
        detail = world.audit.rows[world.a.id][-1].detail
        assert str(detail["after"]["attrs"]).startswith("sha256:")

    def test_approving_a_tool_needs_agents_approve(self, world: World) -> None:
        body = {
            "slug": unique("tool"),
            "name": "Shell",
            "kind": "code_interpreter",
            "is_approved": True,
        }
        assert _post(world, "/tools", body, "engineer").status_code == 403
        created = _post(world, "/tools", {**body, "is_approved": False}, "owner").json()
        assert created["is_approved"] is False
        assert (
            _patch(world, f"/tools/{created['id']}", {"is_approved": True}, "admin").status_code
            == 200
        )

    def test_mcp_tool_needs_a_parent(self, world: World) -> None:
        resp = _post(world, "/tools", {"slug": unique("mcp"), "name": "x", "kind": "mcp_tool"})
        assert resp.status_code == 422


@pytest.fixture
def public_dns() -> Iterator[None]:
    async def resolver(host: str, port: int) -> list[str]:
        return {"llm.example.com": ["93.184.216.34"], "evil.example.com": ["10.0.0.5"]}.get(
            host, []
        )

    ssrf.set_resolver(resolver)
    yield
    ssrf.set_resolver(None)


class TestProviders:
    def test_create_known_and_resolver_checked(self, world: World, public_dns: None) -> None:
        world.audit.clear()
        known = _post(
            world,
            "/providers",
            {
                "slug": unique("oai"),
                "name": "OpenAI",
                "provider_kind": "openai",
                "dialect": "openai_compatible",
                "base_url": "https://api.openai.com/v1",
            },
        )
        assert known.status_code == 201, known.text
        assert known.json()["allowlist_basis"] == "known_provider"
        checked = _post(
            world,
            "/providers",
            {
                "slug": unique("own"),
                "name": "Own",
                "provider_kind": "custom",
                "dialect": "openai_compatible",
                "base_url": "https://llm.example.com/v1",
            },
        )
        assert checked.json()["allowlist_basis"] == "resolver_checked"
        sim = _post(
            world,
            "/providers",
            {
                "slug": unique("sim"),
                "name": "Sim",
                "provider_kind": "ollama",
                "dialect": "openai_compatible",
                "base_url": "http://sibyl-sim:8300/ollama/v1",
            },
        )
        assert sim.status_code == 201
        assert world.audit.actions(world.a.id) == ["config.changed"] * 3
        assert "policy_changed" in outbox_events(world, world.a, known.json()["id"])

    @pytest.mark.parametrize(
        "url",
        [
            "http://api.openai.com/v1",
            "https://10.0.0.1/v1",
            "https://localhost/v1",
            "https://evil.example.com/v1",
            "https://nxdomain.example.com/v1",
            "https://user@api.openai.com/v1",
        ],
    )
    def test_ssrf_refusals(self, world: World, public_dns: None, url: str) -> None:
        resp = _post(
            world,
            "/providers",
            {
                "slug": unique("bad"),
                "name": "Bad",
                "provider_kind": "custom",
                "dialect": "openai_compatible",
                "base_url": url,
            },
        )
        assert resp.status_code == 422
        assert resp.json()["type"].endswith("/base_url_not_allowlisted")

    def test_update_and_in_use(self, world: World, public_dns: None) -> None:
        """There is no single-provider GET: the ETag comes from create/update responses."""
        created = _post(
            world,
            "/providers",
            {
                "slug": unique("upd"),
                "name": "Upd",
                "provider_kind": "openai",
                "dialect": "openai_compatible",
                "base_url": "https://api.openai.com/v1",
            },
        )
        pid = created.json()["id"]
        etag = created.headers["etag"]
        mid = model(world, world.a, UUID(pid))
        live = agent(world, tier=2, version={"primary_model_id": str(mid)})
        world.admin.execute(
            "UPDATE sibyl.agent SET lifecycle = 'approved' WHERE tenant_id = $1 AND id = $2",
            world.a.id,
            UUID(live["id"]),
        )

        def patch(body: dict, tag: str, who: str = "owner"):  # type: ignore[no-untyped-def,type-arg]
            return world.client.patch(
                f"/api/v1/providers/{pid}",
                json=body,
                headers=world.headers(who, **{"If-Match": tag}),
            )

        in_use = patch({"is_enabled": False}, etag)
        assert in_use.status_code == 409 and in_use.json()["type"].endswith("/provider_in_use")
        assert patch({"name": "x"}, etag, "engineer").status_code == 403
        renamed = patch({"name": "Renamed", "base_url": "https://llm.example.com/v2"}, etag)
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["allowlist_basis"] == "resolver_checked"
        assert patch({"name": "again"}, etag).status_code == 412
        bad = patch({"base_url": "https://evil.example.com/v1"}, renamed.headers["etag"])
        assert bad.status_code == 422

    def test_status_history_and_list(self, world: World) -> None:
        pid = provider(world, world.a)
        for status in ("operational", "major_outage"):
            world.admin.execute(
                "INSERT INTO sibyl.provider_status (tenant_id, provider_id, source, status,"
                " observed_at) VALUES ($1, $2, 'status_feed', $3,"
                " now() - ($4 || ' min')::interval)",
                world.a.id,
                pid,
                status,
                "5" if status == "operational" else "1",
            )
        hist = world.client.get(f"/api/v1/providers/{pid}/status", headers=world.headers("viewer"))
        assert [s["status"] for s in hist.json()["data"]] == ["major_outage", "operational"]
        listed = world.client.get("/api/v1/providers?limit=200", headers=world.headers("viewer"))
        mine = next(p for p in listed.json()["data"] if p["id"] == str(pid))
        assert mine["latest_status"]["status"] == "major_outage"
        assert (
            world.client.get(
                f"/api/v1/providers/{pid}/status", headers=world.headers("owner-b")
            ).status_code
            == 404
        )


class TestModels:
    def test_create_patch_list_and_catalog(self, world: World) -> None:
        pid = provider(world, world.a)
        catalog = world.client.get(
            "/api/v1/model-catalog?provider_kind=openai&limit=1", headers=world.headers("viewer")
        ).json()["data"]
        body: dict = {
            "provider_id": str(pid),
            "model_name": unique("m"),  # type: ignore[type-arg]
            "input_usd_per_1m": "1.5000",
        }
        if catalog:
            body["catalog_id"] = catalog[0]["catalog_id"]
        created = _post(world, "/models", body)
        assert created.status_code == 201, created.text
        assert created.json()["input_usd_per_1m"] == "1.5000"
        dup = _post(world, "/models", body)
        assert dup.status_code == 409 and dup.json()["type"].endswith("/model_exists")
        mid = created.json()["id"]
        etag = created.headers["etag"]
        patched = world.client.patch(
            f"/api/v1/models/{mid}",
            json={"is_allowed": False, "output_usd_per_1m": "9.0000"},
            headers=world.headers("owner", **{"If-Match": etag}),
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["is_allowed"] is False
        listed = world.client.get(
            f"/api/v1/models?provider_id={pid}&is_allowed=false", headers=world.headers("viewer")
        ).json()["data"]
        assert [m["id"] for m in listed] == [mid]
        unknown = _post(world, "/models", {"provider_id": str(uuid4()), "model_name": "x"})
        assert unknown.status_code == 422
        stale = world.client.patch(
            f"/api/v1/models/{mid}",
            json={"is_allowed": True},
            headers=world.headers("owner", **{"If-Match": etag}),
        )
        assert stale.status_code == 412
