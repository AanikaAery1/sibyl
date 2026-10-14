"""INT-1 contract additions for the registry module: ``getProvider`` (ETag), the explicit
``tenant_wide`` object rule on catalog / provider / model writes, and an optional body
``reason`` (or ``X-Sibyl-Reason``) that lands on the ``config.changed`` audit row."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

import pytest
from sibyl_control.api.contract import operation
from sibyl_lane_r_harness import World
from sibyl_lane_r_registry import provider, unique

OPENAI = {
    "provider_kind": "openai",
    "dialect": "openai_compatible",
    "base_url": "https://api.openai.com/v1",
}


def _reasons(world: World) -> list[str | None]:
    return [r.reason for r in world.audit.rows.get(world.a.id, [])]


def _new_model(world: World) -> tuple[str, str]:
    created = world.client.post(
        "/api/v1/models",
        json={"provider_id": str(provider(world, world.a)), "model_name": unique("m")},
        headers=world.idem("owner"),
    )
    assert created.status_code == 201, created.text
    return created.json()["id"], created.headers["etag"]


class TestGetProvider:
    def test_one_provider_with_etag_and_conditional_get(self, world: World) -> None:
        pid = provider(world, world.a)
        resp = world.client.get(f"/api/v1/providers/{pid}", headers=world.headers("viewer"))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == str(pid) and body["provider_kind"] == "openai"
        etag = resp.headers["etag"]
        again = world.client.get(
            f"/api/v1/providers/{pid}", headers=world.headers("viewer", **{"If-None-Match": etag})
        )
        assert again.status_code == 304

    def test_its_etag_feeds_if_match(self, world: World) -> None:
        pid = provider(world, world.a)
        got = world.client.get(f"/api/v1/providers/{pid}", headers=world.headers("owner"))
        patched = world.client.patch(
            f"/api/v1/providers/{pid}",
            json={"name": "Renamed"},
            headers=world.headers("owner", **{"If-Match": got.headers["etag"]}),
        )
        assert patched.status_code == 200, patched.text
        assert patched.headers["etag"] != got.headers["etag"]

    def test_missing_and_foreign_providers_are_404(self, world: World) -> None:
        foreign = provider(world, world.b)
        for pid in (foreign, uuid4()):
            resp = world.client.get(f"/api/v1/providers/{pid}", headers=world.headers("owner"))
            assert resp.status_code == 404, resp.text

    def test_is_unaudited(self, world: World) -> None:
        pid = provider(world, world.a)
        world.audit.clear()
        world.client.get(f"/api/v1/providers/{pid}", headers=world.headers("owner"))
        assert world.audit.actions(world.a.id) == []


TENANT_WIDE_CREATES: list[tuple[str, Callable[[World], dict[str, Any]]]] = [
    ("/tools", lambda w: {"slug": unique("t"), "name": "T", "kind": "function"}),
    ("/data-sources", lambda w: {"slug": unique("d"), "name": "D", "kind": "database"}),
    ("/business-processes", lambda w: {"slug": unique("b"), "name": "B"}),
    ("/providers", lambda w: {"slug": unique("p"), "name": "P", **OPENAI}),
    ("/models", lambda w: {"provider_id": str(provider(w, w.a)), "model_name": unique("m")}),
]
_IDS = [path.strip("/") for path, _ in TENANT_WIDE_CREATES]


class TestTenantWideRule:
    @pytest.mark.parametrize(
        "op_id",
        [
            "createTool",
            "updateTool",
            "createDataSource",
            "updateDataSource",
            "createBusinessProcess",
            "updateBusinessProcess",
            "createProvider",
            "updateProvider",
            "createModel",
            "updateModel",
        ],
    )
    def test_the_contract_declares_it(self, op_id: str) -> None:
        assert "tenant_wide" in operation(op_id).object_rules

    @pytest.mark.parametrize(("path", "body"), TENANT_WIDE_CREATES, ids=_IDS)
    def test_a_group_limited_engineer_is_refused(
        self, world: World, path: str, body: Callable[[World], dict[str, Any]]
    ) -> None:
        payload = body(world)
        world.audit.clear()
        resp = world.client.post(f"/api/v1{path}", json=payload, headers=world.idem("engineer"))
        assert resp.status_code == 403, resp.text
        assert resp.json()["type"].endswith("/forbidden")
        assert world.audit.actions(world.a.id) == ["access.denied"]

    @pytest.mark.parametrize(("path", "body"), TENANT_WIDE_CREATES, ids=_IDS)
    def test_a_tenant_wide_owner_passes(
        self, world: World, path: str, body: Callable[[World], dict[str, Any]]
    ) -> None:
        resp = world.client.post(f"/api/v1{path}", json=body(world), headers=world.idem("owner"))
        assert resp.status_code == 201, resp.text

    def test_a_patch_by_a_group_limited_engineer_is_refused(self, world: World) -> None:
        mid, etag = _new_model(world)
        resp = world.client.patch(
            f"/api/v1/models/{mid}",
            json={"is_allowed": False},
            headers=world.headers("engineer", **{"If-Match": etag}),
        )
        assert resp.status_code == 403, resp.text


class TestReason:
    def test_body_reason_lands_on_the_audit_row(self, world: World) -> None:
        world.audit.clear()
        resp = world.client.post(
            "/api/v1/tools",
            json={
                "slug": unique("t"),
                "name": "T",
                "kind": "function",
                "reason": "CAB-1234 approved the search tool",
            },
            headers=world.idem("owner"),
        )
        assert resp.status_code == 201, resp.text
        assert "reason" not in resp.json()
        assert _reasons(world) == ["CAB-1234 approved the search tool"]

    def test_header_reason_is_used_without_a_body_reason(self, world: World) -> None:
        world.audit.clear()
        resp = world.client.post(
            "/api/v1/providers",
            json={"slug": unique("p"), "name": "P", **OPENAI},
            headers=world.idem("owner", **{"X-Sibyl-Reason": "onboarding the second vendor"}),
        )
        assert resp.status_code == 201, resp.text
        assert _reasons(world) == ["onboarding the second vendor"]

    def test_without_any_reason_the_route_label_is_used(self, world: World) -> None:
        world.audit.clear()
        resp = world.client.post(
            "/api/v1/business-processes",
            json={"slug": unique("b"), "name": "B"},
            headers=world.idem("owner"),
        )
        assert resp.status_code == 201, resp.text
        assert _reasons(world) == ["via api: createBusinessProcess"]

    def test_body_reason_wins_over_the_header(self, world: World) -> None:
        pid = provider(world, world.a)
        got = world.client.get(f"/api/v1/providers/{pid}", headers=world.headers("owner"))
        world.audit.clear()
        resp = world.client.patch(
            f"/api/v1/providers/{pid}",
            json={"name": "Renamed", "reason": "vendor renamed their product"},
            headers=world.headers(
                "owner",
                **{"If-Match": got.headers["etag"], "X-Sibyl-Reason": "the header loses here"},
            ),
        )
        assert resp.status_code == 200, resp.text
        assert _reasons(world) == ["vendor renamed their product"]

    def test_a_model_patch_carries_its_reason(self, world: World) -> None:
        mid, etag = _new_model(world)
        world.audit.clear()
        resp = world.client.patch(
            f"/api/v1/models/{mid}",
            json={"is_allowed": False, "reason": "model failed the red-team review"},
            headers=world.headers("owner", **{"If-Match": etag}),
        )
        assert resp.status_code == 200, resp.text
        assert _reasons(world) == ["model failed the red-team review"]

    def test_a_patch_with_only_a_reason_is_422(self, world: World) -> None:
        mid, etag = _new_model(world)
        resp = world.client.patch(
            f"/api/v1/models/{mid}",
            json={"reason": "nothing else changes here"},
            headers=world.headers("owner", **{"If-Match": etag}),
        )
        assert resp.status_code == 422, resp.text

    def test_a_short_reason_is_422(self, world: World) -> None:
        resp = world.client.post(
            "/api/v1/tools",
            json={"slug": unique("t"), "name": "T", "kind": "function", "reason": "short"},
            headers=world.idem("owner"),
        )
        assert resp.status_code == 422
