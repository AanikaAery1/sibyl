"""The lane R harness comes up: migrated database, two tenants, the api on a real pool."""

from __future__ import annotations

from sibyl_lane_r_harness import World


def test_world_has_two_tenants_with_keys_and_dev_hosts(world: World) -> None:
    keys = world.admin.fetch(
        "SELECT tenant_id, purpose FROM sibyl.tenant_key WHERE state = 'active'"
    )
    assert {(r["tenant_id"], r["purpose"]) for r in keys} >= {
        (world.a.id, "credential"),
        (world.b.id, "credential"),
    }
    assert world.admin.fetchval("SELECT sibyl.is_allowlisted_base_url('http://sibyl-sim:8300/v1')")


def test_unauthenticated_request_is_401(world: World) -> None:
    assert world.client.get("/api/v1/agents").status_code == 401
