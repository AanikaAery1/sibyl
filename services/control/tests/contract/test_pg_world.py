"""The shared contract world itself: real sessions and real keys resolve, tenants are distinct."""

from __future__ import annotations

from .pg_world import ContractWorld


def test_sessions_and_keys_resolve(cworld: ContractWorld) -> None:
    me = cworld.client.get("/api/v1/auth/me", headers=cworld.headers("owner"))
    assert me.status_code == 200, me.text
    other = cworld.client.get("/api/v1/auth/me", headers=cworld.headers("owner-b"))
    assert other.status_code == 200 and other.json() != me.json()
    agent = cworld.a.agents["bound"]
    own = cworld.client.get(f"/api/v1/agents/{agent}/routing", headers=cworld.headers("bound"))
    assert own.status_code == 200, own.text
    tenant_key = cworld.client.get(
        f"/api/v1/agents/{agent}/routing", headers=cworld.headers("keys")
    )
    assert tenant_key.status_code == 200, tenant_key.text
