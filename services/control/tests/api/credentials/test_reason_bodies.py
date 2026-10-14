"""Optional body ``reason`` on provider-credential create and rotate (INT-1)."""

from __future__ import annotations

from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from sibyl_control.api.registry import ssrf
from sibyl_lane_r_harness import World

BASE = "/api/v1/provider-credentials"


@pytest.fixture
def no_dns() -> Iterator[None]:
    async def refuse(host: str, port: int) -> list[str]:
        raise AssertionError(f"unexpected DNS lookup of {host}")

    ssrf.set_resolver(refuse)
    yield
    ssrf.set_resolver(None)


def _provider(world: World) -> UUID:
    pid: UUID = world.admin.fetchval(
        "INSERT INTO sibyl.provider (tenant_id, slug, name, provider_kind, dialect, base_url)"
        " VALUES ($1, $2, $2, 'openai', 'openai_compatible', 'https://api.openai.com/v1')"
        " RETURNING id",
        world.a.id,
        f"p-{uuid4().hex[:10]}",
    )
    return pid


def _reasons(world: World) -> list[str | None]:
    return [r.reason for r in world.audit.rows.get(world.a.id, [])]


def test_create_and_rotate_record_the_body_reason(world: World, no_dns: None) -> None:
    world.audit.clear()
    created = world.client.post(
        BASE,
        json={
            "provider_id": str(_provider(world)),
            "name": "fallback key",
            "base_url": "http://sibyl-sim:8300/openai/v1",
            "auth_scheme": "bearer",
            "secret": "sk-test-0123456789abcdefSECRETtail",
            "reason": "vaulted fallback for the claims agent",
        },
        headers=world.idem("owner", **{"X-Sibyl-Reason": "the header loses here"}),
    )
    assert created.status_code == 201, created.text
    assert "reason" not in created.json()
    rotated = world.client.post(
        f"{BASE}/{created.json()['id']}/rotate",
        json={"secret": "sk-test-rotated-0123456789abcdef", "reason": "vendor forced a rotation"},
        headers=world.idem("owner"),
    )
    assert rotated.status_code == 201, rotated.text
    assert _reasons(world) == [
        "vaulted fallback for the claims agent",
        "vendor forced a rotation",
    ]


def test_header_reason_without_a_body_reason(world: World, no_dns: None) -> None:
    world.audit.clear()
    created = world.client.post(
        BASE,
        json={
            "provider_id": str(_provider(world)),
            "name": "fallback key",
            "base_url": "http://sibyl-sim:8300/openai/v1",
            "auth_scheme": "bearer",
            "secret": "sk-test-0123456789abcdefSECRETtail",
        },
        headers=world.idem("owner", **{"X-Sibyl-Reason": "set up during the DR drill"}),
    )
    assert created.status_code == 201, created.text
    assert _reasons(world) == ["set up during the DR drill"]
