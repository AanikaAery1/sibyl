"""Optional body ``reason`` on API-key create and rotate (INT-1): it lands on the audit row and
wins over ``X-Sibyl-Reason``; it is never echoed in the response."""

from __future__ import annotations

from typing import Any

import pytest
import sibyl_lane_a_kit as kit  # loaded by conftest

API = "/api/v1"


@pytest.fixture
def ready(lane: Any, world: Any) -> Any:
    kit.add_capture_policy(lane.db, world.tenant, world.users["owner"])
    return world


def _last_reason(lane: Any, world: Any, action: str) -> str:
    return str(kit.audit_rows(lane.db, world.tenant, action)[-1]["reason"])


def test_create_and_rotate_record_the_body_reason(lane: Any, ready: Any) -> None:
    token = kit.add_session(lane.db, ready.tenant, ready.users["admin"])
    created = lane.client.post(
        f"{API}/api-keys",
        json={
            "name": "gateway",
            "env": "test",
            "scopes": ["gateway:proxy", "routing:read"],
            "reason": "gateway for the claims pilot",
        },
        headers=lane.bearer(token, **kit.idem(), **{"X-Sibyl-Reason": "the header loses"}),
    )
    assert created.status_code == 201, created.text
    assert "reason" not in created.json()
    assert _last_reason(lane, ready, "api_key.created") == "gateway for the claims pilot"
    rotated = lane.client.post(
        f"{API}/api-keys/{created.json()['id']}/rotate",
        json={"grace_s": 60, "reason": "quarterly rotation, CHG-7781"},
        headers=lane.bearer(token, **kit.idem()),
    )
    assert rotated.status_code == 201, rotated.text
    assert _last_reason(lane, ready, "api_key.rotated") == "quarterly rotation, CHG-7781"


def test_a_short_reason_is_422(lane: Any, ready: Any) -> None:
    token = kit.add_session(lane.db, ready.tenant, ready.users["admin"])
    resp = lane.client.post(
        f"{API}/api-keys",
        json={"name": "g", "env": "test", "scopes": ["routing:read"], "reason": "short"},
        headers=lane.bearer(token, **kit.idem()),
    )
    assert resp.status_code == 422
