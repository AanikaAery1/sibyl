"""Optional body ``reason`` on audited tenancy writes (INT-1): the operator's own words land on
the audit row; the body wins over ``X-Sibyl-Reason``; a patch with only a reason is 422."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import sibyl_lane_a_kit as kit  # loaded by conftest

API = "/api/v1"


def tok(lane: Any, w: Any, role: str) -> str:
    return kit.add_session(lane.db, w.tenant, w.users[role])


def _last_reason(lane: Any, world: Any, action: str) -> str:
    return str(kit.audit_rows(lane.db, world.tenant, action)[-1]["reason"])


def test_tenant_patch_body_reason_wins_over_the_header(lane: Any, world: Any) -> None:
    token = tok(lane, world, "owner")
    etag = lane.client.get(f"{API}/tenant", headers=lane.bearer(token)).headers["etag"]
    resp = lane.client.patch(
        f"{API}/tenant",
        json={"raw_retention_days": 9, "reason": "DPO asked for nine days of raw data"},
        headers=lane.bearer(token, **{"If-Match": etag, "X-Sibyl-Reason": "the header loses"}),
    )
    assert resp.status_code == 200, resp.text
    assert "reason" not in resp.json()
    assert _last_reason(lane, world, "config.changed") == "DPO asked for nine days of raw data"


def test_tenant_patch_with_only_a_reason_is_422(lane: Any, world: Any) -> None:
    token = tok(lane, world, "owner")
    etag = lane.client.get(f"{API}/tenant", headers=lane.bearer(token)).headers["etag"]
    resp = lane.client.patch(
        f"{API}/tenant",
        json={"reason": "nothing else is being changed"},
        headers=lane.bearer(token, **{"If-Match": etag}),
    )
    assert resp.status_code == 422, resp.text


def test_group_create_and_patch_carry_the_reason(lane: Any, world: Any) -> None:
    admin = tok(lane, world, "admin")
    slug = f"g-{uuid4().hex[:8]}"
    made = lane.client.post(
        f"{API}/agent-groups",
        json={"slug": slug, "name": "Claims", "reason": "claims team onboarding, ticket 42"},
        headers=lane.bearer(admin, **kit.idem()),
    )
    assert made.status_code == 201, made.text
    assert _last_reason(lane, world, "config.changed") == "claims team onboarding, ticket 42"
    path = f"{API}/agent-groups/{made.json()['id']}"
    etag = lane.client.get(path, headers=lane.bearer(admin)).headers["etag"]
    patched = lane.client.patch(
        path,
        json={"name": "Claims EU", "reason": "split per region after the reorg"},
        headers=lane.bearer(admin, **{"If-Match": etag}),
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["name"] == "Claims EU"
    assert _last_reason(lane, world, "config.changed") == "split per region after the reorg"


def test_invitation_carries_the_reason(lane: Any, world: Any) -> None:
    admin = tok(lane, world, "admin")
    resp = lane.client.post(
        f"{API}/users/invitations",
        json={
            "oidc_issuer_id": str(world.issuer_id),
            "scope_kind": "tenant",
            "email": f"v-{uuid4().hex[:6]}@x.test",
            "role_name": "viewer",
            "reason": "new analyst starting Monday",
        },
        headers=lane.bearer(admin, **kit.idem()),
    )
    assert resp.status_code == 201, resp.text
    assert _last_reason(lane, world, "user.provisioned") == "new analyst starting Monday"
