"""End to end on PG17: tenant-scope erasure (offboarding) by two owners → worker → zero residue.

Own module (own database): the erasure wipes tenant ``acme``. Checks the crypto-shred of every
tenant key, the BlobStore prefix, PII per ``sibyl.erasure_residue`` (users anonymised, issuer
secrets gone, pseudonym key shredded), the certificate's shredded key versions, the tenant
row reduced to its key columns, the signed ledger entry, and that the other tenant is intact.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import sibyl_lane_u_helpers as h
from sibyl_control.migrate.__main__ import main as migrate_cli
from sibyl_control.worker.housekeeping import erasure_exec, erasure_ledger, ledger_store

NOW = datetime.now(UTC)
REASON = "tenant offboarding: contract ended 2026-09-30"


def _act(world: Any, rid: str, action: str, token: str) -> Any:
    return world.post(
        token,
        f"/erasure-requests/{rid}/actions",
        {"action": action, "reason": f"{action}: {REASON}"},
    )


@pytest.fixture(scope="module")
def erased(world: Any) -> dict[str, Any]:
    agents = [world.add_agent(world.a, f"t-agent-{i}") for i in range(2)]
    refs = [h.add_payload(world, world.a.id, agent=a) for a in agents]
    refs.append(h.add_payload(world, world.a.id, agent=None, kind="anchor_export"))
    b_agent = world.add_agent(world.b, "b-survivor")
    b_ref = h.add_payload(world, world.b.id, agent=b_agent)
    h.append_rows(world, world.a.id, 3, agent=agents[0])

    hold = world.post(
        "security_admin",
        "/legal-holds",
        {
            "scope_kind": "tenant",
            "window_from": (NOW - timedelta(days=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=10)).isoformat(),
            "reason": "regulator inquiry pending",
        },
    )
    assert hold.status_code == 201, hold.text
    created = world.post(
        "owner",
        "/erasure-requests",
        {"scope_kind": "tenant", "legal_basis": "tenant_offboarding", "reason": REASON},
    )
    assert created.status_code == 201, created.text
    rid = created.json()["id"]
    assert created.json()["state"] == "hold_blocked"
    world.post(
        "security_admin", f"/legal-holds/{hold.json()['id']}/release", {"reason": "inquiry closed"}
    )
    denied = _act(world, rid, "approve", "approver")  # security_admin: tenant scope needs owner
    assert denied.status_code == 403
    assert _act(world, rid, "approve", "owner").json()["type"].endswith("/self_approval")
    approved = _act(world, rid, "approve", "owner2")
    assert approved.status_code == 200, approved.text
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(erasure_exec, "DEK_CACHE_TTL", timedelta(0))
        world.tick(erasure_exec)
    return {"id": rid, "agents": agents, "refs": refs, "b_ref": b_ref}


def test_tenant_erasure_completes(world: Any, erased: dict[str, Any]) -> None:
    doc = world.get("owner2", f"/erasure-requests/{erased['id']}").json()
    assert doc["state"] == "completed", doc["error"]
    steps = [e["step"] for e in doc["execution_log"]]
    assert steps == [
        "requested",
        "approved",
        "executing",
        "keys_shredded",
        "objects_deleted",
        "derived_purged",
        "verified",
        "completed",
    ]


def test_residue_is_zero_and_pii_is_gone(world: Any, erased: dict[str, Any]) -> None:
    tenant = world.a.id
    residue = world.in_tenant(tenant, "SELECT * FROM sibyl.erasure_residue($1)", UUID(erased["id"]))
    assert residue == []
    users = world.fetch(
        "SELECT email::text, subject, display_name FROM sibyl.app_user WHERE tenant_id = $1", tenant
    )
    assert users, "users referenced by the audit chain are kept, anonymised"
    for user in users:
        assert user["email"].startswith("erased+") and user["email"].endswith("@invalid")
        assert user["subject"].startswith("erased:") and user["display_name"] is None
    assert world.fetchval("SELECT count(*) FROM sibyl.membership WHERE tenant_id = $1", tenant) == 0
    assert world.fetchval("SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", tenant) == 0
    assert (
        world.fetchval(
            "SELECT count(*) FROM sibyl.oidc_issuer WHERE tenant_id = $1"
            " AND client_secret_ct IS NOT NULL",
            tenant,
        )
        == 0
    )
    assert (
        world.fetchval(
            "SELECT count(*) FROM sibyl.tenant_pseudonym_key WHERE tenant_id = $1"
            " AND hmac_key IS NOT NULL",
            tenant,
        )
        == 0
    )


def test_keys_are_shredded_and_objects_deleted(world: Any, erased: dict[str, Any]) -> None:
    tenant = world.a.id
    keys = world.fetch(
        "SELECT purpose, state, wrapped_dek FROM sibyl.tenant_key WHERE tenant_id = $1", tenant
    )
    assert {k["purpose"] for k in keys} == {"payload", "credential", "config"}
    assert all(k["state"] == "shredded" and k["wrapped_dek"] is None for k in keys)
    assert world.run(world.blob.list_prefix(f"tenant/{tenant}/")) == []
    assert (
        world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE tenant_id = $1", tenant) == 0
    )
    b_id, b_key = erased["b_ref"]
    assert world.run(world.blob.head(b_key)) is not None
    assert world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE id = $1", b_id) == 1


def test_tenant_row_keeps_only_its_key_columns(world: Any, erased: dict[str, Any]) -> None:
    row = world.fetchrow("SELECT * FROM sibyl.tenant WHERE id = $1", world.a.id)
    assert row["status"] == "erased" and row["name"] is None and row["slug"] == "acme"
    assert (
        world.fetchrow("SELECT status FROM sibyl.tenant WHERE id = $1", world.b.id)["status"]
        == "active"
    )


def test_certificate_lists_shredded_keys_and_the_ledger_entry(
    world: Any, erased: dict[str, Any], tmp_path: Path
) -> None:
    resp = world.get("auditor", f"/erasure-requests/{erased['id']}/certificate")
    assert resp.status_code == 200, resp.text
    cert = resp.json()["certificate"]
    assert sorted((k["purpose"], k["version"]) for k in cert["shredded_keys"]) == [
        ("config", 1),
        ("credential", 1),
        ("payload", 1),
    ]
    assert cert["affected_objects"]["keys_shredded"]["tenant_key"] == 3
    assert cert["affected_objects"]["objects_deleted"]["blob_objects"] == 3
    assert cert["legal_basis"] == "tenant_offboarding"
    world.tick(erasure_ledger)
    text = world.run(ledger_store.read_jsonl(world.blob))
    entry = next(json.loads(ln) for ln in text.splitlines() if erased["id"] in ln)
    assert entry["scope_kind"] == "tenant" and len(entry["key_ids"]) == 3
    assert entry["seq"] == cert["ledger"]["seq"]
    head = json.loads(world.run(world.blob.get(ledger_store.HEAD_KEY)))
    ledger_path = tmp_path / "ledger.jsonl"
    ledger_path.write_text(text)
    assert (
        migrate_cli(
            [
                "ledger-verify",
                "--ledger",
                str(ledger_path),
                "--public-key",
                str(world.ledger_public_path),
                "--expected-count",
                str(head["count"]),
                "--expected-head",
                head["head_hash"],
            ]
        )
        == 0
    )


def test_audit_chain_survives_the_erasure(world: Any, erased: dict[str, Any]) -> None:
    ok = world.in_tenant(world.a.id, "SELECT ok, kind FROM sibyl.audit_verify($1)", world.a.id)
    assert ok[0]["ok"] is True, ok
    actions = world.actions(world.a.id, 0)
    assert actions.count("tenant_key.shredded") == 3
    assert {"erasure.keys_shredded", "erasure.completed"} <= set(actions)
    anchors = world.fetch(
        "SELECT kind FROM sibyl.audit_anchors WHERE tenant_id = $1 AND kind = 'erasure'", world.a.id
    )
    assert len(anchors) == 2  # after the shred and at completion
