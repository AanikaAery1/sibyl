"""The signed snapshot carries the approved action policies of the agents in scope (D48):
agent > agent_group > tenant, drafts never, one copy per document, schema-valid, within B4."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from sibyl_ag_gate import TRANSFER_POLICY, Gate
from sibyl_control.api.action_gate.service import POLICY_BUDGET_BYTES
from sibyl_control.api.snapshot.builder import SnapshotScope, build_tenant_block
from sibyl_schemas.canonical import canonicalize
from sibyl_schemas.models.snapshot import TenantBlock


def routable_agent(gate: Gate, *, group: UUID | None = None) -> UUID:
    """An agent the snapshot lists: current version on a model of an https provider."""
    agent = gate.agent(group=group)
    provider, model, version = uuid4(), uuid4(), uuid4()
    admin, tenant = gate.w.admin, gate.tenant
    admin.in_tenant(
        tenant,
        "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect, base_url,"
        " is_known_provider) VALUES ($1, $2, $3, $3, 'openai', 'openai_compatible',"
        " 'https://api.openai.com/v1', true)",
        tenant,
        provider,
        f"p-{provider.hex[:8]}",
    )
    admin.in_tenant(
        tenant,
        "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name) VALUES ($1, $2, $3, $4)",
        tenant,
        model,
        provider,
        f"m-{model.hex[:8]}",
    )
    admin.in_tenant(
        tenant,
        "INSERT INTO sibyl.agent_version (tenant_id, id, agent_id, version_no, primary_model_id,"
        " source) VALUES ($1, $2, $3, 1, $4, 'api')",
        tenant,
        version,
        agent,
        model,
    )
    admin.in_tenant(
        tenant,
        "UPDATE sibyl.agent SET current_version_id = $3 WHERE tenant_id = $1 AND id = $2",
        tenant,
        agent,
        version,
    )
    return agent


def block(gate: Gate, agent_id: UUID | None = None) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        conn = gate.w.admin.raw
        async with conn.transaction():
            await conn.execute("SELECT sibyl.set_tenant($1)", gate.tenant)
            scope = SnapshotScope(gate.tenant, agent_id, include_keys=False)
            return await build_tenant_block(conn, scope, demo_mode=False)

    out: dict[str, Any] = gate.w.admin.run(run())
    return out


def test_approved_policies_enter_the_snapshot_by_precedence(gate: Gate) -> None:
    group = gate.w.a.other_group_id
    own, grouped, plain = (
        routable_agent(gate),
        routable_agent(gate, group=group),
        routable_agent(gate),
    )
    agent_policy = gate.approved_policy(own, TRANSFER_POLICY)
    group_policy = gate.approved_policy(group, TRANSFER_POLICY, scope_kind="agent_group")
    tenant_policy = gate.approved_policy(None, {**TRANSFER_POLICY, "default_effect": "escalate"})
    draft = gate.create_policy(TRANSFER_POLICY, scope_id=plain).json()["id"]
    tenant_block = block(gate)
    TenantBlock.model_validate_json(json.dumps(tenant_block))  # B22 layout, documents validated
    documents = tenant_block["action_policies"]
    refs = {a: tenant_block["agents"][str(a)].get("action_policies") for a in (own, grouped, plain)}
    assert refs[own] == [agent_policy, tenant_policy]  # agent-specific first
    assert refs[grouped] == [group_policy, tenant_policy]
    assert refs[plain] == [tenant_policy]
    assert draft not in documents
    for policy_id, document in documents.items():
        assert document["policy_id"] == policy_id  # keyed by its own id
    canonicalize(tenant_block)  # the signed body is JCS of the block


def test_an_agent_scoped_snapshot_carries_only_its_policies(gate: Gate) -> None:
    own, other = routable_agent(gate), routable_agent(gate)
    mine = gate.approved_policy(own, TRANSFER_POLICY)
    theirs = gate.approved_policy(other, TRANSFER_POLICY)
    tenant_block = block(gate, own)
    assert set(tenant_block["agents"]) == {str(own)}
    assert mine in tenant_block["action_policies"]
    assert theirs not in tenant_block["action_policies"]


def test_agent_allowlist_enforcement_carries_the_identity_tools(gate: Gate) -> None:
    agent = routable_agent(gate)
    gate.w.admin.in_tenant(
        gate.tenant,
        "INSERT INTO sibyl.agent_identity (tenant_id, agent_id, allowed_tools, tools_hash)"
        " VALUES ($1, $2, $3, $4)",
        gate.tenant,
        agent,
        ["payments.transfer", "email.send"],
        b"\x01" * 32,
    )
    policy = gate.approved_policy(agent, {**TRANSFER_POLICY, "tool_allowlist_enforced": True})
    document = block(gate, agent)["action_policies"][policy]
    assert document["tool_allowlist"] == ["email.send", "payments.transfer"]


def test_the_approved_documents_stay_within_the_b4_budget(gate: Gate) -> None:
    raw = len(json.dumps(block(gate).get("action_policies", {})).encode())
    assert raw <= POLICY_BUDGET_BYTES
