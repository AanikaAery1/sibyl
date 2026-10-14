"""Action policies inside the signed `sibyl.policy_snapshot/1` (additive, B4 budget).

The `valid_action_policies` signature vector is regenerated deterministically from the public
TEST-ONLY seed (Ed25519 signatures are deterministic), so this test proves the committed vector
is exactly what the documented procedure produces.
"""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
from typing import Any

import pytest
from sibyl_schemas import action_gate as ag
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.canonical import canonicalize
from sibyl_schemas.golden import load_fixture
from sibyl_schemas.models import PolicySnapshot, SignedPolicySnapshot
from sibyl_schemas.values import SNAPSHOT_MAX_BYTES

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
VECTORS: dict[str, Any] = load_fixture("snapshot", "vectors.json")
TENANT = "0192767f-0000-7000-8000-00000000a001"
QUOTE = "0192767f-0000-7000-8000-00000000c011"
RAW_SNAPSHOT_BUDGET = 3 * 1024 * 1024  # B4: <= 3 MiB raw canonical JSON


def _case(name: str) -> dict[str, Any]:
    return next(c for c in VECTORS["cases"] if c["name"] == name)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_signed_vector_regenerates_from_the_public_test_seed() -> None:
    seed = hashlib.sha256(VECTORS["test_signing_seed_sha256_input"].encode()).digest()
    key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    case = _case("valid_action_policies")
    raw = canonicalize(case["envelope"]["body"])
    assert _b64u(key.sign(raw)) == case["envelope"]["sig"]
    assert hashlib.sha256(raw).hexdigest() == case["body_jcs_sha256"]


def test_vector_adds_only_action_policies_to_the_valid_body() -> None:
    plain = copy.deepcopy(_case("valid")["envelope"]["body"])
    gated = copy.deepcopy(_case("valid_action_policies")["envelope"]["body"])
    block = gated["tenants"][TENANT]
    policies = block.pop("action_policies")
    for agent in block["agents"].values():
        agent.pop("action_policies", None)
    assert gated.pop("version") == plain.pop("version") + 1
    assert gated == plain
    assert set(policies) == {
        "0192767f-0000-7000-8000-0000000ac001",
        "0192767f-0000-7000-8000-0000000ac002",
    }


def test_snapshot_model_exposes_policies_and_agent_refs() -> None:
    envelope = SignedPolicySnapshot.model_validate(_case("valid_action_policies")["envelope"])
    block = envelope.body.tenants[TENANT]
    refs = block.agents[QUOTE].action_policies
    assert isinstance(refs, list) and len(refs) == 2
    assert isinstance(block.action_policies, dict)
    resolved = [block.action_policies[ref] for ref in refs]
    decision = ag.evaluate_all(resolved, "payments.transfer", {"amount": 99_999})
    assert decision.effect is ag.Effect.BLOCK and decision.rule_id == "transfer-over-limit"


def test_snapshot_without_action_policies_still_round_trips() -> None:
    body = load_fixture("snapshot", "valid/snapshot_body.json")
    dumped = PolicySnapshot.model_validate(body).model_dump(mode="json", by_alias=True)
    assert dumped == body
    assert "action_policies" not in json.dumps(dumped)


def _fleet_with_policies(agents_total: int, rules_per_policy: int) -> dict[str, Any]:
    """Worst-case fleet (the richest fixture agent everywhere) where every agent has its own
    policy of `rules_per_policy` rules plus a shared tenant policy."""
    template = load_fixture("snapshot", "valid/snapshot_body.json")
    payments = load_fixture("action_gate", "vectors.json")["policies"]["payments"]
    tenant_id, block = next(iter(template["tenants"].items()))
    richest = max(block["agents"].values(), key=lambda a: len(canonicalize(a)))
    rules = (payments["rules"] * (rules_per_policy // len(payments["rules"]) + 1))[
        :rules_per_policy
    ]
    tenants: dict[str, Any] = {}
    for t in range(3):
        tenant = copy.deepcopy(block)
        shared = {**payments, "policy_id": f"0192767f-{t:04x}-7000-8000-0000000ac000"}
        policies = {shared["policy_id"]: shared}
        agents: dict[str, Any] = {}
        for n in range(agents_total // 3 + (1 if t < agents_total % 3 else 0)):
            agent = copy.deepcopy(richest)
            agent["slug"] = f"agent-{t}-{n}"
            own = f"0192767f-{t:04x}-7000-9000-{n:012x}"
            policies[own] = {
                **payments,
                "policy_id": own,
                "rules": [{**r, "rule_id": f"r{i}"} for i, r in enumerate(rules)],
            }
            agent["action_policies"] = [own, shared["policy_id"]]
            agents[f"0192767f-{t:04x}-7000-8000-{n:012x}"] = agent
        tenant["agents"] = agents
        tenant["action_policies"] = policies
        tenants[f"{tenant_id[:-4]}{t:04x}"] = tenant
    return {**template, "tenants": tenants}


def test_shared_policies_are_signed_once_per_tenant() -> None:
    """A tenant-wide policy referenced by every agent costs its bytes once, not per agent."""
    base = load_fixture("snapshot", "valid/snapshot_body.json")
    shared = load_fixture("snapshot", "valid/snapshot_body_action_policies.json")
    extra = len(canonicalize(shared)) - len(canonicalize(base))
    one_policy = len(canonicalize(load_fixture("action_gate", "valid/payments_policy.json")))
    assert extra < 3 * one_policy  # two documents plus three short reference lists


@pytest.mark.parametrize("agents", [400, 2000])
def test_per_agent_policies_fit_the_b4_budget(agents: int) -> None:
    """B4 at 2,000 worst-case agents, each with its own 4-rule policy plus a shared one: the
    gzipped transfer must stay within 2 MiB. The raw 3 MiB bound is reported for the chair
    (it already does not hold for an all-worst-case fleet without policies)."""
    body = _fleet_with_policies(agents, 4)
    assert sj.is_valid("sibyl.policy_snapshot/1", body)
    canonical = canonicalize(body)
    assert len(gzip.compress(canonical)) <= SNAPSHOT_MAX_BYTES
    if agents <= 400:
        assert len(canonical) <= RAW_SNAPSHOT_BUDGET
