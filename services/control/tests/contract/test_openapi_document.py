"""The frozen contract itself: valid OpenAPI 3.1, complete x-sibyl-* extensions, no drift."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
from openapi_spec_validator import validate
from sibyl_control.api.contract import (
    API_MODULES,
    contract_path,
    load_document,
    operations,
)
from sibyl_control.api.routers import ROUTER_MODULES
from sibyl_control.core.audit import AUDIT_ACTIONS
from sibyl_control.core.authz import PSEUDO_SCOPES, SCOPES
from sibyl_control.core.problems import PROBLEM_CODES
from sibyl_control.core.ratelimit import POLICIES
from sibyl_control.core.risk import RiskDocument

from ._examples import example

# + 11 D48 Action Gate operations (lane AG-CORE), + 4 D51 drift operations (lane DRIFT)
# + 7 D52 Sentinel operations (lane SENTINEL), + 2 AG-LIVE operations
# + clearPreemptiveBreaker (INT-3, B19), + listRuns/getRun (GAPS)
# + 9 D53 monitor operations and 4 D53 findings operations (lane EXTMON)
# + getDriftThresholds/putDriftThresholds (wave 4 HARDEN, tenant-tunable drift thresholds)
EXPECTED_OPERATIONS = 188  # API.md §5 (138 control-plane) + §4 ingest (3) + policy keys pair (2)
#                          + tenant-key list/rotate (2, security-auditor §3.4, added 2026-10-10)
#                          + getProvider (INT-1, 2026-10-11); the queue summary rides on listQueue
#                          + simulateActionPolicyDraft, getActionSummary (AG-LIVE, 2026-10-12)
EXPECTED_PATHS = 148  # + 9 D48 Action Gate, + 4 D51 drift, + 6 D52 Sentinel, + 2 AG-LIVE, + 1 INT-3
#                     + 2 GAPS (/runs, /runs/{run_id}), + 7 D53 /monitors…, + 3 D53 /findings…
#                     + 1 HARDEN (/drift/thresholds)
OPS = operations()
IDS = [op.operation_id for op in OPS]
CONTENT_RESOURCE_DELETE_ALLOWLIST = {"revokeSession", "revokeMembership", "closeDependencyEdge"}


def test_document_is_valid_openapi_3_1() -> None:
    validate(load_document())


def test_document_has_no_drift_from_its_generator() -> None:
    build = contract_path().parent / "build.py"
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(build), "--check"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_route_count_reconciles_with_api_md() -> None:
    assert len(OPS) == EXPECTED_OPERATIONS
    assert len(load_document()["paths"]) == EXPECTED_PATHS
    assert len(set(IDS)) == len(IDS)


@pytest.mark.parametrize("op", OPS, ids=IDS)
def test_every_operation_declares_scope_and_audit(op) -> None:
    raw = op.raw
    assert "x-sibyl-scope" in raw and "x-sibyl-audit" in raw
    assert op.scope in SCOPES | PSEUDO_SCOPES
    assert set(op.scope_any) <= SCOPES
    assert set(op.key_scopes) <= SCOPES
    assert raw["x-sibyl-audit"] == "none" or set(op.audit) <= AUDIT_ACTIONS
    assert op.module in API_MODULES
    assert op.rate_limit in POLICIES
    for action in op.actions.values():
        assert action["scope"] in SCOPES
        assert set(action["audit"]) <= AUDIT_ACTIONS


@pytest.mark.parametrize("op", OPS, ids=IDS)
def test_problem_codes_are_registered_with_their_status(op) -> None:
    for status, codes in op.problems.items():
        for code in codes:
            assert code in PROBLEM_CODES, code
            assert status in PROBLEM_CODES[code].statuses, (code, status)


def test_state_changing_posts_require_idempotency_keys() -> None:
    exempt_modules = {"auth", "ingest"}
    for op in OPS:
        if op.method == "post" and op.module not in exempt_modules:
            assert op.idempotency, op.operation_id


def test_policy_writes_require_if_match() -> None:
    for op in OPS:
        if op.method in ("put", "patch"):
            assert op.if_match in ("required", "required_or_star"), op.operation_id


def test_no_bulk_or_content_deletes() -> None:
    deletes = {op.operation_id for op in OPS if op.method == "delete"}
    assert deletes == CONTENT_RESOURCE_DELETE_ALLOWLIST
    assert all("{" in op.path for op in OPS if op.method == "delete")


def test_break_glass_key_reaches_exactly_one_route() -> None:
    routes = [op.operation_id for op in OPS if "killswitch:pull" in op.key_scopes]
    assert routes == ["pullKillSwitch"]


def test_release_is_never_reachable_by_a_key() -> None:
    release = next(op for op in OPS if op.operation_id == "releaseKillSwitch")
    assert release.key_scopes == () and "api_key" not in release.principals


def test_machine_only_scopes_are_key_only_routes() -> None:
    for op in OPS:
        if op.scope in {"gateway:proxy", "ingest:write"}:
            assert op.principals == ("api_key",), op.operation_id


def test_audited_reads_are_declared() -> None:
    reveal_routes = {op.operation_id for op in OPS if "data.revealed" in op.audit}
    assert reveal_routes == {"getHandoffPacket", "getPayload"}


def test_policy_routes_live_under_api_v1_policy_and_well_known() -> None:
    mounts = {op.mount_path for op in OPS if op.module == "snapshot"}
    assert mounts == {
        "/api/v1/policy/snapshot",
        "/api/v1/policy/credentials",
        "/api/v1/policy/keys",
        "/.well-known/sibyl-keys.json",
    }


def test_router_modules_cover_every_non_ingest_module() -> None:
    assert set(ROUTER_MODULES) == set(API_MODULES) - {"ingest"}
    assert ROUTER_MODULES.index("sse") < ROUTER_MODULES.index("reads")


@pytest.mark.parametrize("op", [o for o in OPS if o.request_schema], ids=lambda o: o.operation_id)
def test_generated_request_examples_validate(op) -> None:
    doc = load_document()
    schema = {"$ref": f"#/components/schemas/{op.request_schema}", "components": doc["components"]}
    jsonschema.Draft202012Validator(schema).validate(example(schema))


def test_risk_document_model_matches_the_contract() -> None:
    component = load_document()["components"]["schemas"]["RiskDocument"]
    assert set(component["properties"]) == set(RiskDocument.model_fields)
    assert set(component["required"]) <= {
        name for name, f in RiskDocument.model_fields.items() if f.is_required()
    } | {"rules_source"}


def test_contract_path_points_at_the_repo_file() -> None:
    assert contract_path() == Path(contract_path()).resolve()
    assert contract_path().name == "sibyl-api.v1.yaml"


def test_key_set_component_matches_the_signed_wire_shape() -> None:
    """Security M6 / schema 1.1.0: the contract's KeySet is the signed ``{kid, alg, sig, body}``
    document; every vector the schemas accept validates and the legacy shape does not."""
    from jsonschema import Draft202012Validator
    from sibyl_control.api.contract import load_document
    from sibyl_schemas.golden import load_fixture

    doc = load_document()
    schema = {"$ref": "#/components/schemas/KeySet", "components": doc["components"]}
    validator = Draft202012Validator(schema)
    vectors = load_fixture("snapshot", "key_set_vectors.json")
    for case in vectors["cases"]:
        for step in case["steps"]:
            if "document" not in step:
                continue
            ok = validator.is_valid(step["document"])
            assert ok is (step["expected"] != "malformed"), case["name"]
    from sibyl_control.api.contract import operation

    def ok_schema(op_id: str) -> dict:
        return operation(op_id).raw["responses"]["200"]["content"]["application/json"]["schema"]

    assert ok_schema("getWellKnownKeys") == {"$ref": "#/components/schemas/KeySet"}
    # B10: /policy/keys answers the single set, or with ?since= the chain after that sequence.
    assert ok_schema("getPolicyKeys") == {"$ref": "#/components/schemas/KeySetResponse"}
    assert doc["components"]["schemas"]["KeySetResponse"]["oneOf"] == [
        {"$ref": "#/components/schemas/KeySet"},
        {"$ref": "#/components/schemas/KeySetChain"},
    ]
    since = [p for p in operation("getPolicyKeys").raw["parameters"] if p["name"] == "since"]
    assert since and since[0]["in"] == "query" and not since[0].get("required")
    chain_schema = {"$ref": "#/components/schemas/KeySetChain", "components": doc["components"]}
    chain = Draft202012Validator(chain_schema)
    valid = next(c for c in vectors["cases"] if c["name"] == "valid_rotation")
    documents = [step["document"] for step in valid["steps"]]
    assert chain.is_valid({"data": documents, "latest_sequence": 3})
    assert not chain.is_valid({"data": documents})
    response = Draft202012Validator(
        {"$ref": "#/components/schemas/KeySetResponse", "components": doc["components"]}
    )
    assert response.is_valid(documents[0])
    assert response.is_valid({"data": documents, "latest_sequence": 3})
