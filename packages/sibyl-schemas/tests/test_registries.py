"""G0 single-source registries: problems, audit taxonomy, state edges, scopes, rate policies.

These are the catalogues the kernel, the OpenAPI generator and the database seeds import or
diff against (G0 reconciliation, chair rulings G0-1 to G0-4).
"""

from __future__ import annotations

import re

import pytest
import sibyl_schemas
from sibyl_schemas import values as v

ACTION_NAME = re.compile(r"^[a-z_]+\.[a-z_]+$")


def test_schemas_version_is_1_1_0() -> None:
    assert sibyl_schemas.__version__ == "1.1.0"


def test_contract_tag_is_1_1_0_per_ruling_g0_9() -> None:
    assert sibyl_schemas.CONTRACT_TAG == "contracts-v1.1.0"


# --- problem codes ----------------------------------------------------------------------


def test_every_problem_code_has_status_and_title() -> None:
    for code in v.ProblemCode:
        assert code in v.PROBLEM_STATUS, code
        assert v.PROBLEM_TITLE[code].strip(), code
    assert set(v.PROBLEM_TITLE) == set(v.ProblemCode)


def test_problem_registry_is_superset_of_kernel_and_schemas_codes() -> None:
    kernel_wave0 = {
        "invalid_cursor": 400,
        "forbidden": 403,
        "agent_binding_violation": 403,
        "unsupported_media_type": 415,
        "stream_limit": 429,
        "tenant_rate_limit": 429,
        "ingest_saturated": 429,
        "not_implemented": 501,
        "database_unavailable": 503,
        "serialization_failure": 503,
        "database_timeout": 503,
        "conflict": 409,
        "expires_at_out_of_range": 422,
        "reference_unknown": 422,
    }
    for code, status in kernel_wave0.items():
        assert v.PROBLEM_STATUS[v.ProblemCode(code)] == status, code
    assert v.PROBLEM_STATUS[v.ProblemCode.SERVICE_UNAVAILABLE] == 503


def test_forbidden_is_the_single_plain_403_code_per_ruling_g0_5() -> None:
    assert "access_denied" not in {c.value for c in v.ProblemCode}
    assert not hasattr(v.ProblemCode, "ACCESS_DENIED")
    assert v.PROBLEM_STATUS[v.ProblemCode.FORBIDDEN] == 403


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("idempotency_key_reuse", 422),
        ("idempotent_replay_unavailable", 409),
        ("erasure_not_approved", 409),
        ("key_field_immutable", 409),
        ("invalid_cursor", 400),
    ],
)
def test_g0_fix_pass_problem_codes(code: str, status: int) -> None:
    problem = v.ProblemCode(code)
    assert v.PROBLEM_STATUS[problem] == status
    assert v.problem_statuses(problem) == (status,)
    assert v.PROBLEM_TITLE[problem].strip()


@pytest.mark.parametrize(
    ("db_code", "problem"),
    [
        ("idempotency_key_reuse", "idempotency_key_reuse"),
        ("erasure_not_approved", "erasure_not_approved"),
        ("key_field_immutable", "key_field_immutable"),
        ("ledger_invalid", "internal_error"),
    ],
)
def test_g0_fix_pass_db_error_codes_map_to_same_named_problems(db_code: str, problem: str) -> None:
    assert v.DB_ERROR_PROBLEM[db_code] is v.ProblemCode(problem)
    assert v.parse_db_error_code(f"sibyl:{db_code}: detail") == db_code


def test_ledger_error_has_a_single_db_code() -> None:
    assert "erasure_ledger_invalid" not in v.DB_ERROR_PROBLEM
    assert v.DB_ERROR_PROBLEM["ledger_invalid"] is v.ProblemCode.INTERNAL_ERROR


def test_audit_content_keys_are_the_union_of_kernel_and_database_lists() -> None:
    kernel = {"prompt", "completion", "messages", "body", "content", "headers", "input", "output"}
    database = {
        "prompt",
        "completion",
        "messages",
        "body",
        "content",
        "headers",
        "input_messages",
        "output_messages",
    }
    assert isinstance(v.AUDIT_CONTENT_KEYS, frozenset)
    assert v.AUDIT_CONTENT_KEYS == kernel | database
    assert all(key == key.lower() and key.strip() == key for key in v.AUDIT_CONTENT_KEYS)
    assert "AUDIT_CONTENT_KEYS" in v.__all__


def test_transition_error_is_invalid_transition() -> None:
    assert v.PROBLEM_STATUS[v.ProblemCode.INVALID_TRANSITION] == 409
    assert "illegal_transition" not in {c.value for c in v.ProblemCode}


def test_erasure_blocked_by_chain_is_a_409() -> None:
    assert v.PROBLEM_STATUS[v.ProblemCode.ERASURE_BLOCKED_BY_CHAIN] == 409


def test_problem_statuses_lists_primary_first() -> None:
    assert v.problem_statuses(v.ProblemCode.CAPTURE_POLICY_MISSING) == (409, 403, 404)
    assert v.problem_statuses(v.ProblemCode.NOT_FOUND) == (404,)


def test_every_db_error_code_maps_to_a_problem() -> None:
    assert all(isinstance(p, v.ProblemCode) for p in v.DB_ERROR_PROBLEM.values())
    assert v.DB_ERROR_PROBLEM["invalid_transition"] is v.ProblemCode.INVALID_TRANSITION
    assert v.DB_ERROR_PROBLEM["stale_precondition"] is v.ProblemCode.STALE_PRECONDITION
    assert v.DB_ERROR_PROBLEM["erasure_blocked_by_chain"] is (
        v.ProblemCode.ERASURE_BLOCKED_BY_CHAIN
    )
    assert v.DB_ERROR_PROBLEM["audit_action_unknown"] is v.ProblemCode.INTERNAL_ERROR
    assert v.DB_ERROR_PROBLEM["legal_hold_active"] is v.ProblemCode.HOLD_BLOCKED


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("sibyl:invalid_transition: routing killed -> active (trigger undo)", "invalid_transition"),
        ("sibyl:stale_precondition", "stale_precondition"),
        ("sibyl:erasure_blocked_by_chain: agent x", "erasure_blocked_by_chain"),
        ("duplicate key value", None),
        ("sibyl:", None),
        ("sibyl:Bad Code: x", None),
    ],
)
def test_parse_db_error_code(message: str, expected: str | None) -> None:
    assert v.parse_db_error_code(message) == expected


# --- audit taxonomy ---------------------------------------------------------------------


def test_audit_actions_are_well_formed() -> None:
    assert len(v.AUDIT_ACTIONS) >= 113
    for name, spec in v.AUDIT_ACTIONS.items():
        assert spec.name == name
        assert ACTION_NAME.fullmatch(name), name
        assert spec.actor_types and spec.actor_types <= set(v.ActorType), name
        assert isinstance(spec.severity, v.AuditSeverity)
        assert len(set(spec.required_fields)) == len(spec.required_fields), name


@pytest.mark.parametrize(
    "name",
    [
        "erasure.cancelled",
        "handoff.lock_extended",
        "handoff.claim_released",
        "credential.bundle_issued",
        "tenant_key.rotated",
        "access.break_glass",
        "access.denied",
    ],
)
def test_g0_audit_additions_exist(name: str) -> None:
    assert name in v.AUDIT_ACTIONS


def test_humans_may_create_handoffs_and_request_approvals() -> None:
    assert v.ActorType.HUMAN in v.AUDIT_ACTIONS["handoff.created"].actor_types
    assert v.ActorType.HUMAN in v.AUDIT_ACTIONS["approval.requested"].actor_types


def test_chair_ruling_g0_4_widening() -> None:
    a = v.AUDIT_ACTIONS
    assert {v.ActorType.SYSTEM, v.ActorType.HUMAN} <= a["route.changed"].actor_types
    assert {v.ActorType.SYSTEM, v.ActorType.HUMAN} <= a["failover.completed"].actor_types
    assert v.ActorType.POLICY in a["quarantine.applied"].actor_types
    for name in ("alert.acked", "alert.labelled", "alert.silenced"):
        assert a[name].required_fields == ("alert_id",), name


def test_break_glass_kill_is_attributed_to_the_api_key() -> None:
    pulled = v.AUDIT_ACTIONS["killswitch.pulled"]
    assert v.ActorType.API_KEY.value == "api_key"
    assert pulled.actor_types == {v.ActorType.HUMAN, v.ActorType.API_KEY}
    assert v.ActorType.SYSTEM not in pulled.actor_types


def test_break_glass_access_allows_the_key_and_the_system_per_b21() -> None:
    glass = v.AUDIT_ACTIONS["access.break_glass"]
    assert glass.actor_types == {v.ActorType.SYSTEM, v.ActorType.API_KEY}


def test_every_agent_action_also_accepts_the_api_key_actor_per_g0_6() -> None:
    agent_actions = {n for n, s in v.AUDIT_ACTIONS.items() if v.ActorType.AGENT in s.actor_types}
    assert agent_actions == {
        "asset.created",
        "asset.updated",
        "handoff.created",
        "credential.bundle_issued",
    }
    for name in agent_actions:
        assert v.ActorType.API_KEY in v.AUDIT_ACTIONS[name].actor_types, name
    key_actions = {n for n, s in v.AUDIT_ACTIONS.items() if v.ActorType.API_KEY in s.actor_types}
    # INT-1: ingest records first sight of an unregistered agent as the sending key.
    g0_12 = {"audit.exported", "erasure.blocked_by_hold"}  # ruling G0-12 (lane U)
    assert (
        key_actions
        == agent_actions
        | {
            "killswitch.pulled",
            "access.denied",
            "asset.discovered",
            "killswitch.applied",  # lane S: the applying gateway key (G0-6)
            "access.break_glass",  # B21: the break-glass key itself
        }
        | g0_12
        | {"action.allowed", "action.blocked", "action.escalated"}  # D48: enforcement keys
        | {"agent.discovered"}  # D50: ingest records first sight as the sending key
        | {"finding.submitted"}  # D53: a monitor-bound key submits a finding
    )


def test_export_completion_is_the_workers_record_per_g0_12() -> None:
    completed = v.AUDIT_ACTIONS["audit.export_completed"]
    assert completed.actor_types == {v.ActorType.SYSTEM}
    assert completed.required_fields == ("export_sha256", "anchor_id")
    assert v.AUDIT_ACTIONS["audit.exported"].actor_types == {
        v.ActorType.HUMAN,
        v.ActorType.API_KEY,
    }
    assert v.AUDIT_ACTIONS["erasure.blocked_by_hold"].actor_types == {
        v.ActorType.SYSTEM,
        v.ActorType.HUMAN,
        v.ActorType.API_KEY,
    }


def test_access_denied_records_whoever_attempted_it_per_g0_11() -> None:
    denied = v.AUDIT_ACTIONS["access.denied"]
    assert denied.actor_types == {v.ActorType.SYSTEM, v.ActorType.HUMAN, v.ActorType.API_KEY}


def test_routing_actor_kinds_include_the_break_glass_key() -> None:
    assert {k.value for k in v.ActorKind} == {"human", "rule", "policy", "system", "api_key"}


# --- state edges ------------------------------------------------------------------------


def _routing() -> set[tuple[str, str, str]]:
    return {(e.from_state, e.to_state, e.trigger) for e in v.STATE_EDGES if e.machine == "routing"}


def test_ten_state_machines() -> None:
    assert {e.machine for e in v.STATE_EDGES} == {m.value for m in v.StateMachine}
    assert {m.value for m in v.StateMachine} == {
        "routing",
        "failover",
        "approval",
        "handoff",
        "alert",
        "erasure",
        "tenant_key",
        "held_action",  # D48 Action Gate
        "action_policy",  # D48 Action Gate
        "kill_switch",
        "lifecycle",
        "job",
    }


def test_routing_edges_use_frozen_states_and_triggers() -> None:
    states = {s.value for s in v.RoutingState} | {""}
    triggers = {t.value for t in v.TransitionTrigger}
    for from_state, to_state, trigger in _routing():
        assert from_state in states and to_state in states and to_state
        assert trigger in triggers


def test_undo_inverts_every_automated_routing_edge() -> None:
    edges = _routing()
    automated = {(f, t) for f, t, trig in edges if trig in {"rule", "policy"} and f != t}
    assert automated
    assert {(t, f) for f, t in automated} == {(f, t) for f, t, trig in edges if trig == "undo"}


def test_chair_ruling_g0_3_edges() -> None:
    edges = _routing()
    for state in ("active", "degraded", "quarantined"):
        assert (state, state, "operator") in edges, state
    assert ("failed_over", "failed_over", "rule") in edges
    assert ("failing_back", "failing_back", "canary") in edges
    assert ("", "active", "register") in edges


def test_lifecycle_and_erasure_edges_use_frozen_states() -> None:
    lifecycle = {s.value for s in v.Lifecycle} | {""}
    erasure = {s.value for s in v.ErasureState} | {""}
    for e in v.STATE_EDGES:
        if e.machine == "lifecycle":
            assert {e.from_state, e.to_state} <= lifecycle
        if e.machine == "erasure":
            assert {e.from_state, e.to_state} <= erasure


# --- scopes and rate policies -----------------------------------------------------------


def test_step_up_and_machine_only_sets() -> None:
    assert {s.value for s in v.STEP_UP_SCOPES} == {
        "tenant:write",
        "oidc:manage",
        "credentials:manage",
        "keys:rotate",
        "killswitch:pull",
        "killswitch:release",
        "erasure:approve",
        "holds:manage",
    }
    assert {s.value for s in v.MACHINE_ONLY_SCOPES} == {
        "gateway:proxy",
        "ingest:write",
        "handoff:write",
        "actions:hold",  # D48: gateway / SDK enforcement points
        "monitor:read",  # D53: monitor-bound keys
        "findings:write",
    }
    assert v.BREAK_GLASS_SCOPE is v.Scope.KILLSWITCH_PULL


def test_rate_policies_cover_api_2_8() -> None:
    specs = v.RATE_POLICY_SPECS
    assert set(specs) == {
        "read",
        "mutation",
        "apikeys_create",
        "tenant_key_rotate",
        "credentials_create",
        "erasure_create",
        "payload_reveal",
        "killswitch",
        "break_glass_key",
        "break_glass_tenant",
        "audit_jobs",
        "auth",
        "auth_tenant",
        "snapshot",
        "sse",
        "ingest",
        "ingest_key_batches",
        "gateway_401_ip",
    }
    assert (specs["tenant_key_rotate"].quota, specs["tenant_key_rotate"].window_s) == (6, 3600)
    assert specs["ingest"].burst == 5000
    assert v.RATE_POLICIES == {n: (s.quota, s.window_s) for n, s in specs.items()}
    for name, spec in specs.items():
        assert spec.name == name and spec.quota > 0 and spec.window_s > 0


def test_hash_only_keys_exempt_only_flat_sha256_objects() -> None:
    digest = "0f" * 32
    assert v.AUDIT_HASH_ONLY_KEYS == frozenset({"content_hashes"})
    assert "AUDIT_HASH_ONLY_KEYS" in v.__all__ and "is_hash_only_subtree" in v.__all__
    assert v.is_hash_only_subtree("content_hashes", {"input": digest, "output_sha256": digest})
    assert v.is_hash_only_subtree("Content_Hashes", {})
    assert not v.is_hash_only_subtree("content_hashes", {"input": "text"})
    assert not v.is_hash_only_subtree("content_hashes", {"input": digest.upper()})
    assert not v.is_hash_only_subtree("content_hashes", {"input": {"x": digest}})
    assert not v.is_hash_only_subtree("content_hashes", [digest])
    assert not v.is_hash_only_subtree("hashes", {"input": digest})
