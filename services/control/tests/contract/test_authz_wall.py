"""Authz red wall, generated from the OpenAPI document: one case per (route, rule).

Guard-level cases run on the in-memory ``harness``; cases that need real objects (foreign-tenant
ids, group, bound agent, job owner) run on the DB-backed ``contract_world`` with each operation's
scenario. Implemented modules are strict; see ``_cases`` for the marking rules.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sibyl_control.api.contract import ContractOperation, operations
from sibyl_control.core.authz import ROLE_GRANTS, SCOPES, Mark, Principal, PrincipalKind
from sibyl_control.core.authz import Grant as _Grant

from ._cases import (
    PENDING_MODULES,
    STUB_BY_RULING,
    STUBS,
    call,
    guard_params,
    needs_world,
    scenario,
    world_call,
    world_params,
)
from ._examples import concrete_path
from .conftest import TENANT_A
from .scenarios import CUT_BY_RULING, EXEMPT, SCENARIOS

API_OPS = [op for op in operations() if op.surface != "ingest"]
PROTECTED = [op for op in API_OPS if op.scope != "public"]
SCOPED = [op for op in PROTECTED if op.scope != "authenticated" and "self" not in op.object_rules]
WITH_IDS = [op for op in SCOPED if op.path_params and "api_key" not in op.principals]
SESSION_ONLY = [op for op in SCOPED if "api_key" not in op.principals]
STEP_UP = [op for op in SCOPED if op.step_up == "always"]
NOT_BREAK_GLASS = [op for op in PROTECTED if op.operation_id != "pullKillSwitch"]


def _has_agent_id(op: ContractOperation) -> bool:
    return any(p["name"] == "agent_id" for p in op.path_params)


# Object-rule cases (security M3): the rule must hold once the route is real.
GROUP_SCOPED = [
    op
    for op in SCOPED
    if "group" in op.object_rules
    and _has_agent_id(op)
    and ROLE_GRANTS["engineer"].get(op.scope) is Mark.GROUP
]
BOUND_AGENT = [
    op
    for op in SCOPED
    if "bound_agent" in op.object_rules and _has_agent_id(op) and "api_key" in op.principals
]
JOB_OWNER = [op for op in API_OPS if "job_owner" in op.object_rules]
CONDITIONAL_STEP_UP = {
    "createApiKey": {"name": "break-glass", "env": "live", "scopes": ["killswitch:pull"]},
    "pullKillSwitch": {"scope_kind": "tenant", "reason": "contract wall: stale session pulls"},
}

# Test review F8: pin the generated subsets so a filter regression cannot shrink the wall.
EXPECTED_SIZES = {  # + clearPreemptiveBreaker (INT-3, B19) on every line it belongs to
    "API_OPS": 185,  # 188 operations - 3 ingest (getQueueSummary folded into listQueue)
    # + 4 D51 drift, + 7 D52 Sentinel, + 2 AG-LIVE, + 1 INT-3, + 2 GAPS runs, + 13 D53 EXTMON
    # + 2 HARDEN drift thresholds (get/put)
    "PROTECTED": 181,
    "SCOPED": 173,
    "WITH_IDS": 80,  # + 3 D51 drift, + 2 D52 Sentinel, + 1 INT-3, + getRun, + 3 D53 (key-free)
    # + 10 D53 admin and feedback routes, - 10 reads monitor keys may now call (D53),
    # + 2 HARDEN drift thresholds
    "SESSION_ONLY": 142,
    "STEP_UP": 12,  # + putSentinelConfig, + clearPreemptiveBreaker
    "NOT_BREAK_GLASS": 180,
    "GROUP_SCOPED": 10,
    "BOUND_AGENT": 8,
    "JOB_OWNER": 1,
}


def _type(resp) -> str:
    try:
        body = resp.json()
    except ValueError:
        return ""
    return body.get("type", "") if isinstance(body, dict) else ""


# --- guard-level (in-memory harness) -----------------------------------------------------------


@pytest.mark.parametrize("op", guard_params(PROTECTED))
def test_no_principal_is_401(harness, op) -> None:
    resp = call(harness, op, None)
    assert resp.status_code == 401
    assert _type(resp).endswith("/unauthenticated")


@pytest.mark.parametrize("op", guard_params(SCOPED))
def test_principal_without_scope_is_403(harness, op) -> None:
    resp = call(harness, op, "nobody-a")
    assert resp.status_code == 403
    assert _type(resp).endswith("/forbidden")
    assert "access.denied" in harness.audit.all_actions()


@pytest.mark.parametrize("op", guard_params(SESSION_ONLY))
def test_api_keys_cannot_reach_session_only_routes(harness, op) -> None:
    resp = call(harness, op, "keys-a")
    assert resp.status_code == 403


@pytest.mark.parametrize("op", guard_params(NOT_BREAK_GLASS))
def test_break_glass_key_is_refused_outside_its_route(harness, op) -> None:
    resp = call(harness, op, "breakglass-a")
    assert resp.status_code == 403
    assert _type(resp).endswith("/break_glass_key_misuse")


@pytest.mark.parametrize("op", guard_params(STEP_UP))
def test_step_up_routes_refuse_a_stale_session(harness, op) -> None:
    resp = call(harness, op, "owner-a-stale")
    assert resp.status_code == 403
    assert _type(resp).endswith("/step_up_required")
    assert resp.json().get("step_up_url")


@pytest.mark.parametrize("op", guard_params(SCOPED))
def test_every_scope_but_the_routes_own_is_403(harness, op) -> None:
    """A principal holding every other scope is still refused: catches a route guarded by the
    wrong scope, which the no-roles case cannot see."""
    wanted = {op.scope, *op.scope_any}
    grants = {s: _Grant(s) for s in SCOPES - wanted}
    principal = Principal(PrincipalKind.SESSION, TENANT_A, uuid4(), grants, session_id=uuid4())
    harness.principals.add("all-but", principal)
    resp = call(harness, op, "all-but")
    assert resp.status_code == 403
    assert _type(resp).endswith("/forbidden")


@pytest.mark.parametrize(
    "op", guard_params([o for o in API_OPS if o.operation_id in CONDITIONAL_STEP_UP])
)
def test_conditional_step_up_applies_to_break_glass_paths(harness, op) -> None:
    resp = harness.client.request(
        op.method.upper(),
        concrete_path(op),
        json=CONDITIONAL_STEP_UP[op.operation_id],
        headers={
            "Authorization": "Bearer owner-a-stale",
            "Idempotency-Key": f"cs-{op.operation_id}",
        },
    )
    assert resp.status_code == 403
    assert _type(resp).endswith("/step_up_required")


def test_generated_subsets_have_the_pinned_sizes() -> None:
    actual = {name: len(globals()[name]) for name in EXPECTED_SIZES}
    assert actual == EXPECTED_SIZES


# --- object rules on real objects (contract_world) ---------------------------------------------


# Path parameters that name no tenant object: the foreign owner acts on its own tenant.
OWN_TENANT_ONLY = {"rotateTenantKey": "the path names a key purpose, not a tenant-A object"}


@pytest.mark.parametrize("op", world_params(WITH_IDS))
def test_foreign_tenant_ids_are_404_never_403(request, op) -> None:
    if not needs_world(op):
        resp = call(request.getfixturevalue("harness"), op, "owner-b")
        assert resp.status_code == 404
        return
    world = request.getfixturevalue("cworld")
    if op.operation_id in OWN_TENANT_ONLY:
        before = world.admin.fetch(
            "SELECT id, version, state FROM sibyl.tenant_key WHERE tenant_id = $1 ORDER BY id",
            world.a.id,
        )
        resp = world_call(world, op, scenario(world, op), "owner-b")
        assert resp.status_code < 300, resp.text
        after = world.admin.fetch(
            "SELECT id, version, state FROM sibyl.tenant_key WHERE tenant_id = $1 ORDER BY id",
            world.a.id,
        )
        assert [dict(r) for r in after] == [dict(r) for r in before]  # tenant A untouched
        return
    resp = world_call(world, op, scenario(world, op), "owner-b")
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize("op", world_params(GROUP_SCOPED))
def test_group_limited_principal_gets_404_outside_its_group(request, op) -> None:
    if not needs_world(op):
        resp = call(request.getfixturevalue("harness"), op, "engineer-group-a")
        assert resp.status_code == 404
        return
    world = request.getfixturevalue("cworld")
    req = scenario(world, op)
    assert req.agent_id is not None  # the scenario's agent is outside the engineer's group
    resp = world_call(world, op, req, "engineer")
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize("op", world_params(BOUND_AGENT))
def test_agent_bound_key_gets_404_on_another_agent(request, op) -> None:
    if not needs_world(op):
        resp = call(request.getfixturevalue("harness"), op, "bound-key-a")
        assert resp.status_code == 404
        return
    world = request.getfixturevalue("cworld")
    req = scenario(world, op)
    assert req.agent_id is not None and req.agent_id != str(world.a.agents["bound"])
    resp = world_call(world, op, req, "bound")
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize("op", world_params(JOB_OWNER))
def test_jobs_of_another_user_are_404(request, op) -> None:
    if not needs_world(op):
        resp = call(request.getfixturevalue("harness"), op, "nobody-a")
        assert resp.status_code == 404
        return
    world = request.getfixturevalue("cworld")
    req = scenario(world, op)  # a job the owner requested
    assert world_call(world, op, req, "owner").status_code == 200
    for other in ("admin", "nobody", "owner-b"):
        resp = world_call(world, op, req, other)
        assert resp.status_code == 404, (other, resp.text)


def test_every_implemented_operation_has_a_scenario_or_an_exemption() -> None:
    implemented = {op.operation_id for op in PROTECTED if op.module not in PENDING_MODULES}
    missing = sorted(implemented - set(SCENARIOS) - set(EXEMPT))
    assert missing == []
    assert set(SCENARIOS).isdisjoint(EXEMPT)
    stale = sorted(set(SCENARIOS) - {op.operation_id for op in API_OPS})
    assert stale == []


@pytest.mark.parametrize("op", [o for o in API_OPS if o.operation_id in CUT_BY_RULING])
def test_cut_operations_answer_501_only_after_authorisation(harness, op) -> None:
    """A guarded 501 (cut by ruling, not a mounted stub): its whole guard-level wall stays
    strict above, and an authorised principal gets ``not_implemented`` with nothing audited."""
    assert op.operation_id not in STUBS
    resp = call(harness, op, "owner-a")
    assert resp.status_code == 501, resp.text
    assert _type(resp).endswith("/not_implemented")
    assert harness.audit.actions(TENANT_A) == []


def test_pending_modules_are_derived_from_mounted_stubs() -> None:
    """Stub detection works (the by-ruling stub is seen) and pending = modules with a stub."""
    assert STUB_BY_RULING <= STUBS
    modules = {op.operation_id: op.module for op in API_OPS}
    assert {modules[s] for s in STUBS - STUB_BY_RULING} == PENDING_MODULES
