"""Scope catalogue (API §2.2, R21, D20, D30) and role mapping."""

from __future__ import annotations

import re

import pytest
from sibyl_schemas.values import (
    DEFAULT_SDK_KEY_SCOPES,
    GATEWAY_KEY_SCOPES,
    MACHINE_SCOPES,
    RATE_POLICIES,
    ROLE_SCOPES,
    SCOPE_CATALOGUE,
    SCOPE_PATTERN,
    SDK_FORBIDDEN_SCOPES,
    TENANT_KEY_ROUTES,
    GrantMode,
    IncidentAction,
    MachineGrant,
    Role,
    RoutingState,
    Scope,
    TenantKeyPurpose,
    TenantKeyState,
    api_key_scope_errors,
    incident_action_scope,
)


def test_every_scope_uses_resource_verb_grammar() -> None:
    pattern = re.compile(SCOPE_PATTERN)
    for scope in Scope:
        assert pattern.fullmatch(scope.value), scope


def test_catalogue_is_total_and_has_44_scopes() -> None:
    assert set(SCOPE_CATALOGUE) == set(Scope)
    # 38 + four D48 Action Gate + two D51 drift + two D52 Sentinel + three D53 monitor scopes
    assert len(Scope) == 49


def test_keys_read_matches_keys_rotate_grants_without_step_up() -> None:
    read = SCOPE_CATALOGUE[Scope.KEYS_READ]
    rotate = SCOPE_CATALOGUE[Scope.KEYS_ROTATE]
    assert set(read.grants) == set(rotate.grants) == {Role.OWNER, Role.SECURITY_ADMIN}
    assert all(g.mode is GrantMode.TENANT and not g.step_up for g in read.grants.values())
    assert read.machine is MachineGrant.NONE
    assert Scope.KEYS_READ not in MACHINE_SCOPES


def test_tenant_key_routes_contract() -> None:
    listing, rotate = TENANT_KEY_ROUTES
    assert (listing.method, listing.scope, listing.audit) == ("GET", Scope.KEYS_READ, None)
    assert not listing.step_up
    assert rotate.path == "/api/v1/tenant-keys/{purpose}/rotate"
    assert (rotate.scope, rotate.step_up, rotate.idempotent) == (Scope.KEYS_ROTATE, True, True)
    assert rotate.audit == "tenant_key.rotated"
    assert rotate.rate_policy is not None
    assert RATE_POLICIES[rotate.rate_policy] == (6, 3600)
    assert [p.value for p in TenantKeyPurpose] == ["payload", "credential", "config"]
    assert [s.value for s in TenantKeyState] == ["active", "retired", "shredded"]


def test_step3_names_are_not_aliased() -> None:
    values = {s.value for s in Scope}
    for legacy in ("telemetry:write", "registry:read", "registry:write", "route:read"):
        assert legacy not in values
    assert "gateway:snapshot" not in values  # R26/D31: no platform gateway credential


def test_seven_roles() -> None:
    assert [r.value for r in Role] == [
        "owner",
        "admin",
        "security_admin",
        "engineer",
        "operator",
        "auditor",
        "viewer",
    ]
    assert set(ROLE_SCOPES) == set(Role)


def test_machine_only_scopes_are_never_granted_to_roles() -> None:
    for scope in (Scope.GATEWAY_PROXY, Scope.INGEST_WRITE, Scope.HANDOFF_WRITE):
        assert SCOPE_CATALOGUE[scope].machine is MachineGrant.ONLY
        assert not SCOPE_CATALOGUE[scope].grants
        for role in Role:
            assert scope not in ROLE_SCOPES[role]


def test_machine_grantable_set() -> None:
    assert (
        frozenset(
            {
                Scope.AGENTS_READ,
                Scope.AGENTS_WRITE,
                Scope.ROUTING_READ,
                Scope.KILLSWITCH_PULL,
                Scope.GATEWAY_PROXY,
                Scope.INGEST_WRITE,
                Scope.HANDOFF_WRITE,
                Scope.ACTIONS_HOLD,
                Scope.MONITOR_READ,
                Scope.FINDINGS_WRITE,
            }
        )
        == MACHINE_SCOPES
    )
    assert SCOPE_CATALOGUE[Scope.MONITOR_READ].machine is MachineGrant.MONITOR_BOUND
    assert SCOPE_CATALOGUE[Scope.KILLSWITCH_PULL].machine is MachineGrant.EXCLUSIVE
    assert SCOPE_CATALOGUE[Scope.AGENTS_WRITE].machine is MachineGrant.BOUND_ONLY


def test_viewer_is_read_only() -> None:
    assert ROLE_SCOPES[Role.VIEWER] == frozenset(
        {
            Scope.TENANT_READ,
            Scope.AGENTS_READ,
            Scope.ROUTING_READ,
            Scope.ACTIONS_READ,
            Scope.DRIFT_READ,
        }
    )


def test_step_up_and_audited_markers() -> None:
    pull = SCOPE_CATALOGUE[Scope.KILLSWITCH_PULL].grants
    assert set(pull) == {Role.OWNER, Role.SECURITY_ADMIN}
    assert all(g.step_up for g in pull.values())
    reveal = SCOPE_CATALOGUE[Scope.PAYLOADS_REVEAL].grants
    assert all(g.audited for g in reveal.values())
    assert SCOPE_CATALOGUE[Scope.ROUTING_OVERRIDE].grants[Role.ENGINEER].mode is GrantMode.GROUP
    assert SCOPE_CATALOGUE[Scope.INCIDENTS_ACT].grants[Role.OPERATOR].note


def test_r56_demo_personas_can_perform_scripted_actions() -> None:
    # Platform Admin = owner, On-call Operator = operator + security_admin,
    # Compliance Auditor = auditor (R56)
    on_call = ROLE_SCOPES[Role.OPERATOR] | ROLE_SCOPES[Role.SECURITY_ADMIN]
    assert {Scope.QUEUE_ACT, Scope.APPROVALS_DECIDE, Scope.KILLSWITCH_PULL} <= on_call
    assert {Scope.AUDIT_VERIFY, Scope.AUDIT_EXPORT} <= ROLE_SCOPES[Role.AUDITOR]
    assert Scope.KILLSWITCH_PULL in ROLE_SCOPES[Role.OWNER]


def test_quickstart_key_scopes_are_valid() -> None:
    assert api_key_scope_errors(DEFAULT_SDK_KEY_SCOPES, agent_bound=True, env="live") == []
    assert api_key_scope_errors(GATEWAY_KEY_SCOPES, agent_bound=False, env="live") == []
    assert SDK_FORBIDDEN_SCOPES == frozenset({Scope.GATEWAY_PROXY, Scope.KILLSWITCH_PULL})


@pytest.mark.parametrize(
    ("scopes", "agent_bound", "env", "fragment"),
    [
        ((Scope.KILLSWITCH_PULL, Scope.ROUTING_READ), False, "live", "exclusive"),
        ((Scope.KILLSWITCH_PULL,), True, "live", "tenant-level"),
        ((Scope.KILLSWITCH_PULL,), False, "test", "live"),
        ((Scope.AUDIT_READ,), False, "live", "not grantable"),
        ((Scope.AGENTS_WRITE,), False, "live", "agent-bound"),
        ((), True, "live", "at least one"),
        ((Scope.INGEST_WRITE, Scope.INGEST_WRITE), True, "live", "duplicate"),
        ((Scope.INGEST_WRITE,), True, "prod", "env"),
    ],
)
def test_api_key_scope_rules(
    scopes: tuple[Scope, ...], agent_bound: bool, env: str, fragment: str
) -> None:
    errors = api_key_scope_errors(scopes, agent_bound=agent_bound, env=env)
    assert any(fragment in e for e in errors), errors


def test_break_glass_key_shape_is_valid() -> None:
    assert api_key_scope_errors((Scope.KILLSWITCH_PULL,), agent_bound=False, env="live") == []


def test_incident_action_scopes_follow_r25_table() -> None:
    assert incident_action_scope(IncidentAction.FAILOVER) is Scope.ROUTING_OVERRIDE
    assert incident_action_scope(IncidentAction.KILL) is Scope.KILLSWITCH_PULL
    assert incident_action_scope(IncidentAction.APPROVE) is Scope.APPROVALS_DECIDE
    assert incident_action_scope(IncidentAction.QUARANTINE) is Scope.QUARANTINE_ACT
    assert (
        incident_action_scope(IncidentAction.RELEASE, from_state=RoutingState.KILLED)
        is Scope.KILLSWITCH_RELEASE
    )
    assert (
        incident_action_scope(IncidentAction.RELEASE, from_state=RoutingState.QUARANTINED)
        is Scope.QUARANTINE_ACT
    )
    with pytest.raises(ValueError, match="from_state"):
        incident_action_scope(IncidentAction.RELEASE)
    with pytest.raises(ValueError, match="release"):
        incident_action_scope(IncidentAction.RELEASE, from_state=RoutingState.ACTIVE)
    for action in IncidentAction:
        if action is not IncidentAction.RELEASE:
            assert isinstance(incident_action_scope(action), Scope)
