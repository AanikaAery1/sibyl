from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.authz import (
    KEY_SCOPES,
    M_ONLY_SCOPES,
    ROLE_GRANTS,
    ROLES,
    SCOPES,
    MembershipGrant,
    Principal,
    PrincipalKind,
    authorize,
    grants_for_api_key,
    grants_from_memberships,
)
from sibyl_control.core.problems import ProblemError

NOW = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)
TENANT = UUID("01927000-0000-7000-8000-000000000001")
GROUP_A = UUID("01927000-0000-7000-8000-00000000000a")
GROUP_B = UUID("01927000-0000-7000-8000-00000000000b")


def human(role: str, group: UUID | None = None, *, step_up_at=None, kind=PrincipalKind.SESSION):
    return Principal(
        kind=kind,
        tenant_id=TENANT,
        id=uuid4(),
        grants=grants_from_memberships([MembershipGrant(role, group)]),
        session_id=uuid4() if kind is PrincipalKind.SESSION else None,
        step_up_at=step_up_at,
        roles=frozenset({role}),
    )


def key(*scopes: str, agent: UUID | None = None) -> Principal:
    return Principal(
        kind=PrincipalKind.API_KEY,
        tenant_id=TENANT,
        id=uuid4(),
        grants=grants_for_api_key(scopes),
        bound_agent_id=agent,
    )


def test_catalogue_has_44_scopes_in_resource_verb_grammar() -> None:
    # 38 + four D48 Action Gate + two D51 drift + two D52 Sentinel + three D53 monitor scopes
    assert len(SCOPES) == 49
    assert all(s.count(":") == 1 for s in SCOPES)
    assert KEY_SCOPES <= SCOPES
    assert M_ONLY_SCOPES == {
        "gateway:proxy",
        "ingest:write",
        "handoff:write",
        "actions:hold",
        "monitor:read",  # D53
        "findings:write",
    }


def test_no_role_holds_a_machine_only_scope() -> None:
    for role in ROLES:
        assert not (set(ROLE_GRANTS[role]) & M_ONLY_SCOPES), role


def test_owner_holds_every_human_scope() -> None:
    assert set(ROLE_GRANTS["owner"]) == SCOPES - M_ONLY_SCOPES


@pytest.mark.parametrize(
    ("role", "scope", "allowed"),
    [
        ("viewer", "agents:read", True),
        ("viewer", "agents:write", False),
        ("operator", "queue:act", True),
        ("operator", "routing:override", False),
        ("engineer", "routing:override", True),
        ("auditor", "payloads:reveal", True),
        ("auditor", "audit:verify", True),
        ("admin", "killswitch:pull", False),
        ("security_admin", "killswitch:release", True),
        ("admin", "erasure:approve", False),
    ],
)
def test_role_matrix_samples(role: str, scope: str, allowed: bool) -> None:
    principal = human(role)
    if allowed:
        authorize(principal, scope, now=NOW)
    else:
        with pytest.raises(ProblemError) as err:
            authorize(principal, scope, now=NOW)
        assert err.value.status == 403
        assert err.value.audit_denied


def test_unauthenticated_is_401() -> None:
    with pytest.raises(ProblemError) as err:
        authorize(None, "agents:read", now=NOW)
    assert err.value.status == 401
    assert err.value.code == "unauthenticated"


def test_group_rule_out_of_group_is_404_not_403() -> None:
    engineer = human("engineer", GROUP_A)
    authorize(engineer, "agents:write", resource_group_id=GROUP_A, now=NOW)
    with pytest.raises(ProblemError) as err:
        authorize(engineer, "agents:write", resource_group_id=GROUP_B, now=NOW)
    assert err.value.status == 404


def test_tenant_wide_mark_ignores_membership_group() -> None:
    engineer = human("engineer", GROUP_A)
    authorize(engineer, "agents:read", resource_group_id=GROUP_B, now=NOW)


def test_tenant_scoped_membership_makes_group_marks_tenant_wide() -> None:
    engineer = human("engineer", None)
    authorize(engineer, "agents:write", resource_group_id=GROUP_B, now=NOW)


def test_memberships_merge_to_the_widest_grant() -> None:
    grants = grants_from_memberships(
        [MembershipGrant("engineer", GROUP_A), MembershipGrant("engineer", GROUP_B)]
    )
    assert grants["agents:write"].group_ids == frozenset({GROUP_A, GROUP_B})
    grants = grants_from_memberships(
        [MembershipGrant("engineer", GROUP_A), MembershipGrant("admin", None)]
    )
    assert grants["agents:write"].group_ids is None


def test_audited_mark_is_carried_on_the_grant() -> None:
    grant = authorize(human("auditor"), "payloads:reveal", now=NOW)
    assert grant.audited


def test_scope_any_accepts_an_alternative() -> None:
    grant = authorize(
        human("engineer", GROUP_A),
        "apikeys:manage",
        scope_any=("apikeys:manage_agent",),
        resource_group_id=GROUP_A,
        now=NOW,
    )
    assert grant.scope == "apikeys:manage_agent"


def test_self_rule_allows_own_resource_without_scope() -> None:
    viewer = human("viewer")
    authorize(viewer, "users:manage", self_id=viewer.id, now=NOW)
    with pytest.raises(ProblemError):
        authorize(viewer, "users:manage", self_id=uuid4(), now=NOW)


def test_step_up_required_when_stale_or_missing() -> None:
    fresh = human("owner", step_up_at=NOW - timedelta(minutes=4))
    authorize(fresh, "tenant:write", step_up=True, now=NOW)
    for stale in (None, NOW - timedelta(minutes=6)):
        with pytest.raises(ProblemError) as err:
            authorize(
                human("owner", step_up_at=stale),
                "tenant:write",
                step_up=True,
                step_up_url="/api/v1/auth/step-up",
                now=NOW,
            )
        assert err.value.code == "step_up_required"
        assert err.value.extensions["step_up_url"] == "/api/v1/auth/step-up"


def test_jwt_principals_can_never_satisfy_step_up() -> None:
    jwt = human("owner", step_up_at=NOW, kind=PrincipalKind.OIDC)
    with pytest.raises(ProblemError) as err:
        authorize(jwt, "tenant:write", step_up=True, now=NOW)
    assert err.value.code == "step_up_required"


def test_keys_only_reach_routes_that_list_their_scope() -> None:
    k = key("agents:read")
    authorize(k, "agents:read", key_scopes=("agents:read",), now=NOW)
    with pytest.raises(ProblemError) as err:
        authorize(k, "agents:read", key_scopes=(), now=NOW)
    assert err.value.status == 403


def test_keys_skip_step_up() -> None:
    k = key("killswitch:pull")
    authorize(k, "killswitch:pull", key_scopes=("killswitch:pull",), step_up=True, now=NOW)


def test_break_glass_key_is_refused_everywhere_else() -> None:
    k = key("killswitch:pull")
    assert k.is_break_glass
    with pytest.raises(ProblemError) as err:
        authorize(k, "agents:read", key_scopes=("agents:read",), now=NOW)
    assert err.value.code == "break_glass_key_misuse"


def test_bound_key_cannot_reach_another_agent() -> None:
    agent = uuid4()
    k = key("agents:read", agent=agent)
    authorize(k, "agents:read", key_scopes=("agents:read",), resource_agent_id=agent, now=NOW)
    with pytest.raises(ProblemError) as err:
        authorize(k, "agents:read", key_scopes=("agents:read",), resource_agent_id=uuid4(), now=NOW)
    assert err.value.status == 404


def test_group_limited_grant_cannot_reach_an_ungrouped_resource() -> None:
    with pytest.raises(ProblemError) as err:
        authorize(human("engineer", GROUP_A), "agents:write", resource_group_id=None, now=NOW)
    assert err.value.status == 404


def test_unknown_scope_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="unknown scope"):
        authorize(human("owner"), "agents:delete", now=NOW)


def test_principal_is_immutable() -> None:
    p = human("viewer")
    with pytest.raises(AttributeError):
        p.tenant_id = uuid4()  # type: ignore[misc]
