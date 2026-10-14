"""G0: the kernel's catalogues are imports of ``sibyl_schemas.values``, never local copies.

Each test pins one catalogue to the schemas registry; the ``*_unchanged`` tests freeze the
wave-0 behaviour the import replaced, so moving the source cannot silently change authz.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sibyl_control.core import audit, authz, problems, ratelimit
from sibyl_control.core.authz import Principal, PrincipalKind
from sibyl_control.migrate import errcodes
from sibyl_schemas import values as v

# The wave-0 kernel matrix (T tenant, G group, A audited, . none), frozen as the expectation.
# fmt: off
_WAVE0_MATRIX = {
    "tenant:read":          "TTTTTTT", "tenant:write":       "T......",
    "users:manage":         "TT.....", "oidc:manage":        "TT.....",
    "apikeys:manage":       "TT.....", "apikeys:manage_agent": "TT.G...",
    "agents:read":          "TTTTTTT", "agents:write":       "TT.G...",
    "agents:approve":       "TTT....", "identity:write":     "TTTG...",
    "capture:write":        "TTT....", "credentials:manage": "TTT....",
    "credentials:read":     "TTTG.T.", "keys:read":          "T.T....",
    "keys:rotate":          "T.T....", "routing:read":       "TTTTTTT",
    "routing:write":        "TTTG...", "incidents:act":      "T.TGT..",
    "routing:override":     "T.TG...", "approvals:decide":   "T.T....",
    "quarantine:act":       "T.T....", "killswitch:pull":    "T.T....",
    "killswitch:release":   "T.T....", "queue:act":          "T...T..",
    "packets:read":         "T.TGTA.", "payloads:read":      "T.TG.A.",
    "payloads:reveal":      "A.A..A.", "alerts:act":         "T.TGT..",
    "audit:read":           "TTTG.T.", "audit:verify":       "TTT..T.",
    "audit:export":         "A.A..A.", "data:export":        "A.A..A.",
    "erasure:request":      "TTT....", "erasure:approve":    "T.T....",
    "holds:manage":         "T.T....", "gateway:proxy":      ".......",
    "ingest:write":         ".......", "handoff:write":      ".......",
    # D48 Action Gate (lane AG-CORE)
    "actions:read":         "TTTTTTT", "actions:decide":     "T.T.T..",
    "action_policies:write": "TTT....", "actions:hold":      ".......",
    "drift:read":           "TTTTTTT", "drift:write":        "TTT....",  # D51
    # D52 Sibyl Sentinel
    "sentinel:read":        "TTT.TT.", "sentinel:admin":     "TTT....",
    # D53 external monitors (monitor:read and findings:write are monitor-bound keys only)
    "monitor:read":         ".......", "findings:write":     ".......",
    "monitors:admin":       "TTT....",
}
# fmt: on


def test_authz_has_no_local_matrix() -> None:
    assert not hasattr(authz, "_MATRIX")
    assert authz.SCOPE_CATALOGUE is v.SCOPE_CATALOGUE


def test_role_grants_unchanged() -> None:
    assert authz.ROLES == tuple(r.value for r in v.Role)
    derived = {
        scope: "".join(
            authz.ROLE_GRANTS[role][scope].value if scope in authz.ROLE_GRANTS[role] else "."
            for role in authz.ROLES
        )
        for scope in _WAVE0_MATRIX
    }
    assert derived == _WAVE0_MATRIX
    assert len(authz.SCOPES) == 49 and set(authz.SCOPES) == set(_WAVE0_MATRIX)


def test_scope_sets_unchanged() -> None:
    assert authz.KEY_SCOPES == {
        "ingest:write",
        "gateway:proxy",
        "routing:read",
        "handoff:write",
        "agents:read",
        "agents:write",
        "killswitch:pull",
        "actions:hold",
        "monitor:read",  # D53: monitor-bound keys only
        "findings:write",
    }
    assert authz.M_ONLY_SCOPES == {
        "gateway:proxy",
        "ingest:write",
        "handoff:write",
        "actions:hold",
        "monitor:read",  # D53
        "findings:write",
    }
    assert authz.BREAK_GLASS_SCOPE == "killswitch:pull"
    assert authz.STEP_UP_SCOPES == {
        "tenant:write",
        "oidc:manage",
        "credentials:manage",
        "keys:rotate",
        "killswitch:pull",
        "killswitch:release",
        "erasure:approve",
        "holds:manage",
    }
    assert "keys:read" in authz.SCOPES and "keys:read" not in authz.STEP_UP_SCOPES
    assert all(type(s) is str for s in authz.SCOPES | authz.KEY_SCOPES | authz.STEP_UP_SCOPES)


def test_problem_registry_is_the_schemas_registry() -> None:
    assert set(problems.PROBLEM_CODES) == {c.value for c in v.ProblemCode}
    for code in v.ProblemCode:
        spec = problems.PROBLEM_CODES[code.value]
        assert spec.statuses == v.problem_statuses(code), code
        assert spec.title == v.PROBLEM_TITLE[code], code


def test_db_error_registry_matches_migration_errcodes() -> None:
    assert set(errcodes.SQLSTATE_TO_CODE.values()) == set(v.DB_ERROR_PROBLEM)
    assert all(state.startswith(v.DB_ERROR_SQLSTATE_CLASS) for state in errcodes.SQLSTATE_TO_CODE)


def test_audit_registry_is_the_schemas_registry() -> None:
    assert audit.AUDIT_ACTIONS == v.AUDIT_ACTION_NAMES
    assert audit.ACTOR_TYPES == {a.value for a in v.ActorType}


def test_audit_record_refuses_an_actor_the_taxonomy_forbids() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        audit.AuditRecord(action="killswitch.pulled", actor_type="system", resource_type="k")
    audit.AuditRecord(action="killswitch.pulled", actor_type="api_key", resource_type="k")


def _key(scopes: set[str], agent: bool = False) -> Principal:
    return Principal(
        kind=PrincipalKind.API_KEY,
        tenant_id=uuid4(),
        id=uuid4(),
        grants=authz.grants_for_api_key(scopes),
        bound_agent_id=uuid4() if agent else None,
    )


def test_break_glass_key_is_the_audit_actor() -> None:
    key = _key({"killswitch:pull"})
    actor = audit.audit_actor(key)
    assert actor == audit.AuditActor("api_key", None, key.id, None)
    record = audit.AuditRecord(
        action="killswitch.pulled",
        resource_type="kill_switch",
        **actor.fields(),
    )
    assert record.actor_type == "api_key" and record.actor_key_id == key.id


def test_audit_actor_for_humans_agents_and_gateways() -> None:
    """Chair ruling G0-6: every API-key principal is ``api_key`` with its key id."""
    session = uuid4()
    human = Principal(PrincipalKind.SESSION, uuid4(), uuid4(), session_id=session)
    assert audit.audit_actor(human) == audit.AuditActor("human", human.id, None, session)
    bound = _key({"ingest:write"}, agent=True)
    assert audit.audit_actor(bound) == audit.AuditActor("api_key", None, bound.id, None)
    gateway = _key({"gateway:proxy", "routing:read"})
    assert audit.audit_actor(gateway) == audit.AuditActor("api_key", None, gateway.id, None)


def test_rate_policies_are_the_schemas_policies() -> None:
    assert set(ratelimit.POLICIES) == set(v.RATE_POLICY_SPECS)
    for name, spec in v.RATE_POLICY_SPECS.items():
        policy = ratelimit.POLICIES[name]
        assert (policy.quota, policy.window_s, policy.burst) == (
            spec.quota,
            spec.window_s,
            spec.burst,
        )


def test_outbox_topics_and_channels_are_the_schemas_bus() -> None:
    from sibyl_control.core import outbox

    assert outbox.TOPICS == tuple(t.value for t in v.OutboxTopic)
    assert outbox.EVENT_TOPICS == {e: t.value for e, t in v.OUTBOX_EVENT_TOPIC.items()}
    assert {t: outbox.channel_for(t) for t in outbox.TOPICS} == {
        t.value: c.value for t, c in v.TOPIC_CHANNEL.items()
    }
    assert (outbox.POLICY_CHANNEL, outbox.OUTBOX_CHANNEL) == (
        v.NotifyChannel.POLICY.value,
        v.NotifyChannel.OUTBOX.value,
    )
    assert type(outbox.TOPICS[0]) is str


def test_transition_error_is_spelled_invalid_transition_everywhere() -> None:
    from pathlib import Path

    from sibyl_control.api.contract import contract_path

    assert "illegal_transition" not in Path(contract_path()).read_text(encoding="utf-8")
    assert "illegal_transition" not in problems.PROBLEM_CODES
    assert problems.PROBLEM_CODES["invalid_transition"].statuses == (409,)
    migrations = sorted((Path(errcodes.__file__).parents[3] / "migrations").glob("*.sql"))
    assert len(migrations) >= 16
    assert all("illegal_transition" not in p.read_text() for p in migrations)
