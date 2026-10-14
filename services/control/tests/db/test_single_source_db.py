"""G0 drift: the migrated database's catalogues equal ``sibyl_schemas.values`` exactly.

``role_permission`` = the scope catalogue's role grants (API §2.2 + ``keys:read``),
``audit_action`` = the audit taxonomy (rulings G0-2, G0-4 and the break-glass actor),
``state_edge`` = the ten machines (G0-3, B14 ``job``), and the CHECK constraints that enumerate
actor kinds, anchor kinds and key statuses equal the schemas value sets.
"""

from __future__ import annotations

import re
import uuid
from enum import Enum

import asyncpg
import pytest
from sibyl_control.core.problems import problem_from_db_error
from sibyl_schemas import values as sv

from .conftest import Conn
from .fixtures import TenantFixture, h32, populate_tenant


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "single-source")


def test_role_permission_equals_schemas_role_grants(admin: Conn) -> None:
    rows = admin.fetch(
        "SELECT role_name, permission, scope_rule, step_up, self_audited FROM sibyl.role_permission"
    )
    db = {
        (r["role_name"], r["permission"]): (r["scope_rule"], r["step_up"], r["self_audited"])
        for r in rows
    }
    expected = {
        (role.value, spec.scope.value): (
            "scoped" if grant.mode is sv.GrantMode.GROUP else "tenant",
            grant.step_up,
            grant.audited,
        )
        for spec in sv.SCOPE_CATALOGUE.values()
        for role, grant in spec.grants.items()
    }
    assert len(rows) == len(db)
    assert db == expected, {
        "db_only": sorted(set(db) - set(expected)),
        "schemas_only": sorted(set(expected) - set(db)),
        "different": sorted(k for k in set(db) & set(expected) if db[k] != expected[k]),
    }
    roles = {r["name"] for r in admin.fetch("SELECT name FROM sibyl.role")}
    assert roles == {r.value for r in sv.Role}


def test_audit_action_rows_equal_schemas_taxonomy(admin: Conn) -> None:
    rows = admin.fetch("SELECT * FROM sibyl.audit_action")
    db = {
        r["name"]: (
            r["domain"],
            frozenset(r["actor_types"]),
            r["resource_type"],
            tuple(r["required_fields"]),
            r["reason_required"],
            r["is_evidence"],
            r["severity"],
        )
        for r in rows
    }
    expected = {
        a.name: (
            a.domain,
            frozenset(t.value for t in a.actor_types),
            a.resource_type,
            a.required_fields,
            a.reason_required,
            a.is_evidence,
            a.severity.value,
        )
        for a in sv.AUDIT_ACTIONS.values()
    }
    assert db == expected, {
        "db_only": sorted(set(db) - set(expected)),
        "schemas_only": sorted(set(expected) - set(db)),
        "different": {
            k: (db[k], expected[k]) for k in set(db) & set(expected) if db[k] != expected[k]
        },
    }


def test_state_edges_equal_schemas(admin: Conn) -> None:
    rows = admin.fetch("SELECT machine, from_state, to_state, trigger FROM sibyl.state_edge")
    db = {sv.StateEdge(r["machine"], r["from_state"], r["to_state"], r["trigger"]) for r in rows}
    assert len(rows) == len(db)
    assert db == sv.STATE_EDGES, {
        "db_only": sorted(db - sv.STATE_EDGES),
        "schemas_only": sorted(sv.STATE_EDGES - db),
    }


@pytest.mark.parametrize(
    ("table", "constraint", "value_set"),
    [
        ("audit_events", "ck_audit_events_actor_type", sv.ActorType),
        ("routing_transition", "ck_routing_transition_actor_kind", sv.ActorKind),
        ("failover", "ck_failover_actor_kind", sv.ActorKind),
        ("audit_anchors", "ck_audit_anchors_kind", sv.AnchorKind),
        ("api_key", "ck_api_key_status", sv.ApiKeyStatus),
        ("audit_events", "ck_audit_events_severity", sv.AuditSeverity),
        ("outbox", "ck_outbox_topic", sv.OutboxTopic),
    ],
)
def test_check_constraints_equal_schemas_value_sets(
    admin: Conn, table: str, constraint: str, value_set: type[Enum]
) -> None:
    definition = admin.fetchval(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = $1::regclass AND conname = $2",
        f"sibyl.{table}",
        constraint,
    )
    assert definition, f"{table}.{constraint} missing"
    assert set(re.findall(r"'([^']*)'::text", definition)) == {str(m.value) for m in value_set}


# --- every enumerated CHECK against the schemas value sets (G0-tests F12) -----------------

# Each single-column `col IN (...)` CHECK whose values are a schemas value set, by enum name.
CHECK_VALUE_SETS: dict[str, str] = {
    "agent_identity.enforcement": "IdentityEnforcement",
    "agent.fail_mode": "FailMode",
    "agent.kind": "AgentKind",
    "agent.lifecycle": "Lifecycle",
    "agent.risk_class": "RiskClass",
    "alert_rule.kind": "RuleKind",
    "alert_rule.severity": "AlertSeverity",
    "alert.severity": "AlertSeverity",
    "alert.state": "AlertState",
    "alert.verdict": "Verdict",
    "api_key.env": "ApiKeyEnv",
    "api_key.status": "ApiKeyStatus",
    "approval.requested_action": "ApprovalAction",
    "approval.requested_by_kind": "ApprovalRequesterKind",
    "approval.risk": "StepRisk",
    "approval.state": "ApprovalState",
    "approval.timeout_policy": "ApprovalTimeoutPolicy",
    "audit_action.severity": "AuditSeverity",
    "audit_anchors.kind": "AnchorKind",
    "audit_events.actor_type": "ActorType",
    "audit_events.severity": "AuditSeverity",
    "capture_policy.capture_mode": "CaptureMode",
    "checkpoint.capture_mode": "CaptureMode",
    "continuity_plan.approval_timeout_policy": "ApprovalTimeoutPolicy",
    "continuity_plan.degraded_mode": "DegradedMode",
    "continuity_plan.preemptive_mode": "PreemptiveMode",
    "erasure_request.state": "ErasureState",
    "events_rejected.reason": "RejectReason",
    "events.capture_mode": "CaptureMode",
    "events.error_class": "ErrorClass",
    "events.event_type": "EventType",
    "events.policy_state": "PolicyState",
    "events.route_decision": "RouteDecision",
    "events.source": "EventSource",
    "events.status": "EventStatus",
    "failover.actor_kind": "ActorKind",
    "failover.kind": "SagaKind",
    "failover.state": "SagaState",
    "failover.step": "SagaStep",
    "fallback_step.kind": "FallbackKind",
    "fallback_step.risk": "StepRisk",
    "handoff_task.assembled_by": "AssembledBy",
    "handoff_task.fidelity": "Fidelity",
    "handoff_task.outcome": "HandoffOutcome",
    "handoff_task.state": "HandoffState",
    "health_snapshot.band": "HealthBand",
    "health_snapshot.routing_state_at": "RoutingState",
    "job.kind": "JobKind",
    "job.state": "JobState",
    "kill_switch.scope_kind": "KillSwitchScope",
    "kill_switch.state": "KillSwitchState",
    "label.judges_kind": "JudgesKind",
    "label.kind": "LabelKind",
    "label.labeller_kind": "LabellerKind",
    "legal_hold.state": "HoldState",
    "ml_prediction_shadow.band": "ProbabilityBand",
    "model_catalog.provider_kind": "ProviderKind",
    "outbox.topic": "OutboxTopic",
    "payload_refs.capture_mode": "CaptureMode",
    "payload_refs.state": "PayloadState",
    "prediction.confidence": "StepRisk",
    "prediction.probability_band": "ProbabilityBand",
    "provider_incident.severity": "AlertSeverity",
    "provider_status.status": "ProviderStatus",
    "provider.dialect": "Dialect",
    "provider.provider_kind": "ProviderKind",
    "risk_assessment.declared_class": "RiskClass",
    "routing_state.state": "RoutingState",
    "routing_state.target_kind": "TargetKind",
    "routing_transition.actor_kind": "ActorKind",
    "routing_transition.trigger": "TransitionTrigger",
    "signing_key.state": "SigningKeyState",
    "state_edge.machine": "StateMachine",
    "tenant_key.purpose": "TenantKeyPurpose",
    "tenant_key.state": "TenantKeyState",
    "tenant.unknown_agent_fail_mode": "FailMode",
    # D48 Action Gate
    "action_policy.scope_kind": "ActionScopeKind",
    "action_policy.state": "ActionPolicyState",
    "action_rule.effect": "ActionEffect",
    "held_action.state": "HeldActionState",
    "held_action.source": "ActionSource",
    "held_action.server_effect": "ActionEffect",
    "action_decision.effect": "ActionEffect",
    "action_decision.source": "ActionSource",
    # D51 model drift
    "drift_baseline.state": "DriftBaselineState",
    "drift_report.verdict": "DriftVerdict",
    # D52 Sibyl Sentinel
    "sentinel_config.provider": "SentinelProvider",
    "sentinel_finding.kind": "SentinelTask",
    "sentinel_finding.provider": "SentinelProvider",
    "sentinel_finding.severity": "SentinelSeverity",
    # D53 external monitors
    "monitor.kind": "MonitorKind",
    "monitor.state": "MonitorState",
    "monitor_webhook.state": "WebhookState",
    "webhook_delivery.event_type": "WebhookEventType",
    "webhook_delivery.status": "DeliveryStatus",
    "external_finding.kind": "ExternalFindingKind",
    "external_finding.subject_kind": "ExternalSubjectKind",
    "external_finding.severity": "SentinelSeverity",
}
# Reviewed DB-only value sets (no schemas enum; G0-10 tracks the API-only ones). A new CHECK
# must land in one of the two tables, so a schemas enum can never drift from the DB silently.
DB_ONLY_VALUE_SETS = frozenset(
    {
        "erasure_request.origin",
        "continuity_plan.credential_mode",
        "data_source.classification",
        "dependency_edge.edge_type",
        "dependency_edge.origin",
        "failover.priority",
        "health_snapshot.write_reason",
        "label.label_strength",
        "ml_model.horizon_s",
        "ml_prediction_shadow.horizon_s",
        "partition_registry.grain",
        "partition_registry.state",
        "prediction.horizon_s",
        "provider_credential.allowlist_basis",
        "rollup_job.kind",
        "signing_key.purpose",
        "data_source.kind",
        "erasure_request.legal_basis",
        "scoring_config.origin",
        "alert_rule.origin",
        "idempotency_record.state",
        "ml_model.state",
        "idempotency_record.principal_kind",
        "payload_refs.source_kind",
        "redaction_profile.origin",
        "tool.kind",
        "alert_rule.comparator",
        "app_user.status",
        "provider_status.source",
        "tenant.status",
        "feature_snapshot.reason",
        "provider_credential.purpose",
        "fallback_chain.status",
        "prediction.outcome",
        "agent_version.source",
        "alert.outcome_observed",
        "blast_radius.node_kind",
        "dependency_edge.dst_kind",
        "dependency_edge.src_kind",
        "membership.scope_kind",
        "oidc_issuer.status",
        "role_permission.scope_rule",
        "legal_hold.scope_kind",
        "alert_rule.scope",
        "alert.scope",
        "erasure_request.scope_kind",
        "job.requested_by_kind",
        "signing_key_set.purpose",
        "rollup_job.state",
        "call_merge.state",
        "capture_policy.scope_kind",
        "provider_incident.state",
        "agent_risk.risk_band",
        "business_process.criticality",
        "provider_credential.status",
        "risk_assessment.suggested_class",
        "payload_refs.kind",
        "action_policy.default_effect",
    }
)
_IN_LIST = re.compile(r"CHECK \(\((\w+) = ANY \(ARRAY\[(.*)\]\)\)\)")


def _enumerated_checks(admin: Conn) -> dict[str, frozenset[str]]:
    rows = admin.fetch(
        "SELECT cl.relname, pg_get_constraintdef(co.oid) AS d FROM pg_constraint co "
        "JOIN pg_class cl ON cl.oid = co.conrelid JOIN pg_namespace n ON n.oid = cl.relnamespace "
        "WHERE n.nspname = 'sibyl' AND co.contype = 'c' AND NOT cl.relispartition"
    )
    out: dict[str, frozenset[str]] = {}
    for r in rows:
        m = _IN_LIST.fullmatch(r["d"])
        if m:
            out[f"{r['relname']}.{m.group(1)}"] = frozenset(re.findall(r"'([^']*)'", m.group(2)))
    return out


def test_every_enumerated_check_is_classified_and_equals_its_value_set(admin: Conn) -> None:
    checks = _enumerated_checks(admin)
    unclassified = sorted(set(checks) - set(CHECK_VALUE_SETS) - DB_ONLY_VALUE_SETS)
    assert unclassified == [], "classify these CHECKs in CHECK_VALUE_SETS or DB_ONLY_VALUE_SETS"
    assert sorted((set(CHECK_VALUE_SETS) | DB_ONLY_VALUE_SETS) - set(checks)) == []
    drift = {
        column: {
            "db_only": sorted(checks[column] - expected),
            "schemas_only": sorted(expected - checks[column]),
        }
        for column, name in CHECK_VALUE_SETS.items()
        if checks[column] != (expected := frozenset(str(m.value) for m in getattr(sv, name)))
    }
    assert drift == {}


def test_db_only_value_sets_have_no_schemas_twin(admin: Conn) -> None:
    """A DB-only set that now equals a schemas enum must move to CHECK_VALUE_SETS."""
    checks = _enumerated_checks(admin)
    enums = {
        name: frozenset(str(m.value) for m in member)
        for name, member in vars(sv).items()
        if isinstance(member, type) and issubclass(member, Enum)
    }
    twins = {
        column: name
        for column in DB_ONLY_VALUE_SETS
        for name, values in enums.items()
        if values == checks[column]
    }
    assert twins == {}


# --- break-glass kill attribution (G0 exception to ruling G0-4) ---------------------------


def _break_glass_key(app: Conn, fx: TenantFixture) -> uuid.UUID:
    with app.tx(fx.tenant_id):
        return app.fetchval(
            "INSERT INTO sibyl.api_key (tenant_id, agent_id, name, env, prefix, secret_hash, "
            "scopes, expires_at) VALUES ($1, NULL, 'bg', 'live', $2, $3, '{killswitch:pull}', "
            "now() + interval '1 year') RETURNING id",
            fx.tenant_id,
            "bgsinglesrc1",
            h32("bg-single-source"),
        )


_KILL = (
    "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'killed', NULL, 'operator', $3, "
    "NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'break-glass pull', $4, "
    "'killswitch.pulled', $5::jsonb, NULL, NULL, NULL, $6)"
)
_KILL_DETAIL = (
    '{"scope_kind": "agent", "scope_id": null, "snapshot_version": 1, "session_id": null}'
)


def test_break_glass_kill_is_attributed_to_the_key(
    admin: Conn, roles: dict[str, Conn], fx: TenantFixture
) -> None:
    app = roles["sibyl_app"]
    key = _break_glass_key(app, fx)
    with app.tx(fx.tenant_id):
        row = app.fetchrow(
            _KILL, fx.tenant_id, fx.agent_b, "api_key", f"bg-kill:{key}", _KILL_DETAIL, key
        )
    event = admin.fetchrow(
        "SELECT actor_type, actor_id, actor_key_id, action FROM sibyl.audit_events "
        "WHERE tenant_id = $1 AND seq = $2",
        fx.tenant_id,
        row["audit_seq"],
    )
    assert dict(event) == {
        "actor_type": "api_key",
        "actor_id": None,
        "actor_key_id": key,
        "action": "killswitch.pulled",
    }
    transition = admin.fetchrow(
        "SELECT actor_kind, actor_key_id FROM sibyl.routing_transition WHERE tenant_id = $1 "
        "AND id = $2",
        fx.tenant_id,
        row["transition_id"],
    )
    assert dict(transition) == {"actor_kind": "api_key", "actor_key_id": key}


def test_break_glass_kill_may_not_be_attributed_to_system(
    roles: dict[str, Conn], fx: TenantFixture
) -> None:
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError, match="sibyl:audit_actor_not_allowed") as caught:
        with app.tx(fx.tenant_id, rollback=True):
            app.fetchrow(
                _KILL, fx.tenant_id, fx.agent_a, "system", "bg-kill:system", _KILL_DETAIL, None
            )
    assert caught.value.sqlstate == "SB021"


def test_api_key_actor_needs_its_key_id(roles: dict[str, Conn], fx: TenantFixture) -> None:
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError, match="sibyl:routing_arguments"):
        with app.tx(fx.tenant_id, rollback=True):
            app.fetchrow(
                _KILL, fx.tenant_id, fx.agent_a, "api_key", "bg-kill:nokey", _KILL_DETAIL, None
            )


# --- chair ruling G0-1: the kernel maps the SB class / sibyl: prefix ----------------------


def test_kernel_maps_a_real_invalid_transition(roles: dict[str, Conn], fx: TenantFixture) -> None:
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError) as caught:
        with app.tx(fx.tenant_id, rollback=True):
            app.fetchrow(
                "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'failing_back', NULL, "
                "'undo', 'system', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "
                "'bad-edge', 'route.changed', NULL, NULL, NULL, NULL)",
                fx.tenant_id,
                fx.agent_a,
            )
    assert caught.value.sqlstate == "SB010"
    problem = problem_from_db_error(caught.value)
    assert (problem.code, problem.status, problem.detail) == ("invalid_transition", 409, None)
