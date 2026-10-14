"""(g) DATAMODEL §7 gate 3 schema invariants plus the contract points other lanes rely on:
frozen value sets, grants and definer hygiene, partitions ahead, error-code map, rules seed,
tenant_create seeds, tier defaults (R38/R40), D22 force-hold, key rotation."""

from __future__ import annotations

import hashlib
import re
import uuid

import asyncpg
import pytest
from sibyl_control.migrate import rules_seed
from sibyl_control.migrate.errcodes import SQLSTATE_TO_CODE
from sibyl_control.migrate.runner import default_migrations_dir, discover

from .conftest import LOGIN_ROLES, Conn
from .fixtures import TenantFixture, create_tenant, h32, populate_tenant

# DATAMODEL §4.0 value sets with the Step 4/5 amendments (R21, R37, R40, R42, ML §10.1, X1).
VALUE_SETS: dict[tuple[str, str], set[str]] = {
    ("events", "ck_events_event_type"): {
        "gen_ai.request",
        "tool.call",
        "agent.invoke",
        "checkpoint",
        "handoff.requested",
        "handoff.completed",
        "handoff.returned",
        "feedback",
        "task.outcome",
        "agent.discovered",
        "policy.decision",
        "observation.gap",
        "provider.status",
        "health.transition",
    },
    ("events", "ck_events_source"): {"sdk", "gateway", "ingest", "worker", "api"},
    ("events", "ck_events_status"): {"ok", "error", "handed_off", "cancelled"},
    ("events", "ck_events_error_class"): {
        "timeout",
        "rate_limit",
        "server_error",
        "client_error",
        "blocked",
        "other",
    },
    ("events", "ck_events_policy_state"): {
        "fresh",
        "stale",
        "expired",
        "unavailable",
        "not_applicable",
    },
    ("events", "ck_events_route_decision"): {
        "primary",
        "failover",
        "inline_fallback",
        "canary",
        "stale_primary",
    },
    ("events", "ck_events_capture_mode"): {"full", "redacted", "metadata"},
    ("events_rejected", "ck_events_rejected_reason"): {
        "schema_invalid",
        "missing_required",
        "unknown_type",
        "late_contribution",
        "outside_retention",
        "no_partition",
        "capture_policy_missing",
        "tenant_erasing",
        "env_mismatch",
        "agent_not_permitted",
    },
    ("payload_refs", "ck_payload_refs_kind"): {
        "span_content",
        "raw_batch",
        "prompt",
        "checkpoint_state",
        "handoff_packet",
        "feature_snapshot",
        "bom_export",
        "anchor_export",
        "comment",
        "model_artifact",
        "model_card",
        "action_args",  # D48
    },
    ("payload_refs", "ck_payload_refs_state"): {"stored", "swept", "shredded"},
    ("audit_events", "ck_audit_events_actor_type"): {
        "human",
        "rule",
        "policy",
        "system",
        "agent",
        "api_key",
    },
    ("routing_state", "ck_routing_state_state"): {
        "active",
        "degraded",
        "awaiting_approval",
        "failed_over",
        "failing_back",
        "quarantined",
        "killed",
    },
    ("routing_state", "ck_routing_state_target_kind"): {"primary", "model", "agent", "human_queue"},
    ("routing_transition", "ck_routing_transition_trigger"): {
        "register",
        "rule",
        "approval",
        "approval_timeout",
        "operator",
        "policy",
        "failback_probe",
        "canary",
        "undo",
        "system",
    },
    ("routing_transition", "ck_routing_transition_actor_kind"): {
        "human",
        "rule",
        "policy",
        "system",
        "api_key",
    },
    ("failover", "ck_failover_kind"): {
        "failover",
        "preemptive",
        "failback",
        "undo",
        "quarantine",
        "release",
        "kill",
        "degrade",
        "recover",
        "drill",
    },
    ("failover", "ck_failover_state"): {
        "pending",
        "running",
        "waiting_approval",
        "done",
        "cancelled",
        "failed",
    },
    ("failover", "ck_failover_step"): {
        "validate",
        "check_viability",
        "write_routing",
        "create_handoff_tasks",
        "mark_alert_actioned",
        "done",
    },
    ("fallback_step", "ck_fallback_step_kind"): {
        "retry",
        "alt_model_same_provider",
        "alt_provider",
        "backup_agent",
        "degraded_safe_mode",
        "human_queue",
    },
    ("approval", "ck_approval_requested_action"): {
        "alt_provider_failover",
        "backup_agent_failover",
        "preemptive_failover",
        "quarantine",
        "inline_fallback_enable",
    },
    ("approval", "ck_approval_state"): {"pending", "approved", "denied", "expired", "cancelled"},
    ("handoff_task", "ck_handoff_task_state"): {
        "queued",
        "claimed",
        "completed",
        "returned",
        "expired",
    },
    ("handoff_task", "ck_handoff_task_outcome"): {
        "resolved",
        "escalated",
        "abandoned",
        "returned_to_agent",
        "expired_unclaimed",
    },
    ("handoff_task", "ck_handoff_task_fidelity"): {"checkpoint", "request_only"},
    ("alert", "ck_alert_state"): {"open", "acked", "resolved"},
    ("alert", "ck_alert_verdict"): {"tp", "fp", "unsure"},
    ("alert_rule", "ck_alert_rule_scope"): {"agent", "provider", "platform"},
    ("alert_rule", "ck_alert_rule_kind"): {"detected", "leading"},
    ("health_snapshot", "ck_health_snapshot_band"): {"healthy", "watch", "degraded", "failed"},
    ("provider_status", "ck_provider_status_status"): {
        "operational",
        "degraded_performance",
        "partial_outage",
        "major_outage",
        "maintenance",
        "unknown",
    },
    ("erasure_request", "ck_erasure_request_state"): {
        "requested",
        "hold_blocked",
        "approved",
        "executing",
        "keys_shredded",
        "objects_deleted",
        "derived_purged",
        "verified",
        "completed",
        "rejected",
        "cancelled",
    },
    ("legal_hold", "ck_legal_hold_state"): {"active", "released", "expired"},
    ("kill_switch", "ck_kill_switch_state"): {"pulled", "released"},
    ("tenant_key", "ck_tenant_key_state"): {"active", "retired", "shredded"},
    ("agent", "ck_agent_lifecycle"): {
        "discovered",
        "proposed",
        "approved",
        "deployed",
        "monitored",
        "retired",
    },
    ("agent", "ck_agent_risk_class"): {
        "unclassified",
        "minimal",
        "limited",
        "high",
        "unacceptable",
    },
    ("agent", "ck_agent_kind"): {
        "chatbot",
        "copilot",
        "autonomous_agent",
        "multi_agent",
        "rag_pipeline",
        "mcp_server",
        "model_endpoint",
        "workflow",
    },
    ("agent", "ck_agent_fail_mode"): {"open", "closed"},
    ("label", "ck_label_kind"): {
        "alert_verdict",
        "task_outcome",
        "feedback",
        "failover_outcome",
        "handoff_outcome",
        "provider_incident",
    },
    ("label", "ck_label_label_strength"): {"verdict", "outcome", "provider_feed"},
    ("audit_anchors", "ck_audit_anchors_kind"): {
        "hourly",
        "partition_boundary",
        "erasure",
        "export",
        "rekey",
        "break_glass",
    },
    ("continuity_plan", "ck_continuity_plan_preemptive_mode"): {
        "auto",
        "degrade_then_auto",
        "approval",
    },
    ("outbox", "ck_outbox_topic"): {
        "policy",
        "killswitch",
        "graph",
        "health",
        "alert",
        "provider_incident",
        "incident",
        "approval",
        "handoff",
        "erasure",
        "audit",
        "agent",
        "job",
        "action",  # D48
    },
    ("api_key", "ck_api_key_scopes"): {
        "ingest:write",
        "gateway:proxy",
        "routing:read",
        "handoff:write",
        "agents:read",
        "agents:write",
        "killswitch:pull",
        "actions:hold",  # D48
        "monitor:read",  # D53 (monitor-bound keys only)
        "findings:write",  # D53
    },
}

# API §2.2 scope catalogue minus the API-key-only scopes, plus the chair's keys:read.
ROLE_SCOPES = {
    "tenant:read",
    "tenant:write",
    "users:manage",
    "oidc:manage",
    "apikeys:manage",
    "apikeys:manage_agent",
    "agents:read",
    "agents:write",
    "agents:approve",
    "identity:write",
    "capture:write",
    "credentials:manage",
    "credentials:read",
    "keys:rotate",
    "keys:read",
    "routing:read",
    "routing:write",
    "incidents:act",
    "routing:override",
    "approvals:decide",
    "quarantine:act",
    "killswitch:pull",
    "killswitch:release",
    "queue:act",
    "packets:read",
    "payloads:read",
    "payloads:reveal",
    "alerts:act",
    "audit:read",
    "audit:verify",
    "audit:export",
    "data:export",
    "erasure:request",
    "erasure:approve",
    "holds:manage",
    # D48 Action Gate (actions:hold is machine-only: no role row)
    "actions:read",
    "actions:decide",
    "action_policies:write",
    # D51 model drift
    "drift:read",
    "drift:write",
    # D52 Sibyl Sentinel
    "sentinel:read",
    "sentinel:admin",
    # D53 external monitors (monitor:read and findings:write are monitor-bound: no role row)
    "monitors:admin",
}


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "invariants")


def test_frozen_value_sets(admin: Conn) -> None:
    mismatched = {}
    for (table, name), expected in VALUE_SETS.items():
        definition = admin.fetchval(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = $1::regclass AND conname = $2",
            f"sibyl.{table}",
            name,
        )
        assert definition, f"{table}.{name} missing"
        found = set(re.findall(r"'([^']*)'::text", definition))
        if found != expected:
            mismatched[f"{table}.{name}"] = {"missing": expected - found, "extra": found - expected}
    assert mismatched == {}
    assert set(admin.fetchval("SELECT sibyl.failure_modes()")) == {
        "provider_outage",
        "latency_degradation",
        "quality_collapse",
        "prompt_injection",
        "policy_violation",
        "tool_failure",
        "data_source_failure",
        "infinite_loop",
        "cost_runaway",
        "permission_error",
        "model_deprecation",
        "silent_drift",
    }


def test_no_secret_named_columns(admin: Conn) -> None:
    rows = admin.fetch(
        "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = "
        "'sibyl' "
        "AND (column_name LIKE 'password%' OR column_name LIKE 'secret%' OR column_name LIKE "
        "'totp%')"
    )
    found = {(r["table_name"], r["column_name"]) for r in rows}
    allowed = {
        ("api_key", "secret_hash"),
        ("provider_credential", "secret_sha256"),
        ("provider_credential", "secret_hint"),
        ("provider_credential_meta", "secret_hint"),
    }
    assert found <= allowed


def test_no_defaults_where_a_choice_is_required(admin: Conn) -> None:
    for table, column in (("capture_policy", "capture_mode"), ("agent", "fail_mode")):
        assert (
            admin.fetchval(
                "SELECT column_default FROM information_schema.columns WHERE table_schema = "
                "'sibyl' "
                "AND table_name = $1 AND column_name = $2",
                table,
                column,
            )
            is None
        )


def test_security_definers_pin_search_path_and_nothing_is_public(admin: Conn) -> None:
    rows = admin.fetch(
        "SELECT p.proname, p.prosecdef, p.proconfig, has_function_privilege('public', p.oid, "
        "'EXECUTE') AS pub "
        "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'sibyl' "
        "AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')"
    )
    definers = [r for r in rows if r["prosecdef"]]
    assert len(definers) >= 15
    assert [
        r["proname"] for r in definers if "search_path=sibyl, pg_temp" not in (r["proconfig"] or [])
    ] == []
    assert [r["proname"] for r in rows if r["pub"]] == []


def test_login_roles_hold_no_dml_on_function_only_tables(admin: Conn) -> None:
    for table in ("routing_state", "routing_transition", "audit_events"):
        for role in (*LOGIN_ROLES, "sibyl_migrate"):
            for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                assert not admin.fetchval(
                    "SELECT has_table_privilege($1, $2, $3)", role, f"sibyl.{table}", privilege
                ), (role, table, privilege)


def test_partitions_exist_ahead_and_are_registered(admin: Conn) -> None:
    policy = admin.fetch("SELECT table_name, grain, ahead FROM sibyl.partition_policy()")
    partitioned = {
        r["relname"]
        for r in admin.fetch(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'sibyl' AND c.relkind = 'p'"
        )
    }
    assert {r["table_name"] for r in policy} == partitioned
    for row in policy:
        covered = admin.fetchval(
            "SELECT count(*) FROM sibyl.partition_registry WHERE table_name = $1 AND state = "
            "'attached' "
            "AND range_to >= now() + $2::interval - sibyl.partition_period_step($3)",
            row["table_name"],
            row["ahead"],
            row["grain"],
        )
        assert covered >= 1, row["table_name"]
    assert admin.fetchval("SELECT count(DISTINCT grain) FROM sibyl.partition_registry") == 3


def test_extension_allowlist(admin: Conn) -> None:
    installed = {r["extname"] for r in admin.fetch("SELECT extname FROM pg_extension")}
    assert installed <= {"plpgsql", "pgcrypto", "citext", "pg_trgm", "btree_gin", "pgaudit"}
    assert {"pgcrypto", "citext", "pg_trgm", "btree_gin"} <= installed


def test_every_raise_maps_to_the_error_registry() -> None:
    pattern = re.compile(
        r"RAISE EXCEPTION '((?:[^']|'')*)'.*?USING ERRCODE = '([A-Z0-9]{5})'", re.S
    )
    seen = 0
    for migration in discover():
        assert migration.sql.count("RAISE EXCEPTION") == len(pattern.findall(migration.sql)), (
            migration.path.name
        )
        for message, state in pattern.findall(migration.sql):
            seen += 1
            assert state in SQLSTATE_TO_CODE, (migration.path.name, state)
            assert message.startswith(f"sibyl:{SQLSTATE_TO_CODE[state]}"), (
                migration.path.name,
                message,
            )
    assert seen >= 50


def test_rules_seed_migration_matches_the_yaml() -> None:
    seed = rules_seed.load()
    latest = rules_seed.latest_seed_migration(default_migrations_dir())
    assert latest is not None and latest.read_text() == rules_seed.render_sql(seed)


def test_rule_table_contents() -> None:
    seed = rules_seed.load()
    by_code = {r["code"]: r for r in seed.rules}
    short = {r["short_code"] for r in seed.rules if r["short_code"]}
    assert short == {f"R{i}" for i in range(1, 10)} | {f"L{i}" for i in range(1, 8)}
    assert {
        "quality_proxy",
        "tool_loop",
        "drift_cusum",
        "context_saturation",
        "credential_expiry",
        "model_deprecation",
    } <= set(by_code)
    for rule in seed.rules:
        if rule["kind"] == "leading" and rule["thresholds"]["tiers"]["2"]["cap"] > 0:
            for tier in ("2", "3"):
                assert rule["thresholds"]["tiers"][tier]["hysteresis_in"] >= 1
        if rule["code"] in {"error_trend", "latency_trend", "fallback_pressure", "refusal_trend"}:
            assert rule["thresholds"]["tiers"]["2"]["hysteresis_in"] >= 3  # R41
    assert (
        by_code["provider_status"]["collapses_to_provider"]
        and by_code["provider_status"]["scope"] == "provider"
    )
    assert by_code["refusal_share"]["thresholds"]["tiers"]["1"]["threshold"] == 0.1


def test_tenant_create_seeds(admin: Conn, fx: TenantFixture) -> None:
    seed = rules_seed.load()
    t = fx.tenant_id
    assert admin.fetchval(
        "SELECT count(*) FROM sibyl.alert_rule WHERE tenant_id = $1 AND origin = 'seed'", t
    ) == len(seed.rules)
    config = admin.fetchrow(
        "SELECT config_sha256, origin FROM sibyl.scoring_config WHERE tenant_id = $1 "
        "AND activated_at IS NOT NULL AND superseded_at IS NULL",
        t,
    )
    assert (
        bytes(config["config_sha256"]) == hashlib.sha256(seed.scoring_canonical.encode()).digest()
    )
    keys = admin.fetch(
        "SELECT purpose, version, state FROM sibyl.tenant_key WHERE tenant_id = $1 ORDER BY 1", t
    )
    assert [(k["purpose"], k["version"], k["state"]) for k in keys] == [
        ("config", 1, "active"),
        ("credential", 1, "active"),
        ("payload", 1, "active"),
    ]
    other = create_tenant(admin, "invariants-other")
    hashes = admin.fetch(
        "SELECT tenant_id, name, content_hash FROM sibyl.redaction_profile "
        "WHERE tenant_id = ANY($1::uuid[]) AND origin = 'system'",
        [t, other],
    )
    by_name: dict[str, set[bytes]] = {}
    for row in hashes:
        by_name.setdefault(row["name"], set()).add(bytes(row["content_hash"]))
    assert set(by_name) == {"secrets_only", "pii_standard"}
    assert all(len(v) == 1 for v in by_name.values()), (
        "system profile hash must be tenant-independent (R15)"
    )


def test_role_permission_matrix(admin: Conn) -> None:
    rows = admin.fetch(
        "SELECT role_name, permission, scope_rule, step_up FROM sibyl.role_permission"
    )
    assert {r["permission"] for r in rows} == ROLE_SCOPES
    owner = {r["permission"] for r in rows if r["role_name"] == "owner"}
    assert owner == ROLE_SCOPES
    assert {(r["role_name"]) for r in rows if r["permission"] in ("keys:read", "keys:rotate")} == {
        "owner",
        "security_admin",
    }
    assert {r["role_name"] for r in rows if r["scope_rule"] == "scoped"} == {"engineer"}
    assert {r["permission"] for r in rows if r["step_up"] and r["role_name"] == "owner"} >= {
        "killswitch:pull",
        "erasure:approve",
        "holds:manage",
        "keys:rotate",
    }


def test_state_machines_and_audit_actions_seeded(admin: Conn) -> None:
    machines = {r["machine"] for r in admin.fetch("SELECT DISTINCT machine FROM sibyl.state_edge")}
    assert machines == {
        "routing",
        "failover",
        "approval",
        "handoff",
        "alert",
        "erasure",
        "tenant_key",
        "kill_switch",
        "lifecycle",
        "job",
        "held_action",
        "action_policy",
    }
    actions = {r["name"]: r for r in admin.fetch("SELECT * FROM sibyl.audit_action")}
    for name in (
        "erasure.cancelled",
        "handoff.lock_extended",
        "handoff.claim_released",
        "credential.bundle_issued",
        "access.break_glass",
        "tenant_key.shredded",
        "rollup.backfill",
        "scoring_config.activated",
    ):
        assert name in actions, name
    assert "human" in actions["handoff.created"]["actor_types"]
    assert "human" in actions["approval.requested"]["actor_types"]


def test_tier_defaults_and_d22(admin: Conn, fx: TenantFixture) -> None:
    plan = admin.fetchrow(
        "SELECT rto_s, rpo_s, preemptive_mode, inline_fallback FROM sibyl.continuity_plan "
        "WHERE tenant_id = $1 AND agent_id = $2",
        fx.tenant_id,
        fx.agent_a,
    )
    assert dict(plan) == {
        "rto_s": 900,
        "rpo_s": 60,
        "preemptive_mode": "approval",
        "inline_fallback": False,
    }
    approval = admin.fetchrow(
        "SELECT timeout_policy, evidence->>'timeout_policy_applied' AS applied "
        "FROM sibyl.approval WHERE tenant_id = $1 AND agent_id = $2",
        fx.tenant_id,
        fx.agent_a,
    )
    assert (approval["timeout_policy"], approval["applied"]) == ("hold", "hold_forced_d22")
    with admin.tx(fx.tenant_id, rollback=True):
        for tier, rto, mode in ((2, 3600, "degrade_then_auto"), (3, 14400, "auto")):
            agent = uuid.uuid4()
            admin.execute(
                "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode) "
                "VALUES ($1, $2, $3, 'x', 'chatbot', $4, 'open')",
                fx.tenant_id,
                agent,
                f"tier-{tier}",
                tier,
            )
            row = admin.fetchrow(
                "INSERT INTO sibyl.continuity_plan (tenant_id, agent_id) VALUES ($1, $2) "
                "RETURNING rto_s, preemptive_mode, inline_fallback",
                fx.tenant_id,
                agent,
            )
            assert (row["rto_s"], row["preemptive_mode"], row["inline_fallback"]) == (
                rto,
                mode,
                True,
            )


def test_agent_fail_mode_rules(admin: Conn, fx: TenantFixture) -> None:
    with admin.tx(fx.tenant_id, rollback=True):
        mode = admin.fetchval(
            "INSERT INTO sibyl.agent (tenant_id, slug, name, kind, is_provisional) VALUES "
            "($1, 'unclaimed/0a1b2c3d', 'auto', 'chatbot', true) RETURNING fail_mode",
            fx.tenant_id,
        )
        assert mode == "closed"
    with pytest.raises(asyncpg.PostgresError, match="sibyl:fail_mode_required"):
        with admin.tx(fx.tenant_id, rollback=True):
            admin.execute(
                "INSERT INTO sibyl.agent (tenant_id, slug, name, kind) VALUES ($1, 'x', 'x', "
                "'chatbot')",
                fx.tenant_id,
            )


def test_breakglass_keys(admin: Conn, roles: dict[str, Conn], fx: TenantFixture) -> None:
    app = roles["sibyl_app"]
    insert = (
        "INSERT INTO sibyl.api_key (tenant_id, agent_id, name, env, prefix, secret_hash, scopes, "
        "expires_at) "
        "VALUES ($1, $2, 'bg', 'live', $3, $4, $5, now() + interval '1 year')"
    )
    with pytest.raises(asyncpg.CheckViolationError):
        with app.tx(fx.tenant_id, rollback=True):
            app.execute(
                insert,
                fx.tenant_id,
                None,
                "bgexclusive1",
                h32("a"),
                ["killswitch:pull", "routing:read"],
            )
    with pytest.raises(asyncpg.CheckViolationError):
        with app.tx(fx.tenant_id, rollback=True):
            app.execute(
                insert, fx.tenant_id, fx.agent_a, "bgboundagent", h32("b"), ["killswitch:pull"]
            )
    with pytest.raises(asyncpg.PostgresError, match="sibyl:breakglass_limit"):
        with app.tx(fx.tenant_id, rollback=True):
            for i in range(3):
                app.execute(
                    insert, fx.tenant_id, None, f"bglimit0000{i}", h32(f"c{i}"), ["killswitch:pull"]
                )


def test_tenant_key_rotation(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, "rotation")
    app = roles["sibyl_app"]
    with app.tx(tenant):
        row = app.fetchrow(
            "SELECT * FROM sibyl.tenant_key_rotate('payload', $1, 'kek-2')", h32("new")
        )
    states = admin.fetch(
        "SELECT id, version, state FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = "
        "'payload' "
        "ORDER BY version",
        tenant,
    )
    assert [(s["version"], s["state"]) for s in states] == [(1, "retired"), (2, "active")]
    assert (row["retired_id"], row["active_id"]) == (states[0]["id"], states[1]["id"])
    with admin.tx():
        admin.execute("UPDATE sibyl.tenant SET status = 'erasing' WHERE id = $1", tenant)
    with pytest.raises(asyncpg.PostgresError, match="sibyl:tenant_erasing"):
        with app.tx(tenant, rollback=True):
            app.fetchrow(
                "SELECT * FROM sibyl.tenant_key_rotate('payload', $1, 'kek-3')", h32("newer")
            )


def test_helpers(admin: Conn) -> None:
    ids = [admin.fetchval("SELECT sibyl.uuidv7()") for _ in range(3)]
    assert all(i.version == 7 for i in ids)
    assert (
        admin.fetchval("SELECT sibyl.hist_bucket(1)") == 0
        and admin.fetchval("SELECT sibyl.hist_bucket(600000)") == 39
    )
    p50 = admin.fetchval(
        "SELECT sibyl.hist_quantile(sibyl.hist_sum(h), 0.5) FROM (VALUES "
        "(sibyl.hist_add(sibyl.zero_hist(), array_fill(0, ARRAY[40]))), "
        "((SELECT array_agg(CASE WHEN i = 15 THEN 10 ELSE 0 END ORDER BY i) "
        "FROM generate_series(1, 40) i))) v(h)"
    )
    assert 100 <= p50 <= 160
    assert (
        admin.fetchval('SELECT sibyl.jcs(\'{"b": [1, true, null], "a": "\\u00e9\\n"}\'::jsonb)')
        == '{"a":"é\\n","b":[1,true,null]}'
    )
    assert admin.fetchval("SELECT sibyl.is_allowlisted_base_url('http://127.0.0.1:8080')") is False
    assert admin.fetchval("SELECT sibyl.is_allowlisted_base_url('https://10.0.0.5/v1')") is False
    assert (
        admin.fetchval("SELECT sibyl.is_allowlisted_base_url('https://api.openai.com/v1')") is True
    )
