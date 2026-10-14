# ruff: noqa: S608 -- SQL identifiers here come from pg_catalog or fixed literals, never from input
"""Populate one tenant with at least one row in every tenant-scoped table.

Rows are written as the admin superuser but always under the tenant's transaction context
and through the real functions (tenant_create, routing_apply, audit_append) and triggers, so
the data is what the services would produce. ``test_fixture_covers_every_tenant_table``
fails when a new tenant table has no fixture row here.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from .conftest import Conn


def new_id() -> uuid.UUID:
    return uuid.uuid4()


def h32(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


@dataclass(frozen=True)
class TenantFixture:
    tenant_id: uuid.UUID
    slug: str
    owner: uuid.UUID
    approver: uuid.UUID
    engineer: uuid.UUID
    session: uuid.UUID
    agent_a: uuid.UUID
    agent_b: uuid.UUID
    model_a: uuid.UUID
    provider_a: uuid.UUID
    rule_error_rate: uuid.UUID
    scoring_config: uuid.UUID


def create_tenant(admin: Conn, slug: str) -> uuid.UUID:
    with admin.tx():
        return admin.fetchval(
            "SELECT sibyl.tenant_create($1, $2, 'closed', 'eu-west', 'kek-test', $3, $4, $5)",
            slug,
            slug.title(),
            h32(slug + "p"),
            h32(slug + "c"),
            h32(slug + "g"),
        )


def register(conn: Conn, tenant: uuid.UUID, agent: uuid.UUID) -> Any:
    return conn.fetchrow(
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, NULL, 'active', NULL, 'register', "
        "'system', NULL, NULL, "
        "NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $3, 'route.changed', NULL, NULL, NULL, "
        "NULL)",
        tenant,
        agent,
        f"register:{agent}",
    )


def _identity(c: Conn, t: uuid.UUID, slug: str) -> dict[str, uuid.UUID]:
    ids = {k: new_id() for k in ("issuer", "owner", "approver", "engineer", "group", "session")}
    c.execute(
        "INSERT INTO sibyl.oidc_issuer (tenant_id, id, issuer_url, client_id) VALUES ($1, $2, $3, "
        "'sibyl')",
        t,
        ids["issuer"],
        f"https://dex.example/{slug}",
    )
    for role in ("owner", "approver", "engineer"):
        c.execute(
            "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email, "
            "display_name, status) "
            "VALUES ($1, $2, $3, $4, $5, $6, 'active')",
            t,
            ids[role],
            ids["issuer"],
            f"{slug}-{role}",
            f"{role}@{slug}.example",
            role.title(),
        )
    c.execute(
        "INSERT INTO sibyl.agent_group (tenant_id, id, slug, name, owner_user_id) "
        "VALUES ($1, $2, 'sales-ops', 'Sales ops', $3)",
        t,
        ids["group"],
        ids["owner"],
    )
    for user, role, kind, scope in (
        (ids["owner"], "owner", "tenant", None),
        (ids["approver"], "security_admin", "tenant", None),
        (ids["engineer"], "engineer", "agent_group", ids["group"]),
    ):
        c.execute(
            "INSERT INTO sibyl.membership (tenant_id, user_id, role_name, scope_kind, scope_id) "
            "VALUES ($1, $2, $3, $4, $5)",
            t,
            user,
            role,
            kind,
            scope,
        )
    c.execute(
        "INSERT INTO sibyl.session (tenant_id, id, user_id, token_hash, step_up_at) VALUES ($1, "
        "$2, $3, $4, now())",
        t,
        ids["session"],
        ids["owner"],
        h32(f"{slug}-session-{secrets.token_hex(4)}"),
    )
    return ids


def _registry(c: Conn, t: uuid.UUID, slug: str, ids: dict[str, uuid.UUID]) -> dict[str, uuid.UUID]:
    r = {k: new_id() for k in ("bp", "p1", "p2", "m1", "m2", "tool", "ds", "a", "b", "va", "bom")}
    c.execute(
        "INSERT INTO sibyl.business_process (tenant_id, id, slug, name, criticality) "
        "VALUES ($1, $2, 'billing', 'Billing', 'high')",
        t,
        r["bp"],
    )
    for key, n in (("p1", "one"), ("p2", "two")):
        c.execute(
            "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect, "
            "base_url, "
            "is_known_provider) VALUES ($1, $2, $3, $3, 'openai', 'openai_compatible', $4, true)",
            t,
            r[key],
            f"provider-{n}",
            f"https://api.provider-{n}.example/v1",
        )
    c.execute(
        "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name) VALUES ($1, $2, $3, "
        "'large-1')",
        t,
        r["m1"],
        r["p1"],
    )
    c.execute(
        "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name) VALUES ($1, $2, $3, "
        "'large-2')",
        t,
        r["m2"],
        r["p2"],
    )
    c.execute(
        "INSERT INTO sibyl.tool (tenant_id, id, slug, name, kind) VALUES ($1, $2, 'lookup', "
        "'Lookup', 'function')",
        t,
        r["tool"],
    )
    c.execute(
        "INSERT INTO sibyl.data_source (tenant_id, id, slug, name, kind, classification) "
        "VALUES ($1, $2, 'crm', 'CRM', 'database', 'pii')",
        t,
        r["ds"],
    )
    c.execute(
        "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode, "
        "agent_group_id, owner_user_id, "
        "business_process_id) VALUES ($1, $2, 'billing-agent', 'Billing agent', "
        "'autonomous_agent', 1, 'closed', "
        "$3, $4, $5)",
        t,
        r["a"],
        ids["group"],
        ids["owner"],
        r["bp"],
    )
    c.execute(
        "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode) "
        "VALUES ($1, $2, 'triage-bot', 'Triage bot', 'chatbot', 2, 'open')",
        t,
        r["b"],
    )
    c.execute(
        "INSERT INTO sibyl.agent_version (tenant_id, id, agent_id, version_no, primary_model_id, "
        "source) "
        "VALUES ($1, $2, $3, 1, $4, 'api')",
        t,
        r["va"],
        r["a"],
        r["m1"],
    )
    c.execute(
        "UPDATE sibyl.agent SET current_version_id = $3 WHERE tenant_id = $1 AND id = $2",
        t,
        r["a"],
        r["va"],
    )
    c.execute(
        "INSERT INTO sibyl.agent_identity (tenant_id, agent_id, tools_hash) VALUES ($1, $2, $3)",
        t,
        r["a"],
        h32("tools"),
    )
    c.execute(
        "INSERT INTO sibyl.ai_bom (tenant_id, agent_version_id, content, content_sha256, "
        "generator_version) "
        "VALUES ($1, $2, '{\"bomFormat\": \"CycloneDX\"}', $3, 'bom/1')",
        t,
        r["va"],
        h32("bom"),
    )
    seq = c.fetchval(
        "SELECT seq FROM sibyl.audit_append($1, 'human', $2, NULL, NULL, 'asset.approved', "
        "'agent', $3, "
        "NULL, 'reviewed', $4::jsonb, NULL, now(), NULL)",
        t,
        ids["owner"],
        r["a"],
        json.dumps(
            {"lifecycle_from": "discovered", "lifecycle_to": "proposed", "approval_ref": "x"}
        ),
    )
    c.execute(
        "INSERT INTO sibyl.lifecycle_transition (tenant_id, agent_id, from_stage, to_stage, "
        "actor_user_id, "
        "audit_seq) VALUES ($1, $2, 'discovered', 'proposed', $3, $4)",
        t,
        r["a"],
        ids["owner"],
        seq,
    )
    c.execute(
        "UPDATE sibyl.agent SET lifecycle = 'proposed' WHERE tenant_id = $1 AND id = $2", t, r["a"]
    )
    for dst_kind, dst, edge in (
        ("tool", r["tool"], "calls_tool"),
        ("data_source", r["ds"], "reads_data"),
    ):
        c.execute(
            "INSERT INTO sibyl.dependency_edge (tenant_id, src_kind, src_id, dst_kind, dst_id, "
            "edge_type, origin) "
            "VALUES ($1, 'agent', $2, $3, $4, $5, 'declared')",
            t,
            r["a"],
            dst_kind,
            dst,
            edge,
        )
    c.execute("SELECT sibyl.blast_radius_refresh($1, 'tool', $2)", t, r["tool"])
    c.execute(
        "INSERT INTO sibyl.provider_status (tenant_id, provider_id, source, status, observed_at) "
        "VALUES ($1, $2, 'status_feed', 'operational', now())",
        t,
        r["p1"],
    )
    prefix = secrets.token_hex(6)
    c.execute(
        "INSERT INTO sibyl.api_key (tenant_id, agent_id, name, env, prefix, secret_hash, scopes, "
        "expires_at, "
        "created_by) VALUES ($1, $2, 'sdk', 'live', $3, $4, "
        "'{ingest:write,routing:read,handoff:write}', "
        "now() + interval '1 year', $5)",
        t,
        r["a"],
        prefix,
        h32(prefix),
        ids["owner"],
    )
    return r


def _policy(c: Conn, t: uuid.UUID, ids: dict[str, uuid.UUID], r: dict[str, uuid.UUID]) -> uuid.UUID:
    profile = c.fetchval(
        "SELECT id FROM sibyl.redaction_profile WHERE tenant_id = $1 AND name = 'secrets_only'", t
    )
    c.execute(
        "INSERT INTO sibyl.capture_policy (tenant_id, scope_kind, capture_mode, "
        "redaction_profile_id, "
        "consequences_version, chosen_by, version_no) VALUES ($1, 'tenant', 'full', $2, 'c1', $3, "
        "1)",
        t,
        profile,
        ids["owner"],
    )
    c.execute(
        "INSERT INTO sibyl.capture_policy (tenant_id, scope_kind, agent_id, capture_mode, "
        "redaction_profile_id, "
        "consequences_version, chosen_by, version_no) VALUES ($1, 'agent', $2, 'redacted', $3, "
        "'c1', $4, 1)",
        t,
        r["a"],
        profile,
        ids["owner"],
    )
    key = c.fetchval(
        "SELECT id FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'credential'", t
    )
    cred = new_id()
    c.execute(
        "INSERT INTO sibyl.provider_credential (tenant_id, id, provider_id, name, base_url, "
        "allowlist_basis, "
        "auth_scheme, ciphertext, nonce, tenant_key_id, key_version, secret_sha256, created_by) "
        "VALUES "
        "($1, $2, $3, 'fallback', 'https://api.provider-two.example/v1', 'known_provider', "
        "'bearer', $4, $5, $6, "
        "1, $7, $8)",
        t,
        cred,
        r["p2"],
        b"ciphertext",
        b"\x01" * 12,
        key,
        h32("secret"),
        ids["owner"],
    )
    return cred


def _routing(
    c: Conn, t: uuid.UUID, ids: dict[str, uuid.UUID], r: dict[str, uuid.UUID], cred: uuid.UUID
) -> dict[str, uuid.UUID]:
    x = {
        k: new_id() for k in ("chain", "failover", "approval", "alert", "incident", "kill", "task")
    }
    c.execute(
        "INSERT INTO sibyl.fallback_chain (tenant_id, id, agent_id, version_no, "
        "requested_by_user_id) "
        "VALUES ($1, $2, $3, 1, $4)",
        t,
        x["chain"],
        r["a"],
        ids["owner"],
    )
    for pos, kind, provider, model, credential in (
        (0, "retry", None, None, None),
        (1, "alt_model_same_provider", None, r["m1"], None),
        (2, "alt_provider", r["p2"], r["m2"], cred),
        (3, "human_queue", None, None, None),
    ):
        c.execute(
            "INSERT INTO sibyl.fallback_step (tenant_id, chain_id, position, kind, provider_id, "
            "model_id, "
            "credential_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            t,
            x["chain"],
            pos,
            kind,
            provider,
            model,
            credential,
        )
    c.execute(
        "UPDATE sibyl.fallback_chain SET status = 'approved', approved_by_user_id = $3, "
        "approved_at = now() "
        "WHERE tenant_id = $1 AND id = $2",
        t,
        x["chain"],
        ids["approver"],
    )
    c.execute(
        "INSERT INTO sibyl.continuity_plan (tenant_id, agent_id, fallback_chain_id) VALUES ($1, "
        "$2, $3)",
        t,
        r["a"],
        x["chain"],
    )
    register(c, t, r["a"])
    register(c, t, r["b"])
    x["rule"] = c.fetchval(
        "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = 'error_rate'", t
    )
    c.execute(
        "INSERT INTO sibyl.failover (tenant_id, id, agent_id, kind, idempotency_key, actor_kind, "
        "from_state) "
        "VALUES ($1, $2, $3, 'failover', $4, 'rule', 'active')",
        t,
        x["failover"],
        r["a"],
        f"f:{x['failover']}",
    )
    c.execute(
        "INSERT INTO sibyl.approval (tenant_id, id, failover_id, agent_id, requested_action, "
        "risk, tier, "
        "requested_by_kind, requested_by_rule_id, expires_at, timeout_policy) VALUES ($1, $2, $3, "
        "$4, "
        "'alt_provider_failover', 'high', 1, 'rule', $5, now() + interval '10 minutes', "
        "'fail_safe')",
        t,
        x["approval"],
        x["failover"],
        r["a"],
        x["rule"],
    )
    c.execute(
        "INSERT INTO sibyl.alert (tenant_id, id, rule_id, scope, agent_id, severity, dedupe_key, "
        "what_to_do, "
        "summary, failover_id) VALUES ($1, $2, $3, 'agent', $4, 'warning', $5, 'check', 'errors', "
        "$6)",
        t,
        x["alert"],
        x["rule"],
        r["a"],
        f"error_rate:{r['a']}",
        x["failover"],
    )
    c.execute(
        "INSERT INTO sibyl.provider_incident (tenant_id, id, provider_id, severity, summary) "
        "VALUES ($1, $2, $3, 'warning', 'outage')",
        t,
        x["incident"],
        r["p1"],
    )
    c.execute(
        "INSERT INTO sibyl.handoff_task (tenant_id, id, agent_id, failover_id, task_id, "
        "packet_id, packet, "
        "packet_sha256, fidelity, failure_mode, trigger_kind, assembled_by, priority, "
        "deadline_at, next_action, "
        "summary) VALUES ($1, $2, $3, $4, $5, $6, '{}', $7, 'request_only', 'provider_outage', "
        "'rule', "
        "'control_plane', 1, now() + interval '15 minutes', 'review', 'handoff')",
        t,
        x["task"],
        r["a"],
        x["failover"],
        new_id(),
        new_id(),
        h32("packet"),
    )
    c.execute(
        "INSERT INTO sibyl.kill_switch (tenant_id, id, scope_kind, scope_id, reason, pulled_by, "
        "step_up_session_id, routing_version_at_pull) VALUES ($1, $2, 'agent', $3, 'test', $4, "
        "$5, 1)",
        t,
        x["kill"],
        r["b"],
        ids["owner"],
        ids["session"],
    )
    c.execute(
        "INSERT INTO sibyl.kill_switch_ack (tenant_id, kill_switch_id, gateway_id, "
        "snapshot_version, applied_at) "
        "VALUES ($1, $2, 'gw-1', 1, now())",
        t,
        x["kill"],
    )
    return x


def _telemetry(
    c: Conn,
    t: uuid.UUID,
    ids: dict[str, uuid.UUID],
    r: dict[str, uuid.UUID],
    x: dict[str, uuid.UUID],
) -> uuid.UUID:
    payload_key = c.fetchval(
        "SELECT id FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'payload'", t
    )
    rh = h32("profile")
    c.execute(
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, "
        "call_id, emitter_id, seq, "
        "policy_state, capture_mode, redaction_profile_hash, normaliser_version, status, "
        "latency_ms) VALUES "
        "($1, $2, now(), 'gen_ai.request', 'gateway', $3, $4, 'gw-1', 1, 'fresh', 'full', $5, "
        "'normaliser/1.0', "
        "'ok', 120)",
        t,
        new_id(),
        r["a"],
        new_id(),
        rh,
    )
    c.execute(
        "INSERT INTO sibyl.events_rejected (tenant_id, reason) VALUES ($1, 'schema_invalid')", t
    )
    c.execute(
        "INSERT INTO sibyl.call_merge (tenant_id, call_id, sdk_contribution) VALUES ($1, $2, '{}')",
        t,
        new_id(),
    )
    c.execute(
        "INSERT INTO sibyl.payload_refs (tenant_id, kind, uri, sha256, size_bytes, stored_bytes, "
        "tenant_key_id, "
        "key_version, nonce, capture_mode, redaction_profile_hash, agent_id, source_kind, "
        "expires_at) VALUES "
        "($1, 'span_content', 'tenant/x/payload.bin', $2, 10, 12, $3, 1, $4, 'full', $5, $6, "
        "'event', "
        "now() + interval '30 days')",
        t,
        h32("payload"),
        payload_key,
        b"\x02" * 12,
        rh,
        r["a"],
    )
    c.execute(
        "INSERT INTO sibyl.checkpoint (tenant_id, id, agent_id, task_id, seq, step_index, "
        "state_bytes, state, "
        "state_schema, doc, capture_mode, redaction_profile_hash) VALUES ($1, $2, $3, $4, 1, 0, "
        "2, '{}', "
        "'state/1', '{}', 'full', $5)",
        t,
        new_id(),
        r["a"],
        new_id(),
        rh,
    )
    for table, bucket in (
        ("agent_metrics_1m", "date_trunc('minute', now())"),
        ("agent_metrics_5m", "date_bin('5 minutes', now(), '2000-01-01'::timestamptz)"),
        ("agent_metrics_1h", "date_trunc('hour', now())"),
    ):
        c.execute(
            f"INSERT INTO sibyl.{table} (tenant_id, agent_id, provider, model, bucket_start, "
            f"request_count) "
            f"VALUES ($1, $2, 'provider-one', 'large-1', {bucket}, 5)",
            t,
            r["a"],
        )
    c.execute(
        "INSERT INTO sibyl.provider_metrics_5m (tenant_id, provider, model, bucket_start) VALUES "
        "($1, 'provider-one', '*', date_bin('5 minutes', now(), '2000-01-01'::timestamptz))",
        t,
    )
    fs = new_id()
    c.execute(
        "INSERT INTO sibyl.feature_snapshot (tenant_id, id, agent_id, as_of, feature_set, reason, "
        "observation_coverage) VALUES ($1, $2, $3, now(), 'features/v1', 'alert', 1)",
        t,
        fs,
        r["a"],
    )
    label = new_id()
    c.execute(
        "INSERT INTO sibyl.label (tenant_id, id, agent_id, kind, label_strength, judges_kind, "
        "judges_id, "
        "feature_snapshot_id, judged_as_of, labeller_kind, value) VALUES ($1, $2, $3, "
        "'alert_verdict', "
        "'verdict', 'alert', $4, $5, now(), 'operator', '{\"verdict\": \"tp\"}')",
        t,
        label,
        r["a"],
        str(x["alert"]),
        fs,
    )
    c.execute(
        "UPDATE sibyl.alert SET verdict = 'tp', verdict_label_id = $3 WHERE tenant_id = $1 AND id "
        "= $2",
        t,
        x["alert"],
        label,
    )
    c.execute(
        "INSERT INTO sibyl.ingest_batch_seen (tenant_id, batch_id, api_key_id, response_sha256, "
        "response_body) "
        "VALUES ($1, 'batch-1', $2, $3, '{}')",
        t,
        new_id(),
        h32("resp"),
    )
    c.execute(
        "INSERT INTO sibyl.idempotency_record (tenant_id, route, idempotency_key, principal_kind, "
        "principal_id, "
        "request_sha256) VALUES ($1, 'POST /api/v1/incidents', 'k-1', 'user', $2, $3)",
        t,
        ids["owner"],
        h32("req"),
    )
    return fs


def _scoring(c: Conn, t: uuid.UUID, r: dict[str, uuid.UUID], fs: uuid.UUID) -> uuid.UUID:
    sc = c.fetchval(
        "SELECT id FROM sibyl.scoring_config WHERE tenant_id = $1 AND activated_at IS NOT NULL", t
    )
    hs = new_id()
    c.execute(
        "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, id, agent_id, score, band, "
        "provisional, "
        "events_seen, observation_coverage, scoring_config_id, policy_version, routing_state_at, "
        "window_start, "
        "window_end, grain_s) VALUES ($1, now(), $2, $3, 90, 'healthy', false, 10, 1, $4, 1, "
        "'active', "
        "now() - interval '5 minutes', now(), 300)",
        t,
        hs,
        r["a"],
        sc,
    )
    c.execute(
        "INSERT INTO sibyl.agent_trend_state (tenant_id, agent_id, metric, last_bucket, "
        "scoring_config_id) "
        "VALUES ($1, $2, 'error_rate', "
        "date_bin('5 minutes', now(), '2000-01-01'::timestamptz), $3)",
        t,
        r["a"],
        sc,
    )
    c.execute(
        "INSERT INTO sibyl.agent_baseline (tenant_id, agent_id, metric, hour_of_week, "
        "computed_at, baseline_ref) "
        "VALUES ($1, $2, 'error_rate', 10, now(), 'own/how4w')",
        t,
        r["a"],
    )
    c.execute(
        "INSERT INTO sibyl.prediction (tenant_id, predicted_at, agent_id, health_snapshot_id, "
        "feature_snapshot_id, "
        "scoring_config_id, horizon_s, source, probability_band, confidence) VALUES ($1, now(), "
        "$2, $3, $4, $5, "
        "900, 'rules/v1', '0.05', 'low')",
        t,
        r["a"],
        hs,
        fs,
        sc,
    )
    c.execute(
        "INSERT INTO sibyl.health_1h (tenant_id, agent_id, bucket_start, ticks) "
        "VALUES ($1, $2, date_trunc('hour', now()), 6)",
        t,
        r["a"],
    )
    c.execute(
        "INSERT INTO sibyl.agent_risk (tenant_id, agent_id, as_of, risk_score, risk_band, "
        "inherent, "
        "control_coverage, health_28d, contributions, scoring_config_id, graph_version) VALUES "
        "($1, $2, current_date, 40, 'medium', '{}', '{}', '{}', '[]', $3, 1)",
        t,
        r["a"],
        sc,
    )
    c.execute(
        "INSERT INTO sibyl.rollup_job (tenant_id, kind, grains, range_from, range_to, reason) "
        "VALUES "
        "($1, 'backfill', '{1m}', now() - interval '1 hour', now(), 'test')",
        t,
    )
    c.execute(
        "INSERT INTO sibyl.job (tenant_id, kind, params, requested_by_kind) "
        "VALUES ($1, 'audit_verify', '{\"from_seq\": 0}', 'system')",
        t,
    )
    model = new_id()
    c.execute(
        "INSERT INTO sibyl.ml_model (tenant_id, id, name, version, horizon_s, feature_set, "
        "trained_at, train_from, "
        "train_to, n_rows, n_pos, artifact_ref_id, artifact_sha256) VALUES ($1, $2, 'sibyl-gbt', "
        "'2026-10-10.1', "
        "900, 'features/v1', now(), now() - interval '30 days', now(), 100, 3, $3, $4)",
        t,
        model,
        new_id(),
        h32("artifact"),
    )
    c.execute(
        "INSERT INTO sibyl.ml_prediction_shadow (tenant_id, evaluated_at, health_snapshot_id, "
        "model_id, horizon_s, "
        "band) VALUES ($1, now(), $2, $3, 900, '0.05')",
        t,
        hs,
        model,
    )
    c.execute(
        "INSERT INTO sibyl.risk_assessment (tenant_id, agent_id, suggested_class, declared_class, "
        "graph_version) "
        "VALUES ($1, $2, 'high', 'unclassified', 1)",
        t,
        r["a"],
    )
    return sc


def _agent_b(
    c: Conn,
    t: uuid.UUID,
    ids: dict[str, uuid.UUID],
    r: dict[str, uuid.UUID],
    x: dict[str, uuid.UUID],
    sc: uuid.UUID,
) -> None:
    """Agent-keyed rows for agent B as well, so an agent-scope erasure of either agent has a
    victim and a bystander with data (G0-tests F3). Fallback chains stay A-only: tests build
    B's chains themselves."""
    b = r["b"]
    rh = h32("profile-b")
    payload_key = c.fetchval(
        "SELECT id FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'payload'", t
    )
    c.execute(
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, "
        "call_id, emitter_id, seq, policy_state, capture_mode, redaction_profile_hash, "
        "normaliser_version, status, latency_ms) VALUES ($1, $2, now(), 'gen_ai.request', "
        "'gateway', $3, $4, 'gw-1', 2, 'fresh', 'full', $5, 'normaliser/1.0', 'ok', 80)",
        t,
        new_id(),
        b,
        new_id(),
        rh,
    )
    c.execute(
        "INSERT INTO sibyl.payload_refs (tenant_id, kind, uri, sha256, size_bytes, stored_bytes, "
        "tenant_key_id, key_version, nonce, capture_mode, redaction_profile_hash, agent_id, "
        "source_kind, expires_at) VALUES ($1, 'span_content', 'tenant/x/payload-b.bin', $2, 10, "
        "12, $3, 1, $4, 'full', $5, $6, 'event', now() + interval '30 days')",
        t,
        h32("payload-b"),
        payload_key,
        b"\x05" * 12,
        rh,
        b,
    )
    c.execute(
        "INSERT INTO sibyl.checkpoint (tenant_id, id, agent_id, task_id, seq, step_index, "
        "state_bytes, state, state_schema, doc, capture_mode, redaction_profile_hash) VALUES "
        "($1, $2, $3, $4, 1, 0, 2, '{}', 'state/1', '{}', 'full', $5)",
        t,
        new_id(),
        b,
        new_id(),
        rh,
    )
    for table, bucket in (
        ("agent_metrics_1m", "date_trunc('minute', now())"),
        ("agent_metrics_5m", "date_bin('5 minutes', now(), '2000-01-01'::timestamptz)"),
        ("agent_metrics_1h", "date_trunc('hour', now())"),
    ):
        c.execute(
            f"INSERT INTO sibyl.{table} (tenant_id, agent_id, provider, model, bucket_start, "
            f"request_count) VALUES ($1, $2, 'provider-one', 'large-1', {bucket}, 3)",
            t,
            b,
        )
    version = new_id()
    c.execute(
        "INSERT INTO sibyl.agent_version (tenant_id, id, agent_id, version_no, primary_model_id, "
        "source) VALUES ($1, $2, $3, 1, $4, 'api')",
        t,
        version,
        b,
        r["m2"],
    )
    c.execute(
        "INSERT INTO sibyl.ai_bom (tenant_id, agent_version_id, content, content_sha256, "
        "generator_version) VALUES ($1, $2, '{\"bomFormat\": \"CycloneDX\"}', $3, 'bom/1')",
        t,
        version,
        h32("bom-b"),
    )
    c.execute(
        "INSERT INTO sibyl.agent_identity (tenant_id, agent_id, tools_hash) VALUES ($1, $2, $3)",
        t,
        b,
        h32("tools-b"),
    )
    c.execute(
        "INSERT INTO sibyl.dependency_edge (tenant_id, src_kind, src_id, dst_kind, dst_id, "
        "edge_type, origin) VALUES ($1, 'agent', $2, 'tool', $3, 'calls_tool', 'declared')",
        t,
        b,
        r["tool"],
    )
    c.execute("SELECT sibyl.blast_radius_refresh($1, 'tool', $2)", t, r["tool"])
    prefix = secrets.token_hex(6)
    c.execute(
        "INSERT INTO sibyl.api_key (tenant_id, agent_id, name, env, prefix, secret_hash, scopes, "
        "expires_at, created_by) VALUES ($1, $2, 'sdk-b', 'live', $3, $4, '{ingest:write}', "
        "now() + interval '1 year', $5)",
        t,
        b,
        prefix,
        h32(prefix),
        ids["owner"],
    )
    profile = c.fetchval(
        "SELECT id FROM sibyl.redaction_profile WHERE tenant_id = $1 AND name = 'pii_standard'", t
    )
    c.execute(
        "INSERT INTO sibyl.capture_policy (tenant_id, scope_kind, agent_id, capture_mode, "
        "redaction_profile_id, consequences_version, chosen_by, version_no) VALUES ($1, 'agent', "
        "$2, 'metadata', $3, 'c1', $4, 1)",
        t,
        b,
        profile,
        ids["owner"],
    )
    c.execute("INSERT INTO sibyl.continuity_plan (tenant_id, agent_id) VALUES ($1, $2)", t, b)
    seq = c.fetchval(
        "SELECT seq FROM sibyl.audit_append($1, 'human', $2, NULL, NULL, 'asset.approved', "
        "'agent', $3, NULL, 'reviewed', $4::jsonb, NULL, now(), NULL)",
        t,
        ids["owner"],
        b,
        json.dumps(
            {"lifecycle_from": "discovered", "lifecycle_to": "proposed", "approval_ref": "y"}
        ),
    )
    c.execute(
        "INSERT INTO sibyl.lifecycle_transition (tenant_id, agent_id, from_stage, to_stage, "
        "actor_user_id, audit_seq) VALUES ($1, $2, 'discovered', 'proposed', $3, $4)",
        t,
        b,
        ids["owner"],
        seq,
    )
    c.execute(
        "UPDATE sibyl.agent SET lifecycle = 'proposed' WHERE tenant_id = $1 AND id = $2", t, b
    )
    failover, approval, alert, fs, hs, label = (new_id() for _ in range(6))
    c.execute(
        "INSERT INTO sibyl.failover (tenant_id, id, agent_id, kind, idempotency_key, actor_kind, "
        "from_state) VALUES ($1, $2, $3, 'failover', $4, 'rule', 'active')",
        t,
        failover,
        b,
        f"f:{failover}",
    )
    c.execute(
        "INSERT INTO sibyl.approval (tenant_id, id, failover_id, agent_id, requested_action, "
        "risk, tier, requested_by_kind, requested_by_rule_id, expires_at, timeout_policy) VALUES "
        "($1, $2, $3, $4, 'alt_provider_failover', 'medium', 2, 'rule', $5, "
        "now() + interval '10 minutes', 'hold')",
        t,
        approval,
        failover,
        b,
        x["rule"],
    )
    c.execute(
        "INSERT INTO sibyl.alert (tenant_id, id, rule_id, scope, agent_id, severity, dedupe_key, "
        "what_to_do, summary) VALUES ($1, $2, $3, 'agent', $4, 'warning', $5, 'check', 'errors')",
        t,
        alert,
        x["rule"],
        b,
        f"error_rate:{b}",
    )
    c.execute(
        "INSERT INTO sibyl.handoff_task (tenant_id, id, agent_id, failover_id, task_id, "
        "packet_id, packet, packet_sha256, fidelity, failure_mode, trigger_kind, assembled_by, "
        "priority, deadline_at, next_action, summary) VALUES ($1, $2, $3, $4, $5, $6, '{}', $7, "
        "'request_only', 'provider_outage', 'rule', 'control_plane', 2, "
        "now() + interval '15 minutes', 'review', 'handoff')",
        t,
        new_id(),
        b,
        failover,
        new_id(),
        new_id(),
        h32("packet-b"),
    )
    c.execute(
        "INSERT INTO sibyl.feature_snapshot (tenant_id, id, agent_id, as_of, feature_set, reason, "
        "observation_coverage) VALUES ($1, $2, $3, now(), 'features/v1', 'alert', 1)",
        t,
        fs,
        b,
    )
    c.execute(
        "INSERT INTO sibyl.label (tenant_id, id, agent_id, kind, label_strength, judges_kind, "
        "judges_id, feature_snapshot_id, judged_as_of, labeller_kind, value) VALUES ($1, $2, $3, "
        "'alert_verdict', 'verdict', 'alert', $4, $5, now(), 'operator', '{\"verdict\": \"fp\"}')",
        t,
        label,
        b,
        str(alert),
        fs,
    )
    c.execute(
        "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, id, agent_id, score, band, "
        "provisional, events_seen, observation_coverage, scoring_config_id, policy_version, "
        "routing_state_at, window_start, window_end, grain_s) VALUES ($1, now(), $2, $3, 70, "
        "'degraded', false, 10, 1, $4, 1, 'active', now() - interval '5 minutes', now(), 300)",
        t,
        hs,
        b,
        sc,
    )
    c.execute(
        "INSERT INTO sibyl.agent_trend_state (tenant_id, agent_id, metric, last_bucket, "
        "scoring_config_id) VALUES ($1, $2, 'error_rate', "
        "date_bin('5 minutes', now(), '2000-01-01'::timestamptz), $3)",
        t,
        b,
        sc,
    )
    c.execute(
        "INSERT INTO sibyl.agent_baseline (tenant_id, agent_id, metric, hour_of_week, "
        "computed_at, baseline_ref) VALUES ($1, $2, 'error_rate', 11, now(), 'own/how4w')",
        t,
        b,
    )
    c.execute(
        "INSERT INTO sibyl.prediction (tenant_id, predicted_at, agent_id, health_snapshot_id, "
        "feature_snapshot_id, scoring_config_id, horizon_s, source, probability_band, "
        "confidence) VALUES ($1, now(), $2, $3, $4, $5, 900, 'rules/v1', '0.05', 'low')",
        t,
        b,
        hs,
        fs,
        sc,
    )
    c.execute(
        "INSERT INTO sibyl.health_1h (tenant_id, agent_id, bucket_start, ticks) "
        "VALUES ($1, $2, date_trunc('hour', now()), 4)",
        t,
        b,
    )
    c.execute(
        "INSERT INTO sibyl.agent_risk (tenant_id, agent_id, as_of, risk_score, risk_band, "
        "inherent, control_coverage, health_28d, contributions, scoring_config_id, "
        "graph_version) VALUES ($1, $2, current_date, 20, 'low', '{}', '{}', '{}', '[]', $3, 1)",
        t,
        b,
        sc,
    )
    c.execute(
        "INSERT INTO sibyl.risk_assessment (tenant_id, agent_id, suggested_class, declared_class, "
        "graph_version) VALUES ($1, $2, 'limited', 'unclassified', 1)",
        t,
        b,
    )


def _lifecycle(
    c: Conn, t: uuid.UUID, slug: str, ids: dict[str, uuid.UUID], r: dict[str, uuid.UUID]
) -> None:
    c.execute(
        "INSERT INTO sibyl.erasure_request (tenant_id, scope_kind, scope_ref, legal_basis, "
        "requested_by) "
        "VALUES ($1, 'subject', 'subject-hash', 'gdpr_art17', $2)",
        t,
        ids["owner"],
    )
    c.execute(
        "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, window_from, reason, placed_by, "
        "state, released_by, "
        "released_at, release_reason) VALUES ($1, 'tenant', now() - interval '1 day', "
        "'litigation', $2, "
        "'released', $2, now(), 'case closed')",
        t,
        ids["approver"],
    )
    kid = f"anchor-{slug}-{secrets.token_hex(3)}"
    c.execute(
        "INSERT INTO sibyl.signing_key (kid, purpose, public_key, private_key_ref, state) "
        "VALUES ($1, 'audit_anchor', $2, 'file:test', 'retired')",
        kid,
        b"\x03" * 32,
    )
    head = c.fetchrow(
        "SELECT seq, hash FROM sibyl.audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1", t
    )
    c.execute(
        "INSERT INTO sibyl.audit_anchors (tenant_id, kind, seq_from, seq_to, head_hash, "
        "signing_kid, signature) "
        "VALUES ($1, 'hourly', 0, $2, $3, $4, $5)",
        t,
        head["seq"],
        head["hash"],
        kid,
        b"\x04" * 64,
    )


def _action_gate(c: Conn, t: uuid.UUID, ids: dict[str, uuid.UUID], r: dict[str, uuid.UUID]) -> None:
    """D48 Action Gate rows for both agents (lane AG-CORE): an approved agent-scoped policy
    with one rule, a held action, a cumulative counter window and a decision."""
    for label in ("a", "b"):
        agent = r[label]
        policy = new_id()
        c.execute(
            "INSERT INTO sibyl.action_policy (tenant_id, id, name, scope_kind, agent_id,"
            " version_no, state, document, document_sha256, default_effect, hold_timeout_s,"
            " rule_count, created_by_user_id, approved_by_user_id, approved_at)"
            " VALUES ($1, $2, $3, 'agent', $4, 1, 'approved',"
            " '{\"schema\": \"sibyl-action-policy/1\"}', $5, 'escalate', 900, 1, $6, $7, now())",
            t,
            policy,
            f"payments-{label}",
            agent,
            h32(f"policy-{label}"),
            ids["owner"],
            ids["approver"],
        )
        c.execute(
            "INSERT INTO sibyl.action_rule (tenant_id, policy_id, position, rule_id, tool, effect,"
            " reason, when_expr) VALUES ($1, $2, 1, 'over_limit', 'payments.transfer', 'block',"
            " 'over the per-transfer limit', '{\"gt\": [\"/amount\", 10000]}')",
            t,
            policy,
        )
        c.execute(
            "INSERT INTO sibyl.held_action (tenant_id, agent_id, policy_id, policy_version,"
            " rule_id, call_id, tool, source, args_sha256, args_bytes, server_effect, reason,"
            " requested_by_key_id, hold_timeout_s, expires_at) VALUES ($1, $2, $3, 1, 'over_limit',"
            " $4, 'payments.transfer', 'sdk', $5, 20, 'escalate', 'needs a human', $6, 900,"
            " now() + interval '15 minutes')",
            t,
            agent,
            policy,
            f"call-{label}-1",
            h32(f"args-{label}"),
            new_id(),
        )
        c.execute(
            "INSERT INTO sibyl.action_counter (tenant_id, agent_id, counter_key, window_s,"
            " window_start, value, max_value, calls) VALUES ($1, $2, 'daily_cap', 86400,"
            " date_trunc('day', now()), 100, 50000, 1)",
            t,
            agent,
        )
        c.execute(
            "INSERT INTO sibyl.action_decision (tenant_id, agent_id, call_id, tool, policy_id,"
            " policy_version, rule_id, effect, reason, source, api_key_id) VALUES ($1, $2, $3,"
            " 'payments.transfer', $4, 1, 'over_limit', 'allow', 'under the cap', 'sdk', $5)",
            t,
            agent,
            f"call-{label}-2",
            policy,
            new_id(),
        )


_DRIFT_FEATURES = '{"refusal": {"kind": "categorical", "n": 600, "probs": {"no": 1.0}}}'


def _drift(c: Conn, t: uuid.UUID, r: dict[str, uuid.UUID]) -> None:
    """D51 drift rows for both agents (lane DRIFT): a frozen baseline with one report."""
    for label in ("a", "b"):
        baseline = new_id()
        c.execute(
            "INSERT INTO sibyl.drift_baseline (tenant_id, id, agent_id, provider, model, state,"
            " window_start, window_end, sample_count, features, served_models, fingerprints,"
            " frozen_at) VALUES ($1, $2, $3, 'openai', 'gpt-4o', 'frozen',"
            " now() - interval '8 hours', now() - interval '1 hour', 600, $4::jsonb,"
            " '{gpt-4o-2024-08-06}', '{fp_a}', now() - interval '1 hour')",
            t,
            baseline,
            r[label],
            _DRIFT_FEATURES,
        )
        c.execute(
            "INSERT INTO sibyl.drift_report (tenant_id, baseline_id, agent_id, provider, model,"
            " window_start, window_end, sample_count, verdict, behaviour_evaluated, features)"
            " VALUES ($1, $2, $3, 'openai', 'gpt-4o', now() - interval '1 hour', now(), 250,"
            " 'none', true, '[]')",
            t,
            baseline,
            r[label],
        )


def _drift_thresholds(c: Conn, t: uuid.UUID, ids: dict[str, uuid.UUID]) -> None:
    """Wave 4 HARDEN: the tenant's drift threshold overrides (PSI drift and call minimum set,
    the rest null = deployment default)."""
    c.execute(
        "INSERT INTO sibyl.drift_thresholds (tenant_id, psi_drift, min_samples_calls,"
        " updated_by_user_id) VALUES ($1, 0.3, 400, $2)",
        t,
        ids["owner"],
    )


def _sentinel(c: Conn, t: uuid.UUID, ids: dict[str, uuid.UUID], r: dict[str, uuid.UUID]) -> None:
    """D52 Sibyl Sentinel rows (lane SENTINEL): the tenant's config with a sealed key, a drift
    finding per agent, a fleet summary and one day of usage."""
    key = c.fetchval(
        "SELECT id FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'credential'", t
    )
    c.execute(
        "INSERT INTO sibyl.sentinel_config (tenant_id, enabled, provider, model, ciphertext, nonce,"
        " tenant_key_id, key_version, key_hint, key_updated_at, daily_budget_usd, sampling_rate,"
        " tasks, updated_by_user_id) VALUES ($1, true, 'anthropic', 'claude-fable-5-1', $2, $3, $4,"
        " 1, '6789', now(), 5, 0.25, ARRAY['semantic_drift', 'fleet_summary'], $5)",
        t,
        b"\x01" * 48,
        b"\x02" * 12,
        key,
        ids["owner"],
    )
    for label in ("a", "b"):
        c.execute(
            "INSERT INTO sibyl.sentinel_finding (tenant_id, kind, subject_kind, subject_id,"
            " agent_id, severity, summary, provider, model, prompt_sha256, trigger, dedupe_key)"
            " VALUES ($1, 'semantic_drift', 'agent', $2, $2, 'info', 'on purpose', 'anthropic',"
            " 'claude-fable-5-1', $3, 'scheduled', $4)",
            t,
            r[label],
            h32(f"sentinel-{label}"),
            f"drift:{r[label]}:fixture",
        )
    c.execute(
        "INSERT INTO sibyl.sentinel_finding (tenant_id, kind, subject_kind, severity, summary,"
        " provider, model, prompt_sha256, trigger) VALUES ($1, 'fleet_summary', 'fleet', 'info',"
        " 'all quiet', 'anthropic', 'claude-fable-5-1', $2, 'scheduled')",
        t,
        h32("sentinel-fleet"),
    )
    c.execute(
        "INSERT INTO sibyl.sentinel_usage (tenant_id, day, spent_usd, calls, findings)"
        " VALUES ($1, current_date, 0.25, 3, 3)",
        t,
    )


def _monitors(c: Conn, t: uuid.UUID, ids: dict[str, uuid.UUID], r: dict[str, uuid.UUID]) -> None:
    """D53 external monitor rows (lane EXTMON): a monitor watching every group, its bound key, a
    signed webhook with one delivery per agent, and an external finding per agent plus a fleet
    finding."""
    key = c.fetchval(
        "SELECT id FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'credential'", t
    )
    monitor = c.fetchval(
        "INSERT INTO sibyl.monitor (tenant_id, name, kind, owner_user_id, created_by_user_id)"
        " VALUES ($1, 'claude-watch', 'mcp', $2, $2) RETURNING id",
        t,
        ids["owner"],
    )
    prefix = secrets.token_hex(6)
    api_key = c.fetchval(
        "INSERT INTO sibyl.api_key (tenant_id, monitor_id, name, env, prefix, secret_hash, scopes,"
        " expires_at, created_by) VALUES ($1, $2, 'monitor', 'live', $3, $4,"
        " '{monitor:read,findings:write}', now() + interval '1 year', $5) RETURNING id",
        t,
        monitor,
        prefix,
        h32(prefix),
        ids["owner"],
    )
    webhook = c.fetchval(
        "INSERT INTO sibyl.monitor_webhook (tenant_id, monitor_id, url, event_types, ciphertext,"
        " nonce, tenant_key_id, key_version, created_by_user_id) VALUES ($1, $2,"
        " 'https://hooks.example.com/sibyl', '{alert.fired,run.failed}', $3, $4, $5, 1, $6)"
        " RETURNING id",
        t,
        monitor,
        b"\x03" * 48,
        b"\x04" * 12,
        key,
        ids["owner"],
    )
    for label in ("a", "b"):
        c.execute(
            "INSERT INTO sibyl.webhook_delivery (tenant_id, webhook_id, monitor_id, event_type,"
            " event_key, agent_id, payload) VALUES ($1, $2, $3, 'run.failed', $4, $5, '{}')",
            t,
            webhook,
            monitor,
            f"run:fixture-{label}",
            r[label],
        )
        c.execute(
            "INSERT INTO sibyl.external_finding (tenant_id, monitor_id, api_key_id, kind,"
            " subject_kind, subject_id, agent_id, severity, summary, provider, model)"
            " VALUES ($1, $2, $3, 'semantic_drift', 'agent', $4, $4, 'warning', 'looks off',"
            " 'anthropic', 'claude-fable-5-1')",
            t,
            monitor,
            api_key,
            r[label],
        )
    c.execute(
        "INSERT INTO sibyl.external_finding (tenant_id, monitor_id, api_key_id, kind, subject_kind,"
        " severity, summary) VALUES ($1, $2, $3, 'fleet_summary', 'fleet', 'info', 'all quiet')",
        t,
        monitor,
        api_key,
    )


def populate_tenant(admin: Conn, slug: str) -> TenantFixture:
    tenant = create_tenant(admin, slug)
    with admin.tx(tenant):
        ids = _identity(admin, tenant, slug)
        r = _registry(admin, tenant, slug, ids)
        cred = _policy(admin, tenant, ids, r)
        x = _routing(admin, tenant, ids, r, cred)
        fs = _telemetry(admin, tenant, ids, r, x)
        sc = _scoring(admin, tenant, r, fs)
        _agent_b(admin, tenant, ids, r, x, sc)
        _lifecycle(admin, tenant, slug, ids, r)
        _action_gate(admin, tenant, ids, r)
        _drift(admin, tenant, r)
        _drift_thresholds(admin, tenant, ids)
        _sentinel(admin, tenant, ids, r)
        _monitors(admin, tenant, ids, r)
    return TenantFixture(
        tenant_id=tenant,
        slug=slug,
        owner=ids["owner"],
        approver=ids["approver"],
        engineer=ids["engineer"],
        session=ids["session"],
        agent_a=r["a"],
        agent_b=r["b"],
        model_a=r["m1"],
        provider_a=r["p1"],
        rule_error_rate=x["rule"],
        scoring_config=sc,
    )


ALLOWLIST = frozenset(
    {
        "tenant",
        "role",
        "role_permission",
        "model_catalog",
        "state_edge",
        "signing_key",
        "audit_action",
        "consumer_offsets",
        "partition_registry",
        "policy_snapshot_issue",
        "schema_migrations",
        "base_url_dev_host",
        "signing_key_set",
    }
)


def tenant_tables(conn: Conn) -> list[str]:
    """Every base (or partitioned parent) table in schema sibyl outside the allowlist."""
    rows = conn.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'sibyl' AND c.relkind IN ('r', 'p') AND NOT c.relispartition ORDER BY 1"
    )
    return [r["relname"] for r in rows if r["relname"] not in ALLOWLIST]


def row_counts(conn: Conn, tenant: uuid.UUID, tables: list[str]) -> dict[str, int]:
    return {
        t: conn.fetchval(f"SELECT count(*) FROM sibyl.{t} WHERE tenant_id = $1", tenant)
        for t in tables
    }
