"""INT-1 database amendments (wave 2 integration lane, item 4).

* ``continuity_plan.expected_cadence_s`` (R9 heartbeat cadence used by the health engine);
* a seeded ``flapping`` alert rule (R48 flap detector, warning, no score penalty);
* ``fillfactor = 70`` on every ``agent_metrics_{1m,5m,1h}`` partition (HOT rollup upserts);
* ``content_hashes`` subtrees of digests are exempt from the content-key denylist;
* ``api_key`` may emit ``asset.discovered``; ``system`` may emit ``membership.granted``;
* a ``metadata``-mode checkpoint row may carry neither inline state nor a state ref;
* ingest scrub counts live in ``events.scrub_late_hits`` / ``events.scrub_rules_fired``.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import asyncpg
import pytest
from sibyl_schemas import values as sv

from .conftest import Conn
from .fixtures import TenantFixture, create_tenant, h32, new_id, populate_tenant
from .test_audit_g0 import APPEND, CHANGE, _jcs

HEX = "ab" * 32


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "int1-amend")


# --- continuity_plan.expected_cadence_s ------------------------------------------------------


def test_continuity_plan_stores_an_expected_cadence(
    fx: TenantFixture, roles: dict[str, Conn]
) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        app.execute(
            "UPDATE sibyl.continuity_plan SET expected_cadence_s = 60 WHERE agent_id = $1",
            fx.agent_a,
        )
        value = app.fetchval(
            "SELECT expected_cadence_s FROM sibyl.continuity_plan WHERE agent_id = $1", fx.agent_a
        )
    assert value == 60


def test_continuity_plan_cadence_defaults_to_null(admin: Conn, fx: TenantFixture) -> None:
    with admin.tx(fx.tenant_id, rollback=True):
        assert (
            admin.fetchval(
                "SELECT expected_cadence_s FROM sibyl.continuity_plan WHERE agent_id = $1",
                fx.agent_b,
            )
            is None
        )


@pytest.mark.parametrize("bad", [0, -5])
def test_continuity_plan_cadence_must_be_positive(admin: Conn, fx: TenantFixture, bad: int) -> None:
    with pytest.raises(asyncpg.CheckViolationError, match="ck_continuity_plan_cadence"):
        with admin.tx(fx.tenant_id, rollback=True):
            admin.execute(
                "UPDATE sibyl.continuity_plan SET expected_cadence_s = $2 WHERE agent_id = $1",
                fx.agent_a,
                bad,
            )


# --- flapping alert rule ----------------------------------------------------------------------


def test_new_tenants_get_a_flapping_warning_rule(admin: Conn) -> None:
    tenant = create_tenant(admin, "int1-flap")
    with admin.tx(tenant, rollback=True):
        row = admin.fetchrow(
            "SELECT severity, penalty, origin, kind, scope, enabled FROM sibyl.alert_rule"
            " WHERE tenant_id = $1 AND code = 'flapping'",
            tenant,
        )
    assert row is not None
    assert dict(row) == {
        "severity": "warning",
        "penalty": 0,
        "origin": "seed",
        "kind": "detected",
        "scope": "agent",
        "enabled": True,
    }


# --- fillfactor on the rollup grains ----------------------------------------------------------

METRICS = ("agent_metrics_1m", "agent_metrics_5m", "agent_metrics_1h")


def _partitions(admin: Conn, table: str) -> list[asyncpg.Record]:
    return admin.fetch(
        "SELECT c.relname, c.reloptions FROM pg_inherits i"
        " JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent"
        " JOIN pg_namespace n ON n.oid = p.relnamespace"
        " WHERE n.nspname = 'sibyl' AND p.relname = $1",
        table,
    )


@pytest.mark.parametrize("table", METRICS)
def test_metric_partitions_use_fillfactor_70(admin: Conn, table: str) -> None:
    parts = _partitions(admin, table)
    assert parts, f"{table} has no partitions"
    assert all("fillfactor=70" in (p["reloptions"] or []) for p in parts), parts


def test_partitions_created_later_keep_fillfactor_70(admin: Conn, roles: dict[str, Conn]) -> None:
    worker = roles["sibyl_worker"]
    before = {p["relname"] for p in _partitions(worker, "agent_metrics_1h")}
    with worker.tx(rollback=True):
        worker.fetchval(
            "SELECT sibyl.partition_ensure('agent_metrics_1h', now() + interval '2 years',"
            " now() + interval '2 years 1 month')"
        )
        added = [p for p in _partitions(worker, "agent_metrics_1h") if p["relname"] not in before]
    assert added
    assert all("fillfactor=70" in (p["reloptions"] or []) for p in added)
    events = _partitions(admin, "events")
    assert events
    assert all(not any("fillfactor" in o for o in (p["reloptions"] or [])) for p in events)


# --- content_hashes exemption -----------------------------------------------------------------


@pytest.mark.parametrize(
    "doc",
    [
        {"content_hashes": {"input": HEX, "output": HEX, "system": HEX}},
        {"content_hashes": {"input_sha256": HEX, "output_sha256": HEX, "system_sha256": HEX}},
        {"nested": [{"Content_Hashes": {"input": HEX}}]},
        {"content_hashes": {}},
    ],
)
def test_content_hash_subtrees_are_not_content(admin: Conn, doc: dict[str, Any]) -> None:
    assert admin.fetchval("SELECT sibyl.has_content_key($1::jsonb)", json.dumps(doc)) is False


@pytest.mark.parametrize(
    "doc",
    [
        {"prompt": "hello"},
        {"content_hashes": {"input": "the raw prompt text"}},
        {"content_hashes": {"input": HEX.upper()}},
        {"content_hashes": {"input": {"prompt": HEX}}},
        {"content_hashes": [{"prompt": "x"}]},
        {"hashes": {"input": HEX}},
        {"content_hashes": {"input": HEX}, "output": "x"},
    ],
)
def test_content_keys_are_still_refused(admin: Conn, doc: dict[str, Any]) -> None:
    assert admin.fetchval("SELECT sibyl.has_content_key($1::jsonb)", json.dumps(doc)) is True


def test_hash_only_keys_are_the_schemas_list(admin: Conn) -> None:
    assert set(admin.fetchval("SELECT sibyl.audit_hash_only_keys()")) == set(
        sv.AUDIT_HASH_ONLY_KEYS
    )


def test_event_attrs_store_content_hashes(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    ingest = roles["sibyl_ingest"]
    attrs = {"content_hashes": {"input": HEX, "output": HEX, "system": HEX}}
    with ingest.tx(fx.tenant_id, rollback=True):
        _insert_event(ingest, fx, attrs=attrs)


def test_event_attrs_with_content_are_refused(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    ingest = roles["sibyl_ingest"]
    with pytest.raises(asyncpg.CheckViolationError, match="ck_events_attrs"):
        with ingest.tx(fx.tenant_id, rollback=True):
            _insert_event(ingest, fx, attrs={"content_hashes": {"input": "plain text prompt"}})


def test_audit_detail_stores_content_hashes(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, "int1-audit-hash")
    app = roles["sibyl_app"]
    detail = {**CHANGE, "content_hashes": {"input_sha256": HEX, "input": HEX}}
    with app.tx(tenant, rollback=True):
        row = app.fetchrow(
            APPEND,
            tenant,
            "human",
            uuid.uuid4(),
            "config.changed",
            "why",
            json.dumps(detail),
            _jcs(detail).encode(),
        )
    assert row is not None


def test_audit_detail_with_a_content_key_is_refused(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, "int1-audit-prompt")
    app = roles["sibyl_app"]
    detail = {**CHANGE, "content_hashes": {"input": HEX}, "prompt": "x"}
    with pytest.raises(asyncpg.PostgresError, match="audit_detail_invalid"):
        with app.tx(tenant, rollback=True):
            app.fetchrow(
                APPEND,
                tenant,
                "human",
                uuid.uuid4(),
                "config.changed",
                "why",
                json.dumps(detail),
                _jcs(detail).encode(),
            )


# --- audit actor widening ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "actor"), [("asset.discovered", "api_key"), ("membership.granted", "system")]
)
def test_actor_widening_is_seeded_and_in_the_taxonomy(admin: Conn, action: str, actor: str) -> None:
    seeded = admin.fetchval("SELECT actor_types FROM sibyl.audit_action WHERE name = $1", action)
    assert actor in seeded
    assert actor in {a.value for a in sv.AUDIT_ACTIONS[action].actor_types}


def test_system_grants_membership_without_a_reason(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, "int1-jit")
    app = roles["sibyl_app"]
    detail = {"user_id": str(new_id()), "role": "viewer", "scope_kind": "tenant", "scope_id": None}
    with app.tx(tenant, rollback=True):
        row = app.fetchrow(
            "SELECT * FROM sibyl.audit_append($1, 'system', NULL, NULL, NULL,"
            " 'membership.granted', 'membership', $2, NULL, NULL, $3::jsonb, $4, now(), NULL)",
            tenant,
            new_id(),
            json.dumps(detail),
            _jcs(detail).encode(),
        )
    assert row is not None


def test_api_key_records_asset_discovered(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, "int1-disc")
    app = roles["sibyl_app"]
    key = new_id()
    detail = {"slug": "unclaimed/x", "api_key_id": str(key), "default_fail_mode": "open"}
    with app.tx(tenant, rollback=True):
        row = app.fetchrow(
            "SELECT * FROM sibyl.audit_append($1, 'api_key', NULL, $2, NULL,"
            " 'asset.discovered', 'agent', $3, NULL, NULL, $4::jsonb, $5, now(), NULL)",
            tenant,
            key,
            new_id(),
            json.dumps(detail),
            _jcs(detail).encode(),
        )
    assert row is not None


# --- metadata-mode checkpoints ----------------------------------------------------------------


def _insert_checkpoint(
    conn: Conn, fx: TenantFixture, *, mode: str, state: str | None, ref: uuid.UUID | None
) -> None:
    conn.execute(
        "INSERT INTO sibyl.checkpoint (tenant_id, id, agent_id, task_id, seq, step_index,"
        " state_bytes, state, state_ref_id, state_schema, doc, capture_mode,"
        " redaction_profile_hash) VALUES ($1, $2, $3, $4, 1, 0, $5, $6::jsonb, $7, 'state/1',"
        " '{}', $8, $9)",
        fx.tenant_id,
        new_id(),
        fx.agent_a,
        new_id(),
        2 if ref is None else 70000,
        state,
        ref,
        mode,
        h32("profile"),
    )


def test_metadata_checkpoint_may_carry_no_state(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    ingest = roles["sibyl_ingest"]
    with ingest.tx(fx.tenant_id, rollback=True):
        _insert_checkpoint(ingest, fx, mode="metadata", state=None, ref=None)


@pytest.mark.parametrize("mode", ["full", "redacted"])
def test_captured_checkpoint_still_needs_state_or_ref(
    admin: Conn, fx: TenantFixture, mode: str
) -> None:
    with pytest.raises(asyncpg.CheckViolationError):
        with admin.tx(fx.tenant_id, rollback=True):
            _insert_checkpoint(admin, fx, mode=mode, state=None, ref=None)


def test_metadata_checkpoint_never_carries_state(admin: Conn, fx: TenantFixture) -> None:
    with pytest.raises(asyncpg.CheckViolationError, match="ck_checkpoint_metadata"):
        with admin.tx(fx.tenant_id, rollback=True):
            _insert_checkpoint(admin, fx, mode="metadata", state="{}", ref=None)


def test_checkpoint_never_has_both_state_and_ref(admin: Conn, fx: TenantFixture) -> None:
    with pytest.raises(asyncpg.CheckViolationError):
        with admin.tx(fx.tenant_id, rollback=True):
            _insert_checkpoint(admin, fx, mode="full", state="{}", ref=new_id())


# --- scrub counts on events -------------------------------------------------------------------


def _insert_event(
    conn: Conn,
    fx: TenantFixture,
    *,
    attrs: dict[str, Any] | None = None,
    late_hits: int | None = None,
    rules: list[str] | None = None,
) -> None:
    conn.execute(
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id,"
        " call_id, emitter_id, seq, policy_state, capture_mode, redaction_profile_hash,"
        " normaliser_version, status, attrs, scrub_late_hits, scrub_rules_fired) VALUES"
        " ($1, $2, now(), 'gen_ai.request', 'gateway', $3, $4, 'gw-int1', 1, 'fresh', 'full', $5,"
        " 'normaliser/1.0', 'ok', $6::jsonb, $7, $8)",
        fx.tenant_id,
        new_id(),
        fx.agent_a,
        new_id(),
        h32("profile"),
        json.dumps(attrs or {}),
        late_hits,
        rules,
    )


def test_events_store_scrub_counts(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    ingest = roles["sibyl_ingest"]
    with ingest.tx(fx.tenant_id, rollback=True):
        _insert_event(ingest, fx, late_hits=2, rules=["secrets.openai_key", "pii.email"])
        row = ingest.fetchrow(
            "SELECT scrub_late_hits, scrub_rules_fired FROM sibyl.events"
            " WHERE emitter_id = 'gw-int1'"
        )
    assert row is not None and row["scrub_late_hits"] == 2
    assert row["scrub_rules_fired"] == ["secrets.openai_key", "pii.email"]


@pytest.mark.parametrize(
    ("late_hits", "rules"),
    [(-1, None), (None, ["Not A Rule"]), (None, ["x" * 65]), (None, [f"r{i}" for i in range(65)])],
)
def test_scrub_counts_are_bounded(
    admin: Conn, fx: TenantFixture, late_hits: int | None, rules: list[str] | None
) -> None:
    with pytest.raises(asyncpg.CheckViolationError, match="ck_events_scrub"):
        with admin.tx(fx.tenant_id, rollback=True):
            _insert_event(admin, fx, late_hits=late_hits, rules=rules)
