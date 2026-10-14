"""Lane EXTMON (D53) schema: the four monitor tables under RLS, monitor-bound API keys (scope
shape, binding immutability, the pre-tenant lookup), the revoked-is-terminal guard, webhook URL
gate, external finding subject rules, and the grant matrix (sealed secrets unreadable,
findings immutable but for feedback and the alert link)."""

from __future__ import annotations

import secrets
import uuid

import asyncpg
import pytest

from .conftest import Conn
from .fixtures import TenantFixture, h32, populate_tenant

TABLES = ("monitor", "monitor_webhook", "webhook_delivery", "external_finding")
FIXTURE_ROWS = {"monitor": 1, "monitor_webhook": 1, "webhook_delivery": 2, "external_finding": 3}


@pytest.fixture(scope="module")
def pair(admin: Conn) -> tuple[TenantFixture, TenantFixture]:
    return populate_tenant(admin, "monitors-a"), populate_tenant(admin, "monitors-b")


def _monitor(conn: Conn, fx: TenantFixture) -> uuid.UUID:
    return conn.fetchval(
        "SELECT id FROM sibyl.monitor WHERE tenant_id = $1 ORDER BY created_at LIMIT 1",
        fx.tenant_id,
    )


@pytest.mark.parametrize("table", TABLES)
def test_rls_hides_the_other_tenant(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn], table: str
) -> None:
    a, b = pair
    for role in ("sibyl_app", "sibyl_worker"):
        conn = roles[role]
        with conn.tx(b.tenant_id, rollback=True):
            own = conn.fetchval(f"SELECT count(*) FROM sibyl.{table}")  # noqa: S608 - fixed
            foreign = conn.fetchval(
                f"SELECT count(*) FROM sibyl.{table} WHERE tenant_id = $1",  # noqa: S608
                a.tenant_id,
            )
            assert (own, foreign) == (FIXTURE_ROWS[table], 0), (role, table)
        with conn.tx(rollback=True):
            assert conn.fetchval(f"SELECT count(*) FROM sibyl.{table}") == 0  # noqa: S608


def _key(conn: Conn, fx: TenantFixture, scopes: str, monitor: object, agent: object) -> None:
    prefix = secrets.token_hex(6)
    conn.execute(
        "INSERT INTO sibyl.api_key (tenant_id, monitor_id, agent_id, name, env, prefix,"
        " secret_hash, scopes, expires_at, created_by) VALUES ($1, $2, $3, 'k', 'live', $4, $5,"
        " $6::text[], now() + interval '30 days', $7)",
        fx.tenant_id,
        monitor,
        agent,
        prefix,
        h32(prefix),
        scopes.split(","),
        fx.owner,
    )


@pytest.mark.parametrize(
    ("scopes", "bound", "agent"),
    [
        ("monitor:read", False, False),  # monitor scope without a monitor
        ("findings:write,ingest:write", True, False),  # anything else on a monitor key
        ("monitor:read", True, True),  # a monitor key is never agent-bound
        ("agents:read", True, False),  # a monitor key holds monitor scopes only
    ],
)
def test_monitor_key_shape(
    pair: tuple[TenantFixture, TenantFixture],
    roles: dict[str, Conn],
    scopes: str,
    bound: bool,
    agent: bool,
) -> None:
    a, _ = pair
    app = roles["sibyl_app"]
    with app.tx(a.tenant_id, rollback=True), pytest.raises(asyncpg.CheckViolationError):
        _key(app, a, scopes, _monitor(app, a) if bound else None, a.agent_a if agent else None)


def test_the_binding_is_immutable_and_the_lookup_names_it(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn], admin: Conn
) -> None:
    a, _ = pair
    app = roles["sibyl_app"]
    with app.tx(a.tenant_id, rollback=True):
        key = app.fetchrow(
            "SELECT id, prefix, monitor_id FROM sibyl.api_key WHERE monitor_id IS NOT NULL"
        )
        assert key is not None
        other = app.fetchval(
            "INSERT INTO sibyl.monitor (tenant_id, name, kind, owner_user_id, created_by_user_id)"
            " VALUES ($1, 'second', 'api', $2, $2) RETURNING id",
            a.tenant_id,
            a.owner,
        )
        with pytest.raises(asyncpg.PostgresError, match="key_field_immutable"):
            app.execute("UPDATE sibyl.api_key SET monitor_id = $2 WHERE id = $1", key["id"], other)
    ingest = roles["sibyl_ingest"]
    with ingest.tx(rollback=True):
        row = ingest.fetchrow("SELECT * FROM sibyl.api_key_lookup($1)", key["prefix"])
    assert row["monitor_id"] == key["monitor_id"] and row["tenant_id"] == a.tenant_id


def test_a_revoked_monitor_is_terminal(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn]
) -> None:
    a, _ = pair
    app = roles["sibyl_app"]
    with app.tx(a.tenant_id, rollback=True), pytest.raises(asyncpg.CheckViolationError):
        # revoked needs revoked_at and a reason
        app.execute("UPDATE sibyl.monitor SET state = 'revoked' WHERE id = $1", _monitor(app, a))
    with app.tx(a.tenant_id, rollback=True):
        monitor = _monitor(app, a)
        app.execute(
            "UPDATE sibyl.monitor SET state = 'revoked', revoked_at = now(),"
            " revoke_reason = 'test' WHERE id = $1",
            monitor,
        )
        with pytest.raises(asyncpg.PostgresError, match="invalid_transition"):
            app.execute("UPDATE sibyl.monitor SET state = 'active' WHERE id = $1", monitor)
    with app.tx(a.tenant_id, rollback=True):
        with pytest.raises(asyncpg.PostgresError, match="immutable_row"):
            app.execute("UPDATE sibyl.monitor SET kind = 'webhook' WHERE id = $1", _monitor(app, a))


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/x",
        "https://10.0.0.1/x",
        "https://localhost/x",
        "https://169.254.169.254/latest",
        "ftp://hooks.example.com/x",
    ],
)
def test_webhook_urls_must_be_public_https(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn], admin: Conn, url: str
) -> None:
    a, _ = pair
    hook = admin.fetchrow(
        "SELECT monitor_id, tenant_key_id FROM sibyl.monitor_webhook WHERE tenant_id = $1 LIMIT 1",
        a.tenant_id,
    )
    app = roles["sibyl_app"]
    with app.tx(a.tenant_id, rollback=True), pytest.raises(asyncpg.CheckViolationError):
        app.execute(
            "INSERT INTO sibyl.monitor_webhook (tenant_id, monitor_id, url, event_types,"
            " ciphertext, nonce, tenant_key_id, key_version, created_by_user_id)"
            " VALUES ($1, $2, $3, '{run.failed}', $4, $5, $6, 1, $7)",
            a.tenant_id,
            hook["monitor_id"],
            url,
            b"\x01" * 40,
            b"\x02" * 12,
            hook["tenant_key_id"],
            a.owner,
        )


def test_sealed_secrets_are_unreadable_but_the_definer_opens_its_tenants(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn]
) -> None:
    a, b = pair
    for role in ("sibyl_app", "sibyl_worker"):
        conn = roles[role]
        with conn.tx(a.tenant_id, rollback=True):
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                conn.fetch("SELECT ciphertext FROM sibyl.monitor_webhook")
        with conn.tx(a.tenant_id, rollback=True):
            hook = conn.fetchval("SELECT id FROM sibyl.monitor_webhook LIMIT 1")
            sealed = conn.fetchrow("SELECT * FROM sibyl.monitor_webhook_secret($1)", hook)
            assert sealed is not None and len(bytes(sealed["nonce"])) == 12
        with conn.tx(b.tenant_id, rollback=True):
            assert conn.fetchrow("SELECT * FROM sibyl.monitor_webhook_secret($1)", hook) is None
    with roles["sibyl_ingest"].tx(rollback=True), pytest.raises(asyncpg.InsufficientPrivilegeError):
        roles["sibyl_ingest"].fetch("SELECT * FROM sibyl.monitor_webhook_secret($1)", hook)


def test_external_findings_are_immutable_but_for_feedback_and_the_alert_link(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn]
) -> None:
    a, _ = pair
    app, worker = roles["sibyl_app"], roles["sibyl_worker"]
    with app.tx(a.tenant_id, rollback=True):
        finding = app.fetchval("SELECT id FROM sibyl.external_finding LIMIT 1")
        app.execute(
            "UPDATE sibyl.external_finding SET feedback = 'useful', feedback_by_user_id = $2,"
            " feedback_at = now() WHERE id = $1",
            finding,
            a.owner,
        )
    for conn, column in ((app, "summary"), (app, "alert_id"), (worker, "summary")):
        with conn.tx(a.tenant_id, rollback=True), pytest.raises(asyncpg.InsufficientPrivilegeError):
            conn.execute(
                f"UPDATE sibyl.external_finding SET {column} = NULL WHERE id = $1",  # noqa: S608
                finding,
            )
    with worker.tx(a.tenant_id, rollback=True), pytest.raises(asyncpg.InsufficientPrivilegeError):
        worker.execute("DELETE FROM sibyl.external_finding WHERE id = $1", finding)


@pytest.mark.parametrize(
    ("kind", "subject_kind", "with_subject"),
    [
        ("incident_explanation", "agent", True),
        ("held_action_review", "incident", True),
        ("semantic_drift", "run", True),
        ("fleet_summary", "fleet", True),
        ("anomaly", "fleet", True),
        ("anomaly", "agent", False),
    ],
)
def test_external_finding_subjects(
    pair: tuple[TenantFixture, TenantFixture],
    roles: dict[str, Conn],
    kind: str,
    subject_kind: str,
    with_subject: bool,
) -> None:
    a, _ = pair
    app = roles["sibyl_app"]
    with app.tx(a.tenant_id, rollback=True), pytest.raises(asyncpg.CheckViolationError):
        app.execute(
            "INSERT INTO sibyl.external_finding (tenant_id, monitor_id, api_key_id, kind,"
            " subject_kind, subject_id, agent_id, severity, summary)"
            " SELECT tenant_id, monitor_id, api_key_id, $2, $3, $4, $5, 'info', 'x'"
            " FROM sibyl.external_finding WHERE tenant_id = $1 LIMIT 1",
            a.tenant_id,
            kind,
            subject_kind,
            a.agent_a if with_subject else None,
            a.agent_a,
        )


def test_catalogue_rows(admin: Conn) -> None:
    roles = {
        r["role_name"]
        for r in admin.fetch(
            "SELECT role_name FROM sibyl.role_permission WHERE permission = 'monitors:admin'"
        )
    }
    assert roles == {"owner", "admin", "security_admin"}
    assert not admin.fetchval(
        "SELECT count(*) FROM sibyl.role_permission"
        " WHERE permission IN ('monitor:read', 'findings:write')"
    )
    actions = {
        r["name"]: list(r["actor_types"])
        for r in admin.fetch(
            "SELECT name, actor_types FROM sibyl.audit_action WHERE domain = 'monitor'"
        )
    }
    assert actions["finding.submitted"] == ["api_key"]
    assert actions["webhook.delivery_failed"] == ["system"]
    assert len(actions) == 7
