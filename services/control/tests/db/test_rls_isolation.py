# ruff: noqa: S608 -- SQL identifiers here come from pg_catalog or fixed literals, never from input
"""(a) Generated tenant-isolation suite (DATAMODEL §7 gate 1, ADR-7, S12).

For every tenant table in the catalogue (never a hand-kept list) and every login role, with
tenant B's context: A's rows are invisible, UPDATE and DELETE of A's rows affect nothing,
inserting a row of A raises; with no tenant set nothing is visible. Structure checks: RLS
enabled and forced, exactly one policy rls_tenant_<table>, every index leads with tenant_id,
a (tenant_id, id) key wherever id exists, partitions unreachable by login roles.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import asyncpg
import pytest

from .conftest import LOGIN_ROLES, Conn
from .fixtures import TenantFixture, populate_tenant, tenant_tables

# Global lookup keys resolved before a tenant is known (served by SECURITY DEFINER lookups).
INDEX_LEADING_EXCEPTIONS = frozenset({"ux_api_key_prefix", "ux_session_token_hash"})
# BEFORE INSERT triggers that look up the row's parents run first (WITH CHECK is evaluated
# after BEFORE triggers); under tenant B they cannot see A's parents and refuse. Any error
# other than the RLS violation (42501) is a finding.
TRIGGER_REFUSALS = {
    "capture_policy": "SB043",
    "continuity_plan": "SB048",
    "dependency_edge": "SB045",
    "fallback_step": "SB040",
}


@pytest.fixture(scope="module")
def pair(admin: Conn) -> tuple[TenantFixture, TenantFixture]:
    return populate_tenant(admin, "isolation-a"), populate_tenant(admin, "isolation-b")


@pytest.fixture(scope="module")
def tables(admin: Conn) -> list[str]:
    return tenant_tables(admin)


def _priv(admin: Conn, role: str, table: str, privilege: str) -> bool:
    fn = "has_table_privilege" if privilege == "DELETE" else "has_any_column_privilege"
    return bool(
        admin.fetchval(f"SELECT {fn}($1, format('sibyl.%I', $2::text), $3)", role, table, privilege)
    )


def _updatable_column(admin: Conn, role: str, table: str) -> str | None:
    return admin.fetchval(
        "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = format('sibyl.%I', "
        "$2::text)::regclass "
        "AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = '' "
        "AND has_column_privilege($1, a.attrelid, a.attname, 'UPDATE') ORDER BY a.attnum LIMIT 1",
        role,
        table,
    )


def _insertable_columns(admin: Conn, role: str, table: str) -> list[str]:
    rows = admin.fetch(
        "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = format('sibyl.%I', "
        "$2::text)::regclass "
        "AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = '' "
        "AND has_column_privilege($1, a.attrelid, a.attname, 'INSERT') ORDER BY a.attnum",
        role,
        table,
    )
    return [r["attname"] for r in rows]


@pytest.fixture(scope="module")
def failures() -> Iterator[list[str]]:
    found: list[str] = []
    yield found


def _check_role(admin: Conn, conn: Conn, role: str, table: str, a: Any, b: Any) -> list[str]:
    problems: list[str] = []
    if _priv(admin, role, table, "SELECT"):
        with conn.tx(b, rollback=True):
            leaked = conn.fetchval(f"SELECT count(*) FROM sibyl.{table} WHERE tenant_id <> $1", b)
            if leaked:
                problems.append(f"{role} sees {leaked} foreign rows")
            if conn.fetchval(f"SELECT count(*) FROM sibyl.{table}") == 0:
                problems.append(f"{role} sees none of its own rows")
        with conn.tx(rollback=True):
            if conn.fetchval(f"SELECT count(*) FROM sibyl.{table}"):
                problems.append(f"{role} sees rows with no tenant set")
    column = _updatable_column(admin, role, table)
    if column and _priv(admin, role, table, "SELECT"):
        with conn.tx(b, rollback=True):
            status = conn.execute(
                f'UPDATE sibyl.{table} SET "{column}" = "{column}" WHERE tenant_id = $1', a
            )
            if status != "UPDATE 0":
                problems.append(f"{role} updated foreign rows: {status}")
    if _priv(admin, role, table, "DELETE") and _priv(admin, role, table, "SELECT"):
        with conn.tx(b, rollback=True):
            status = conn.execute(f"DELETE FROM sibyl.{table} WHERE tenant_id = $1", a)
            if status != "DELETE 0":
                problems.append(f"{role} deleted foreign rows: {status}")
    columns = _insertable_columns(admin, role, table)
    if "tenant_id" in columns:
        with admin.tx(a, rollback=True):
            row = admin.fetchval(
                f"SELECT to_jsonb(t) FROM sibyl.{table} t WHERE tenant_id = $1 LIMIT 1", a
            )
        cols = ", ".join(f'"{c}"' for c in columns)
        try:
            with conn.tx(b, rollback=True):
                conn.execute(
                    f"INSERT INTO sibyl.{table} ({cols}) SELECT {cols} FROM "
                    f"jsonb_populate_record(NULL::sibyl.{table}, $1::jsonb)",
                    row,
                )
            problems.append(f"{role} inserted a row of another tenant")
        except asyncpg.PostgresError as exc:
            if exc.sqlstate != "42501" and TRIGGER_REFUSALS.get(table) != exc.sqlstate:
                problems.append(
                    f"{role} foreign insert raised {exc.sqlstate} instead of the RLS violation"
                )
    return problems


def test_every_tenant_table_isolates_every_role(
    admin: Conn,
    roles: dict[str, Conn],
    tables: list[str],
    pair: tuple[TenantFixture, TenantFixture],
) -> None:
    a, b = pair[0].tenant_id, pair[1].tenant_id
    report: dict[str, list[str]] = {}
    for table in tables:
        for role in LOGIN_ROLES:
            problems = _check_role(admin, roles[role], role, table, a, b)
            if problems:
                report.setdefault(table, []).extend(problems)
    assert report == {}, json.dumps(report, indent=1)


def test_foreign_insert_raises_rls_violation_where_no_trigger_intervenes(
    admin: Conn, roles: dict[str, Conn], pair: tuple[TenantFixture, TenantFixture]
) -> None:
    a, b = pair[0].tenant_id, pair[1].tenant_id
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="row-level security"):
        with app.tx(b, rollback=True):
            app.execute(
                "INSERT INTO sibyl.tool (tenant_id, slug, name, kind) VALUES ($1, 'x', 'x', "
                "'function')",
                a,
            )


def test_rls_structure(admin: Conn, tables: list[str]) -> None:
    report: dict[str, list[str]] = {}
    for table in tables:
        problems: list[str] = []
        rel = admin.fetchrow(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass",
            f"sibyl.{table}",
        )
        if not (rel["relrowsecurity"] and rel["relforcerowsecurity"]):
            problems.append("RLS not enabled and forced")
        policies = [
            r["policyname"]
            for r in admin.fetch(
                "SELECT policyname FROM pg_policies WHERE schemaname = 'sibyl' AND tablename = $1",
                table,
            )
        ]
        if policies != [f"rls_tenant_{table}"]:
            problems.append(f"policies {policies}")
        for idx in admin.fetch(
            "SELECT i.relname, a.attname FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid "
            "LEFT JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = x.indkey[0] "
            "WHERE x.indrelid = $1::regclass",
            f"sibyl.{table}",
        ):
            if idx["attname"] != "tenant_id" and idx["relname"] not in INDEX_LEADING_EXCEPTIONS:
                problems.append(f"index {idx['relname']} leads with {idx['attname']}")
        has_id = admin.fetchval(
            "SELECT count(*) FROM pg_attribute WHERE attrelid = $1::regclass AND attname = 'id' "
            "AND NOT attisdropped",
            f"sibyl.{table}",
        )
        if has_id and not admin.fetchval(
            "SELECT count(*) FROM pg_constraint c WHERE c.conrelid = $1::regclass AND c.contype "
            "IN ('p', 'u') "
            "AND (SELECT array_agg(attname::text ORDER BY attname) FROM pg_attribute "
            "     WHERE attrelid = c.conrelid AND attnum = ANY (c.conkey)) @> ARRAY['id', "
            "'tenant_id'] "
            "AND cardinality(c.conkey) <= 3",
            f"sibyl.{table}",
        ):
            problems.append("no (tenant_id, id) key")
        if problems:
            report[table] = problems
    assert report == {}, json.dumps(report, indent=1)


def test_partitions_are_unreachable_and_forced(admin: Conn) -> None:
    partitions = admin.fetch(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'sibyl' AND "
        "c.relispartition "
        "AND c.relkind IN ('r', 'p')"
    )
    assert partitions, "partition_ensure_ahead created no partitions"
    for part in partitions:
        assert part["relrowsecurity"] and part["relforcerowsecurity"], part["relname"]
        for role in LOGIN_ROLES:
            assert not admin.fetchval(
                "SELECT has_table_privilege($1, format('sibyl.%I', $2::text), "
                "'SELECT,INSERT,UPDATE,DELETE')",
                role,
                part["relname"],
            ), part["relname"]


def test_service_roles_cannot_bypass_rls(admin: Conn) -> None:
    rows = admin.fetch(
        "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname LIKE "
        "'sibyl\\_%'"
    )
    by_name = {r["rolname"]: r for r in rows}
    assert set(by_name) == {
        "sibyl_app",
        "sibyl_ingest",
        "sibyl_worker",
        "sibyl_audit",
        "sibyl_routing",
        "sibyl_migrate",
    }
    assert not any(r["rolsuper"] or r["rolbypassrls"] for r in rows)
    assert not by_name["sibyl_audit"]["rolcanlogin"] and not by_name["sibyl_routing"]["rolcanlogin"]


def test_key_lookup_works_before_tenant_and_only_through_the_definer(
    roles: dict[str, Conn], admin: Conn, pair: tuple[TenantFixture, TenantFixture]
) -> None:
    a = pair[0].tenant_id
    with admin.tx(a, rollback=True):
        prefix = admin.fetchval("SELECT prefix FROM sibyl.api_key WHERE tenant_id = $1 LIMIT 1", a)
    ingest = roles["sibyl_ingest"]
    with ingest.tx(rollback=True):
        assert ingest.fetchval("SELECT count(*) FROM sibyl.api_key WHERE prefix = $1", prefix) == 0
        row = ingest.fetchrow("SELECT * FROM sibyl.api_key_lookup($1)", prefix)
    assert row["tenant_id"] == a
    assert list(row.keys()) == [
        "tenant_id",
        "id",
        "env",
        "secret_hash",
        "scopes",
        "agent_id",
        "status",
        "expires_at",
        "rotation_grace_until",
        "monitor_id",  # D53: the monitor a key is bound to
    ]


def test_worker_cannot_read_secret_columns(
    roles: dict[str, Conn], pair: tuple[TenantFixture, TenantFixture]
) -> None:
    worker = roles["sibyl_worker"]
    for sql in (
        "SELECT secret_hash FROM sibyl.api_key",
        "SELECT ciphertext FROM sibyl.provider_credential",
    ):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            with worker.tx(pair[0].tenant_id, rollback=True):
                worker.fetch(sql)
    with worker.tx(pair[0].tenant_id, rollback=True):
        assert worker.fetchval("SELECT count(*) FROM sibyl.provider_credential_meta") == 1


def test_strict_mode_raises_without_tenant(roles: dict[str, Conn]) -> None:
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError, match="sibyl:tenant_not_set"):
        with app.tx(rollback=True):
            app.execute("SET LOCAL app.tenant_strict = 'on'")
            app.fetch("SELECT * FROM sibyl.agent")


def test_checker_detects_a_disabled_policy(
    admin: Conn, roles: dict[str, Conn], pair: tuple[TenantFixture, TenantFixture]
) -> None:
    """Negative control: the generated check must fail when isolation is actually broken."""
    a, b = pair[0].tenant_id, pair[1].tenant_id
    admin.execute("ALTER TABLE sibyl.tool DISABLE ROW LEVEL SECURITY")
    try:
        problems = _check_role(admin, roles["sibyl_app"], "sibyl_app", "tool", a, b)
    finally:
        admin.execute("ALTER TABLE sibyl.tool ENABLE ROW LEVEL SECURITY")
    assert any("foreign rows" in p for p in problems)
    assert any("instead of the RLS violation" in p for p in problems)


def test_checks_reach_every_table(admin: Conn, tables: list[str]) -> None:
    selectable = [t for t in tables if any(_priv(admin, r, t, "SELECT") for r in LOGIN_ROLES)]
    insertable = [
        t
        for t in tables
        if any("tenant_id" in _insertable_columns(admin, r, t) for r in LOGIN_ROLES)
    ]
    assert selectable == tables, "every tenant table is readable by some service role"
    assert len(insertable) >= 50


def test_committed_tenant_context_does_not_survive_the_transaction(
    db: Any, pair: tuple[TenantFixture, TenantFixture]
) -> None:
    """A session-scoped set_tenant would leak into the next pooled transaction (G0-tests F6):
    commit, as every real request does, then use the same connection with no tenant."""
    a = pair[0].tenant_id
    conn = db.connect("sibyl_app")
    try:
        with conn.tx(a):
            assert conn.fetchval("SELECT count(*) FROM sibyl.agent") > 0
        with conn.tx(rollback=True):
            assert conn.fetchval("SELECT sibyl.current_tenant()") is None
            assert conn.fetchval("SELECT count(*) FROM sibyl.agent") == 0
        assert conn.fetchval("SELECT sibyl.current_tenant()") is None
    finally:
        conn.close()


def test_login_roles_are_members_of_nothing(admin: Conn) -> None:
    """A membership in sibyl_audit would let SET ROLE reach the cross-tenant lookup policy."""
    rows = admin.fetch(
        "SELECT m.rolname AS member, r.rolname AS role FROM pg_auth_members am "
        "JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid "
        "WHERE m.rolname = ANY($1::text[])",
        list(LOGIN_ROLES),
    )
    assert [dict(r) for r in rows] == []


def test_no_readable_relation_bypasses_rls(admin: Conn, tables: list[str]) -> None:
    """Every relation a login role can read, in any schema and of any kind, that carries
    tenant data is an RLS-forced tenant table; views must be security_invoker, materialized
    and foreign tables are refused (G0-tests F13)."""
    rows = admin.fetch(
        "SELECT n.nspname, c.relname, c.relkind::text AS relkind, "
        "coalesce(c.reloptions, '{}') AS opts FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') "
        "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
        "AND n.nspname NOT LIKE 'pg\\_toast%' AND EXISTS (SELECT 1 FROM pg_attribute a "
        "WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped) "
        "AND EXISTS (SELECT 1 FROM unnest($1::text[]) r "
        "WHERE has_any_column_privilege(r, c.oid, 'SELECT'))",
        list(LOGIN_ROLES),
    )
    allowed_tables = set(tables) | {"consumer_offsets"}
    bad = []
    for r in rows:
        if (
            r["relkind"] in ("r", "p")
            and r["nspname"] == "sibyl"
            and r["relname"] in allowed_tables
        ):
            continue
        if r["relkind"] == "v" and "security_invoker=true" in r["opts"]:
            continue
        bad.append((f"{r['nspname']}.{r['relname']}", r["relkind"]))
    assert bad == []


def test_the_relation_sweep_catches_a_materialized_view(admin: Conn, tables: list[str]) -> None:
    """Negative control for the sweep above."""
    with admin.tx(rollback=True):
        admin.execute(
            "CREATE MATERIALIZED VIEW sibyl.zz_leak AS SELECT tenant_id, id FROM sibyl.agent"
        )
        admin.execute("GRANT SELECT ON sibyl.zz_leak TO sibyl_app")
        with pytest.raises(AssertionError):
            test_no_readable_relation_bypasses_rls(admin, tables)
