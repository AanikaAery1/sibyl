"""Generated guard: the fixture writes a row into every tenant table, so a new tenant table
without a fixture (and therefore without isolation and erasure coverage) fails here."""

from __future__ import annotations

from .conftest import Conn
from .fixtures import ALLOWLIST, populate_tenant, row_counts, tenant_tables


def test_table_inventory(admin: Conn) -> None:
    tables = tenant_tables(admin)
    # + audit_chain_head, tenant_pseudonym_key (G0), job (B14), five Action Gate tables (D48),
    # two drift tables (D51), three Sentinel tables (D52), four external monitor tables (D53),
    # drift_thresholds (wave 4 HARDEN)
    assert len(tables) == 83
    allowlisted = admin.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'sibyl' AND c.relkind IN ('r', 'p') AND NOT c.relispartition "
        "AND c.relname = ANY($1::text[])",
        list(ALLOWLIST),
    )
    assert len(allowlisted) == len(ALLOWLIST) == 13  # + base_url_dev_host, signing_key_set


def test_fixture_covers_every_tenant_table(admin: Conn) -> None:
    fixture = populate_tenant(admin, "coverage")
    counts = row_counts(admin, fixture.tenant_id, tenant_tables(admin))
    empty = sorted(t for t, n in counts.items() if n == 0)
    assert empty == [], f"tenant tables without fixture rows: {empty}"
