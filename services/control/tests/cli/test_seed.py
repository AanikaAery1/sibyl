"""``sibyl seed`` builds the D29 world through the real handlers, and a second run is a no-op."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import re
import secrets
import sys
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from pydantic import SecretStr
from sibyl_control.cli import seed as seed_cli
from sibyl_control.core.settings import Settings


def _harness() -> ModuleType:
    name = "sibyl_lane_r_harness"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "api" / "registry" / "_harness.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


H = _harness()
COUNTED = (
    "agent",
    "provider",
    "model",
    "provider_credential",
    "continuity_plan",
    "fallback_chain",
    "dependency_edge",
    "tool",
    "data_source",
    "business_process",
    "agent_group",
    "app_user",
    "membership",
    "capture_policy",
)


def _dsn(name: str, role: str) -> str:
    parts = urlsplit(H.ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, f"{role}@{host}", f"/{name}", "", ""))


class Db:
    def __init__(self, loop: asyncio.AbstractEventLoop, name: str) -> None:
        self.loop = loop
        self.name = name

    def fetch(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        async def run() -> list[asyncpg.Record]:
            conn = await asyncpg.connect(_dsn(self.name, "postgres"))
            try:
                return list(await conn.fetch(sql, *args))
            finally:
                await conn.close()

        return self.loop.run_until_complete(run())

    def val(self, sql: str, *args: Any) -> Any:
        rows = self.fetch(sql, *args)
        return rows[0][0] if rows else None

    def settings(self) -> Settings:
        return Settings(
            pg_dsn=SecretStr(_dsn(self.name, "sibyl_app")),
            kek=SecretStr(H.KEK_ENV),
            kek_id=H.KEK_ID,
        )

    def counts(self, slug: str) -> dict[str, int]:
        tenant = self.val("SELECT id FROM sibyl.tenant WHERE slug = $1", slug)
        return {
            t: int(self.val(f"SELECT count(*) FROM sibyl.{t} WHERE tenant_id = $1", tenant))  # noqa: S608
            for t in COUNTED
        }


@pytest.fixture(scope="module")
def db() -> Iterator[Db]:
    loop = asyncio.new_event_loop()
    if not H._available(loop):
        loop.close()
        pytest.skip("PostgreSQL 17 not reachable (make db-up)")
    name = f"sibyl_rseed_{secrets.token_hex(6)}"
    loop.run_until_complete(H._admin_exec(f'CREATE DATABASE "{name}"'))
    try:
        loop.run_until_complete(
            H.apply(
                H.MigrateConfig(migrate=H._spec(name, "sibyl_migrate"), admin=H._spec(name, None))
            )
        )
        yield Db(loop, name)
    finally:
        loop.run_until_complete(H._admin_exec(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        loop.close()


@pytest.fixture(scope="module")
def first_run(db: Db) -> seed_cli.Report:
    with pytest.raises(seed_cli.SeedError, match="base_url_dev_host"):
        asyncio.run(seed_cli.seed(db.settings()))
    return asyncio.run(seed_cli.seed(db.settings(), migrate_dsn=_dsn(db.name, "sibyl_migrate")))


def test_world_matches_d29(db: Db, first_run: seed_cli.Report) -> None:
    agents = {
        slug: int(
            db.val(
                "SELECT count(*) FROM sibyl.agent a JOIN sibyl.tenant t ON t.id = a.tenant_id"
                " WHERE t.slug = $1",
                slug,
            )
        )
        for slug in ("meridian", "northstar", "sandbox")
    }
    assert agents == {"meridian": 20, "northstar": 3, "sandbox": 0}
    tiers = dict(
        db.fetch(
            "SELECT a.tier, count(*) FROM sibyl.agent a JOIN sibyl.tenant t ON t.id = a.tenant_id"
            " WHERE t.slug = 'meridian' GROUP BY a.tier"
        )
    )
    assert tiers == {1: 4, 2: 8, 3: 8}
    providers = db.fetch(
        "SELECT p.slug, p.base_url FROM sibyl.provider p JOIN sibyl.tenant t ON t.id = p.tenant_id"
        " WHERE t.slug = 'meridian' ORDER BY p.slug"
    )
    assert [p["slug"] for p in providers] == ["anthropic-stub", "ollama-stub", "openai-stub"]
    assert all(p["base_url"].startswith("https://sim:18082/") for p in providers)
    sandbox = db.counts("sandbox")
    assert sandbox["agent"] == 0 and sandbox["capture_policy"] == 0
    assert first_run.awaiting_bound_key and all(
        a.startswith("meridian/") for a in first_run.awaiting_bound_key
    )


def test_every_stub_model_has_a_documented_price() -> None:
    """Spend (R5, L4, the gateway's budget limit) is priced from the model rows at ingest: an
    unpriced seed leaves every agent's month-to-date spend at zero (S-05, S-06)."""
    models = {m for tenant in seed_cli.WORLD for p in tenant.providers for m in p.models}
    assert set(seed_cli.MODEL_PRICES) == models
    for name, (input_usd, output_usd) in seed_cli.MODEL_PRICES.items():
        for price in (input_usd, output_usd):
            assert re.fullmatch(r"[0-9]+\.[0-9]{4}", price), (name, price)
        assert Decimal(output_usd) >= Decimal(input_usd), name  # output tokens never cheaper


def test_seeded_models_carry_their_prices(db: Db, first_run: seed_cli.Report) -> None:
    rows = db.fetch("SELECT model_name, input_usd_per_1m, output_usd_per_1m FROM sibyl.model")
    assert rows
    for r in rows:
        want = tuple(Decimal(p) for p in seed_cli.MODEL_PRICES[r["model_name"]])
        assert (r["input_usd_per_1m"], r["output_usd_per_1m"]) == want, r["model_name"]


def test_personas_follow_r56_and_b3(db: Db, first_run: seed_cli.Report) -> None:
    rows = db.fetch(
        "SELECT t.slug, u.subject, m.role_name FROM sibyl.membership m"
        " JOIN sibyl.app_user u ON u.tenant_id = m.tenant_id AND u.id = m.user_id"
        " JOIN sibyl.tenant t ON t.id = m.tenant_id"
    )
    bound = {(r["slug"], r["subject"][-4:], r["role_name"]) for r in rows}
    assert bound == {
        ("meridian", "d001", "owner"),
        ("meridian", "d002", "operator"),
        ("meridian", "d002", "security_admin"),
        ("meridian", "d003", "auditor"),
        ("northstar", "d001", "owner"),
        ("northstar", "d002", "operator"),
        ("northstar", "d002", "security_admin"),
        ("northstar", "d003", "auditor"),
        ("sandbox", "d001", "owner"),
    }


def test_every_agent_has_a_plan_and_an_approved_chain(db: Db, first_run: seed_cli.Report) -> None:
    rows = db.fetch(
        "SELECT a.slug, a.tier, a.lifecycle, p.fallback_chain_id, c.status, c.requested_by_user_id,"
        " c.approved_by_user_id FROM sibyl.agent a"
        " JOIN sibyl.continuity_plan p ON p.tenant_id = a.tenant_id AND p.agent_id = a.id"
        " JOIN sibyl.fallback_chain c ON c.tenant_id = a.tenant_id AND c.id = p.fallback_chain_id"
    )
    assert len(rows) == 23
    assert all(r["status"] == "approved" for r in rows)
    for r in rows:
        if r["tier"] == 1:
            assert r["approved_by_user_id"] != r["requested_by_user_id"]  # four eyes
            assert r["lifecycle"] == "proposed"  # R35: waits for an agent-bound key
        else:
            assert r["lifecycle"] == "deployed"
    kinds = {r["kind"] for r in db.fetch("SELECT DISTINCT kind FROM sibyl.fallback_step")}
    assert {"alt_model_same_provider", "alt_provider", "backup_agent", "human_queue"} <= kinds
    unvaulted = db.val(
        "SELECT count(*) FROM sibyl.fallback_step WHERE kind = 'alt_provider'"
        " AND credential_id IS NULL"
    )
    assert unvaulted == 0
    sealed = db.fetch("SELECT ciphertext, secret_hint FROM sibyl.provider_credential")
    assert sealed and all(r["ciphertext"] is not None for r in sealed)
    assert not any(b"demo-key" in bytes(r["ciphertext"]) for r in sealed)


def test_graph_and_audit_were_written_through_the_api(db: Db, first_run: seed_cli.Report) -> None:
    meridian = db.counts("meridian")
    assert meridian["dependency_edge"] >= 20 + 6  # uses_model per agent + served_by per model
    actions = dict(
        db.fetch(
            "SELECT e.action, count(*) FROM sibyl.audit_events e JOIN sibyl.tenant t"
            " ON t.id = e.tenant_id WHERE t.slug = 'meridian' GROUP BY e.action"
        )
    )
    assert actions["asset.created"] == 20
    assert actions["credential.created"] == 3
    assert actions["capture.policy_set"] == 1
    assert "config.changed" in actions and "asset.approved" in actions


def test_second_run_is_a_no_op(db: Db, first_run: seed_cli.Report) -> None:
    before = {slug: db.counts(slug) for slug in ("meridian", "northstar", "sandbox")}
    audit_before = db.val("SELECT count(*) FROM sibyl.audit_events")
    outbox_before = db.val("SELECT count(*) FROM sibyl.outbox")
    again = asyncio.run(seed_cli.seed(db.settings()))
    assert again.total == 0, again.created
    assert {slug: db.counts(slug) for slug in before} == before
    assert db.val("SELECT count(*) FROM sibyl.audit_events") == audit_before
    assert db.val("SELECT count(*) FROM sibyl.outbox") == outbox_before


def test_persona_names_are_role_based_and_reconciled(db: Db, first_run: seed_cli.Report) -> None:
    def people() -> set[tuple[str, str, str]]:
        rows = db.fetch("SELECT subject, email, display_name FROM sibyl.app_user")
        return {(r["subject"][-4:], r["email"], r["display_name"]) for r in rows}

    expected = {
        ("d001", "admin@demo.sibyl.example", "Platform Admin"),
        ("d002", "operator@demo.sibyl.example", "On-call Operator"),
        ("d003", "auditor@demo.sibyl.example", "Compliance Auditor"),
    }
    assert people() == expected
    # A stack seeded under an earlier persona naming is brought in line by the next seed.
    db.fetch(
        "UPDATE sibyl.app_user SET email = 'legacy@demo.sibyl.example', display_name = 'Legacy'"
        " WHERE subject LIKE '%d002'"
    )
    again = asyncio.run(seed_cli.seed(db.settings()))
    assert again.created == {"app_user_renamed": 2}  # meridian + northstar
    assert people() == expected


def test_cli_entry_point(
    db: Db,
    first_run: seed_cli.Report,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SIBYL_PG_DSN", _dsn(db.name, "sibyl_app"))
    monkeypatch.setenv("SIBYL_KEK", H.KEK_ENV)
    monkeypatch.setenv("SIBYL_KEK_ID", H.KEK_ID)
    assert seed_cli.main(["--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["created"] == {}
    assert seed_cli.main(["--sim-host", "not-allowlisted"]) == 2
    assert "base_url_dev_host" in capsys.readouterr().err
