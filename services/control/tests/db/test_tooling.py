"""Unit tests for the migrate tooling that need no database."""

from __future__ import annotations

import base64
import importlib
import json
from pathlib import Path

import pytest
from sibyl_control.migrate import ledger, rules_seed
from sibyl_control.migrate.__main__ import main
from sibyl_control.migrate.config import from_env
from sibyl_control.migrate.errcodes import CODE_TO_SQLSTATE, code_for
from sibyl_control.migrate.rules_seed import RulesSeedError, load
from sibyl_schemas.canonical import canonicalize


class TestSingleCanonicaliser:
    """G0-1: the migrate tooling has no canonicaliser of its own."""

    def test_migrate_jcs_module_is_gone(self) -> None:
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("sibyl_control.migrate.jcs")

    def test_rules_seed_uses_the_shared_canonicaliser(self) -> None:
        assert rules_seed.canonicalize is canonicalize
        text = load().scoring_canonical
        assert canonicalize(json.loads(text)).decode() == text


def _signed(key: object, n: int, scope: str = "tenant") -> tuple:
    entries: tuple = ()
    for i in range(n):
        entries = ledger.append(
            entries,
            signing_key=key,  # type: ignore[arg-type]
            tenant_id=f"00000000-0000-0000-0000-00000000000{i}",
            erasure_request_id=f"00000000-0000-0000-0000-0000000000a{i}",
            scope_kind=scope,
            scope_ref=None,
            key_ids=[],
            completed_at="2026-10-10T00:00:00.000000Z",
            subject_set={"agent_ids": [], "window_from": "x", "window_to": None}
            if scope == "subject"
            else None,
        )
    return entries


class TestLedger:
    key = ledger.generate_signing_key()
    pub = ledger.public_key_of(key)

    def test_round_trip_and_chain(self) -> None:
        entries = _signed(self.key, 2)
        verified = ledger.verify(ledger.to_jsonl(entries), self.pub)
        assert [e["seq"] for e in verified] == [0, 1]
        assert verified[0]["prev_hash"] == ledger.GENESIS_PREV_HASH
        assert verified[1]["prev_hash"] == ledger.entry_hash(verified[0])
        assert ledger.head_of(()) == (0, ledger.GENESIS_PREV_HASH)

    def test_detects_tamper_reorder_and_unknown_fields(self) -> None:
        text = ledger.to_jsonl(_signed(self.key, 2))
        for bad in (
            text.replace("00000000001", "00000000009"),
            "\n".join(reversed(text.splitlines())),
            text.replace('"sig"', '"extra":1,"sig"', 1),
            "not json\n",
        ):
            with pytest.raises(ledger.LedgerError):
                ledger.verify(bad, self.pub)

    def test_rejects_unknown_scope_and_a_misplaced_subject_set(self) -> None:
        with pytest.raises(ledger.LedgerError):
            _signed(self.key, 1, scope="planet")
        with pytest.raises(ledger.LedgerError):
            ledger.append(
                (),
                signing_key=self.key,
                tenant_id="t",
                erasure_request_id="r",
                scope_kind="subject",
                scope_ref="s",
                key_ids=[],
                completed_at="x",
            )

    def test_head_record_detects_a_cut_tail(self) -> None:
        entries = _signed(self.key, 3)
        record = ledger.sign_head(entries, self.key, at="2026-10-10T00:00:00Z")
        ledger.verify_head(record, entries, self.pub)
        with pytest.raises(ledger.LedgerError):
            ledger.verify_head(record, entries[:2], self.pub)
        with pytest.raises(ledger.LedgerError):
            ledger.verify_head({**record, "count": 2}, entries[:2], self.pub)
        with pytest.raises(ledger.LedgerError):
            ledger.load_head("[]")

    def test_key_formats(self, tmp_path: Path) -> None:
        pem = ledger.private_key_pem(self.key)
        assert ledger.load_private_key(pem).public_key().public_bytes_raw() == (
            self.pub.public_bytes_raw()
        )
        raw = ledger.load_public_key(ledger.public_key_pem(self.pub)).public_bytes_raw()
        b64 = base64.urlsafe_b64encode(raw).rstrip(b"=")
        assert ledger.load_public_key(b64).public_bytes_raw() == raw
        assert ledger.load_public_key(raw).public_bytes_raw() == raw
        for bad in (b"nonsense", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"):
            with pytest.raises((ledger.LedgerError, ValueError)):
                ledger.load_public_key(bad)
        with pytest.raises(ledger.LedgerError):
            ledger.load_private_key(b"short")

    def test_cli_rejects_a_missing_file(self, tmp_path: Path) -> None:
        pub = tmp_path / "k.pub"
        pub.write_bytes(ledger.public_key_pem(self.pub))
        code = main(["ledger-head", "--ledger", str(tmp_path / "nope"), "--public-key", str(pub)])
        assert code == 4


class TestConfig:
    def test_compose_contract(self) -> None:
        cfg = from_env(
            {
                "SIBYL_DB_HOST": "postgres",
                "SIBYL_DB_PORT": "5432",
                "SIBYL_DB_NAME": "sibyl",
                "SIBYL_DB_USER": "sibyl_migrate",
                "SIBYL_DB_PASSWORD": "m",
                "SIBYL_PG_ADMIN_USER": "postgres",
                "SIBYL_PG_ADMIN_PASSWORD": "a",
                "SIBYL_ROLE_PASSWORD_SIBYL_APP": "p1",
                "SIBYL_ROLE_PASSWORD_SIBYL_INGEST": "p2",
                "SIBYL_ROLE_PASSWORD_SIBYL_WORKER": "p3",
            }
        )
        assert cfg.migrate.kwargs() == {
            "dsn": None,
            "host": "postgres",
            "port": 5432,
            "user": "sibyl_migrate",
            "password": "m",
            "database": "sibyl",
        }
        assert (
            cfg.admin is not None and cfg.admin.user == "postgres" and cfg.admin.database == "sibyl"
        )
        assert dict(cfg.role_passwords) == {
            "sibyl_app": "p1",
            "sibyl_ingest": "p2",
            "sibyl_worker": "p3",
            "sibyl_migrate": "m",
        }
        assert "p1" not in repr(cfg) and "'m'" not in repr(cfg.migrate)

    def test_dsn_mode_and_no_admin(self) -> None:
        cfg = from_env({"SIBYL_PG_MIGRATE_DSN": "postgresql://sibyl_migrate@db/sibyl"})
        assert cfg.admin is None and cfg.migrate.dsn == "postgresql://sibyl_migrate@db/sibyl"


def test_errcode_map_is_bijective() -> None:
    assert code_for("SB010") == "invalid_transition" and code_for("23505") is None
    assert len(CODE_TO_SQLSTATE) == len(set(CODE_TO_SQLSTATE.values()))


def test_cli_rules_seed_check_and_verify() -> None:
    assert main(["rules-seed", "--check"]) == 0
    assert main(["verify"]) == 0


def test_rules_seed_rejects_bad_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "defaults.yaml"
    bad.write_text(
        "schema: sibyl-rules/1\nrules_source: rules/v1\nseed_version: '1'\nfeature_set: "
        "features/v1\n"
        "scoring: {}\nrules:\n  - {code: x_rule, kind: detected, metric: m, comparator: above, "
        "window_s: 1,"
        " min_samples: 1, cap: [1, 2], hysteresis_in: [1, 1, 1], hysteresis_out: [1, 1, 1],"
        " cooldown_s: [1, 1, 1], what_to_do: x}\n"
    )
    with pytest.raises(RulesSeedError, match="three per-tier"):
        load(bad)
