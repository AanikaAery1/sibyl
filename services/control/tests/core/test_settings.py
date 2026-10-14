import importlib.util
from pathlib import Path

import pytest
from sibyl_control.core.canonical import USING_SHARED_CANONICALISER
from sibyl_control.core.settings import NATIVE_PORTS, PROCESS_SECRETS, Settings


def test_dsn_from_parts_quotes_credentials(monkeypatch) -> None:
    for key, value in {
        "SIBYL_DB_HOST": "postgres",
        "SIBYL_DB_PORT": "5432",
        "SIBYL_DB_NAME": "sibyl",
        "SIBYL_DB_USER": "sibyl_app",
        "SIBYL_DB_PASSWORD": "p@ss/word",
    }.items():
        monkeypatch.setenv(key, value)
    assert Settings().dsn() == "postgresql://sibyl_app:p%40ss%2Fword@postgres:5432/sibyl"


def test_full_dsn_override_wins(monkeypatch) -> None:
    monkeypatch.setenv("SIBYL_PG_DSN", "postgresql://x@y/z")
    assert Settings().dsn() == "postgresql://x@y/z"


def test_ports_default_to_native_and_honour_http_port(monkeypatch) -> None:
    monkeypatch.delenv("SIBYL_HTTP_PORT", raising=False)
    assert NATIVE_PORTS == {"api": 8010, "ingest": 8011, "worker": 8012}
    assert Settings().port_for("api") == 8010
    monkeypatch.setenv("SIBYL_HTTP_PORT", "8000")
    assert Settings().port_for("api") == 8000


def test_oidc_issuer_is_rewritten_to_the_internal_base() -> None:
    s = Settings(oidc_issuer="http://localhost:5556/dex", oidc_internal_url="http://dex:5556/dex")
    assert s.oidc_discovery_url() == "http://dex:5556/dex/.well-known/openid-configuration"
    assert s.oidc_internal("http://localhost:5556/dex/keys") == "http://dex:5556/dex/keys"
    assert s.oidc_internal("http://localhost:5556/dexter") == "http://localhost:5556/dexter"
    assert Settings(oidc_issuer=None).oidc_discovery_url() is None


def test_blob_settings_and_secret_checks(tmp_path) -> None:
    s = Settings(blob_root="/data/blob", key_pepper=None)
    assert s.blob_root == "/data/blob"
    with pytest.raises(RuntimeError, match="PEPPER"):
        s.require_secrets("api")
    good = Settings(**_secrets_for("api", tmp_path), blob_backend="gcs")
    with pytest.raises(RuntimeError, match="BLOB_BACKEND"):
        good.require_secrets("api")
    assert "aa" * 32 not in repr(good)


def test_canonicaliser_source_is_reported() -> None:
    assert USING_SHARED_CANONICALISER is True


# --- per-process secrets (compose live run follow-up; chair ruling B7) -------------------------

_VALUES = {
    "SIBYL_KEY_PEPPER": "aa" * 32,
    "SIBYL_KEK": "kek-material",
    "SIBYL_SNAPSHOT_SIGNING_KEY": "snapshot-seed",
    "SIBYL_SUBJECT_SALT": "subject-salt",
    "SIBYL_SCRUB_SALT": "scrub-salt",
    "SIBYL_ANCHOR_SIGNING_KEY": "anchor-seed",
}


def _secrets_for(process: str, tmp_path) -> dict:
    out = {}
    for name in PROCESS_SECRETS[process]:
        field = name.removeprefix("SIBYL_").lower()
        if name == "SIBYL_LEDGER_SIGNING_KEY_FILE":
            key = tmp_path / "ledger_signing_key"
            key.write_text("seed")
            out[field] = str(key)
        else:
            out[field] = _VALUES[name]
    return out


EXPECTED = {
    "api": {"SIBYL_KEY_PEPPER", "SIBYL_KEK", "SIBYL_SNAPSHOT_SIGNING_KEY", "SIBYL_SUBJECT_SALT"},
    "ingest": {"SIBYL_KEY_PEPPER", "SIBYL_KEK", "SIBYL_SCRUB_SALT", "SIBYL_SUBJECT_SALT"},
    "worker": {"SIBYL_KEK", "SIBYL_LEDGER_SIGNING_KEY_FILE", "SIBYL_ANCHOR_SIGNING_KEY"},
    "gateway": {"SIBYL_SCRUB_SALT"},
}


def test_each_process_requires_exactly_its_secrets() -> None:
    assert {p: set(names) for p, names in PROCESS_SECRETS.items()} == EXPECTED


@pytest.mark.parametrize("process", sorted(EXPECTED))
def test_a_process_starts_with_only_its_own_secrets(process: str, tmp_path, monkeypatch) -> None:
    for name in {n for names in EXPECTED.values() for n in names}:
        monkeypatch.delenv(name, raising=False)
    Settings(**_secrets_for(process, tmp_path)).require_secrets(process)


@pytest.mark.parametrize("process", sorted(EXPECTED))
def test_every_missing_secret_is_named_and_no_value_leaks(process: str, tmp_path) -> None:
    for name in EXPECTED[process]:
        given = _secrets_for(process, tmp_path)
        del given[name.removeprefix("SIBYL_").lower()]
        with pytest.raises(RuntimeError, match=name) as err:
            Settings(**given).require_secrets(process)
        for value in _VALUES.values():
            assert value not in str(err.value)


def test_the_worker_does_not_need_the_pepper_and_the_api_does(tmp_path) -> None:
    worker = Settings(**_secrets_for("worker", tmp_path))
    worker.require_secrets("worker")
    with pytest.raises(RuntimeError, match="SIBYL_KEY_PEPPER"):
        worker.require_secrets("api")


def test_the_ledger_key_file_must_exist(tmp_path) -> None:
    given = _secrets_for("worker", tmp_path)
    given["ledger_signing_key_file"] = str(tmp_path / "missing")
    with pytest.raises(RuntimeError, match="SIBYL_LEDGER_SIGNING_KEY_FILE"):
        Settings(**given).require_secrets("worker")


def test_a_short_pepper_is_refused(tmp_path) -> None:
    given = {**_secrets_for("api", tmp_path), "key_pepper": "aa" * 8}
    with pytest.raises(RuntimeError, match="SIBYL_KEY_PEPPER"):
        Settings(**given).require_secrets("api")


def test_unknown_processes_are_refused() -> None:
    with pytest.raises(ValueError, match="unknown process"):
        Settings().require_secrets("sim")


def _deployed_matrix() -> dict[str, dict[str, str]]:
    root = Path(__file__).resolve().parents[4]
    path = root / "ci" / "tests" / "sibyl_ci_secret_matrix.py"
    spec = importlib.util.spec_from_file_location("sibyl_ci_secret_matrix", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SECRET_MATRIX


# Chair ruling B7 gives ingest the KEK; the compose matrix grants it, so nothing is pending.
B7_PENDING: set[tuple[str, str]] = set()


@pytest.mark.parametrize("process", sorted(EXPECTED))
def test_required_secrets_are_granted_by_the_deployed_matrix(process: str) -> None:
    granted = set(_deployed_matrix()[process])
    if "ledger_signing_key" in granted:  # file-only secret, read through *_FILE
        granted.add("SIBYL_LEDGER_SIGNING_KEY_FILE")
    missing = {(process, name) for name in PROCESS_SECRETS[process] if name not in granted}
    assert missing <= B7_PENDING


def test_the_api_refuses_to_start_without_its_secrets(monkeypatch) -> None:
    from fastapi.testclient import TestClient
    from sibyl_control.api.app import build_app

    for name in EXPECTED["api"]:
        monkeypatch.delenv(name, raising=False)
    app = build_app(Settings(key_pepper="aa" * 32))
    with pytest.raises(RuntimeError, match="SIBYL_SNAPSHOT_SIGNING_KEY"), TestClient(app):
        pass


# ---- SIBYL_S3_* (INT-1): the blob store's S3 configuration lives on Settings ------------------


_S3_ENV = {
    "SIBYL_S3_ENDPOINT": "https://s3.eu-west-1.amazonaws.com",
    "SIBYL_S3_BUCKET": "sibyl-blobs",
    "SIBYL_S3_REGION": "eu-west-1",
    "SIBYL_S3_ACCESS_KEY_ID": "AKIDEXAMPLE",
    "SIBYL_S3_SECRET_ACCESS_KEY": "wJalrXUtnFEMI-s3-secret-value",
    "SIBYL_S3_SESSION_TOKEN": "session-token-value",
    "SIBYL_S3_PREFIX": "prod/",
    "SIBYL_S3_PATH_STYLE": "false",
    "SIBYL_S3_ALLOW_HTTP": "false",
}


def test_s3_settings_are_read_from_the_environment(monkeypatch) -> None:
    for key, value in _S3_ENV.items():
        monkeypatch.setenv(key, value)
    s = Settings()
    assert (s.s3_endpoint, s.s3_bucket, s.s3_region) == (
        "https://s3.eu-west-1.amazonaws.com",
        "sibyl-blobs",
        "eu-west-1",
    )
    assert s.s3_access_key_id == "AKIDEXAMPLE"
    assert s.s3_secret_access_key is not None
    assert s.s3_secret_access_key.get_secret_value() == _S3_ENV["SIBYL_S3_SECRET_ACCESS_KEY"]
    assert s.s3_prefix == "prod/" and s.s3_path_style is False and s.s3_allow_http is False
    for secret in ("SIBYL_S3_SECRET_ACCESS_KEY", "SIBYL_S3_SESSION_TOKEN"):
        assert _S3_ENV[secret] not in repr(s)


def test_s3_config_matches_the_blob_store_reading_the_same_env(monkeypatch) -> None:
    from sibyl_control.core.blob.s3 import S3Config

    for key, value in _S3_ENV.items():
        monkeypatch.setenv(key, value)
    assert Settings().s3_config() == S3Config.from_env(_S3_ENV)


def test_s3_defaults(monkeypatch) -> None:
    for key in _S3_ENV:
        monkeypatch.delenv(key, raising=False)
    s = Settings()
    assert s.s3_region == "us-east-1" and s.s3_prefix == "" and s.s3_path_style is True
    assert s.s3_allow_http is False and s.s3_endpoint is None


def test_the_s3_backend_needs_its_settings(tmp_path, monkeypatch) -> None:
    for key in _S3_ENV:
        monkeypatch.delenv(key, raising=False)
    given = _secrets_for("api", tmp_path)
    with pytest.raises(RuntimeError) as err:
        Settings(**given, blob_backend="s3").require_secrets("api")
    for name in (
        "SIBYL_S3_ENDPOINT",
        "SIBYL_S3_BUCKET",
        "SIBYL_S3_ACCESS_KEY_ID",
        "SIBYL_S3_SECRET_ACCESS_KEY",
    ):
        assert name in str(err.value)
    s3 = {
        "blob_backend": "s3",
        "s3_bucket": "b",
        "s3_access_key_id": "k",
        "s3_secret_access_key": "s3-secret-should-not-leak",
    }
    Settings(**given, **s3, s3_endpoint="https://minio.internal:9000").require_secrets("api")
    with pytest.raises(RuntimeError, match="SIBYL_S3") as bad:
        Settings(**given, **s3, s3_endpoint="http://minio.internal:9000").require_secrets("api")
    assert "s3-secret-should-not-leak" not in str(bad.value)


def test_lane_s_saga_gates(monkeypatch) -> None:
    """SIBYL_PREDICTED_AUTOMATION_BAND (0.90 until sibyl-sim clears the floors, then 0.60) and
    SIBYL_FAILBACK_RAMP (Phase 1.5 canary ramp, off by default)."""
    from pydantic import ValidationError
    from sibyl_control.core.settings import Settings

    monkeypatch.delenv("SIBYL_PREDICTED_AUTOMATION_BAND", raising=False)
    monkeypatch.delenv("SIBYL_FAILBACK_RAMP", raising=False)
    defaults = Settings()
    assert (defaults.predicted_automation_band, defaults.failback_ramp) == ("0.90", False)
    monkeypatch.setenv("SIBYL_PREDICTED_AUTOMATION_BAND", "0.60")
    monkeypatch.setenv("SIBYL_FAILBACK_RAMP", "1")
    tuned = Settings()
    assert (tuned.predicted_automation_band, tuned.failback_ramp) == ("0.60", True)
    monkeypatch.setenv("SIBYL_PREDICTED_AUTOMATION_BAND", "0.75")
    with pytest.raises(ValidationError):
        Settings()


def test_probe_ca_file_setting(monkeypatch) -> None:
    from sibyl_control.core.settings import Settings

    monkeypatch.setenv("SIBYL_UPSTREAM_CA_FILE", "/run/secrets/sim-ca.pem")
    assert Settings().upstream_ca_file == "/run/secrets/sim-ca.pem"
