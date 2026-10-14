"""Process configuration from ``SIBYL_*`` environment variables (12-factor, D4).

Matches the W0-INF runtime contract: ``SIBYL_DB_{HOST,PORT,NAME,USER,PASSWORD}``,
``SIBYL_PUBLIC_URL``, ``SIBYL_OIDC_ISSUER`` (public) + ``SIBYL_OIDC_INTERNAL_URL`` (in-network
discovery/JWKS base), ``SIBYL_BLOB_BACKEND``/``SIBYL_BLOB_ROOT``, ``SIBYL_HTTP_PORT``. Native dev
ports default to 8010 (api), 8011 (ingest), 8012 (worker); containers set ``SIBYL_HTTP_PORT``
(8000/8002). Secrets are ``SecretStr``; ``require_secrets(process)`` fails fast at startup and
asks each process only for the secrets it is deployed with (``PROCESS_SECRETS``, kept in step
with the compose matrix ``ci/tests/sibyl_ci_secret_matrix.py`` by a drift test).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal
from urllib.parse import quote

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from .apikeys import pepper_from_env
from .clientip import Network, parse_trusted_proxies

if TYPE_CHECKING:
    from .blob.s3 import S3Config

NATIVE_PORTS: Mapping[str, int] = MappingProxyType({"api": 8010, "ingest": 8011, "worker": 8012})

PROCESS_SECRETS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "api": (
            "SIBYL_KEY_PEPPER",
            "SIBYL_KEK",
            "SIBYL_SNAPSHOT_SIGNING_KEY",
            "SIBYL_SUBJECT_SALT",
        ),
        # B7: ingest envelope-encrypts payload blobs at write time, so it holds the KEK.
        "ingest": ("SIBYL_KEY_PEPPER", "SIBYL_KEK", "SIBYL_SCRUB_SALT", "SIBYL_SUBJECT_SALT"),
        "worker": ("SIBYL_KEK", "SIBYL_LEDGER_SIGNING_KEY_FILE", "SIBYL_ANCHOR_SIGNING_KEY"),
        "gateway": ("SIBYL_SCRUB_SALT",),
    }
)
"""Process -> the ``SIBYL_*`` secrets it must start with (security review M8 secret split)."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIBYL_", extra="ignore")

    db_host: str = "localhost"
    db_port: int = 5433
    db_name: str = "sibyl"
    db_user: str = "sibyl_app"
    db_password: SecretStr | None = None
    pg_dsn: SecretStr | None = None  # full override; wins over the SIBYL_DB_* parts
    db_pool_min: int = 2
    db_pool_max: int = 10
    db_command_timeout_s: float = 30.0
    statement_timeout_ms: int = 10_000

    # The worker's own pool: long phases (audit_verify, bulk erasure) outlive the api's 30 s.
    worker_pool_min: int = 1
    worker_pool_max: int = 4
    worker_command_timeout_s: float = 900.0
    worker_db_connect_attempts: int = 10
    worker_db_connect_backoff_s: float = 1.0

    # SIBYL_TRUSTED_PROXIES: comma-separated CIDRs whose X-Forwarded-For is believed (Caddy).
    trusted_proxies: str = ""

    http_port: int | None = None
    public_url: str = "http://localhost:8010"
    oidc_issuer: str | None = None
    oidc_internal_url: str | None = None

    blob_backend: str = "fs"
    blob_root: str = "./var/blob"
    # Worker outbound calls (credential probe, B14): an extra CA bundle for provider TLS
    # (e.g. the sim doubles' local CA); unset = the default trust store.
    upstream_ca_file: str | None = None
    # D53 monitor webhooks (SIBYL_WEBHOOK_ALLOWED_HOSTS): comma-separated hosts or ``.suffix``
    # entries a webhook may target; empty = any public https host (connect-time checks apply).
    webhook_allowed_hosts: str = ""
    # Lane S saga gates (env SIBYL_PREDICTED_AUTOMATION_BAND / SIBYL_FAILBACK_RAMP): the
    # D36/R41 predicted-failover band for tiers 2-3 (0.90 until sibyl-sim clears the
    # precision/recall floors, then 0.60) and the canary failback ramp (Phase 1.5, A4).
    predicted_automation_band: Literal["0.60", "0.90"] = "0.90"
    failback_ramp: bool = False
    # SIBYL_S3_*: the S3-compatible blob store (``blob_backend = "s3"``), as read by
    # ``core.blob.s3.S3Config.from_env``; ``s3_config()`` builds it from these fields.
    s3_endpoint: str | None = None
    s3_bucket: str | None = None
    s3_region: str = "us-east-1"
    s3_access_key_id: str | None = None
    s3_secret_access_key: SecretStr | None = None
    s3_session_token: SecretStr | None = None
    s3_prefix: str = ""
    s3_path_style: bool = True
    s3_allow_http: bool = False

    env: str = "live"
    demo: bool = False
    key_pepper: SecretStr | None = None
    kek: SecretStr | None = None
    kek_id: str = "local-kek-1"
    snapshot_signing_key: SecretStr | None = None
    anchor_signing_key: SecretStr | None = None
    subject_salt: SecretStr | None = None
    scrub_salt: SecretStr | None = None
    ledger_signing_key_file: str | None = None  # file-only secret (compose /run/secrets/…)
    console_origins: list[str] = []
    openapi_path: str | None = None

    def trusted_networks(self) -> tuple[Network, ...]:
        return parse_trusted_proxies(self.trusted_proxies)

    def dsn(self) -> str:
        if self.pg_dsn is not None:
            return self.pg_dsn.get_secret_value()
        auth = quote(self.db_user, safe="")
        if self.db_password is not None:
            auth += ":" + quote(self.db_password.get_secret_value(), safe="")
        return f"postgresql://{auth}@{self.db_host}:{self.db_port}/{quote(self.db_name, safe='')}"

    def port_for(self, service: str) -> int:
        return self.http_port if self.http_port is not None else NATIVE_PORTS[service]

    def oidc_internal(self, url: str) -> str:
        """Rewrite a URL under the public issuer onto the in-network base (discovery, JWKS)."""
        if not self.oidc_issuer or not self.oidc_internal_url:
            return url
        public = self.oidc_issuer.rstrip("/")
        if url == public or url.startswith(public + "/"):
            return self.oidc_internal_url.rstrip("/") + url[len(public) :]
        return url

    def oidc_discovery_url(self) -> str | None:
        if not self.oidc_issuer:
            return None
        return self.oidc_internal(
            self.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
        )

    def s3_config(self) -> S3Config:
        """The blob store's ``S3Config`` (raises ``ValueError`` naming what is missing/invalid)."""
        from .blob.s3 import S3Config

        missing = self._s3_missing()
        if missing:
            raise ValueError(", ".join(missing) + " not set")
        assert self.s3_endpoint and self.s3_bucket and self.s3_access_key_id
        assert self.s3_secret_access_key is not None
        token = self.s3_session_token
        return S3Config(
            endpoint_url=self.s3_endpoint,
            bucket=self.s3_bucket,
            region=self.s3_region,
            access_key_id=self.s3_access_key_id,
            secret_access_key=self.s3_secret_access_key.get_secret_value(),
            session_token=token.get_secret_value() if token is not None else None,
            key_prefix=self.s3_prefix,
            path_style=self.s3_path_style,
            allow_http=self.s3_allow_http,
        )

    def _s3_missing(self) -> list[str]:
        secret = self.s3_secret_access_key
        values = {
            "SIBYL_S3_ENDPOINT": self.s3_endpoint,
            "SIBYL_S3_BUCKET": self.s3_bucket,
            "SIBYL_S3_ACCESS_KEY_ID": self.s3_access_key_id,
            "SIBYL_S3_SECRET_ACCESS_KEY": secret.get_secret_value() if secret else None,
        }
        return [name for name, value in values.items() if not value]

    def _s3_problems(self) -> list[str]:
        missing = self._s3_missing()
        if missing:
            return [f"{name} is not set (SIBYL_BLOB_BACKEND=s3)" for name in missing]
        try:
            self.s3_config()
        except ValueError as exc:  # S3Config messages never carry the secret
            return [f"SIBYL_S3_* is invalid: {exc}"]
        return []

    def pepper(self) -> bytes:
        if self.key_pepper is None:
            raise RuntimeError("SIBYL_KEY_PEPPER is not set")
        return pepper_from_env(self.key_pepper.get_secret_value())

    def _secret_problem(self, name: str) -> str | None:
        """Why secret ``name`` is unusable, or ``None``. Never includes the value."""
        value = getattr(self, name.removeprefix("SIBYL_").lower())
        if name == "SIBYL_LEDGER_SIGNING_KEY_FILE":
            if not value:
                return f"{name} is not set"
            return None if Path(value).is_file() else f"{name} does not name a readable file"
        if value is None or not value.get_secret_value():
            return f"{name} is not set"
        if name == "SIBYL_KEY_PEPPER":
            try:
                pepper_from_env(value.get_secret_value())
            except ValueError:
                return f"{name} must decode to at least 32 bytes"
        return None

    def require_secrets(self, process: str) -> None:
        """Fail fast unless ``process`` has every secret it is deployed with, and the rest of its
        configuration is valid. All problems are reported at once, by name only."""
        names = PROCESS_SECRETS.get(process)
        if names is None:
            raise ValueError(
                f"unknown process {process!r}; expected one of {sorted(PROCESS_SECRETS)}"
            )
        problems = [p for p in (self._secret_problem(n) for n in names) if p is not None]
        if self.env not in ("live", "test"):
            problems.append("SIBYL_ENV must be live or test")
        if self.blob_backend not in ("fs", "s3"):
            problems.append("SIBYL_BLOB_BACKEND must be fs or s3")
        elif self.blob_backend == "s3" and process != "gateway":
            problems += self._s3_problems()
        try:
            self.trusted_networks()
        except ValueError as exc:
            problems.append(f"SIBYL_TRUSTED_PROXIES is invalid: {exc}")
        if problems:
            raise RuntimeError(f"{process} cannot start: " + "; ".join(problems))
