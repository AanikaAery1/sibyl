"""The per-service compose secret matrix (M8), shared by the static and live tests.

Each service receives exactly these compose secrets, mounted at /run/secrets/<target> and
exported by the image entrypoint as the environment variable <target> when the target is
SIBYL_*/DEX_*. Lowercase targets stay file-only (the process reads them via a *_FILE path).
Keep in step with the matrix comment at the top of deploy/compose/docker-compose.yml.
"""

from __future__ import annotations

# service -> {target env var (or file name): source secret}
SECRET_MATRIX: dict[str, dict[str, str]] = {
    "postgres": {"postgres_password": "postgres_password"},
    "bootstrap": {
        "SIBYL_PG_ADMIN_PASSWORD": "postgres_password",
        "SIBYL_DB_PASSWORD": "db_password_migrate",
        "SIBYL_ROLE_PASSWORD_SIBYL_APP": "db_password_app",
        "SIBYL_ROLE_PASSWORD_SIBYL_INGEST": "db_password_ingest",
        "SIBYL_ROLE_PASSWORD_SIBYL_WORKER": "db_password_worker",
    },
    "migrate": {"SIBYL_DB_PASSWORD": "db_password_migrate"},
    "api": {
        "SIBYL_DB_PASSWORD": "db_password_app",
        "SIBYL_KEK": "kek",
        "SIBYL_KEY_PEPPER": "key_pepper",
        "SIBYL_SNAPSHOT_SIGNING_KEY": "snapshot_signing_key",
        "SIBYL_SESSION_SECRET": "session_secret",
        "SIBYL_OIDC_CLIENT_SECRET": "oidc_client_secret",
        "SIBYL_SUBJECT_SALT": "subject_salt",
    },
    "ingest": {
        "SIBYL_DB_PASSWORD": "db_password_ingest",
        "SIBYL_KEK": "kek",  # B7: ingest envelope-encrypts payload blobs at write time
        "SIBYL_KEY_PEPPER": "key_pepper",
        "SIBYL_SCRUB_SALT": "scrub_salt",
        "SIBYL_SUBJECT_SALT": "subject_salt",
    },
    "worker": {
        "SIBYL_DB_PASSWORD": "db_password_worker",
        "SIBYL_KEK": "kek",
        "ledger_signing_key": "ledger_signing_key",  # file only: SIBYL_LEDGER_SIGNING_KEY_FILE
        "SIBYL_ANCHOR_SIGNING_KEY": "anchor_signing_key",
    },
    "gateway": {
        "SIBYL_GATEWAY_TENANT_KEYS": "gateway_tenant_keys",
        "SIBYL_INGEST_KEY": "gateway_ingest_key",  # B12: gateway keys lack ingest:write
        "SIBYL_KEY_PEPPER": "key_pepper",  # B12: verifies API keys against the snapshot
        "SIBYL_SCRUB_SALT": "scrub_salt",
    },
    "dex": {
        "DEX_CONSOLE_CLIENT_SECRET": "oidc_client_secret",
        "DEX_API_CLIENT_SECRET": "dex_api_client_secret",
        "DEX_PERSONA_HASH_B64": "dex_persona_hash",
    },
    "caddy": {},
    "console": {},
    "sibyl-sim": {
        "SIBYL_SIM_GATEWAY_KEY": "sim_gateway_key",
        "SIBYL_SIM_INGEST_KEY": "sim_ingest_key",
    },
}
