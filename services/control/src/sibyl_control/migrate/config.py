"""Connection settings for the migrate runner (compose env contract from W0-INF).

Environment, in precedence order:

* ``SIBYL_PG_MIGRATE_DSN`` / ``SIBYL_PG_ADMIN_DSN``: full DSNs (dev, tests). When
  ``SIBYL_DB_NAME`` is also set it overrides the database of both.
* ``SIBYL_DB_HOST``, ``SIBYL_DB_PORT``, ``SIBYL_DB_NAME``, ``SIBYL_DB_USER`` (default
  ``sibyl_migrate``), ``SIBYL_DB_PASSWORD``: the migrate role.
* ``SIBYL_PG_ADMIN_USER``, ``SIBYL_PG_ADMIN_PASSWORD``: the bootstrap admin on the same host.
* ``SIBYL_ROLE_PASSWORD_SIBYL_APP`` / ``_SIBYL_INGEST`` / ``_SIBYL_WORKER``: login passwords the
  bootstrap step sets (``sibyl_migrate`` gets ``SIBYL_DB_PASSWORD``). ``sibyl_audit`` and
  ``sibyl_routing`` are NOLOGIN and have none.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

MIGRATE_ROLE = "sibyl_migrate"
LOGIN_ROLES = ("sibyl_app", "sibyl_ingest", "sibyl_worker")


@dataclass(frozen=True)
class ConnSpec:
    """asyncpg connect arguments; explicit fields override values inside ``dsn``."""

    dsn: str | None = None
    host: str | None = None
    port: int | None = None
    user: str | None = None
    password: str | None = field(default=None, repr=False)
    database: str | None = None

    def kwargs(self) -> dict[str, Any]:
        out: dict[str, Any] = {"dsn": self.dsn}
        for key in ("host", "port", "user", "password", "database"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out


@dataclass(frozen=True)
class MigrateConfig:
    migrate: ConnSpec
    admin: ConnSpec | None
    role_passwords: Mapping[str, str] = field(default_factory=dict, repr=False)


def from_env(env: Mapping[str, str]) -> MigrateConfig:
    """Build the runner configuration from an environment mapping."""
    host = env.get("SIBYL_DB_HOST")
    port = int(env["SIBYL_DB_PORT"]) if env.get("SIBYL_DB_PORT") else None
    database = env.get("SIBYL_DB_NAME")
    migrate = ConnSpec(
        dsn=env.get("SIBYL_PG_MIGRATE_DSN"),
        host=host,
        port=port,
        user=env.get("SIBYL_DB_USER", MIGRATE_ROLE),
        password=env.get("SIBYL_DB_PASSWORD") or None,
        database=database,
    )
    admin: ConnSpec | None = None
    if env.get("SIBYL_PG_ADMIN_DSN") or env.get("SIBYL_PG_ADMIN_USER"):
        admin = ConnSpec(
            dsn=env.get("SIBYL_PG_ADMIN_DSN"),
            host=host,
            port=port,
            user=env.get("SIBYL_PG_ADMIN_USER") or None,
            password=env.get("SIBYL_PG_ADMIN_PASSWORD") or None,
            database=database,
        )
    passwords = {
        role: env[f"SIBYL_ROLE_PASSWORD_{role.upper()}"]
        for role in LOGIN_ROLES
        if env.get(f"SIBYL_ROLE_PASSWORD_{role.upper()}")
    }
    if env.get("SIBYL_DB_PASSWORD"):
        passwords[MIGRATE_ROLE] = env["SIBYL_DB_PASSWORD"]
    return MigrateConfig(migrate=migrate, admin=admin, role_passwords=passwords)
