"""First-run bootstrap of a REAL Sibyl deployment (idempotent): tenant, issuer, first admin.

Run by ``deploy/compose/real.sh up`` inside a one-shot ``api`` container (it holds the KEK to wrap
the tenant's DEKs and the pepper to hash keys, exactly like the operator CLI):

    docker compose ... run --rm -T --no-deps -e SIBYL_BOOTSTRAP_TENANT=acme ... \\
        api python - < deploy/compose/real/bootstrap.py

Steps, each skipped when already done:

1. ``tenant create`` (``SIBYL_BOOTSTRAP_TENANT`` / ``_TENANT_NAME``): the tenant and its three
   KEK-wrapped DEKs.
2. ``tenant add-issuer``: the OIDC issuer (``SIBYL_BOOTSTRAP_ISSUER``: the bundled dex or your
   IdP) with the console's client id and, optionally, email domains allowed to sign in.
3. ``tenant add-user``: the first Platform Admin (role ``owner``, shown as "Admin"). With
   ``SIBYL_BOOTSTRAP_ADMIN_SUBJECT`` the user is bound to that ``sub`` directly; otherwise it is an
   invitation (subject ``invite:<uuid>``, status ``invited``, like the console's People page) that
   the api binds at the first sign-in whose ID token carries ``SIBYL_BOOTSTRAP_ADMIN_EMAIL`` with
   ``email_verified: true`` (dex, Okta, Google, Keycloak do; Entra ID does not: set the subject).
4. The tenant capture policy (D12) when none exists, as that admin through the real api handler
   (validation, audit row, outbox), unless ``SIBYL_BOOTSTRAP_CAPTURE_MODE=none``. Default
   ``metadata``: no prompt or response content is stored until an admin chooses otherwise in
   the console's Settings. Keys cannot be issued before a capture policy exists.
5. With ``SIBYL_BOOTSTRAP_GATEWAY_KEYS=1`` (real.sh sets it while the gateway's secret files are
   empty): the gateway's tenant key (``gateway:proxy``, ``routing:read``) and its ingest key
   (``ingest:write``).

Output on stdout, one ``key=value`` per line, for real.sh to parse: ``tenant_id``,
``tenant_created``, ``admin_user_id``, ``capture_policy`` (created/exists/skipped) and, only when
minted, ``gateway_tenant_key`` / ``gateway_ingest_key``. real.sh writes the two keys straight into
the gateway's file secrets and never prints them. Progress goes to stderr.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
from typing import Any
from uuid import UUID, uuid4

import httpx
from sibyl_control import cli
from sibyl_control.api.app import create_app
from sibyl_control.api.deps import Services, StaticTokenResolver
from sibyl_control.cli.seed import Api, _Unlimited
from sibyl_control.core.db import Database
from sibyl_control.core.idempotency import PgIdempotencyStore
from sibyl_control.core.settings import Settings

CAPTURE_MODES = ("metadata", "redacted", "full", "none")
REASON = "real deployment bootstrap (deploy/compose/real/bootstrap.py)"


def _say(message: str) -> None:
    sys.stderr.write(f"bootstrap: {message}\n")


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(f"SIBYL_BOOTSTRAP_{name}", default)
    if value is None or not value.strip():
        raise SystemExit(f"bootstrap: SIBYL_BOOTSTRAP_{name} is required")
    return value.strip()


def _cli(*argv: str) -> Any:
    """Run one operator-CLI command in-process; returns its JSON output."""
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(["--json", *argv], out=out, err=err)
    if code != 0:
        raise SystemExit(f"bootstrap: {argv[0]} {argv[1]} failed: {err.getvalue().strip()}")
    return json.loads(out.getvalue())


def _tenant(slug: str, name: str) -> tuple[str, bool]:
    for row in _cli("tenant", "list"):
        if row["slug"] == slug:
            _say(f"tenant {slug} exists")
            return str(row["id"]), False
    created = _cli("tenant", "create", slug, "--name", name)
    _say(f"tenant {slug} created")
    return str(created["id"]), True


async def _capture_policy(tenant: UUID, admin: UUID, mode: str) -> str:
    settings = Settings()
    db = await Database.connect(
        settings.dsn(), min_size=1, max_size=2, application_name="sibyl-bootstrap"
    )
    try:
        async with db.tenant_tx(tenant, readonly=True) as conn:
            if await conn.fetchval(
                "SELECT EXISTS (SELECT 1 FROM sibyl.capture_policy WHERE tenant_id = $1"
                " AND scope_kind = 'tenant' AND superseded_by IS NULL)",
                tenant,
            ):
                return "exists"
            profile = await conn.fetchval(
                "SELECT id FROM sibyl.redaction_profile WHERE tenant_id = $1"
                " AND name = 'pii_standard' AND origin = 'system' ORDER BY version_no DESC LIMIT 1",
                tenant,
            )
        if profile is None:
            raise SystemExit("bootstrap: the system redaction profile pii_standard is missing")
        resolver = StaticTokenResolver({})
        services = Services(
            principals=resolver,
            rate_limiter=_Unlimited(),
            db=db,
            idempotency=PgIdempotencyStore(db),
            settings=settings,
        )

        transport = httpx.ASGITransport(app=create_app(services, settings=settings))
        async with httpx.AsyncClient(transport=transport, base_url="http://bootstrap") as client:
            api = Api(client, resolver)
            api.act_as("admin", tenant, admin, ("owner",))
            await api.call(
                "admin",
                "POST",
                "/capture-policies",
                {
                    "scope_kind": "tenant",
                    "capture_mode": mode,
                    "redaction_profile_id": str(profile),
                    "payload_retention_days": 30,
                    "consequences_version": "2026-10",
                    "acknowledged": True,
                    "reason": REASON,
                },
                **{"If-Match": "*"},
            )
        return "created"
    finally:
        await db.close()


async def _existing_admin(tenant: UUID, issuer: str, email: str, subject: str) -> str | None:
    """The subject of the admin bound on an earlier run (by subject, or by email once the
    invitation was redeemed), so re-running never adds a second user."""
    settings = Settings()
    db = await Database.connect(settings.dsn(), min_size=1, max_size=1)
    try:
        async with db.tenant_tx(tenant, readonly=True) as conn:
            found: str | None = await conn.fetchval(
                "SELECT u.subject FROM sibyl.app_user u JOIN sibyl.oidc_issuer i"
                " ON i.tenant_id = u.tenant_id AND i.id = u.oidc_issuer_id"
                " WHERE u.tenant_id = $1 AND i.issuer_url = $2 AND u.status <> 'deprovisioned'"
                " AND (u.subject = $3 OR u.email = $4)"
                " ORDER BY (u.subject = $3) DESC, u.created_at LIMIT 1",
                tenant,
                issuer,
                subject,
                email,
            )
        return found
    finally:
        await db.close()


async def _mark_invited(tenant: UUID, user: UUID) -> None:
    settings = Settings()
    db = await Database.connect(settings.dsn(), min_size=1, max_size=1)
    try:
        async with db.tenant_tx(tenant) as conn:
            await conn.execute(
                "UPDATE sibyl.app_user SET status = 'invited' WHERE tenant_id = $1 AND id = $2"
                " AND subject LIKE 'invite:%' AND last_login_at IS NULL",
                tenant,
                user,
            )
    finally:
        await db.close()


def _admin(tenant: UUID, slug: str, issuer: str, email: str, subject: str) -> str:
    existing = asyncio.run(_existing_admin(tenant, issuer, email, subject))
    bound = existing or subject or f"invite:{uuid4()}"
    admin = _cli(
        "tenant", "add-user", slug, "--issuer-url", issuer, "--subject", bound,
        "--email", email, "--role", "owner",
    )  # fmt: skip
    user = UUID(admin["id"])
    if existing is None and bound.startswith("invite:"):
        asyncio.run(_mark_invited(tenant, user))
        _say(f"admin {email} invited as owner (bound at first sign-in)")
    else:
        _say(f"admin {email} bound as owner")
    return str(user)


def _key(slug: str, name: str, *scopes: str) -> str:
    env = Settings().env
    argv = ["keys", "create", slug, "--name", name, "--env", env, "--reason", REASON]
    for scope in scopes:
        argv += ["--scope", scope]
    secret: str = _cli(*argv)["secret"]
    return secret


def main() -> int:
    slug = _env("TENANT")
    name = _env("TENANT_NAME", slug)
    issuer = _env("ISSUER").rstrip("/")
    client_id = _env("CLIENT_ID", "sibyl-console")
    subject = os.environ.get("SIBYL_BOOTSTRAP_ADMIN_SUBJECT", "").strip()
    email = _env("ADMIN_EMAIL")
    mode = _env("CAPTURE_MODE", "metadata").lower()
    if mode not in CAPTURE_MODES:
        raise SystemExit(f"bootstrap: SIBYL_BOOTSTRAP_CAPTURE_MODE must be one of {CAPTURE_MODES}")
    domains = [d for d in os.environ.get("SIBYL_BOOTSTRAP_EMAIL_DOMAINS", "").split(",") if d]

    tenant_id, created = _tenant(slug, name)
    argv = ["tenant", "add-issuer", slug, "--issuer-url", issuer, "--client-id", client_id]
    for domain in domains:
        argv += ["--domain", domain.strip()]
    _cli(*argv)
    admin = _admin(UUID(tenant_id), slug, issuer, email, subject)
    if mode == "none":
        policy = "skipped"
    else:
        policy = asyncio.run(_capture_policy(UUID(tenant_id), UUID(admin), mode))
    _say(f"capture policy {policy}")

    lines = [
        f"tenant_id={tenant_id}",
        f"tenant_created={int(created)}",
        f"admin_user_id={admin}",
        f"capture_policy={policy}",
    ]
    if os.environ.get("SIBYL_BOOTSTRAP_GATEWAY_KEYS") == "1" and policy != "skipped":
        lines.append(f"gateway_tenant_key={_key(slug, 'gateway', 'gateway:proxy', 'routing:read')}")
        lines.append(f"gateway_ingest_key={_key(slug, 'gateway-ingest', 'ingest:write')}")
        _say("gateway keys minted")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
