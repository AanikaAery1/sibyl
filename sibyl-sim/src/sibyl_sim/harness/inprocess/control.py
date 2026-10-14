"""Control-plane wiring for the in-process stack: settings, persona principals, the api app.

Personas (Admin, Operator, Auditor; D29) authenticate with static bearer tokens resolved to the same
`Principal` the console session would produce from their memberships (R56), chained after the
real API-key resolver. Dex is not in-process; everything after authentication (authz, RLS,
audit, rate limits) is the production code path.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI
from pydantic import SecretStr
from sibyl_control.api.app import create_app
from sibyl_control.api.deps import (
    ApiKeyResolver,
    ChainResolver,
    Services,
    StaticTokenResolver,
    pg_key_lookup,
)
from sibyl_control.api.snapshot import SnapshotService
from sibyl_control.api.snapshot.keys import SignerResolver
from sibyl_control.core.authz import (
    MembershipGrant,
    Principal,
    PrincipalKind,
    grants_from_memberships,
)
from sibyl_control.core.crypto.envelope import LocalKek
from sibyl_control.core.db import Database
from sibyl_control.core.idempotency import PgIdempotencyStore
from sibyl_control.core.ratelimit import RateLimiter
from sibyl_control.core.settings import Settings

from ..world import PersonaInfo, World
from .secrets import StackSecrets


def control_settings(dsn: str, secrets: StackSecrets, blob_root: Path) -> Settings:
    return Settings(
        pg_dsn=SecretStr(dsn),
        key_pepper=SecretStr(secrets.pepper.hex()),
        kek=SecretStr(secrets.kek_b64),
        kek_id=secrets.kek_id,
        scrub_salt=SecretStr(secrets.scrub_salt.hex()),
        subject_salt=SecretStr(secrets.subject_salt.hex()),
        env="live",
        blob_root=str(blob_root),
        db_pool_min=1,
        db_pool_max=6,
    )


def persona_principal(
    tenant_id: UUID, persona: PersonaInfo, *, stepped_up: bool = False
) -> Principal:
    return Principal(
        PrincipalKind.SESSION,
        tenant_id,
        persona.user_id,
        grants_from_memberships(MembershipGrant(r) for r in persona.roles),
        step_up_at=datetime.now(UTC) + timedelta(hours=8) if stepped_up else None,
        roles=frozenset(persona.roles),
    )


STEP_UP_SUFFIX = ".stepup"


def persona_resolver(world: World, *, stepped_up: bool = False) -> StaticTokenResolver:
    """Each persona token, plus `<token>.stepup` resolving to the same membership with a fresh
    step-up (the in-process stand-in for `POST /auth/step-up` after an OIDC re-auth)."""
    resolver = StaticTokenResolver({})
    for tenant in world.tenants.values():
        for persona in tenant.personas.values():
            principal = persona_principal(tenant.id, persona, stepped_up=stepped_up)
            resolver.add(persona.token, principal)
            resolver.add(
                persona.token + STEP_UP_SUFFIX,
                persona_principal(tenant.id, persona, stepped_up=True),
            )
    return resolver


def snapshot_service(db: Database, secrets: StackSecrets) -> SnapshotService:
    return SnapshotService(
        db,
        resolver=SignerResolver(secrets.signer_environ()),
        kek=LocalKek(secrets.kek_id, secrets.kek),
    )


def build_api_app(
    db: Database,
    settings: Settings,
    secrets: StackSecrets,
    tokens: StaticTokenResolver | None,
    *,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    """Runs pass `tokens=None`: the production chain (API key -> console session -> OIDC) and the
    production in-memory limiter. The template build (an operator bootstrap, like `sibyl seed`)
    passes static persona tokens and an unlimited limiter."""
    services = Services(db=db, idempotency=PgIdempotencyStore(db), settings=settings)
    if tokens is None:
        from sibyl_control.api.auth.principals import build_principal_resolver

        services.principals = build_principal_resolver(services, settings)
    else:
        services.principals = ChainResolver(
            ApiKeyResolver(pg_key_lookup(db), secrets.pepper), tokens
        )
    if rate_limiter is not None:
        services.rate_limiter = rate_limiter
    app = create_app(services, settings=settings)
    app.state.snapshot_service = snapshot_service(db, secrets)
    return app
