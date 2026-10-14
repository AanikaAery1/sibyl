"""Real console sessions for the personas, minted per run.

The console's OIDC callback (lane A, `auth/flows.py`) inserts a `session` row whose
`token_hash = sha256(value)` and hands the browser `value`; the BFF then calls the api with
`Authorization: Bearer sibyl_sess_<value>`. Dex is not in-process, so the harness inserts the same
row for each persona binding at clone time (the fixture standing in for the dex login) and the
api resolves it through the production chain (key -> session -> OIDC): memberships, scopes,
idle/absolute expiry and step-up are all the product's. Each persona gets a second session whose
`step_up_at` is fresh (the stand-in for `POST /auth/step-up` after a re-auth): kill-switch pulls,
releases and credential revocation need it, and only that session carries it.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import asyncpg

from ..world import PersonaInfo, TenantInfo, World

BEARER_PREFIX = "sibyl_sess_"
SESSION_HOURS = 8  # the product's absolute lifetime; idle expiry slides on every read


def _hash(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii")).digest()


async def mint(admin_dsn: str, world: World) -> World:
    now = datetime.now(UTC)
    absolute = now + timedelta(hours=SESSION_HOURS)
    conn = await asyncpg.connect(admin_dsn)
    tenants: dict[str, TenantInfo] = {}
    try:
        for slug, tenant in world.tenants.items():
            personas: dict[str, PersonaInfo] = {}
            for name, persona in tenant.personas.items():
                tokens = []
                for step_up in (None, now):
                    value = secrets.token_urlsafe(32)
                    await conn.execute(
                        "INSERT INTO sibyl.session (tenant_id, user_id, token_hash, issued_at,"
                        " absolute_expires_at, idle_expires_at, last_seen_at, step_up_at, ua_class)"
                        " VALUES ($1, $2, $3, $4, $5, $5, $4, $6, 'sibyl-sim')",
                        tenant.id,
                        persona.user_id,
                        _hash(value),
                        now,
                        absolute,
                        step_up,
                    )
                    tokens.append(BEARER_PREFIX + value)
                personas[name] = replace(persona, token=tokens[0], stepup_token=tokens[1])
            tenants[slug] = replace(tenant, personas=personas)
    finally:
        await conn.close()
    return replace(world, tenants=tenants)
