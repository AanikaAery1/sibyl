"""Register the demo deployment's signing keys and the sim dev host (idempotent).

Run by ops/demo/up.sh inside the one-shot ``migrate`` container (the ``sibyl_migrate`` role, the
only role that may write these tables), with the public keys init-env.sh derived from the seeds:

    docker compose run --rm -T --no-deps \
        -e SIBYL_SNAPSHOT_PIN="$(cat env/public/snapshot_pin.json)" \
        -e SIBYL_ANCHOR_PIN="$(cat env/public/anchor_key.json)" \
        migrate python - < ops/demo/register.py

* ``sibyl.signing_key``, purpose ``snapshot``: the key the gateway pins (B12); the api resolves
  its private half from ``env:SIBYL_SNAPSHOT_SIGNING_KEY`` (the compose file secret).
* ``sibyl.signing_key``, purpose ``audit_anchor``: the worker signs audit anchors with
  ``SIBYL_ANCHOR_SIGNING_KEY`` and uses a signer only when it matches this public key (lane U);
  verifiers read the public half from here or from env/public/anchor_signing.pem.
* ``sibyl.base_url_dev_host``: ``sim``, the compose alias of the sibyl-sim doubles (R55). The real
  deployment (``deploy/compose/real.sh``) runs no simulator and sets ``SIBYL_REGISTER_DEV_HOST=``
  (empty), which skips this row: provider base URLs then have to be public https hosts.

An existing active key that differs is never replaced (rotation is an operator act); the other
key is still registered. Exit codes: 0 all in place, 3 an active key differs from ours.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
from typing import Any

import asyncpg
from sibyl_control.migrate.config import from_env

DEV_HOST = os.environ.get("SIBYL_REGISTER_DEV_HOST", "sim").strip()
# purpose -> (env var holding the $defs/signing_key JSON, private_key_ref for the row)
KEYS = {
    "snapshot": ("SIBYL_SNAPSHOT_PIN", "env:SIBYL_SNAPSHOT_SIGNING_KEY"),
    "audit_anchor": ("SIBYL_ANCHOR_PIN", "env:SIBYL_ANCHOR_SIGNING_KEY"),
}


def _public_key(var: str) -> tuple[str, bytes]:
    key = json.loads(os.environ[var])
    if key.get("alg") != "Ed25519":
        raise SystemExit(f"register: {var} is not an Ed25519 key")
    text = str(key["public_key"])
    public = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if len(public) != 32:
        raise SystemExit(f"register: {var} public key is not 32 bytes")
    return str(key["kid"]), public


async def _ensure(conn: Any, purpose: str, var: str, ref: str) -> bool:
    kid, public = _public_key(var)
    active = await conn.fetchrow(
        "SELECT kid, public_key FROM sibyl.signing_key WHERE purpose = $1 AND state = 'active'",
        purpose,
    )
    if active is None:
        await conn.execute(
            "INSERT INTO sibyl.signing_key"
            " (kid, purpose, public_key, private_key_ref, custody_note)"
            " VALUES ($1, $2, $3, $4, $5)",
            kid,
            purpose,
            public,
            ref,
            "compose: env/secrets (ops/demo/up.sh)",
        )
        print(f"register: {purpose} signing key {kid} registered")
        return True
    if active["kid"] == kid and bytes(active["public_key"]) == public:
        print(f"register: {purpose} signing key {kid} already active")
        return True
    print(
        f"register: active {purpose} key {active['kid']} is not ours ({kid}); leaving it"
        " (rotate deliberately, or re-derive the public material)",
        file=sys.stderr,
    )
    return False


async def main() -> int:
    conn = await asyncpg.connect(**from_env(os.environ).migrate.kwargs())
    try:
        async with conn.transaction():
            if DEV_HOST:
                await conn.execute(
                    "INSERT INTO sibyl.base_url_dev_host (host, note)"
                    " VALUES ($1, 'sibyl-sim doubles (compose alias)') ON CONFLICT DO NOTHING",
                    DEV_HOST,
                )
            ok = [await _ensure(conn, p, var, ref) for p, (var, ref) in KEYS.items()]
        print(f"register: dev host {DEV_HOST!r} ok" if DEV_HOST else "register: no dev host")
        return 0 if all(ok) else 3
    finally:
        await conn.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
