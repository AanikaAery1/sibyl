# Security

This page describes how the Phase 1 stack protects secrets, payloads and tenants. It also lists what has **not** been assessed independently yet.

> Sibyl Phase 1 has not had an external security assessment. One is planned before the first paying tenant: an unpaid pilot, then the assessment, then the first invoice (D18, D43). Until then, treat the stack as pre-production. Do not put regulated production data in it.

## Secrets

Every key, salt and password is a **compose file secret**. Each one is granted only to the services that need it. The image entrypoint exports `/run/secrets/<VAR>` as `<VAR>`, so nothing secret appears in `docker inspect` or in env files. `deploy/compose/init-env.sh` generates them under `deploy/compose/env/secrets/`: the directory is `0700`, and the files are `0444` because compose bind-mounts them for the container user.

Secret matrix (source of truth: the header of `deploy/compose/docker-compose.yml`, checked in CI by `ci/tests/test_secrets.py`):

| Secret | Format | Granted to |
|---|---|---|
| `postgres_password` | hex, 32 bytes | postgres, one-shot `bootstrap` |
| `db_password_migrate` | hex | `bootstrap`, `migrate` |
| `db_password_app` / `_ingest` / `_worker` | hex | `bootstrap` and the one process each |
| `kek` (`SIBYL_KEK`) | base64url, 32 bytes (AES-256) | api, ingest (B7), worker |
| `key_pepper` (`SIBYL_KEY_PEPPER`) | hex or base64url, at least 32 bytes | api, ingest, gateway (B12) |
| `snapshot_signing_key` | Ed25519 seed, base64url | api |
| `anchor_signing_key` | Ed25519 seed, base64url | worker |
| `ledger_signing_key` | Ed25519 seed, read from a file (`SIBYL_LEDGER_SIGNING_KEY_FILE`) | worker |
| `session_secret` (`SIBYL_SESSION_SECRET`) | at least 32 characters | api |
| `oidc_client_secret` | hex | api, dex |
| `subject_salt` (`SIBYL_SUBJECT_SALT`) | hex | api, ingest |
| `scrub_salt` (`SIBYL_SCRUB_SALT`) | at least 16 bytes | ingest, gateway |
| `gateway_tenant_keys` | comma-separated `sbl_` keys, one per tenant | gateway |
| `gateway_ingest_key` | an `sbl_` key with `ingest:write` | gateway |
| `sim_gateway_key`, `sim_ingest_key` | `sbl_` keys | sibyl-sim (dev only) |
| `dex_api_client_secret`, `dex_persona_hash` | hex, base64 bcrypt | dex |

Each process checks its secrets at startup (`Settings.require_secrets`). It refuses to start, naming every missing value but never printing one.

**What runs without a secret:**

- The gateway boots without its tenant keys. Its health check answers, and it serves from the last snapshot on disk.
- The public halves of the three signing keys are written to `deploy/compose/env/public/*.pem`. They are not secret.

**Escrow.** Keep the following offline in two places, never next to the backups:

- `secrets/kek`
- `secrets/ledger_signing_key`
- `secrets/anchor_signing_key`
- `secrets/key_pepper`

**Losing the KEK makes every tenant's data unreadable.** Losing the pepper invalidates every API key.

To run the processes natively (dev mode), set the same names yourself:

```bash
export SIBYL_ENV=test
export SIBYL_KEY_PEPPER=$(openssl rand -hex 32)
export SIBYL_KEK=$(openssl rand 32 | base64 | tr -d '=\n' | tr '+/' '-_')
export SIBYL_SUBJECT_SALT=$(openssl rand -hex 32) SIBYL_SCRUB_SALT=$(openssl rand -hex 32)
export SIBYL_SESSION_SECRET=$(openssl rand -hex 32)
# Ed25519 seeds: 32 random bytes, base64url, for snapshot and anchor signing
export SIBYL_SNAPSHOT_SIGNING_KEY=$(openssl rand 32 | base64 | tr -d '=\n' | tr '+/' '-_')
export SIBYL_ANCHOR_SIGNING_KEY=$(openssl rand 32 | base64 | tr -d '=\n' | tr '+/' '-_')
```

The matching public keys must also be registered in `sibyl.signing_key`, as `ops/demo/register.py` does for compose. <!-- verify: a documented native-mode registration step; today only ops/demo/register.py (compose) does it -->

## Keys and what they protect

| Key | Protects | Where it lives |
|---|---|---|
| **KEK** | Wraps every tenant's data keys (DEKs) with AES-256-GCM | Process memory only. Phase 1 has no KMS; a KMS adapter is the planned seam. |
| **Tenant DEKs** | Three per tenant: `payload`, `credential`, `config`. They encrypt payload blobs, vaulted provider credentials and sealed config. The AAD binds tenant, purpose, version and object. | Wrapped in `sibyl.tenant_key`. Rotated with `POST /tenant-keys/{purpose}/rotate`; destroyed on erasure. |
| **Pepper** | API keys are stored as peppered hashes, looked up by prefix | api, ingest, gateway |
| **Snapshot signing key** (Ed25519) | The gateway trusts only snapshots signed by a pinned key or its signed successors | api; public key at `/.well-known/sibyl-keys.json` |
| **Anchor signing key** (Ed25519) | Audit anchors. A signer is used only if it matches the registered public key. | worker; public key at `/api/v1/audit/signing-keys` |
| **Ledger signing key** (Ed25519) | The append-only erasure ledger that restores replay | worker-only volume `erasure_ledger` |

Rotation procedures are in [rotate keys](../../ops/runbooks/rotate-keys.md).

## TLS

- Caddy terminates TLS for the three public origins with its **internal CA**. Trust its root once:

  ```bash
  docker compose -f deploy/compose/docker-compose.yml cp caddy:/data/caddy/pki/authorities/local/root.crt .
  ```

- All published ports bind to `127.0.0.1`.
- Caddy sets HSTS and `X-Content-Type-Options: nosniff`, removes the `Server` header, and adds `X-Frame-Options: DENY` to console pages.
- Inside the stack, services talk plain HTTP on private Docker networks:
  - `edge` holds Caddy and what it fronts.
  - `data` holds Postgres and the three control processes.
  - The gateway, dex, console and simulator cannot reach Postgres.
- Caddy has a pinned address, and only that address is trusted for `X-Forwarded-For` (`SIBYL_TRUSTED_PROXIES`).
- Policy routes (`/api/v1/policy/*`: snapshots, sealed credentials, key sets) are not served on the public origin. The gateway fetches them in-network.
- The simulator's doubles use a throwaway dev CA. The gateway trusts it only for the `sim` dev host.
- Image builds behind a TLS-re-signing proxy take the proxy CA as a build-time secret only. It never lands in an image layer. Never turn off certificate verification.

## Secrets scrubbing

Scrubbing runs on every captured part, in the SDK, the gateway and ingest, **whatever the capture mode** (D12). The scrubber is in `packages/sibyl-schemas/src/sibyl_schemas/scrub/`:

- Its detectors cover provider and cloud keys, tokens, PEM blocks, credentials in URLs and generic high-entropy key-value pairs.
- It also scans decoded views: JSON-escaped, percent-encoded, and with format characters removed.
- Each match is replaced with `[KIND:hash8]`. The hash is salted with `SIBYL_SCRUB_SALT`, so the same secret yields the same token across processes, but the secret cannot be recovered.
- It is tested against a corpus of real-shaped secrets, with zero false positives on a clean corpus.

Known limit (B8): a match longer than 16 KiB may leak its tail at a window boundary. No real credential is that long.

The capture mode then decides what is kept:

| Mode | Kept |
|---|---|
| `full` | The scrubbed content |
| `redacted` | The content after the tenant's redaction profile |
| `metadata` | No content |

An SDK scrub hook that raises downgrades its part to `metadata`.

## Tenant isolation

- **Row-level security** is on every tenant table. Each transaction sets its tenant (`sibyl.set_tenant`), and every policy filters on it. A generated test suite checks isolation for every table.
- **Least privilege per process.** The services connect as separate login roles: `sibyl_app` (api), `sibyl_ingest` and `sibyl_worker`. `sibyl_migrate` owns the schema. Signing-key and dev-host tables are writable only by `sibyl_migrate`. The superuser password reaches only Postgres and the one-shot bootstrap.
- **No existence oracle.** Another tenant's object returns `404`, never `403`. A shared OIDC issuer cannot cross tenants, because the tenant is resolved before the token is checked.
- **Gateway isolation.** The gateway holds one key and one snapshot block per tenant it fronts. There is no platform-wide gateway credential (D31). Tier-1 agents are reachable only with agent-bound keys (D32).
- **Payload reads.** Content reads are scoped by agent group. Auditors and `payloads:reveal` reads require `X-Sibyl-Reveal-Reason` and write `data.revealed` in the same transaction.
- **Hardened containers.** They run read-only, drop all capabilities, and set `no-new-privileges`. Images are pinned by digest.

## Credentials for fallback providers (D11)

- **Primary calls** use your own provider key, passed through the gateway and never stored. The gateway never sends your key to a different provider.
- **Fallback targets** use vaulted credentials. Creating one needs `credentials:manage` and step-up. The secret is envelope-encrypted under the tenant's `credential` DEK.
- **Delivery to the gateway** is a sealed bundle that expires in 300 seconds. The gateway holds the secrets in memory only and zeroes them on expiry.
- **Base URLs** must be on an allowlist. Private and plain-HTTP hosts are refused, except the simulator's dev host.

## Identity

- People sign in through OIDC: dex in the demo, any OIDC issuer in production.
- Sessions are opaque, stored hashed, and last 8 hours absolute or 30 minutes idle.
- High-risk actions need step-up: a sign-in within the last 5 minutes.
- API keys are scoped, may be bound to an agent, expire within 400 days, and rotate with a grace period of up to 24 hours. A key sent from a browser (an `Origin` header) is refused.

## Not yet assessed or not yet built

Be explicit about these with any design partner:

1. **No independent assessment.** There has been no external penetration test or code audit (D18, D43). The reviews so far are internal: the council's security-auditor reviews at each gate.
2. **One operator, one host.** Phase 1 assumes a single operator in business hours and same-host backups (D18). Off-host backups and PITR are the first cloud task; see [backup and restore](../../ops/runbooks/backup-restore.md).
3. **No KMS.** The KEK is a local secret, and there is no KEK rotation tooling. The `kek_id` is recorded on every wrapped key, so a later rewrap is possible.
4. **Signing-key rotation is manual.** The published key set has no pre-announced `next_key` yet (B10 change request). A rotation is followable only while the previous key still signs. See [rotate keys](../../ops/runbooks/rotate-keys.md).
5. **Per-replica rate limits.** Counters live in memory. Running several API replicas multiplies the limits.
6. **Slow break-glass anchors.** The `break_glass` anchor is written on the anchors loop's next run (hourly). The 10-second target waits on the loop waking from database notifications.
7. **No SDK kill check through Caddy.** Caddy refuses `/api/v1/policy/*` on the public origin, so the SDK cannot poll the snapshot through it. The gateway still enforces kills. <!-- verify after INT-2 -->
8. **Residency is declared, not enforced.** It is a field with policy warnings until region-pinned stacks exist (D17).
9. **Supply chain.** The licence gate (D15) checks licences, not vulnerabilities. There is no SBOM signing or dependency CVE gate in CI yet.
