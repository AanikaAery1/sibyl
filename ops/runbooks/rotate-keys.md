# Runbook: rotate keys

| What | When to rotate | Tooling |
|---|---|---|
| [API keys](#api-keys) (SDK, gateway, scripts) | On a schedule (they expire within 400 days), on staff change, on suspected exposure | API and operator CLI |
| [Break-glass keys](#break-glass-keys) | **After every use** and after every drill | API (step-up) |
| [Gateway tenant keys](#gateway-tenant-and-ingest-keys) | Same as API keys | CLI plus compose secret |
| [Tenant data keys](#tenant-data-keys-deks) | On a schedule, after suspected exposure | API (step-up) |
| [Snapshot signing key](#snapshot-signing-key) | Suspected exposure, custody change | **Manual**, no tooling yet |
| [Audit-anchor signing key](#audit-anchor-signing-key) | Suspected exposure, custody change | **Manual**, no tooling yet |
| [Other secrets](#other-secrets) | See the section | Compose secrets |

Every rotation is audited. Record the reason in the incident log as well.

## API keys

**Rotate.** This issues a new secret. The old secret stays valid for `grace_s` seconds: 3600 by default, at most 24 hours. Scopes may only narrow.

```bash
curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/api-keys/$KEY_ID/rotate" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{"grace_s": 3600}' | jq '{id, prefix, secret}'
```

Deploy the new secret to the agent before the grace period ends. The `secret` is shown once. A replay with the same `Idempotency-Key` returns `secret: null`; if you lose it, rotate again.

**Revoke** immediately on suspected exposure. There is no grace period. The gateway drops the key on its next snapshot (target under 2 seconds once the snapshot is fresh).

```bash
curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/api-keys/$KEY_ID/revoke" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{"reason": "Key found in a public repository."}'
```

The operator CLI does the same without a session. It is for bootstrap keys, or when the identity provider is down:

```bash
dc run --rm --no-deps api python -m sibyl_control.cli keys list meridian
dc run --rm --no-deps api python -m sibyl_control.cli keys revoke meridian <key id or prefix from keys list> --reason "Key found in a public repository."
```

Rotating or revoking a key needs `apikeys:manage`, which Admins and Workspace admins hold. An Engineer may manage agent-bound keys for agents in their groups.

## Break-glass keys

A break-glass key holds only `killswitch:pull`, must be `env=live`, and a tenant may have at most two.

Rotating one, or minting a new one, needs **both** `apikeys:manage` and `killswitch:pull` in the same person, plus a fresh step-up. In practice that is an Admin who has just stepped up.

Rotate with `grace_s: 0`, then store the new key offline in two places. <!-- verify: the compose demo runs SIBYL_ENV=test, so break-glass keys cannot exist there -->

## Gateway tenant and ingest keys

The gateway reads its keys from compose file secrets at start.

1. Mint the replacement:
   ```bash
   NEW=$(dc run --rm --no-deps -T api python -m sibyl_control.cli --json keys create meridian \
     --name gateway-meridian-2 --env test --scope gateway:proxy --scope routing:read | jq -r .secret)
   ```
2. Replace the old key in the file. The file holds a comma-separated list with one key per fronted tenant.
   ```bash
   f=deploy/compose/env/secrets/gateway_tenant_keys
   chmod 0644 "$f"; printf '%s' "$NEW" > "$f"; chmod 0444 "$f"
   dc up -d --force-recreate --wait gateway
   ```
3. Check `/readyz` shows a `fresh` snapshot, then revoke the old key.

For the ingest key, do the same with `--scope ingest:write` and `secrets/gateway_ingest_key`.

## Tenant data keys (DEKs)

Each tenant has three data keys: `payload`, `credential` and `config`. Rotating one creates a new active version wrapped under the KEK and retires the old one. A retired key still decrypts existing data; new data uses the new key.

You need `keys:rotate` (an Admin or Security admin), a fresh step-up and a reason. The limit is 6 rotations per hour per tenant.

```bash
curl -s --cacert "$CA" "$SIBYL/api/v1/tenant-keys" -H "Authorization: Bearer $SESSION" | jq '.data[] | {purpose, version, state}'
curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/tenant-keys/payload/rotate" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{"reason": "Quarterly payload key rotation."}'
```

Audited as `tenant_key.rotated`. Shredding a key is not a rotation; it happens only through an approved tenant-scope erasure.

## Snapshot signing key

There is **no tooling yet**. The published key set has no pre-announced `next_key` (change request, B10). A rotation can only be followed by a gateway while the previous key can still sign the new key set.

Rehearse on a scratch stack before doing this for real. <!-- verify: the whole manual procedure below has not been exercised end to end -->

The outline:

1. **Generate a new Ed25519 seed** and make its private half available to the API under a new reference, for example a `file:` path on a mounted secret. Keep the old seed available too.
2. **Swap the rows, as `sibyl_migrate`, in one transaction:**
    - Mark the current `snapshot` row `retiring` with `retiring_until` 24 hours ahead.
    - Insert the new row `active`, with its public key and a `private_key_ref` that resolves in the API (`env:VAR` or `file:/path`).

   The API signs the new key set with the previous key, so a pinned gateway follows the chain.
3. **Wait** until every gateway shows the new version in `/readyz`, and its logs show the key set accepted.
4. **Update the pin** after the overlap. Write the new public key into `deploy/compose/env/public/snapshot_pin.json`, so a freshly started gateway pins the new key. Then remove the old seed.
5. **If the old key was compromised:** mark it `compromised` instead of `retiring`, and re-pin every gateway from a trusted copy of the new public key. Never pin from what the API serves.

## Audit-anchor signing key

Also manual. Old anchors stay verifiable for as long as their public key remains in `sibyl.signing_key`, and `GET /audit/signing-keys` lists every state. <!-- verify -->

1. **Generate a new seed.**
2. **Swap the rows, as `sibyl_migrate`:**
    - Mark the current `audit_anchor` row `retiring`.
    - Insert the new row `active`.
3. **Give the worker the new seed** as `SIBYL_ANCHOR_SIGNING_KEY`, then restart the worker. The worker signs only when its seed matches the active row's public key; otherwise it refuses to anchor.
4. **Distribute the new public key** (`env/public/anchor_signing.pem`) to everyone who verifies exports offline. Keep the old public key as well. `sibyl audit verify` accepts `--public-key` more than once.
5. **If the old key was compromised:** mark it `compromised`. Anchors it signed will then fail verification. Re-anchor with the new key, and record the event in the incident log.

## Other secrets

| Secret | How to rotate | Effect |
|---|---|---|
| DB role passwords | Write a new value to `secrets/db_password_<role>`, run `dc --profile bootstrap run --rm bootstrap`, then restart that service | Brief reconnect |
| `session_secret` | Replace the file, restart the API | Logins in progress fail and must restart. Sessions stored in the database keep working. <!-- verify --> |
| `oidc_client_secret` | Replace the file, restart the API and dex | Sign-ins pause during the restart |
| `key_pepper` | **Not supported without re-issuing every API key**: keys are stored as peppered hashes | Every key stops working |
| `kek` | **Not supported in Phase 1**: there is no rewrap tooling. Every wrapped key records its `kek_id`, so a rewrap job is possible later. | Do not change it. Losing it destroys every tenant's data. |
| `ledger_signing_key` | Do not rotate without a plan for the ledger chain and backup manifests | Restores verify the ledger with its public key ([backup-restore.md](backup-restore.md)) |

Never run `deploy/compose/init-env.sh --force` on a stack holding data. It regenerates **every** secret, including the KEK.
