# Runbook: snapshot stale, gateway fail-open

**Symptoms:**

- Gateway responses carry `X-Sibyl-Policy-State: stale` or `expired`.
- Fail-closed agents are refused with `503 sibyl_policy_expired`.
- After a gateway restart with an empty snapshot volume, everything is refused with `503 sibyl_no_snapshot`.
- `/readyz` on the gateway reports a snapshot state other than `fresh`.

**Sources:** ADR-1, ADR-9, D2, D31, B4, B10, B12.

## How freshness works

The gateway fetches its signed snapshot from the API every 5 seconds (`SIBYL_POLICY_POLL_S`). It sends `If-None-Match` and verifies the Ed25519 signature over the raw bytes it received. It installs the snapshot only if the version is not lower than the one it holds, and keeps the last good snapshot on disk at `/var/lib/sibyl/snapshot`.

| Snapshot age | State | Fail-open agent | Fail-closed agent |
|---|---|---|---|
| ≤ TTL (60 s) | `fresh` | serves | serves |
| ≤ TTL + grace (300 s) | `stale` | serves | serves |
| > TTL + grace | `expired` | serves (`stale_primary`). A `policy.stale_bypass` decision is recorded, at most once a minute per agent. | refused: `sibyl_policy_expired` |
| never verified | `unavailable` | refused: `sibyl_no_snapshot` | refused: `sibyl_no_snapshot` |

A killed agent is refused in every state, including stale and expired, as long as the gateway once loaded a snapshot saying so.

Note what an expired snapshot means: **routing changes, kill switches pulled after the last good snapshot, and key revocations do not reach the gateway.** A fail-open agent keeps running on its last known route.

## Diagnose

### 1. What the gateway holds

```bash
dc exec -T gateway python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8080/readyz').read().decode())"
dc logs --since 15m gateway | grep -iE 'snapshot|rejected|key set|policy' | tail -50
```

### 2. Can the API sign a snapshot?

```bash
dc ps api                         # healthy?
dc logs --since 15m api | grep -iE 'snapshot|signer|signing' | tail -50
psql_sibyl -c "SELECT kid, purpose, state, activated_at FROM sibyl.signing_key ORDER BY purpose, activated_at"
```

There must be exactly one `active` key with purpose `snapshot`, and its private half must resolve. Compose resolves it from `env:SIBYL_SNAPSHOT_SIGNING_KEY`. The API uses a signer only if its public key matches the registered row.

### 3. Does the gateway trust that key?

The gateway pins `deploy/compose/env/public/snapshot_pin.json`, mounted at `/etc/sibyl/snapshot-pin.json`, and follows the signed key set from there.

A pin that does not match the active key leads to rejections, logged with a cause such as `unknown_kid` or `bad_signature`. <!-- verify after INT-2: snapshot_pin.json is written by INT-2's init-env and mounted as a compose config -->

### 4. Does the gateway have its tenant keys?

`secrets/gateway_tenant_keys` holds one `sbl_` key per tenant, with `gateway:proxy` and `routing:read`. An empty file is valid: the gateway then serves only from disk and never refreshes.

The gateway lists configuration problems at start, for example `SIBYL_GATEWAY_TENANT_KEYS empty: serving from disk only`.

### 5. Is the network path open?

The gateway calls `http://api:8000/api/v1/policy/snapshot` on the `edge` network. The public origin answers `404` for `/api/v1/policy/*` by design.

## Fix

| Cause | Fix |
|---|---|
| API down | Bring the API back ([incident-response.md](incident-response.md) step 1). The gateway catches up on its next poll; you need not touch it. |
| No signing-key row | `ops/demo/up.sh` registers it; or run `ops/demo/register.py` as `sibyl_migrate`. <!-- verify after INT-2 --> |
| Pin mismatch after a key change | See [rotate-keys.md](rotate-keys.md#snapshot-signing-key). Re-pin only from a trusted copy of the public key, never from what the API serves. |
| Gateway tenant key revoked or expired | Mint a new key: `python -m sibyl_control.cli keys create <tenant> --name gateway-<tenant> --env <env> --scope gateway:proxy --scope routing:read`. Write it to `secrets/gateway_tenant_keys`, then run `dc up -d --force-recreate gateway`. |
| `sibyl_no_snapshot` after the snapshot volume was lost | The gateway must reach the API once. Fix the API path first. Restarting the gateway does not help while the API is down. |

## Should you change fail modes during an outage?

Usually not:

- Fail-open agents keep serving on their last route.
- Fail-closed agents are refused on purpose. They are the ones whose owners chose safety over availability.

To keep a fail-closed agent running anyway, change its `fail_mode` in the registry. The change reaches the gateway only with a fresh snapshot, so fix the snapshot path first.

A client cannot override its fail mode: the gateway refuses any `X-Sibyl-Fail-Mode` header with `sibyl_header_not_allowed`.
