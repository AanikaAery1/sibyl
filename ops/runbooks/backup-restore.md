# Runbook: backup and restore (Phase 1, localhost)

Owner: operator on duty. Sources: D17, D18, D26, R30, R63, G0 security review H1/M10/M11/L7, project-shipper §3.5 and §4 C0/C1, ARCHITECTURE ADR-5/ADR-12.
Scripts: `ops/backup/backup.sh`, `ops/backup/restore.sh` (both take `--help` and `--dry-run`; restore also `--verify-only`).

## What this covers, and what it does not

| Covered now | Comes later (lane O, wave 2 / Phase 2) |
|---|---|
| Logical `pg_dump` (custom format) piped straight into `age` (no plaintext on disk) | pgBackRest with WAL archiving, PITR, RPO 1 min (D18) |
| Signed manifest: checksum, erasure-ledger head, expiry | `repo2` in an S3-API bucket off host, restic for blobs (C1) |
| Copy to a second location (`--offhost`); retention by manifest date (D26, default 7 days) | Weekly automated drill with metrics (cut A7) |
| Restore: verify everything offline, restore into a **new** closed database, re-shred with the verified ledger head, then swap | |

**RPO with logical dumps is the time since the last run.** Schedule `backup.sh` at least hourly
while design-partner data exists. A backup that was never restored is not a backup: run the
drill below before relying on it.

## Keys (set up once, keep offline)

| Key | Made with | Lives | Used by |
|---|---|---|---|
| Backup encryption identity (age X25519) | `age-keygen -o sibyl-backup.agekey` | **offline**, two places, never next to the backups | restore (`--identity`) |
| Its recipient (public) | `age-keygen -y sibyl-backup.agekey` | the backup host, `SIBYL_BACKUP_AGE_RECIPIENT` | backup |
| Manifest signing key (ssh ed25519) | `ssh-keygen -t ed25519 -N '' -C sibyl-backup -f sibyl-backup-signing` | the backup host only (0600) | backup (`--signing-key`) |
| allowed_signers | one line: `sibyl-backup <type> <base64 public key>` | anywhere a restore runs | restore (`--allowed-signers`) |
| Ledger signing public key | written by `deploy/compose/init-env.sh` to `env/public/ledger_signing.pem` | copy it next to the restore tooling and in escrow | backup + restore (`--ledger-public-key`) |
| Audit-anchor public key | `init-env.sh` writes `env/public/anchor_signing.pem` (and `anchor_key.json`, the `signing_key` row `ops/demo/up.sh` registers as purpose `audit_anchor`) | next to the restore tooling and in escrow | `sibyl audit verify --public-key` (offline) |

`age` (BSD-3-Clause, D15-permissive): `brew install age` / `apt install age`. `ssh-keygen` is OpenSSH and
already present. Also escrow the KEK (`deploy/compose/env/secrets/kek`) and the three signing seeds
offline: losing the KEK equals shredding every tenant, and a backup without its KEK is unreadable payload
data.

## Pre-requisites

- PostgreSQL **17** client tools (`PGBIN=/opt/homebrew/opt/postgresql@17/bin`). The scripts refuse an
  older `pg_dump`.
- A connection that can read every table: the compose `postgres` user via `127.0.0.1:${SIBYL_PORT_PG}`;
  its password is `deploy/compose/env/secrets/postgres_password`. Put it in `~/.pgpass` (0600) rather than
  in the URI. A DSN whose query sets `dbname=` or `service=` is refused: the database is always the URI
  path.
- **Off-host first (C0).** `--offhost` must be a different physical disk or machine; the script warns
  when it shares a device.
- **The erasure ledger** (R63, H1) is append-only, hash-chained and signed by the worker's ledger key.
  The worker's `erasure_ledger` loop keeps it in the **BlobStore** under its own prefix (no tenant
  erasure can delete it): `ledger/erasure/entries/<seq>.json` (create-only, the source of truth),
  `ledger/erasure/ledger.jsonl` (the verified ledger) and `ledger/erasure/head.json` (its signed head
  `{count, head_hash, at, sig}`). With the compose fs backend that is the `blobstore` volume, mounted
  by api, ingest and worker at `/var/lib/sibyl/blob`. Export a read-only copy to the backup host and
  point `SIBYL_BACKUP_BLOB_ROOT` (or `--blob-root`) at the copy's root:
  ```sh
  mkdir -p ~/sibyl/blob && docker compose cp worker:/var/lib/sibyl/blob/ledger ~/sibyl/blob/
  # -> ~/sibyl/blob/ledger/erasure/{ledger.jsonl,head.json,entries/}
  ```
  `--blob-root` checks that `ledger.jsonl` verifies **and** ends exactly at the signed `head.json`
  (a truncated tail or a forged head fails). No `ledger.jsonl` yet means no erasure has completed:
  use `--no-ledger` only if that is true. `--ledger FILE` still takes a bare `ledger.jsonl` (no head
  check). Integrity rests on the signatures and the manifest head, not on file permissions: api and
  ingest can write the same volume.

## Take a backup

```sh
export PGBIN=/opt/homebrew/opt/postgresql@17/bin
export SIBYL_PG_DSN=postgresql://postgres@127.0.0.1:5434/sibyl
export SIBYL_BACKUP_DIR=~/.local/share/sibyl/backups
export SIBYL_BACKUP_OFFHOST=/Volumes/sibyl-backup/sibyl          # different disk
export SIBYL_BACKUP_AGE_RECIPIENT=age1...                         # public key only
export SIBYL_BACKUP_SIGNING_KEY=~/.ssh/sibyl-backup-signing
export SIBYL_BACKUP_BLOB_ROOT=~/sibyl/blob                        # fresh export, see above
export SIBYL_LEDGER_PUBLIC_KEY_FILE=~/sibyl/ledger_signing.pem      # the ledger is verified first
ops/backup/backup.sh --globals
```

Per run, in both locations (prefix `<db>_<UTC>.dump.age`):

| File | Content |
|---|---|
| `.dump.age` | `pg_dump -Fc` encrypted to the recipient |
| `.dump.age.sha256` | checksum of the encrypted dump |
| `.dump.age.manifest` + `.sig` | `sha256`, `ledger_count`, `ledger_head_hash` (from `sibyl_control.migrate ledger-head`, which verifies every signature first), `created_epoch`, `retention_days`, `expires_epoch`, versions, encryption; signed (`ssh-keygen -Y`, namespace `sibyl-backup`) |
| `.globals.sql.age` | roles and grants, **no role passwords** (`--globals`) |
| `.erasure-ledger.jsonl.age` | reference copy of the ledger at backup time; the restore checks it is a byte prefix of the live ledger |

`--no-ledger` records an empty ledger (count 0) and is only for a database where no erasure ever ran.
`--no-encrypt` / `--no-sign` exist for dev clusters; restore then needs `--allow-unencrypted` /
`--allow-unsigned`.

**Expiry (D26).** After each backup, sets older than `--retention-days` (default
`SIBYL_BACKUP_RETENTION_DAYS` or **7**, the value stated on erasure certificates) are deleted from both
locations, judged by the manifest's `created_epoch`, never by file mtime. Run
`backup.sh --prune-only` from cron as well, so expiry happens even if backups stop. Pre-v2 manifests
without `created_epoch` are reported and left for manual deletion.

Also back up the BlobStore volume (`blobstore`) with restic or `tar` while ingest is paused; payload
objects are envelope-encrypted, so the copy is safe at rest.

## Restore

Restoring an old backup brings back wrapped data keys of tenants or agents erased after that backup.
The restore therefore **re-applies every erasure in the live, signed ledger before anything can connect**,
and it **never drops the live database before the new one is verified**.

1. **Stop traffic.** `docker compose stop gateway api ingest worker` (the gateway keeps serving fail-open
   agents from its snapshot; that is expected and safe).
2. **Recreate roles** on a fresh cluster first: `age -d -i <identity> <set>.globals.sql.age | psql`, then
   `docker compose run --rm bootstrap` to set the login-role passwords from `env/secrets/`.
3. **Know the expected ledger head.** By default the restore takes `{ledger_count, ledger_head_hash}`
   from the **newest signed manifest** in the backup directory (`--manifest-dir`). If erasures completed
   after the newest backup, pass the live head from an independent record (WORM export, incident log):
   `--expected-head <hash> --expected-count <n>`. The restore refuses a head older than the one recorded
   in the backup being restored (a truncated ledger).
4. **Verify only** (touches nothing):
   ```sh
   ops/backup/restore.sh --verify-only --dump <set>.dump.age --target-db sibyl \
     --admin-dsn postgresql://postgres@127.0.0.1:5434/postgres \
     --blob-root ~/sibyl/blob --ledger-public-key ledger_signing.pem \
     --identity /Volumes/escrow/sibyl-backup.agekey --allowed-signers allowed_signers
   ```
5. **Restore.** Same command without `--verify-only`, plus `--replace` when `sibyl` exists. In order:
   1. manifest signature, checksum, decrypt into a private temp dir, `pg_restore --list` and a full
      offline read of the archive;
   2. `python -m sibyl_control.migrate ledger-verify --ledger … --public-key … --expected-head H
      --expected-count N` (plus `--head <blob root>/ledger/erasure/head.json` with `--blob-root`);
      the backup's ledger copy must be a prefix of the live ledger;
   3. `CREATE DATABASE sibyl_restore_<ts> CONNECTION LIMIT 0`, `pg_restore --exit-on-error` into it;
   4. `SELECT sibyl.erasure_reapply_from_ledger(<ledger>, N, 'H')` in the new database;
   5. only now: close `sibyl`, rename it to `sibyl_old_<ts>` and the new one to `sibyl` in one
      transaction, open it. `sibyl_old_<ts>` stays closed (`CONNECTION LIMIT 0`) until you drop it, or
      pass `--drop-old`.

   Any failure before step 3 creates nothing. A failed `pg_restore` drops the staging database. A failed
   re-shred leaves `sibyl_restore_<ts>` **closed** for forensics and `sibyl` untouched: do not open it by
   hand; fix the ledger or the head and re-run.
6. **Migrate** to the running release: `docker compose run --rm migrate`.
7. **Verify the audit chains:** `sibyl audit verify --public-key env/public/anchor_signing.pem` for every
   tenant (offline, no database trust needed); anchor heads must equal the off-DB anchor exports.
8. **Start services:** `docker compose up -d --wait`. Check every `/healthz`, then the console.
9. **Record** the restore duration (target ≤ 30 min at Phase 1 volume) and any deviation in the incident
   log. Drop `sibyl_old_<ts>` once the restore is accepted.

`--no-ledger` exists only for databases that never held tenant data (a fresh dev cluster). Using it on a
database that did is an erasure-promise breach (D17).

## Drill (Phase 1 exit item 4.3; two consecutive passes required)

1. Seed `sandbox` with an agent and payloads; take a backup.
2. Erase that agent (`POST /api/v1/erasure-requests`, approval by a second owner after step-up); confirm a
   new signed ledger entry and an `erasure` anchor; take a second backup (its manifest records the new
   head).
3. Restore the **first** backup into a scratch database (`--target-db sibyl_drill`).
4. Assert: re-shred reported ≥ 1 erasure; payload reads for the erased agent return 410
   `payload_shredded`; **zero resurrected rows**; `sibyl audit verify` passes.
5. Try again with a ledger cut to before the erasure: the restore must refuse (head mismatch) and create
   nothing.
6. Drop the scratch database. Record the duration and the results in the drill log.

Automated coverage: `ci/tests/test_backup_restore.py` runs the mechanics on the PG17 dev cluster with a
stub verifier and a stub reapply function: encrypted and signed backup, manifest head, tampered manifest,
stale head, rewritten ledger, truncated dump, verify-before-create, swap, `--drop-old`, closed-on-failure,
retention, L7. `ci/tests/test_backup_restore_ledger.py` runs FIX-DB's real verifier and SQL function
against a really migrated database, including a truncated and a forged signed ledger.

## Dependencies on other lanes

| Item | Owner | Status |
|---|---|---|
| `python -m sibyl_control.migrate ledger-verify --ledger F --public-key F --expected-head H --expected-count N` (exit 0 only when the signed chain verifies and holds that head) | FIX-DB | **landed**; restore stops before touching the cluster when it fails |
| `sibyl.erasure_reapply_from_ledger(ledger_jsonl text, expected_count, expected_head_hash text)` (verifies again in SQL, applies every scope incl. subject, raises on any mismatch) | FIX-DB | **landed**; restore keeps the new database closed when it fails |
| Ledger writer (worker `erasure_ledger` loop into the BlobStore `ledger/erasure/`, key file `SIBYL_LEDGER_SIGNING_KEY_FILE=/run/secrets/ledger_signing_key`) | U | **landed** (wave 2); backup/restore read it with `--blob-root` |
| `sibyl audit verify` offline CLI | U | wave 2 |
| pgBackRest + WAL archiving, automated weekly drill | O | wave 2 / Phase 1.5 (cut A7) |
