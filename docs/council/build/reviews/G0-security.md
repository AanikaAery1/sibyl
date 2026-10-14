# G0 security review: wave 0 merged diff

Reviewer: security-auditor · 2026-10-10 · Diff `681f181..HEAD` (7 commits, 343 files, about 69k lines)
Method: read the code, then probed the DB on a scratch database built by the real migration runner on PG17 :5433 (since dropped), plus Python probes of the kernel, scrubber, canonicaliser and ops scripts. Every finding below was reproduced, or is a direct reading of code whose behaviour a probe confirmed. Rulings G0-5..G0-10 are excluded because they are decided but not yet built.
Suite baseline: `pytest services/control/tests services/gateway/tests` gives 878 passed, 730 xfailed. The repo was not modified apart from this file. Probes are in the session scratchpad (`db/`, `schemas/`, `infra/`).

**Verdict: 4 HIGH, 11 MEDIUM, 10 LOW. No CRITICAL.**
- Fix H1 and H2 before the contract freeze. They change the shape of SQL functions in 0011 and of the ledger format.
- H3 changes the `base_url` CHECK function.
- H4 is a `sibyl-schemas` 1.0.x patch, but it must land before any ingest traffic.

---

## HIGH

### H1. The erasure ledger is unauthenticated: it can be truncated or forged, and subject erasures are silently dropped on restore (R63)
**Where:**
- `services/control/migrations/0011_lifecycle.sql:402-436` (`erasure_ledger_verify`) and `:456` (subject entries skipped)
- `ops/backup/restore.sh:50-56` and `:98-110`
- `services/control/src/sibyl_control/migrate/ledger.py`

**What is wrong:**
- The chain is plain `sha256(prev || JCS(entry))`. There is no key, no signature, and no expected head or count.
- Any prefix of a valid ledger verifies, and so does an empty file.
- Anyone who can write the file can append entries that verify. The runbook puts the ledger on the `blobstore` volume, which api, ingest and worker all mount read-write.
- `erasure_reapply_from_ledger` does `CONTINUE WHEN scope_kind = 'subject'`. It does not count those entries, does not warn, and still returns success.

**Verified:**
- A 2-entry ledger cut to its first line passes `erasure_ledger_verify`.
- `restore.sh --ledger <empty file>` logged "re-shred ok: 0 erasure(s) re-applied", opened the database and exited 0 (infra probe).
- A ledger holding one agent entry and one subject entry returned `1` from `erasure_reapply_from_ledger`, so the subject erasure vanished without a signal.

**Exploits:**
1. **Truncation.** The ledger export fails or is stale, or an operator uses the reference copy from the backup set. Restoring a pre-erasure backup then resurrects erased tenants' wrapped DEKs and rows, and the database opens. This breaks D17 and D26.
2. **Forgery.** An RCE in ingest appends a valid entry `{"scope_kind":"tenant","tenant_id":<victim>}`. The next restore crypto-shreds the victim tenant irreversibly.
3. **Subject erasures.** A GDPR Art. 17 subject erasure completed after the backup is never re-applied, and nothing tells the operator.

**Fix:**
1. Sign each ledger entry, or at least the head, with the `audit_anchor` key. Before applying anything, make `erasure_ledger_verify` require a signed head `(seq, hash)` passed by the operator and fetched from WORM or BlobStore storage separate from the ledger file.
2. Refuse to open the restored database when any `erasure_request` with `state = 'completed'` in it is missing from the ledger, or when the backup set's ledger copy is not a byte prefix of the live ledger.
3. Make `erasure_reapply_from_ledger` return or raise on unapplied subject entries. `restore.sh` must then keep the database closed (`CONNECTION LIMIT 0`) until an operator acknowledges each one.
4. Refuse an empty ledger unless `--no-ledger` is passed.
5. Put the ledger on a path or volume that only the worker can write.

### H2. Tenant erasure leaves personal data behind, and the residue check certifies it as clean
**Where:** `0011_lifecycle.sql:310-316` (anonymise) and `:368` (residue).

**What is wrong:**
1. The anonymise `UPDATE` has `WHERE status <> 'deprovisioned'`. A user deprovisioned **before** the erasure keeps their plaintext `email` and `display_name`. If that user ever appears as an audit `actor_id` (every login does), the row is not deleted either. `erasure_residue` counts only `status <> 'deprovisioned'`, so it reports nothing left.
2. `subject`, the IdP's stable user identifier, is never touched for any user.
3. Every other user's email and display name become **unsalted** `sha256(lower(email))`. That is pseudonymisation, not anonymisation: a dictionary of candidate addresses re-identifies them.

**Verified:** I ran a full tenant-offboarding erasure through `tenant_key_shred` and both phases. `erasure_residue` returned `[]`, yet the table still held:
- `{'subject': 'sub-alice', 'email': 'alice.former@victim.example', 'display_name': 'Alice Former', 'status': 'deprovisioned'}`
- the other users with `subject` intact and hex `sha256(email)`.

**Exploit:** The erasure certificate (`certificate_sha256`) attests to a tenant erasure that left former employees' names, emails and IdP subjects in the database and in every later backup. This is an Art. 17 / DPDP §12 compliance failure, discoverable by anyone with database or backup read access.

**Fix:**
- Anonymise every `app_user` row whatever its status. Set:
  - `email = 'erased+' || id || '@invalid'`
  - `display_name = NULL`
  - `subject = 'erased:' || id`
  - `last_login_at = NULL`
- If linkability is genuinely needed, use an HMAC under a per-erasure random key that is discarded afterwards.
- Make `erasure_residue` check the content (no `@` outside the `.invalid` domain, no non-erased subject), not the status.
- Add a fixture user who is `deprovisioned` and has an audit row to `test_erasure.py`.

### H3. The SSRF allowlist (`sibyl.is_allowlisted_base_url`) has seven bypasses, one of them session-settable
**Where:** `services/control/migrations/0001_foundation.sql:144-170`, used by the CHECKs at `0004_registry_graph.sql:21` and `0005_policy_security.sql:196`; also `packages/sibyl-schemas/src/sibyl_schemas/models/snapshot.py:76` (`^https?://`).

**Verified allowed:**
- **Userinfo:** `https://x@169.254.169.254/latest/meta-data` and `https://api.openai.com\@127.0.0.1/`. The host group `[^/:?#]+` captures `x@169…`, the `::inet` cast fails, and the function returns true.
- **Non-dotted IPv4:** `https://2130706433/`, `https://127.1/`, `https://0x7f000001/`.
- **Trailing dot:** `https://localhost./`, `https://metadata.google.internal./`.
- **IPv6:** `[::ffff:127.0.0.1]`, `[::ffff:a9fe:a9fe]`, `[::]`, `[64:ff9b::7f00:1]`.
- **Missing ranges:** multicast and `255.255.255.255`.
- **Settable dev hosts:** `sibyl.dev_hosts` is a placeholder GUC, so any login role can set it. As `sibyl_app`, `SET LOCAL sibyl.dev_hosts='169.254.169.254,metadata.google.internal'` makes `http://169.254.169.254/latest/meta-data/` return `t`.
- **No DNS check:** the function never resolves DNS, so rebinding is unaddressed.

**Exploit:** A credential or provider writer (or a SQL-injection foothold in api) stores a fallback `base_url` pointing at metadata or loopback. On failover the gateway sends the **vaulted provider secret** there (§2.3 step 4), and can read cloud-instance credentials.

**Fix:**
- Parse the authority strictly. Reject `@`, `\` and `%`, and accept only an LDH hostname containing a letter and no trailing dot, a canonical dotted quad, or a bracketed IPv6 address.
- Unwrap `::ffff:` and `64:ff9b::` and check the embedded IPv4 address.
- Block `::/128`, `224.0.0.0/4`, `240.0.0.0/4`, `198.18.0.0/15` and `192.0.0.0/24`.
- Read dev hosts from a table owned by `sibyl_migrate`, not a GUC.
- Tighten the snapshot schema to `^https://` outside dev.
- Have the gateway's HTTP client re-check the **resolved** IP at connect time.
- Add the bypass list above as a parametrised test.

### H4. Scrubber ReDoS on the ingest and gateway hot path
**Where:** `packages/sibyl-schemas/src/sibyl_schemas/scrub/_detectors.py`:
- `:118` (`_PEM_BODY` lazy `[\s\S]*?`), used at `:178-183`, `:210-214` and `:225-229`
- `:236-241` (dsn `[^\s"']*?[?&]password=`)
- `:247` (basic_auth_url: every `.` restarts the scheme scan)

**Verified, one core:**

| Input | Size | Time |
|---|---|---|
| `"-----BEGIN OPENSSH PRIVATE KEY-----"` × 20,000 | 700 KB | 81 s |
| `"a." * 100000` | 200 KB | 49 s |
| `"postgres://"` × 20,000 | 220 KB | 21 s |

**Exploit:**
- Any `ingest:write` key sends a 4 MiB gzipped batch of `a.a.a.`, which compresses to almost nothing and costs hours of CPU per field.
- The gateway also scrubs response chunks and tool results, so a web page that an agent reads can stall gateway workers.

**Fix:**
- Bound every unbounded run: PEM body `{0,8192}`, DSN path `{0,2048}`, URL scheme `{0,32}`, with no `.` at the start of a scheme.
- Pre-gate each PEM detector on an `-----END` that follows the BEGIN.
- Or run on RE2.
- Add a per-field size cap and a CI timing test: 1 MiB of adversarial input in under 100 ms.

---

## MEDIUM

### M1. The database does not enforce four-eyes approval or legal holds for erasure
**Where:**
- `0011_lifecycle.sql:41` (the state-edge trigger fires on `UPDATE OF state` only)
- `0011_lifecycle.sql:258-290` (`erasure_execute_phase` has no hold check)
- `0006_audit.sql:286-300` (only `tenant_key_shred` checks holds, and only for tenant scope)

**Verified:**
1. **No approval needed.** As `sibyl_app`, `INSERT INTO erasure_request (…, state) VALUES (…, 'executing')` with `approved_by = NULL` succeeds. The worker then ran `tenant_key_shred` (3 keys shredded) and both purge phases.
2. **Holds ignored.** With an active `legal_hold` (scope agent, agent B), an approved agent-scope erasure for agent B moved to `executing`, and both phases deleted agent B (`"agent": 1`).

**Exploit:**
- An api bug, or any `sibyl_app` foothold, gets an irreversible crypto-shred with no approver.
- A hold placed between approval and execution (a race the DB should close, since `tenant_key_shred` already re-checks holds for tenant scope) does not stop the purge. That is spoliation of data under litigation hold (R14).

**Fix:**
- Add a `BEFORE INSERT` trigger forcing `state = 'requested'` unless `current_user = 'sibyl_audit'` (the restore hook).
- Add a CHECK that `state IN ('approved', 'executing', 'keys_shredded', 'objects_deleted', 'derived_purged', 'verified', 'completed')` implies `approved_by IS NOT NULL OR execution_log` holds a restore step.
- Re-check active holds that intersect the scope (tenant hold, `agent_ids @> ARRAY[agent]`, `scope_ref`) at the top of `erasure_execute_phase` and of `tenant_key_shred` for every scope.
- Apply the same INSERT-state rule to the other DB-enforced machines (approval, handoff, fallback_chain).

### M2. The audit chain can be poisoned at append and then reports false tampering; `audit_verify` stops at the first break
**Where:**
- `0006_audit.sql:141-148` (canonical accepted when only `jsonb`-equal)
- `0006_audit.sql:225-227` (verify recomputes with the SQL JCS)
- `0001_foundation.sql:69-70` (`ORDER BY key COLLATE "C"`, code-point order, not RFC 8785's UTF-16 order)

**Verified:**
- **Key-order divergence.** A detail with keys `"ﬁ"` and `"😀"` canonicalised by the kernel (`canonical_detail`) appends fine, then `audit_verify` returns `content_mismatch` at that seq permanently.
- **Non-canonical text accepted.** A `p_detail_canonical` containing a duplicate key and whitespace is accepted; verify then reports `content_mismatch`.
- **Non-integers.** A non-kernel caller passing `{"ratio":0.5}` with its own canonical bytes appends fine, then `audit_verify` **raises** SB023 for the whole tenant chain, and keeps raising on every later run.

**Exploit:**
- If any audit detail ever embeds a user-controlled key (labels, `role_claim_map`, tool names), a tenant user can permanently break their own chain's verification.
- Because `audit_verify` returns only the first break, rows tampered with after the poisoned seq go unreported by the server-side walk. Signed anchors remain the backstop.

**Fix:**
- Restrict detail keys to ASCII in both canonicalisers, or make the SQL JCS sort by UTF-16 code units.
- In `audit_append`, require `convert_from(p_detail_canonical) = sibyl.jcs(p_detail)` byte for byte. The SQL JCS already rejects non-integers, so a bad document fails at append instead of at verify.
- Make `audit_verify` continue past a content mismatch and report every broken seq.

### M3. Object rules are handler-only, fail open by default, and have no tests
**Where:**
- `services/control/src/sibyl_control/api/deps.py:292-318`: the guard calls `authorize()` with `resource_group_id = NOT_APPLICABLE` and `resource_agent_id = None`.
- `core/authz.py:219` and `:247-252`: both rules pass when the argument is omitted.
- `services/control/tests/contract/test_authz_wall.py:18-21`.

**Verified:**
- The contract carries 92 object-rule annotations, including group ×54, bound_agent ×11, rank ×3, job_owner, owner_grants_privileged and second_owner_tenant_kill.
- The generated wall has no case for any of them. It skips `authenticated` and `self` routes, and `STEP_UP` covers only `always`, so conditional step-up on `createApiKey`, `rotateApiKey`, `putAgentIdentity` and `pullKillSwitch` is untested.
- `getJob` is `x-sibyl-scope: authenticated` plus `job_owner`. Any tenant user passes the guard.

**Exploit:** Wave 1 turns the wall green while a single handler that forgets `ctx.check(resource_group_id=…)` lets:
- a group-scoped engineer act on every agent in the tenant;
- an agent-bound key act as any agent (violating D32 and R13);
- any user read another user's audit or data-export job result.

**Fix:**
- Make `AuthContext` record which object rules were evaluated. A response middleware must fail closed with 500 and an alert when an operation with `object_rules` returns 2xx without them.
- Generate wall cases per rule: an out-of-group agent gives 404, a bound key on another agent gives 404, a non-owner job gives 404, and a break-glass key create or kill without step-up gives 403.

### M4. All clients share one rate-limit bucket behind Caddy, so one client can lock everyone out of login
**Where:** `services/control/src/sibyl_control/api/__main__.py:12-19` (`proxy_headers=True`, but no `forwarded_allow_ips`) and `api/deps.py:273-274`.

**Verified:**
- uvicorn trusts `X-Forwarded-For` only from `127.0.0.1,::1` unless `FORWARDED_ALLOW_IPS` is set (`uvicorn/config.py:363`). Neither compose nor the code sets it.
- Caddy is a separate container, so `request.client.host` is Caddy's IP for every user.
- A guard probe showed `authLogin` returning 429 after 30 requests per minute from one bucket, with `X-Forwarded-For` ignored.

**Exploit:**
- About 30 requests per minute from one attacker exhausts the shared `auth` bucket (`authLogin`, `authCallback`) for every user of every tenant. That is a login DoS, including during an incident.
- Every future `ip_hash` (`access.login_failed`, `access.break_glass`, `api_key.anomaly`) will hash Caddy's IP, which blinds that forensics.

**Fix:** set `forwarded_allow_ips` to the Caddy address or network from settings. Caddy already overwrites client-supplied XFF because it has no `trusted_proxies`. Add a test that two different XFF values from the proxy address land in different buckets.

### M5. The snapshot envelope contradicts B4 and allows a duplicate-`body` signature bypass
**Where:** `packages/sibyl-schemas/src/sibyl_schemas/models/snapshot.py:193-199` and `packages/sibyl-schemas/tests/test_snapshot_vectors.py:43-64`.

**What is wrong:**
- `{kid, alg, sig, body}` nests the signed body, so "verify the raw received bytes" means slicing it out. The reference verifier re-canonicalises instead, which B4 forbids.
- **Verified:** an envelope with two `body` members (the genuine body first, an un-kill body second) passes `SignedPolicySnapshot.model_validate_json`, and the parsed body is the tampered one. A gateway that verifies the first raw body and then uses the model would accept an un-kill snapshot.
- An outer `kid` different from `body.kid` is also accepted, and no vector covers it.

**Fix:**
- Use the detached transport from §2.4: the HTTP body is the signed bytes and the signature travels in a header. Verify those bytes, then parse the same bytes with `parse_json_strict`.
- If the envelope must stay, carry `body` as base64url.
- Add vectors for a duplicate `body` and for `kid` ≠ `body.kid`.

### M6. The signing key set is unsigned, so kid pinning reduces to TLS
**Where:** `models/snapshot.py:210-214` and `services/control/src/sibyl_control/core/crypto/signing.py:93-94`.

**What is wrong:** §2.4 requires the key set to be signed by the previous active key, but `SigningKeySet` has no `sig` or `signed_by` field. `SigningKey.not_after` is ignored.

**Exploit:** A tampering relay or cache, or a mis-trusted CA in a customer-cloud gateway, injects a `kid` and then serves forged snapshots: un-kill agents, add keys, change `base_url`.

**Fix:** add `sig` and `signed_by`, accept only sets signed by a currently pinned key, and enforce `not_after`.

### M7. `scrub_json` does not scrub dictionary keys or `bytes`
**Where:** `packages/sibyl-schemas/src/sibyl_schemas/scrub/_scrubber.py:117-121`.

**Verified:** `{sk-ant-…: 1, "nested": {sbl_live_…: "v"}, "b": b"sk-ant-…"}` comes back unchanged with 0 findings. Agent state, tool arguments and OTel attribute keys reach storage, contrary to §5.1 stage 3.

**Fix:** scrub keys (suffix on collision), and scrub or refuse `bytes` and `bytearray`.

### M8. Every platform secret is in ingest and worker
**Where:** `deploy/compose/docker-compose.yml:28-30, 141-145, 158-162, 174-178` and `deploy/compose/env/control.env.example:9-16`.

**Verified:** `docker compose config` gives ingest and worker `SIBYL_MASTER_KEK`, `SIBYL_SNAPSHOT_SIGNING_KEY`, `SIBYL_ANCHOR_SIGNING_KEY`, `SIBYL_SESSION_SECRET`, `SIBYL_OIDC_CLIENT_SECRET`, the pepper and the salts. `migrate.env:6` puts the Postgres superuser password in the migrate container on every `up`.

**Exploit:** An RCE in ingest, the 16 MiB untrusted-OTLP parser, yields:
- every tenant's DEKs;
- forged snapshots that the gateway trusts;
- forged audit anchors.

**Fix:**
- Split secrets per process: ingest gets pepper and scrub salt; worker gets the anchor key and KEK; api gets session, OIDC, snapshot and KEK.
- Use compose `secrets:` files rather than env vars, and `POSTGRES_PASSWORD_FILE`.
- Provide admin credentials only on the first bootstrap.

### M9. Data volumes are root-owned while services run as uid 10001
**Where:** `docker-compose.yml:31-32, 213-214` and `deploy/docker/control.Dockerfile:57-65` (same in `gateway.Dockerfile`).

**Verified:** a fresh volume mounted at `/var/lib/sibyl/{blob,snapshot}` as uid 10001 cannot be written.

**Failure:**
- The gateway cannot persist its last verified snapshot. After a restart during a control-plane outage it serves 503 `no-policy` to all traffic, inverting ADR-1.
- Payload, anchor `external_ref` and ledger writes fail.
- `/healthz` stays green.

**Fix:** `RUN install -d -o sibyl -g sibyl /var/lib/sibyl/blob /var/lib/sibyl/snapshot` before `USER`, plus a live write test.

### M10. Restore drops the target database before it knows the dump is good
**Where:** `ops/backup/restore.sh:84-93` (a missing `.sha256` only warns, at `:58-64`).

**Verified:** a truncated dump with no `.sha256` plus `--confirm-destroy` dropped the target, then pg_restore failed, leaving an empty database. The runbook's step 3 uses exactly these flags.

**Fix:**
- Run `pg_restore --list` first.
- Restore into `<target>_restore_<ts>` and rename only after re-shred succeeds.
- Make a missing checksum fatal unless explicitly overridden.

### M11. Backups are unencrypted, unauthenticated and never expire
**Where:** `ops/backup/backup.sh:75-119`; no pruning anywhere in `ops/`.

**What is wrong:**
- Dumps and off-host copies hold plaintext PII.
- The `.sha256` sits next to the dump, so it authenticates nothing. `restore.sh` runs the dump as superuser, so anyone who can write the backup directory can plant `COPY … FROM PROGRAM` and get a shell at the next restore.
- D26's "pre-shred backups expire" (7 days, stated on the erasure certificate) is not implemented.

**Fix:** encrypt and sign dumps (age, gpg or minisign) with an off-host key, verify before `pg_restore`, and prune both copies after `backup_retention_days`.

---

## LOW

| # | Finding | Where | Verified scenario | Fix |
|---|---|---|---|---|
| L1 | Invalid API keys are never rate-limited: the principal resolver raises 401 before `_rate_limit` runs | `api/deps.py:330-334` | 500 bad-key requests gave 500 × 401, 0 × 429 and 500 `api_key_lookup` DB queries. This is an unthrottled pre-auth DB-load lever, and failed break-glass attempts are not counted (§2.5 counts attempts) | Rate-limit by client IP **and** by the presented prefix before `resolve()`; count break-glass attempts by prefix |
| L2 | `audit_append` forks the chain under REPEATABLE READ or SERIALIZABLE | `0006_audit.sql:155-157` | A REPEATABLE READ transaction took its snapshot, another transaction appended seq 5 and committed, then the first appended **another seq 5** (same `prev_hash`). `audit_verify` gives `gap`. The kernel uses READ COMMITTED today, so this is latent; an `ALTER DATABASE … default_transaction_isolation` or a future export transaction triggers it | Keep the head in a per-tenant `audit_chain_head` row locked `FOR UPDATE`, or raise when `transaction_isolation <> 'read committed'` |
| L3 | The DB does not pin API key scopes, agent binding or expiry | `0003_identity.sql:149-178` and the grant at `:265` | As `sibyl_app`: `UPDATE api_key SET scopes = '{ingest:write,gateway:proxy,agents:write,routing:read}', agent_id = NULL, expires_at = now() + '20 years'` succeeded. The §2.2 contract says scopes are fixed, may only be narrowed, and expire within 400 days; D32 requires tier-1 agents to be key-bound | Column grants without `scopes`, `agent_id`, `prefix`, `secret_hash`, `env`; a trigger allowing only narrowing on rotation; CHECK `expires_at <= created_at + 400 days` |
| L4 | A lookalike replacement token makes the scrubber skip the whole surrounding candidate | `scrub/_scrubber.py:129, 142-143` | `password=hunter2hunter2X[SECRET:00000000]` passes unscrubbed | Trim candidates around token spans instead of dropping them |
| L5 | Detector gaps | `scrub/detectors.v1.json` | `Authorization: Basic …`, `pwd=`, `password%3D` and Google `AIza…` in prose are missed; a zero-width or fullwidth character inside a key defeats detection; `key_sbl_live_…` is missed (lookbehind) | Add `basic_auth_header`, `google_api_key` and `pwd`; NFKC-normalise and strip Cf characters before matching |
| L6 | Lax signature decoding, best-effort zeroisation, and random GCM nonces under a long-lived DEK | `core/crypto/signing.py:31-32, 72-77`; `services/gateway/src/sibyl_gateway/policy/view.py:222-231`; `core/crypto/envelope.py:55-58` | `sig + '=='` and an injected `'!!'` both verify. `reveal()` returns an immutable copy. At 500 events/s the 2^32-nonce bound under one DEK is reached in about 100 days | Strict `^[A-Za-z0-9_-]{86}$` plus `validate=True`; document zeroisation as best-effort; per-object HKDF subkeys or rotation by count |
| L7 | A `dbname=` query parameter in the admin DSN redirects the restore | `ops/backup/lib.sh:24-34` | With `…/postgres?dbname=postgres`, pg_restore and the re-shred run outside the `CONNECTION LIMIT 0` target | Strip or reject `dbname` in the query; pass `-d` separately |
| L8 | One flat compose network | `docker-compose.yml:273-275` | gateway, dex, caddy, console and sim can all reach `postgres:5432`, and hba allows `postgres` from anywhere | Separate `edge` and `data` networks; an hba reject for non-local `postgres` |
| L9 | caddy, dex and postgres are not hardened | `docker-compose.yml:57-111, 220-228` | caddy runs as uid 0 with default capabilities, no `read_only` and no `no-new-privileges` | caddy `user: "1000"`, `cap_drop: [ALL]`, `read_only` with tmpfs; the same for dex |
| L10 | Images pinned by tag, not digest; gateway-only policy routes on the public origin | `docker-compose.yml:58, 79, 96, 222`; `*.Dockerfile:9-10`; `deploy/caddy/Caddyfile:44-49` | `/api/v1/policy/{snapshot,credentials,keys}` (the sealed credential bundle) is reachable on :8443, although the gateway calls `http://api:8000` | Pin `@sha256:` digests; `handle /api/v1/policy/* { respond 404 }` on the public site |

---

## Checked and clean

**Tenant isolation (DB, live catalogue queries)**
- Every table with `tenant_id`, all partitions included, has ENABLE plus FORCE RLS and exactly one policy, `tenant_id = current_tenant()` for both USING and WITH CHECK.
- Two exceptions:
  - `consumer_offsets` is on the R2 allowlist (cursor only).
  - `api_key` and `session` add `OR current_user = 'sibyl_audit'` to USING only. `sibyl_audit` is NOLOGIN with SELECT only, and the two definers that read through it (`api_key_lookup`, `session_resolve`) are exact-match lookups. No other `sibyl_audit`-owned definer reads those tables.
- Every tenant foreign key is composite on `(tenant_id, …)`.
- `set_tenant` is transaction-local, and `current_tenant()` fails closed (raising in strict mode).
- The kernel's `tenant_tx` issues `set_tenant` as its first statement, and `pre_tenant` is read-only.

**Privileges**
- All 16 SECURITY DEFINER functions pin `search_path = sibyl, pg_temp`.
- No non-extension function in `sibyl` carries PUBLIC EXECUTE; default privileges are revoked for all three owner roles.
- TEMP and database CREATE are revoked from every Sibyl role. Schema CREATE is held only by `sibyl_migrate` and the two NOLOGIN owners.
- Every role is `NOSUPERUSER NOBYPASSRLS`.
- `sibyl_migrate` can SET ROLE to (but does not inherit) the owners.
- Audit tables belong to NOLOGIN `sibyl_audit`, no login role holds DML on them, and UPDATE/DELETE/TRUNCATE triggers block mutation.
- Tables with `trg_block_mutation` are deletable only by `sibyl_worker`, and only on `events`, `feature_snapshot` and `outbox` (retention).

**Dynamic SQL**
- `partition_ensure*` validates `p_table` against `partition_policy()` and uses `%I`/`%L`.
- The erasure cascade predicates are constants from an IMMUTABLE function, bound with `USING $1, $2`.
- `grant_insert_except` is revoked from PUBLIC.
- `restore.sh` passes the ledger through a random dollar-quote tag that is checked against the file contents.

**API keys**
- HMAC-SHA-256 with a pepper of at least 32 bytes.
- `fullmatch` parsing.
- One HMAC plus one `compare_digest` on every path, including the dummy compare for unknown prefixes and malformed input.
- Status and environment are checked only **after** the secret matches, so there is no oracle, and every rejection is the same 401.
- Query-string keys and browser-origin keys are refused.

**Break-glass**
- Exclusive scope, live and tenant-level, enforced three times: DB CHECKs, `validate_key_scopes` and the scope catalogue.
- At most two active per tenant, enforced by a trigger under an advisory lock.
- `break_glass_key_misuse` is raised on every non-kill route and on `authenticated` routes.
- `routing_apply` requires `actor_key_id` exactly when `actor_kind = 'api_key'` (G0-4).

**Authorisation**
- Deny by default: API keys need explicit `key_scopes`, unknown scopes raise, and a missing principal gives 401.
- Step-up applies only to a `session` principal with `step_up_at` no more than 5 minutes old.
- `self` routes neither need step-up nor accept API keys.

**Crypto**
- Ed25519 reference verification order matches §2.4 (unknown_kid, bad_signature, non_monotonic, future_issued, bad_ttl), `kid` is bound to `body.kid`, and there is only one `alg`.
- AES-GCM AAD binds tenant, purpose, key version and object.
- The KEK wrap AAD includes `kek_id`.
- BlobStore `validate_key` blocks traversal.
- The Python RFC 8785 canonicaliser matches node `JSON.stringify` on 20,001 numbers and on string edge cases.

**Infra**
- Only `*.env.example` files are tracked, all with empty secrets; `init-env.sh` writes files 0600.
- The corporate CA is used only as a BuildKit secret.
- App containers run as non-root with `read_only`, `cap_drop ALL` and `no-new-privileges`.
- Every published port is bound to 127.0.0.1, and compose Postgres uses scram.
- Caddy runs `admin off`, sets HSTS, caps bodies, and does not trust client XFF.
- dex uses an https issuer, exact redirect URIs and code flow only.

**Not reviewable yet** (routes are 501 stubs; no runtime callers): the gateway PolicyView fetch and verify path, the scrubber, envelope and signing call sites, and the session/OIDC resolver. H3, M3-M6 and L6 are written against the contract as wave 1 will use it.

Housekeeping: four `sibyl_w0db_*` databases (not mine) remain on :5433.
