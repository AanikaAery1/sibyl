# G0 code review (ecc:code-reviewer, 2026-10-10)

Scope `681f181..HEAD`. CI green before review (1,760 passed, 96.6 % coverage). Verdict: WARNING. 0 CRITICAL, 3 HIGH, 8 MEDIUM, 6 LOW. Probes were in the session scratchpad (`p*.py`); findings verified against PG17 unless marked reasoned. Paths relative to `services/control/` unless noted.

## HIGH
- **H1 `routing_apply` idempotency is tenant-global and unchecked.** `migrations/0008_routing_failover.sql:612-618`, unique `uq_routing_transition_idempotency` (`:107`). Same key on agent B returns agent A's transition and B is never moved; same key with a different `to_state` replays the old one; concurrent same-key on two agents → raw 23505 → generic 409. Fix: replay only if `agent_id`, `to_state`, `trigger` match, else raise new SB `idempotency_key_reuse` (422); serialise per (tenant,key) with an advisory lock or catch unique_violation and re-select. Tests: cross-agent reuse, concurrent same key.
- **H2 Audit-lock vs routing-lock deadlock (40P01 reproduced).** `migrations/0006_audit.sql:155`, `0008_routing_failover.sql:610,612,664`. Tx1 `audit_append` then `routing_apply`; Tx2 `routing_apply` → deadlock. Fix: one structural order (e.g. `audit_append` takes the tenant row `FOR NO KEY UPDATE` before the audit lock, or `routing_apply` takes the audit lock first); retry wrapper for 40P01/40001 in `tenant_tx` for idempotent handlers; two-connection test.
- **H3 `OutboxMessage` accepts any topic for any event type.** `src/sibyl_control/core/outbox.py:65-74` (`EVENT_TOPICS` unused), no DB check (`migrations/0012_outbox.sql:21-23`). `policy_changed` under `graph` notifies `sibyl_outbox` not `sibyl_policy`. Fix: validate or derive topic from event type; DB CHECK optional.

## MEDIUM
- **M1 Canonicaliser key-order mismatch breaks the audit chain permanently.** DB `jcs` orders keys by code point (`migrations/0001_foundation.sql:70` COLLATE "C"), Python by UTF-16 (`sibyl_schemas/canonical.py:134`); `audit_append` only checks `canonical::jsonb = detail` (`0006_audit.sql:146`). Keys mixing U+E000–U+FFFF and astral chars → `audit_verify` content_mismatch forever (38/3000 fuzz). Also `1.0` vs `1` accepted then `jcs` raises at verify. Fix: recompute `sibyl.jcs(detail)` in `audit_append` and require byte equality (SB024); make SQL sort UTF-16 order or reject such keys at the API.
- **M2 8 KB limits enforced on jsonb binary size, not canonical size.** `0006_audit.sql:42,150`, `0012_outbox.sql:23`, `core/audit.py:49`, `core/outbox.py:71`. ~3.5 KB canonical fails table CHECK 23514 → client 4xx. Fix: one rule, `octet_length(sibyl.jcs(detail)) <= 8192` in the function raising SB023 before the table CHECK; kernel checks the same.
- **M3 UUID values in audit detail / outbox payload crash the writers.** `core/audit.py:162`, `core/outbox.py:104`. asyncpg jsonb codec can't serialise UUID → 500. Fix: pass `json.loads(canonical)` as the jsonb parameter; canonicalise once in `OutboxMessage.__post_init__`.
- **M4 Audit content-key denylist drifts.** `core/audit.py:29-31` (`input/output`) vs `0006_audit.sql:128`, `0007_telemetry.sql:85` (`input_messages/output_messages`); SQL top-level and case-sensitive, Python recursive and lowercased. Fix: one list in `sibyl_schemas` (union), drift test, case-fold in SQL.
- **M5 Idempotency token lacks fencing.** `core/idempotency.py:208-232,307-328`. After a stale reclaim, late `complete` by A overwrites B's record and serves A's response to B; late `abandon` expires B's live claim. Fix: `claim_id` generation column, fenced `complete`/`abandon`, zero rows = lost claim. Also `\u0000` in JSON body → 22P05 rolls back the business write; encode as base64.
- **M6 Tampered cursors 500.** `core/paging.py:61-71,88`. `["u",5]` → AttributeError, deep nesting → RecursionError, bool accepted as int, naive datetimes accepted; hash binds filters only. Fix: catch broadly → 400 `invalid_cursor`, reject bool, require tz-aware, cap length, bind route + sort + key signature, hash sorted collections.
- **M7 Worker DB-less forever, `/healthz` lies.** `worker/main.py:110-116,95-97`. Startup connect failure suppressed; crashed TaskGroup leaves healthz ok; `db.close()` skipped on raise. Fix: connect with retry/backoff or fail fast, log, healthz 503 when db missing / runner done / all loops failing; own `finally` for close; `serve()` tests.
- **M8 Partitions created once at migrate time; no DEFAULT partition; creation race.** `migrations/0015_partitions_initial.sql`, `0001_foundation.sql:539-573`, `0006_audit.sql:339-362`. Outbox insert at now()+9d fails; concurrent `partition_ensure` → 42P07. Fix: advisory lock in `partition_ensure*`; partitions loop is a G1 blocker (or DEFAULT partitions + horizon alert).

## LOW
- **L1** Outbox `idempotency_key` never dedupes (unique includes `created_at`). Document or dedupe by key.
- **L2** Worker backoff `min(interval*2**n, 300)` speeds up hourly loops; no per-tick timeout. Fix `max(interval, ...)` + `asyncio.wait_for`.
- **L3** `parse_json_strict` leaks OverflowError/ValueError/RecursionError (`sibyl_schemas/canonical.py:82-86`); will see untrusted input in SDK/gateway.
- **L4** Rate limiter LRU eviction resets exhausted buckets (`core/ratelimit.py:96-98`); `cost > capacity` permanently denied with misleading Retry-After.
- **L5** `SecretHandle.reveal()` after `zeroise()` returns `b""` (should raise); copies don't zeroise caller bytes; picklable; contract tables (`ERROR_MAP`, `FAIL_MODE_MATRIX`, `RETRY_AFTER_S`, `POLICIES`, `SQLSTATE_MAP`) mutable → `MappingProxyType`; `OutboxMessage.payload` mutable after validation.
- **L6** Role passwords via `ALTER ROLE ... PASSWORD %L` every `up` (logged under `log_statement=ddl`); `discover()` IndexError on empty file; `status()` ignores applied-but-missing; ledger `seq` cast outside SB060 handler; `erasure_execute_phase` doesn't lock the request row; `erasure_reapply_from_ledger` leaves `app.tenant_id` set; `migrate/jcs.py` is a second canonicaliser (against G0-1); `routing_apply` ~130 lines, `audit_append` ~85, `erasure_execute_phase` ~85.

## Reasoned only
- `command_timeout=30s` (`core/db.py:49`) will kill long worker phases (`audit_verify`, bulk erasure); use a worker pool with a longer timeout.
- `fingerprint()` hashes body only; if `route` excludes the query string, `?dry_run=true` and the plain call share a key.

## Verified clean
Idempotency claim race (8 concurrent → exactly 1 Fresh), `set_tenant` leakage across pooled connections, `outbox_read` horizon, ES6 number formatting, migrate runner lock/transaction handling.
