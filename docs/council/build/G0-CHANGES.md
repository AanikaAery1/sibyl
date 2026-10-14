# G0 fix pass: interface changes wave 1 lanes must adopt (main @ 9cd6f7e)

Wave 1 worktrees branched before this commit. Read the real code in the **main checkout** (the repository root) read-only; the chair reconciles your lane at merge.

## Kernel (`services/control/src/sibyl_control/core`, `api/deps.py`)
- **Idempotency:** `fingerprint(body, *, method=, path=, query=)`; `begin`/`begin_or_raise` require `principal_kind=` (helpers `deps.idempotency_fingerprint(request, body)`, `deps.idempotency_principal_kind(principal)`); claims fenced by `claim_id` (`IdempotencyClaimLost` → 409); new `ReplayUnavailable` outcome (409 `idempotent_replay_unavailable`, bodies > 64 KB); `abandon()` returns bool.
- **Paging:** `encode_cursor` / `decode_cursor` / `paginate` require `route=` and `sort=`; malformed cursor → 400 `invalid_cursor`.
- **Outbox:** `OutboxMessage` validates topic against event type; prefer `OutboxMessage.for_event()`; payload ≤ 8 KB compact JSON.
- **Object rules fail closed:** evaluate every declared rule through `ctx` (`check`, `group_filter`, `agent_filter`, `self_filter`, `check_self`, `object_rule_checked`); call `ctx.step_up_if(...)` on conditional routes; pass `step_up_required=` to conditional actions; otherwise the middleware turns your 2xx into a 500.
- **Audit:** `audit_actor(principal)` → every API key is actor kind `api_key` with its key id; `access.denied` records the attempting principal (G0-11); astral (non-BMP) object keys refused in detail/payloads; content keys from `sibyl_schemas.values.AUDIT_CONTENT_KEYS`.
- **DB retry:** `retry_transient` / `Database.run_in_tenant_tx` retry 40P01/40001 for idempotent handlers.
- **Client IP:** `deps.client_ip(request)` (honours `SIBYL_TRUSTED_PROXIES`); invalid credentials throttled per IP before lookup.
- **Settings:** `Settings.require_secrets(process)` per process (`api`, `ingest`, `worker`, `gateway`); ingest entrypoints must call `require_secrets("ingest")`.
- **Worker:** unimplemented loops idle; `LoopSpec.timeout_s` per tick; worker pool has a 900 s command timeout.
- **Secrets:** `SecretHandle.reveal()` raises after `zeroise()`; contract tables are read-only `MappingProxyType`.

## Database (`services/control/migrations`)
- Call `sibyl.audit_lock(tenant)` **first** in any transaction that appends audit after taking other row locks.
- `routing_apply(..., p_actor_key_id uuid DEFAULT NULL)`; idempotency key reuse with different agent/state/trigger → SB015 `idempotency_key_reuse` (422).
- `api_key` fields immutable after insert (SB044 `key_field_immutable`); rotation creates a new row; lifetime ≤ 400 days.
- `idempotency_record.claim_id`, `response_body_sha256`; `failover.actor_key_id`.
- Erasure: approval guard (SB035 `erasure_not_approved`), legal holds checked in every phase (`hold_blocked`), tombstoned steps for retired chains (G0-7), `sibyl.pseudonymise()` for user identifiers.
- `audit_verify` kinds now include `truncated`, `anchor_mismatch`, `head_mismatch`.
- `sibyl.partition_horizon()` for the partitions loop; `base_url_dev_host` table (writable only by `sibyl_migrate`) for sim doubles; `is_allowlisted_base_url` is strict, https only.
- 67 tenant tables (new `audit_chain_head`, `tenant_pseudonym_key`), 12 allowlisted (`base_url_dev_host`).

## Schemas 1.1.0 (`packages/sibyl-schemas`)
- Scrubber: 23 detectors over decoded views (JSON-escaped, percent-encoded, base64, format characters), `scrub_bytes()`, dict keys scrubbed, `ScrubInputTooLarge` above 16 Mi chars; `PROFILE_HASH` and `detectors.v1.json` changed.
- Strict JSON: `parse_json_strict` rejects duplicate keys, caps size/depth; `parse_signed_snapshot()`, `parse_signing_key_set()`; key sets are a signed rotation chain (`{kid, alg, sig, body{sequence, issued_at, keys, next_key}}`).
- Snapshot `base_url` must be `https://`; dev doubles at `https://127.0.0.1:18082/v1` in fixtures.
- New problems: `idempotency_key_reuse` (422), `idempotent_replay_unavailable`, `erasure_not_approved`, `key_field_immutable` (409); `access_denied` removed (`forbidden` is the plain 403).
