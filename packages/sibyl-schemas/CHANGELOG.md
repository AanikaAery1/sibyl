# Changelog

All notable changes to `sibyl-schemas` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the package uses Semantic
Versioning. Within a document major (`sibyl-event/1`, …) changes are additive only;
removing a field, tightening a required set or changing a type is a new major.

## [Unreleased]

Additive (wave 3B lane GAPS).

### Added
- `sibyl-event/1` `attrs_tool_call`: `action_effect` (`ToolActionEffect`: allow, block, held,
  approved, denied), `action_rule_id` (string ≤ 128) and `held_action_id` (uuid): the Action
  Gate outcome of a tool call. `ToolCallAttrs` gains the same optional fields; the wire schema
  is re-derived. Golden fixtures `valid/event_tool_call_action_gate.json`,
  `invalid/event_tool_call_unknown_action_effect.json`.
- `values.ToolActionEffect`.

## [1.1.0] - 2026-10-10

Additive. G0 integration (Step 7 wave 0): `sibyl_schemas.values` becomes the single source
for every catalogue the kernel, the OpenAPI generator and the database seeds share; drift
tests in `services/control` fail if any copy diverges.

### Added
- Audit taxonomy `AUDIT_ACTIONS` / `AUDIT_ACTION_NAMES` / `AuditActionSpec` (114 actions:
  domain, allowed actor types, resource type, required `detail` keys, reason-required,
  evidence, severity), including `erasure.cancelled`, `handoff.lock_extended`,
  `handoff.claim_released`, `credential.bundle_issued`, `tenant_key.rotated`; human actors on
  `handoff.created` and `approval.requested`; chair ruling G0-4 widening (`route.changed`,
  `failover.completed` accept system and human, `quarantine.applied` accepts policy; alert
  ack/label/silence require only `alert_id`).
- Actor value `api_key` on `ActorType` and `ActorKind`: a break-glass `killswitch.pulled` is
  attributed to the key (`actor_key_id`), never to `system`; it is the only action that
  accepts it.
- State-machine edges `STATE_EDGES` (`StateEdge`, `StateMachine`, `ROUTING_AUTOMATED_EDGES`,
  `ANY_TRIGGER`) for all nine machines, with chair ruling G0-3 (`undo` inverse of every
  automated routing edge, operator self-edges for `clear_hold`, `failed_over` and
  `failing_back` self-edges) and the R63 erasure `restore` edges.
- Problem registry is now the superset of the kernel's and the schemas' codes:
  `invalid_cursor`, `forbidden`, `agent_binding_violation`, `conflict`,
  `unsupported_media_type`, `expires_at_out_of_range`, `reference_unknown`, `stream_limit`,
  `tenant_rate_limit`, `ingest_saturated`, `not_implemented`, `database_unavailable`,
  `serialization_failure`, `database_timeout`, and the new `erasure_blocked_by_chain` (409).
  `PROBLEM_TITLE`, `problem_statuses()`.
- Database error map (chair ruling G0-1): `DB_ERROR_PROBLEM` (every `sibyl:<code>` the
  migrations raise, SQLSTATE class `SB`, mapped to a problem code), `DB_ERROR_PREFIX`,
  `DB_ERROR_SQLSTATE_CLASS`, `parse_db_error_code()`.
- Scope projections `STEP_UP_SCOPES`, `MACHINE_ONLY_SCOPES`, `BREAK_GLASS_SCOPE`.
- Rate policies `RATE_POLICY_SPECS` / `RatePolicySpec` for every API §2.8 policy;
  `RATE_POLICIES` now lists all of them (same `(requests, window_s)` shape).
- `ApiKeyStatus.EXPIRED` (matches the database and API.md); `AnchorKind` (six values, as
  `audit_anchors.kind`).

### G0 fix pass (lane FIX-SCH, same 1.1.0 release; `CONTRACT_TAG = "contracts-v1.1.0"`, ruling G0-9)

#### Security
- **Scrubber ReDoS (security H4).** Every `detectors/v1` pattern is now linear by construction
  and stays ECMAScript-portable (no possessive or atomic groups): bounded runs where more
  pattern follows, run starts anchored by lookbehind, URL userinfo cannot cross `://`, PEM
  bodies cannot contain `-----`. The engine scans in 64 KiB windows with 16 KiB overlap and
  refuses strings over `MAX_SCRUB_CHARS` (16 Mi chars) with `ScrubInputTooLarge` rather
  than passing them through. Review inputs: 700 KB of PEM headers 91.3 s → 0.16 s;
  `a.`×100k 56.2 s → 0.04 s; `postgres://`×20k 22.9 s → 0.09 s. CI timing tests hold every
  detector under 200 ms per MiB of adversarial input and a whole scrub under 6 s per MiB
  (worst case: eight live decoded views).
- **Scrubber bypasses (G0 tests F7, security L4/L5).** Detectors run on decoded views as well
  as the raw text: JSON unescape (up to three levels: tool-call `arguments`), UTF-8 percent
  decoding (up to two), and format-character stripping plus fullwidth folding (zero-width
  splits, `ｓｋ-…`). Base64 runs whose UTF-8 text holds a secret are replaced whole (one
  nested level). Spans map back to whole escape sequences, so scrubbed JSON stays valid JSON,
  and the token hashes the decoded secret (same token in every encoding). Truncated PEM
  blocks (no END line) are caught; DSN and URL passwords may contain `/` and `@`; a lookalike
  `[SECRET:…]` token no longer shields the rest of a candidate. New detectors:
  `gitlab_token`, `huggingface_token`, `slack_webhook`, `google_api_key`,
  `basic_auth_header` (23 in all); `generic_secret_kv` adds `pwd`/`passphrase` and ignores
  filesystem paths (`kv_value` validator); `sibyl_key` matches after `_`; `high_entropy` skips
  data-URI payloads, SRI hashes and percent-encoded fragments. Quoted multi-word passphrases
  stay out of scope (recorded as a strict xfail).
- **`scrub_json` scrubs keys, `bytes` and `bytearray` (security M7).** Colliding scrubbed keys
  get a `#2`, `#3`, … suffix; bytes are decoded with `surrogateescape` so non-UTF-8 bytes
  round-trip; `SecretsScrubber.scrub_bytes()` added. `Finding.via` names the view that found it.
- **Strict JSON (security M5, code review L3).** `parse_json_strict` rejects duplicate members
  at any depth, caps size (`DEFAULT_MAX_JSON_BYTES`, 4 MiB) and depth
  (`DEFAULT_MAX_JSON_DEPTH`, 64), rejects lone surrogates and integers beyond the double
  range, and raises every parser failure (`ValueError`, `OverflowError`, `RecursionError`) as
  `CanonicalizationError`.
- **Snapshot envelope (security M5).** `SignedPolicySnapshot`/`SigningKeySet`
  `model_validate_json` go through `parse_json_strict`; `parse_signed_snapshot()` and
  `parse_signing_key_set()` added. New vectors `kid_mismatch` (`unknown_kid`) and
  `duplicate_body_unkill` (`malformed`); `SnapshotRejectCause.MALFORMED` comes first.
- **Signed key set (security M6).** `$defs/key_set` is now `{kid, alg, sig, body}` with
  `$defs/key_set_body` `{sequence, issued_at, keys, next_key}`: each set is signed by an active
  key of the previously accepted set, `next_key` is inside the signature, and verifiers pin the
  first key and follow rotations (`KeySetRejectCause`: malformed, unknown_signer,
  signer_expired, bad_signature, non_monotonic, chain_broken). Ed25519 vectors in
  `fixtures/snapshot/key_set_vectors.json` (valid rotation, broken chain, unsigned next_key,
  retired signer, replay, expired signer, legacy unsigned shape, duplicate body), regenerated
  deterministically by `tests/test_key_set_chain.py`. **Breaking for 1.0 key-set readers**
  (none ship yet): the unsigned `{keys, next_key}` shape is refused.

- **Upstream `base_url` is `^https://` only** (security H3, schema and model). Dev doubles
  are admitted only through the database `base_url_dev_host` allowlist, never by the schema;
  the fixture dev double moved to `https://127.0.0.1:18082/v1` and every envelope vector was
  re-signed with the test seeds. New invalid fixture `snapshot_http_base_url.json`.

#### Registries
- `AUDIT_CONTENT_KEYS`: lowercased union of the kernel and database content-key lists
  (`prompt`, `completion`, `messages`, `body`, `content`, `headers`, `input`, `output`,
  `input_messages`, `output_messages`) for FIX-DB and FIX-KER (code review M4).
- Problem codes `idempotent_replay_unavailable` (409, ruling G0-8), `erasure_not_approved`
  (409), `key_field_immutable` (409); `idempotency_key_reuse` (422) and `invalid_cursor` (400)
  confirmed. `DB_ERROR_PROBLEM` maps the database codes `idempotency_key_reuse`,
  `erasure_not_approved`, `key_field_immutable` to the same-named problems and
  `ledger_invalid` (SB061) to `internal_error`; the duplicate `erasure_ledger_invalid` is gone.
- Ruling G0-5: `access_denied` removed; `forbidden` is the single plain-403 code.
- Audit taxonomy: `access.denied` accepts `system`, `human` and `api_key` (ruling G0-11);
  every action that allows `agent` now also allows `api_key` (G0-6 follow-on:
  `asset.created`, `asset.updated`, `handoff.created`, `credential.bundle_issued`).
- `golden.scrub_corpus(kind, variants=True)`: the scrub corpus (133 secrets, at least 5 base rows
  per detector; 68 benign) plus deterministic variants (JSON-escaped, double JSON, URL-encoded,
  base64-wrapped, CRLF in prose): 798 secret rows, at least 10 per detector, and 382 benign.
- `PROFILE_HASH` changes (detectors and the new `pipeline` section are hashed);
  `detectors.v1.json` regenerated.

## [1.0.0] - 2026-10-10

Frozen wire contract for `contracts-v1.0.0` (Step 7, wave 0, lane W0-SCH).

### Added
- `sibyl_schemas.values`: every frozen value set as `StrEnum`/`IntEnum` (DATAMODEL §4.0
  plus Step 3-5 wire enums), the R25 incident-action vocabulary, R58 outbox topics
  (12 coarse topics on the `sibyl_policy` / `sibyl_outbox` NOTIFY channels) with the SSE
  event map, rule ids including R6-R9 and L6-L7, RFC 9457 problem codes with HTTP status,
  gateway error codes, and the 38-scope `<resource>:<verb>` catalogue with the
  seven-role mapping and API-key shape rules (`killswitch:pull` exclusive).
- Tenant-key routes frozen by the chair (security-auditor §3.4): scope `keys:read`
  (owner, security_admin; tenant-wide, no step-up, not key-grantable), value sets
  `TenantKeyPurpose` and `TenantKeyState`, `TENANT_KEY_ROUTES` (`GET /api/v1/tenant-keys`
  unaudited; `POST /api/v1/tenant-keys/{purpose}/rotate` with `keys:rotate`, step-up,
  idempotent, rate policy `tenant_key_rotate` 6/h, audit `tenant_key.rotated`).
- JSON Schema 2020-12 documents: `sibyl-event/1`, `sibyl-event-wire/1` (derived,
  `payload_inline`, batch body), `sibyl-health/1`, `sibyl-handoff/1`, `sibyl-checkpoint/1`,
  `sibyl.policy_snapshot/1` (body, detached-signature envelope, key set),
  `sibyl-ingest-response/1`, `sibyl-feature-snapshot/1`, `sibyl-label/1`; every `enum`
  is tagged `x-sibyl-enum` with its value set. Registry-backed loader and validator
  (`sibyl_schemas.jsonschema`) asserting strict RFC 3339 `date-time`.
- Pydantic v2 models (`sibyl_schemas.models`) that accept and reject exactly what the
  hand-written schemas do, proved over the golden corpus three ways (schema, model,
  model-exported schema).
- `sibyl_schemas.canonical`: RFC 8785 JCS with the RFC Appendix B number vectors and the
  §3.2 document vectors; optional float ban for audit `detail`.
- `sibyl_schemas.scrub`: unconditional `secrets_only` scrubber, detector registry
  `detectors/v1` (18 detectors), salted `[{kind}:{hash8}]` replacement, idempotent,
  `PROFILE_HASH` = sha256(JCS(detectors ‖ replacement_format)), ECMAScript-portable
  `detectors.v1.json` for the TypeScript SDK.
- Golden fixtures with manifests (`fixtures/{ingest,health,handoff,checkpoint,snapshot}`),
  Ed25519 snapshot test vectors for every verification cause, JCS vectors, and the scrub
  corpora (65 synthetic secrets, 42 false positives); `sibyl_schemas.golden` exposes them
  to consuming lanes and the wheel bundles them as `sibyl_schemas/_fixtures`.

### Changed (relative to the Step 3/4 drafts)
- All `vigil*` identifiers renamed to `sibyl*` (D19); handoff packet is `sibyl-handoff/1`.
- `sibyl-event/1`: `agent_id` nullable only for `provider.status` and `observation.gap`;
  `redaction_profile` gains `profile_hash`, `emitter_profile_hash`, `late_hits`;
  `payload_ref` gains `truncated`, `bytes_original`; `gen_ai.request` attrs gain
  `policy_sdk_version`, `cost_unpriced`, `capture_override_rejected`; `ingest` gains
  `sdk_version`; `policy.decision` action gains `tool_blocked`.
- `sibyl-health/1` and `sibyl-feature-snapshot/1`: `routing_state` and `provider_status`
  constrained to their value sets; feature-grain keys now typed `number|null` (the draft's
  `{}` placeholders accepted any type).
