# Security Auditor: API + SDK (Step 4) — scopes, authn, per-route authz, threat model, scrub contract

Product: Sibyl (D19) · 2026-10-10 · Inputs: `api/CHAIR-INITIAL.md` (followed), `DECISIONS.md` D1–D29 (D11 credentials, D12 capture, D17 erasure, D20 break-glass, D21 hold, D22 fail_safe, D26 backups, D27 audit retention), `architect/ARCHITECTURE.md` (ADR-7/8/9/10/12), `datamodel/security-auditor.md` (my Step 3 RBAC §6 and taxonomy §3, carried forward verbatim unless amended here), `datamodel/DATAMODEL.md` §4.1/§4.7/§4.8, `datamodel/CHAIR-RULINGS.md` R12/R13.

The backend-architect and ai-engineer route tables were not available while this was written. The route families below are derived from CHAIR-INITIAL §2 and the DATAMODEL entities; where their tables name a route differently, the authz row still applies to the route that performs the same state change. §9 lists what the chair must reconcile.

Rename applied throughout (D19): `vigil-event/1` → `sibyl-event/1`, `X-Vigil-*` → `X-Sibyl-*`, `vgl_` key prefix → `sbl_`, `vigil_app`/`vigil_ingest`/… → `sibyl_app`/`sibyl_ingest`/…, `VIGIL_*` env → `SIBYL_*`, `vigil-schemas` → `sibyl-schemas`, `vigil.*` OTel attributes → `sibyl.*`.

Phase 1 only. No `/v1/messages`, no notification routes, no ML routes beyond `GET …/health` and `GET …/risk`.

---

## 1. Scope catalogue

One grammar for both principal kinds: `<resource>:<verb>`. An OIDC principal's scopes are **derived live** from `role_permission` on every request (membership is never cached in the session, Step 3 §2.4). An API-key principal's scopes are the `api_key.scopes[]` column, fixed at creation, narrowable on rotation, never widenable in place. `authorize()` is deny-by-default and evaluates `(scope ∈ principal.scopes) ∧ object_rule ∧ step_up_rule`.

The Step 3 machine scope names are renamed to fit the grammar. The database column keeps the new names; migration 1 seeds them. Mapping for the chair:

| Step 3 name | Step 4 scope | Note |
|---|---|---|
| `telemetry:write` | `ingest:write` | OTLP + `/v1/events` + checkpoints |
| `gateway:proxy` | `gateway:proxy` | unchanged |
| `route:read` | `routing:read` | SDK `resolve_route()` |
| `handoff:write` | `handoff:write` | SDK packets (distinct from `ingest:write` because packets carry agent state) |
| `registry:read` / `registry:write` | `agents:read` / `agents:write` | bound-agent only for agent-bound keys |
| `killswitch:pull` | `killswitch:pull` | break-glass (D20); exclusive, see §2.4 |

### 1.1 Catalogue

Legend: ✓ tenant-wide · G within the membership's `agent_group` · A allowed and itself audited · S step-up (fresh IdP auth ≤ 5 min) · ✗ no · M = grantable to an API key.

| Scope | Covers (Step 3 permission) | owner | admin | security_admin | engineer | operator | auditor | viewer | M |
|---|---|---|---|---|---|---|---|---|---|
| `tenant:read` | tenant.settings.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `tenant:write` | tenant.settings.write, tenant.delete | ✓S | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | |
| `users:manage` | users.manage, membership.manage | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | |
| `oidc:manage` | oidc_issuer.manage | ✓S | ✓S | ✗ | ✗ | ✗ | ✗ | ✗ | |
| `apikeys:manage` | api_key.manage (tenant-level) | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | |
| `apikeys:manage_agent` | api_key.manage (agent-bound) | ✓ | ✓ | ✗ | G | ✗ | ✗ | ✗ | |
| `agents:read` | agent.read (metadata, health, risk, graph) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | M |
| `agents:write` | agent.register, agent.edit, versions, BOM | ✓ | ✓ | ✗ | G | ✗ | ✗ | ✗ | M (bound agent) |
| `agents:approve` | agent.approve_lifecycle | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | |
| `identity:write` | agent_identity.edit | ✓ | ✓ | ✓ | G (narrow only) | ✗ | ✗ | ✗ | |
| `capture:write` | capture_policy.set, redaction.manage | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | |
| `credentials:manage` | credential.manage (fallback targets) | ✓S | ✓S | ✓S | ✗ | ✗ | ✗ | ✗ | |
| `credentials:read` | credential.read_metadata | ✓ | ✓ | ✓ | G | ✗ | ✓ | ✗ | |
| `keys:rotate` | tenant_key.rotate | ✓S | ✗ | ✓S | ✗ | ✗ | ✗ | ✗ | |
| `routing:read` | routing state, continuity plan, chain read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | M |
| `routing:write` | continuity_plan, fallback_chain draft/approve | ✓ | ✓ | ✓ | G | ✗ | ✗ | ✗ | |
| `incidents:act` | base scope for `POST …/actions` | ✓ | ✗ | ✓ | G | ✓ (queue/alert actions only) | ✗ | ✗ | |
| `routing:override` | action ∈ {failover, undo, release} | ✓ | ✗ | ✓ | G | ✗ | ✗ | ✗ | |
| `approvals:decide` | action ∈ {approve, deny} | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | |
| `quarantine:act` | action ∈ {quarantine, unquarantine} | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | |
| `killswitch:pull` | action = kill; break-glass route | ✓S | ✗ | ✓S | ✗ | ✗ | ✗ | ✗ | M (exclusive) |
| `killswitch:release` | action = release_kill | ✓S | ✗ | ✓S | ✗ | ✗ | ✗ | ✗ | |
| `queue:act` | queue.claim / complete / return | ✓ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | |
| `packets:read` | packet.read incl. agent content | ✓ | ✗ | ✓ | G | ✓ | A | ✗ | |
| `payloads:read` | payload.read (own agents' traces) | ✓ | ✗ | ✓ | G | ✗ | A | ✗ | |
| `payloads:reveal` | payload.reveal (any payload, console) | ✓A | ✗ | ✓A | ✗ | ✗ | A | ✗ | |
| `alerts:act` | alert.ack / verdict / silence | ✓ | ✗ | ✓ | G | ✓ | ✗ | ✗ | |
| `audit:read` | audit.read | ✓ | ✓ | ✓ | G | ✗ | ✓ | ✗ | |
| `audit:verify` | audit.verify | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ | ✗ | |
| `audit:export` | audit.export | ✓A | ✗ | ✓A | ✗ | ✗ | A | ✗ | |
| `data:export` | data.export | ✓A | ✗ | ✓A | ✗ | ✗ | A | ✗ | |
| `erasure:request` | erasure.request | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | |
| `erasure:approve` | erasure.approve | ✓S | ✗ | ✓S (≠ requester) | ✗ | ✗ | ✗ | ✗ | |
| `holds:manage` | hold.place / hold.release | ✓S | ✗ | ✓S | ✗ | ✗ | ✗ | ✗ | |
| `gateway:proxy` | data-plane calls | — | — | — | — | — | — | — | M only |
| `ingest:write` | OTLP, `/v1/events`, checkpoints | — | — | — | — | — | — | — | M only |
| `handoff:write` | SDK handoff packets | — | — | — | — | — | — | — | M only |
| `gateway:snapshot` | fetch snapshot/stream, post acks | — | — | — | — | — | — | — | platform credential, §2.3 |

Rules that are part of the contract:

1. `role_permission` is the single source; this table is the human-readable projection. CI diffs them (Step 3 test 2). Every route in every OpenAPI document declares `x-sibyl-scope` (one scope or an action-indexed map) and `x-sibyl-audit` (event type or `none`); an undeclared route fails the authz test.
2. `incidents:act` is necessary but not sufficient for `POST …/actions`: the action enum selects a second scope (§3.4). A principal with `incidents:act` alone can perform no action.
3. Machine-grantable scopes (M) are the only values accepted by `POST /api/v1/api-keys`. A request asking for a human-only scope is 400 `invalid_scope`, never silently dropped.
4. `killswitch:pull` on an API key is exclusive: `scopes = {killswitch:pull}` exactly, `agent_id IS NULL`, `env = 'live'` (CHECK in migration 1).
5. G (group-scoped) is an object rule, not a scope: the resource's `agent.agent_group_id` must be in the set of groups of the caller's active memberships for that role. Resources with no agent (tenant settings, audit of tenant actions) are never G-visible.
6. A-marked scopes always emit their own audit row (`data.revealed`, `audit.exported`, `data.exported`) in addition to any route audit.

---

## 2. Authentication model

### 2.1 Humans: OIDC bearer (dex in dev/demo, tenant IdP in production)

Sibyl is a relying party only (ADR-8). Two human transports:

| Transport | Used by | Credential | Lifetime | Notes |
|---|---|---|---|---|
| Server-side session cookie | console (Next.js BFF) | `__Host-sibyl_session`, 256-bit random, `Secure; HttpOnly; SameSite=Lax; Path=/` | absolute 8 h, idle 30 min | `session.token_hash = sha256(value)`; the cookie never reaches api directly, the BFF forwards `Authorization: Bearer sibyl_sess_<value>` server-to-server |
| OIDC access token | CLI, scripts, console BFF to api | `Authorization: Bearer <JWT>` from the tenant's issuer, `aud = sibyl-api`, `azp` = registered client | ≤ 1 h | api validates `iss` against `oidc_issuer` **for the tenant named by the request** (slug in host or `X-Sibyl-Tenant`), never issuer-first, so a shared issuer (dex) cannot cross tenants |

Login flow: `GET /auth/{tenant_slug}/login` → authorization code + PKCE → `GET /auth/callback` (state bound to a `__Host-sibyl_oidc_state` cookie, 10 min) → `app_user` upsert by `(tenant, issuer, sub)` → JIT provisioning only if `oidc_issuer.jit_default_role` is set and `email_verified` and domain ∈ `allowed_email_domains` → `session` row → `access.login` audit. Logout revokes the session row and emits `access.logout`. `access.login_failed` on every rejected callback with `cause`, `ip_hash`.

Step-up (S): `POST /auth/step-up` re-runs the code flow with `prompt=login max_age=0`; on success sets `session.step_up_at`. S-marked routes return 403 `step_up_required` (problem type `urn:sibyl:problem:step-up-required`) when `step_up_at` is NULL or older than 5 min, and record `actor_session_id` in the audit row. Step-up is per session, never per token.

CSRF: the BFF accepts state-changing requests only when `Origin` (or `Sec-Fetch-Site`) matches the console origin and the request carries `X-Sibyl-CSRF` equal to the session's CSRF token. api itself is bearer-only and ignores cookies, so api needs no CSRF defence.

### 2.2 Machines: tenant API keys

Format `sbl_<env>_<prefix12>_<secret>` where `env ∈ {live, test}`, `prefix12` is 12 base62 chars (global UK, lookup key), `secret` is 32 random bytes base64url (43 chars). Total 65 chars; regex `^sbl_(live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}$` is published so secret scanners (GitHub, gitleaks, Semgrep) can fingerprint it.

| Property | Contract |
|---|---|
| Storage | `secret_hash = HMAC-SHA-256(SIBYL_KEY_PEPPER, secret)` (R12). Plaintext shown once in the `201` response; never retrievable. |
| Lookup | `api_key_lookup(prefix)` SECURITY DEFINER returning `(tenant_id, id, secret_hash, scopes, agent_id, status, expires_at, rotation_grace_until)`: the only read that happens before `set_tenant()`, because the tenant is not yet known. Owner `sibyl_audit`; EXECUTE to `sibyl_app`, `sibyl_ingest`. |
| Verification | Constant-time compare on ingest/api; the gateway verifies against the `prefix → secret_hash` map inside the signed snapshot, never calls api on the hot path. |
| Scopes | ⊆ M set (§1.1), fixed at creation. Rotation may narrow. |
| Binding | `agent_id` set → key may only act as that agent; `X-Sibyl-Agent` may narrow a tenant-level key to one agent of that tenant, never widen (R13). Mismatch → 403 `agent_binding_violation`, audited `access.denied`. |
| Expiry | `expires_at` mandatory; default 365 d, max 400 d (aligns with `revoked-400d` retention); console warns at 30 d; expired keys are 401 `key_expired` and emit `api_key.expired` once. |
| Rotation | `POST /api/v1/api-keys/{id}/rotate {grace_s ≤ 86400}` → new row with `rotated_from_id`, old row `status = rotating`, `rotation_grace_until`; both verify until then; the snapshot carries both hashes. Audited `api_key.rotated`. |
| Revocation | `DELETE /api/v1/api-keys/{id} {reason}` → `status = revoked`, `outbox(policy_changed)` in the same transaction so the gateway drops the key within the snapshot SLO (< 2 s target). Audited `api_key.revoked`. |
| Last used | `last_used_at`, `last_used_ip_hash` written by ingest/api at most once per minute per key; exposed read-only in `GET /api/v1/api-keys`. Gateway use reaches the column through its own telemetry (`sibyl.api_key_id` attribute), not a direct write. |
| Anomaly | worker emits `api_key.anomaly` when the IP class (hash of /24 or /48) changes within one hour; informational in Phase 1. |
| Transport | `Authorization: Bearer sbl_…` only. Query-string keys are rejected 400 `credential_in_url` and never logged. |
| Test keys | `env = test` keys are refused by `live` gateways and ingest (`401 env_mismatch`) and vice versa; demo tenants (D29) carry test keys. |

### 2.3 Gateway credentials: passthrough, vaulted fallback, platform identity (D11, ADR-10)

**Primary call, passthrough.** The caller's provider credential arrives in `Authorization` (or `x-api-key` for the Anthropic dialect). The gateway authenticates the caller with the `sbl_` key carried in `X-Sibyl-Key` (preferred) or, when `Authorization` holds an `sbl_` key and the provider credential is absent, treats it as a Sibyl-only call that must use a vaulted credential. Contract:

1. `Authorization` destined for the provider is forwarded byte-for-byte to the resolved `base_url` and to nothing else. It is never placed in a span attribute, a payload object, a log line, a metric label or an error body (Step 3 `header_allowlist` CHECK; test 3 canaries).
2. All `X-Sibyl-*` request headers are stripped before forwarding. `traceparent` is forwarded unchanged.
3. Provider response headers are relayed except `Set-Cookie` and any header the dialect adapter marks internal.
4. If the primary route fails and the chosen fallback step has `credential_id`, the gateway substitutes the vaulted secret for that one upstream request only; the client's credential is never sent to the fallback provider. If the step has no `credential_id` and the fallback provider differs from the primary, the step is skipped (never "try the client's key elsewhere").

**Vaulted fallback credentials.** api decrypts `provider_credential.ciphertext` under the tenant `credential` DEK and ships the bundle to the gateway inside the snapshot delivery: `bundle = sealed_box(X25519 gateway public key, AES-256-GCM(secret, AAD = tenant_id ‖ credential_id ‖ key_version ‖ snapshot_version))`. The gateway holds plaintexts in memory ≤ 300 s, keyed by `(credential_id, key_version)`, re-fetched with each snapshot, zeroised on snapshot expiry or process exit, never spilled to disk (the telemetry disk spill is a separate queue that never contains credentials). `base_url` is read from the credential row, never from the request.

**Platform identity (`gateway:snapshot`).** In Phase 1 the gateway is Sibyl-hosted and multi-tenant (one snapshot carries `tenant_versions`), so it cannot authenticate with a tenant key. It uses a platform credential `SIBYL_GATEWAY_TOKEN` (32 random bytes, HMAC-hashed in api config, rotated by the operator CLI with overlap) presented as `Authorization: Bearer sbl_gw_<token>` on `GET /v1/policy/snapshot`, `GET /v1/policy/stream`, `GET /v1/policy/keys`, `POST /v1/policy/acks`. The Phase 2 sidecar instead presents a tenant-level `sbl_` key with scope `gateway:snapshot` and receives a tenant-filtered snapshot. Open question Q1.

### 2.4 Signed policy snapshot: verification contract

```
GET /v1/policy/snapshot          If-None-Match: "<version>"
200 application/json
  ETag: "<version>"
  X-Sibyl-Snapshot-Kid: snap-2026-10-v1
  X-Sibyl-Snapshot-Signature: base64url(Ed25519(JCS(body)))
  body: { version, issued_at, expires_at (issued + 60 s), grace_s: 300, kid,
          tenants: { <tenant_id>: { routing_version, agents: {...}, keys: {prefix: secret_hash}, ... } },
          credential_bundle_ref }
```

Gateway verification order, each failure → refuse the snapshot, keep the held one, emit `snapshot.rejected` with `cause`:

1. `kid` ∈ the pinned key set fetched from `GET /v1/policy/keys` at startup and refreshed hourly; the set is itself signed by the previous active key during `retiring` overlap. Unknown `kid` → `cause = unknown_kid`.
2. Signature verifies over the RFC 8785 canonical form computed by `sibyl-schemas`. `cause = bad_signature`.
3. `version > held_version` (strictly). Equal or lower → `cause = non_monotonic`.
4. `issued_at ≤ now + 30 s` (clock skew bound). `cause = future_issued`.
5. `expires_at`, `grace_s` within `[60, 600]` and `[0, 900]`. `cause = bad_ttl`.

Behaviour on staleness is ADR-9 and unchanged: `fresh` → normal; `stale` (past `expires_at`, within grace) → serve with `sibyl.policy_state=stale`; `expired` → fail-open agents proceed with `stale_bypass` audit, fail-closed agents 503 `X-Sibyl-Reason: policy-expired`, killed agents stay killed; no snapshot ever loaded → refuse all traffic 503 `X-Sibyl-Reason: no-policy` and emit `policy.no_snapshot_refusal` on reconnect.

### 2.5 Break-glass key (D20): one route, hard limits, forced anchor

Exactly one route accepts an API key holding `killswitch:pull`:

```
POST /api/v1/killswitch
Authorization: Bearer sbl_live_<prefix12>_<secret>       (scopes = {killswitch:pull} exactly)
Idempotency-Key: <uuid>
{ "scope_kind": "tenant" | "agent" | "provider", "scope_id": "<uuid>|null", "reason": "<≥ 20 chars>" }
→ 201 { kill_switch_id, routing_version, affected_agents, audit_receipt }
→ 409 already_pulled · 429 break_glass_rate_limited · 403 (any other key or any OIDC principal without S)
```

Contract:

| Rule | Value |
|---|---|
| Who may create such a key | `apikeys:manage` **and** `killswitch:pull` (owner or security_admin with step-up); creation audited `api_key.created` with `scopes = [killswitch:pull]` at severity **warning** |
| Key shape | tenant-level, `env = live`, exclusive scope, `expires_at ≤ 400 d`, at most **2** active per tenant (partial UK on `tenant_id WHERE 'killswitch:pull' = ANY(scopes) AND status = 'active'` plus count trigger) |
| What it can do | pull only. It cannot release, cannot read, cannot list. `scope_kind = tenant` is permitted (that is the point of break-glass). |
| What it cannot do | every other route returns 403 `break_glass_key_misuse` and emits `access.denied`; three misuses within 10 min set `status = revoked` with `revoke_reason = misuse` and emit `api_key.revoked` (critical) |
| Rate limit | 3 requests / 10 min per key; 6 / h per tenant across break-glass keys; limits are counted on attempts, not successes, and a 429 is itself audited `access.break_glass` with `action_taken = rate_limited` |
| Transaction | `kill_switch` insert, one `routing_apply(trigger='operator', to_state='killed', actor_kind='system')` per affected agent, `audit_append('access.break_glass', severity critical, detail {api_key_id, action_taken, scope_kind, scope_id, ip_hash})`, `audit_append('killswitch.pulled', actor_type='system', actor_key_id)` per agent — one transaction |
| Mandatory anchor | the handler enqueues `outbox('audit.anchor_now')`; the worker writes `audit_anchors(kind = 'break_glass')` within 10 s, independent of the hourly cadence, and copies it to BlobStore `external_ref`. **Taxonomy amendment:** `audit_anchors.kind` gains `break_glass`. |
| Release | only a human with `killswitch:release` + step-up via `POST …/actions {action: release_kill}`; the release detail records `pulled_via = break_glass`. |
| IdP-down proof | the route performs no OIDC call and no membership read: key lookup, HMAC, scope check, transaction. The authz test runs it with dex stopped. |
| Observability | every call also emits a `policy.decision` event so the console banner "kill switch pulled via break-glass" lights without an audit query. |

---

## 3. Per-route authorization

### 3.1 Tenant isolation mechanism (applies to every route)

1. **Principal resolution** happens before any tenant-scoped read: OIDC → `(tenant_id from slug/claim, user_id)` with a live `membership` read; API key → `api_key_lookup(prefix)`; platform credential → no tenant.
2. The handler opens one transaction and its **first statement is `SELECT set_tenant($tenant_id)`** (transaction-local; `current_tenant()` is NULL otherwise and every RLS policy fails closed, ADR-7). Connection poolers run in transaction mode; a session-level `SET` is forbidden and detected by the pooler test.
3. Path ids are **never** trusted to select the tenant: `/api/v1/agents/{id}` under tenant A with an id from tenant B returns 404 (RLS yields zero rows), never 403, so existence does not leak across tenants.
4. Multi-tenant platform routes (`/v1/policy/*`) run as `sibyl_app` iterating tenants with one `set_tenant()` per tenant transaction; the snapshot is assembled per tenant and concatenated, never from a cross-tenant query.
5. Ingest batches are grouped by key → tenant; a single HTTP request can never span tenants (one key, one tenant). A batch whose events name an agent of another tenant is rejected per event (`events_rejected('agent_not_found')`).
6. `X-Sibyl-Tenant` is accepted only to **select among the caller's own memberships** (a human in two tenants) and only for OIDC principals; it is ignored for API keys (tenant comes from the key) and rejected 400 when it names a tenant the caller has no membership in (after a constant-time path, so timing does not leak tenant existence).

### 3.2 Gateway data plane

All three routes: scope `gateway:proxy`; principal = `sbl_` key verified from the snapshot; agent = key's bound agent, narrowed by `X-Sibyl-Agent`; unknown agent on a tenant-level key → auto-register with `tenant.unknown_agent_fail_mode`, `asset.discovered` audit via ingest.

| Route | Object rules | Always audited | Notes |
|---|---|---|---|
| `POST /v1/chat/completions` | `agent_identity.allowed_models/providers` (observe → `policy.violated`; block → 403 `X-Sibyl-Reason: model-not-allowed` + `policy.blocked`); routing state `killed`/`quarantined` → 503/403; `fail_mode` on stale/expired | `policy.*` only when triggered; every call emits a `gen_ai.request` event (telemetry, not audit) | Retries only before first byte; SSE relayed byte-for-byte |
| `POST /v1/embeddings` | same | same | no streaming |
| `GET /v1/models` | returns the intersection of the snapshot's models for the agent and `allowed_models`; never the provider's full list (prevents enumeration of other tenants' providers) | none | served from snapshot, no upstream call |

Request headers the gateway reads: `X-Sibyl-Key` (or `Authorization` when no provider credential), `X-Sibyl-Agent`, `X-Sibyl-Call-Id`, `X-Sibyl-Task-Id`, `X-Sibyl-Route` (expected routing_version; mismatch → response header `X-Sibyl-Route-Stale: true`, never a refusal), `traceparent`. Response headers: `X-Sibyl-Route-Decision`, `X-Sibyl-Routing-Version`, `X-Sibyl-Policy-State`, `X-Sibyl-Origin: gateway` on gateway-originated errors, `X-Sibyl-Reason` on refusals. Never on the response: anything containing a key id, tenant id, or snapshot hash (fingerprinting aid).

### 3.3 Ingest

| Route | Scope | Isolation | Object rules | Audited |
|---|---|---|---|---|
| `POST /v1/otlp/traces` | `ingest:write` | key → tenant, §3.1(5) | agent narrowing (R13); `capture_policy` present else 403 `capture_policy_missing`; `tenant.status = erasing` → 429 `tenant_erasing`; body ≤ 5 MB after gzip, ≤ 1,000 spans | `asset.discovered` on auto-register; `ingest.rejected` aggregated per minute; never per event |
| `POST /v1/otlp/logs` | `ingest:write` | same | same; logs are accepted only as `sibyl-event/1` carriers (`policy.decision`, `feedback`, `task.outcome`), free-text log bodies are dropped with `events_rejected('unsupported_log')` | same |
| `POST /v1/events` | `ingest:write` | same | `{"schema":"sibyl-event/1","events":[…]}`; unsupported major → 400 | same |
| `POST /v1/checkpoints` | `ingest:write` **and** `handoff:write` | same | idempotent on `id`; `state ≤ 64 KB` inline else BlobStore; `capture_mode = metadata` → `state` dropped, `state_sha256` kept | none (telemetry) |
| `POST /v1/handoff` (SDK-assembled packet) | `handoff:write` | same | packet ≤ 64 KB inline; `fidelity = checkpoint`; task must belong to the key's agent | `handoff.created` (actor_type `agent`, `actor_key_id`) |

Ingest responses never echo event content; `rejected[]` carries `{index, reason}` only.

### 3.4 Control plane `/api/v1`

Conventions for the whole table: principal is OIDC (session or JWT) unless a row says M; isolation per §3.1; every mutating route requires `Idempotency-Key` (replay returns the stored response with `Idempotent-Replayed: true`; a different body under the same key → 422 `idempotency_key_reused`); policy objects use `ETag`/`If-Match` (412 on mismatch); problems are RFC 9457 with `type = urn:sibyl:problem:<code>`. "Audited" names the taxonomy action (§3 of my Step 3 doc) that the handler must `audit_append()` in the same transaction; `—` means a read with no audit row.

**Tenant, identity, access**

| Route | Scope | Object rules | Audited |
|---|---|---|---|
| `GET /tenant` | `tenant:read` | | — |
| `PATCH /tenant` | `tenant:write` S | `If-Match`; `audit_retention_days ≥ 400`; `unknown_agent_fail_mode` change emits with before/after | `config.changed` |
| `GET /users`, `GET /users/{id}` | `users:manage` or self | self = own row only | — |
| `POST /users` (invite) | `users:manage` | role ≤ caller's role rank; `owner` grant only by owner | `user.provisioned` |
| `PATCH /users/{id}` (disable) | `users:manage` | cannot disable the last active owner | `user.disabled` |
| `POST /memberships`, `DELETE /memberships/{id}` | `users:manage` | caller may not grant/revoke a role above their own; owner-guard trigger; `security_admin` grant requires owner | `membership.granted` / `membership.revoked` |
| `GET /oidc-issuers`, `PUT /oidc-issuers/{id}` | `oidc:manage` S | `issuer_url` https; secret write-only; response never includes `client_secret_ct` | `oidc_issuer.configured` / `changed` / `disabled` |
| `GET /api-keys` | `apikeys:manage`, or `apikeys:manage_agent` G | returns prefix, scopes, status, last_used; never hash | — |
| `POST /api-keys` | `apikeys:manage` (tenant-level) · `apikeys:manage_agent` G (agent-bound) · + `killswitch:pull` S for break-glass | scopes ⊆ M; `capture_policy` must exist (D12 ordering) else 409 `capture_policy_missing` | `api_key.created` |
| `POST /api-keys/{id}/rotate` | as create | grace ≤ 24 h; may narrow scopes | `api_key.rotated` |
| `DELETE /api-keys/{id}` | as create | reason required | `api_key.revoked` |
| `GET /sessions`, `DELETE /sessions/{id}` | self, or `users:manage` | | `session.revoked` |

**Registry and graph**

| Route | Scope | Object rules | Audited |
|---|---|---|---|
| `GET /agents`, `GET /agents/{id}`, `GET /agents/{id}/versions`, `/bom`, `/graph`, `/blast-radius` | `agents:read` (G for group roles; M) | `prompt_ref_id` content is **not** inlined; a `prompt` payload is read through `/payloads/{id}` | — |
| `POST /agents` | `agents:write` (G; M bound key may only register itself: `slug` must match the key's bound agent or key is tenant-level) | `fail_mode` required; `tier` default 3; tier 1 requires `agents:approve` to leave `proposed` | `asset.created` |
| `PATCH /agents/{id}` | `agents:write` G | `If-Match`; `tier`/`risk_class` change by `agents:approve` only | `asset.updated` |
| `POST /agents/{id}/lifecycle` | `agents:approve`; `retired` also `agents:write` | `state_edge(lifecycle)` | `asset.approved` / `asset.retired` |
| `POST /agents/{id}/versions` | `agents:write` G, M | immutable; new prompt hash = new version | `asset.updated` |
| `GET /agents/{id}/identity` | `agents:read` | | — |
| `PUT /agents/{id}/identity` | `identity:write` (engineer G may only remove entries: server diff, widening → 403 `identity_widen_forbidden`) S when `enforcement` changes | `If-Match`; bumps `identity_version` | `agent_identity.changed` (`widened` flag) |
| `GET /agents/{id}/health`, `GET /agents/{id}/risk` | `agents:read` | response carries scores, bands, factors; `factors` never contain content | — |
| `GET/POST/PATCH /agent-groups` | `agents:read` / `users:manage` | | `config.changed` |
| `GET/POST/PATCH /providers`, `/models`, `/tools`, `/data-sources`, `/business-processes` | `agents:read` / `agents:write` (tenant-wide roles only; providers are not G) | `provider.base_url` → `is_allowlisted_base_url()` at write **and** resolver check in the handler (§4 T1); `status_feed_url` same allowlist | `config.changed` |
| `GET /dependencies`, `POST /dependencies` | `agents:read` / `agents:write` G | polymorphic existence within tenant (trigger) | `asset.updated` |

**Routing, continuity, incidents**

| Route | Scope | Object rules | Audited |
|---|---|---|---|
| `GET /agents/{id}/routing`, `GET /routing/transitions` | `routing:read` (M) | | — |
| `GET /route?agent={id}` (SDK `resolve_route`) | `routing:read` M | bound agent only; returns `{routing_version, target, state, policy_state}`; cacheable 10 s | — |
| `GET/PUT /agents/{id}/continuity-plan` | `routing:read` / `routing:write` G | `If-Match`; tier 1 `inline_fallback = true` requires `agents:approve` as approver ≠ editor | `config.changed` |
| `GET/POST /agents/{id}/fallback-chains`, `POST …/{chain}/approve` | `routing:read` / `routing:write`; approve = `routing:write` + (tier 1: approver ≠ requester, `agents:approve`) | `credential_id` must be an active credential whose `provider_id` matches the step; `backup_agent_id ≠ self` | `config.changed` |
| `GET /incidents`, `GET /incidents/{id}` | `agents:read` G | an incident = a `failover` saga, its `approval`, its `alert`s and `handoff_task`s projected together; `evidence` carries refs, never content | — |
| `POST /incidents/{id}/actions` | `incidents:act` + action scope (below) | 409 `invalid_transition` from `state_edge`; 409 `operator_hold` for rule/policy actors (D21) — humans bypass; `reason` required (≥ 10 chars) for every human action; `Idempotency-Key` → `routing_apply(p_idempotency_key)` | per action |
| `GET /approvals`, `GET /approvals/{id}` | `agents:read` G | | — |
| `GET /kill-switches` | `agents:read` | | — |
| `POST /killswitch` | break-glass only, §2.5 | | `access.break_glass` + `killswitch.pulled` |

Action enum for `POST /incidents/{id}/actions` (and the equivalent `POST /agents/{id}/actions` when no incident is open yet; same table):

| `action` | Second scope | S | Object rules | Audited |
|---|---|---|---|---|
| `failover` `{to_step_id}` | `routing:override` | | step ∈ approved chain; tier 1 backup-agent step requires `approvals:decide` as a second human (D13 clarification) | `override.by_human` + `route.changed` |
| `undo` | `routing:override` | | last transition not already inverted; sets `operator_hold_until = now + 30 min` (D21) | `failover.undone` |
| `approve` / `deny` `{approval_id}` | `approvals:decide` | | approver ≠ requester (trigger); pending and not expired | `approval.granted` / `approval.denied` |
| `quarantine` | `quarantine:act` | | | `quarantine.applied` |
| `unquarantine` | `quarantine:act` | | | `quarantine.released` |
| `kill` `{scope_kind, scope_id}` | `killswitch:pull` | S | one `routing_apply` per affected agent, same transaction | `killswitch.pulled` |
| `release_kill` `{kill_switch_id}` | `killswitch:release` | S | reason ≥ 20 chars | `killswitch.released` |
| `ack` / `silence` `{until}` / `verdict` `{tp\|fp\|unsure}` | `alerts:act` | | verdict mandatory before `resolve` (D24): resolving without a verdict → 422 `verdict_required` | `alert.acked` / `alert.silenced` / `alert.labelled` |
| `handoff` `{failure_mode}` | `routing:override` | | creates a `request_only` task if no checkpoint | `handoff.created` |

**Queue and handoff**

| Route | Scope | Object rules | Audited |
|---|---|---|---|
| `GET /queue` | `queue:act` or `agents:read` | list never includes `packet`; summary and `next_action` only | — |
| `GET /queue/{task}` | `packets:read` (G; auditor = A) | packet body returned; `payload_refs` resolved server-side | auditor: `data.revealed` |
| `POST /queue/{task}/claim` | `queue:act` | `FOR UPDATE SKIP LOCKED`; lock 15 min | `handoff.claimed` |
| `POST /queue/{task}/complete` `{outcome, note}` | `queue:act` | claimant only (or owner reassign) | `handoff.completed` |
| `POST /queue/{task}/return` | `queue:act` | | `handoff.returned` |
| `POST /queue/{task}/reassign` | `queue:act` + owner/security_admin | | `handoff.reassigned` |

**Capture, redaction, credentials, keys**

| Route | Scope | Object rules | Audited |
|---|---|---|---|
| `GET /capture-policies` | `tenant:read` | | — |
| `POST /capture-policies` | `capture:write` | `capture_mode` required (no default); agent row ≤ tenant row strictness (trigger); response carries `consequences_version` the console displayed | `capture.policy_set` |
| `GET /redaction-profiles`, `POST /redaction-profiles` | `tenant:read` / `capture:write` | `detectors ⊇ secrets_only` (trigger); immutable; `content_hash` computed by `sibyl-schemas` and verified | `redaction.profile_created` |
| `GET /credentials` | `credentials:read` G | returns `provider_credential_meta` only: name, provider, `base_url`, `secret_hint`, status, `last_verified_at`; **never** `ciphertext`, `nonce`, `secret_sha256` | — |
| `POST /credentials` | `credentials:manage` S | `base_url` allowlist + resolver check; secret in body write-once; response 201 has no secret; demo tenants (`SIBYL_DEMO=1`) → 403 `demo_forbids_credentials` | `credential.created` |
| `POST /credentials/{id}/rotate`, `DELETE /credentials/{id}` | `credentials:manage` S | rotate grace ≤ 24 h; revoke NULLs ciphertext | `credential.rotated` / `credential.revoked` |
| `POST /credentials/{id}/verify` | `credentials:manage` S | probe via worker, never inline from api (SSRF boundary) | `credential.verified` / `credential.probe_failed` |
| `GET /tenant-keys` | `tenant:read` (owner, security_admin only via role) | metadata only; `wrapped_dek` never serialised | — |
| `POST /tenant-keys/{purpose}/rotate` | `keys:rotate` S | | `tenant_key.rotated` |

**Audit and payloads**

| Route | Scope | Object rules | Audited |
|---|---|---|---|
| `GET /audit/events` | `audit:read` (G: rows whose `resource_type = agent` and agent ∈ group; tenant-level rows hidden) | cursor on `(seq)`; filters `action`, `resource`, `actor`, `from`, `to`; `detail` returned as stored (refs and hashes only by construction) | — |
| `GET /audit/events/{seq}` | `audit:read` | | — |
| `GET /audit/anchors` | `audit:read` | | — |
| `POST /audit/verify` `{from_seq, to_seq}` | `audit:verify` | ≤ 1 M rows per call; async job returning 202 + job id above 100 k | `audit.verified` / `audit.verify_failed` |
| `POST /audit/exports` `{from_seq, to_seq, format}` | `audit:export` A | anchor written before export; export is a `payload_refs(kind=anchor_export)` object; download via `/payloads/{id}`; 202 + job | `audit.exported` |
| `GET /payloads/{id}` | `payloads:read` (G by `payload_refs.agent_id`); kinds `handoff_packet`/`checkpoint_state` additionally `packets:read`; auditor = A | decrypt under tenant DEK; `state = swept/shredded` → 410; a `legal_hold` does not change readability; the scrubber ran at write, nothing runs at read | auditor: `data.revealed` |
| `POST /payloads/{id}/reveal` `{reason}` | `payloads:reveal` A | reason ≥ 10 chars; console-only reveal of a payload outside the caller's group scope | `data.revealed` |
| `POST /exports` `{kind, filter}` | `data:export` A | 202 + job; output object encrypted under tenant DEK; link expires 1 h | `data.exported` |

**Erasure and legal hold** (safety rules in §7)

| Route | Scope | Object rules | Audited |
|---|---|---|---|
| `GET /erasure-requests`, `GET …/{id}` | `erasure:request` or `audit:read` | `scope_ref` for `subject` is the stored hash, never the identifier | — |
| `POST /erasure-requests` | `erasure:request` | tenant scope requires `owner`; hold check inline → `hold_blocked` | `erasure.requested` (+ `erasure.blocked_by_hold`) |
| `POST /erasure-requests/{id}/approve` | `erasure:approve` S | approver ≠ requester (trigger); tenant scope: owner | `erasure.approved` |
| `POST /erasure-requests/{id}/reject`, `/cancel` | `erasure:approve` / requester | cancel only before `executing` | `erasure.rejected` |
| `GET /erasure-requests/{id}/certificate` | `audit:read` | available from `completed`; `certificate_sha256` matches | — |
| `GET /legal-holds` | `audit:read` | | — |
| `POST /legal-holds` | `holds:manage` S | explicit scope (R14); `agent_ids` materialised | `hold.placed` |
| `POST /legal-holds/{id}/release` `{reason}` | `holds:manage` S | re-evaluates `hold_blocked` erasures | `hold.released` |

**Platform routes (gateway only)**

| Route | Credential | Notes |
|---|---|---|
| `GET /v1/policy/snapshot` | `gateway:snapshot` platform token | `If-None-Match`; 304 or signed body (§2.4) |
| `GET /v1/policy/stream` | same | SSE `routing_changed {tenant_id, routing_version}`; no payload beyond ids |
| `GET /v1/policy/keys` | same, or unauthenticated **read-only** public-key set (Q2) | JWKS-shaped; Ed25519 public keys only |
| `POST /v1/policy/acks` | same | `{gateway_id, snapshot_version, kill_switch_ids[]}` → `kill_switch_ack` rows + `killswitch.applied` |

**Console streams**

| Route | Scope | Notes |
|---|---|---|
| `GET /api/v1/stream` (SSE) | any authenticated OIDC principal | events are **ids and versions only** (`alert.created {alert_id}`, `routing_changed {agent_id}`); the client re-fetches through the authorised GET, so the stream never needs per-event authz and never carries content. Heartbeat every 15 s; connection ends on session expiry. |

---

## 4. STRIDE pass: top 15 threats and the contract-visible mitigations

Surfaces: **DP** gateway data plane, **CP** control plane, **IN** ingest, **SDK**.

| # | Surface | STRIDE | Threat | Mitigation visible in the API contract |
|---|---|---|---|---|
| T1 | CP, DP | Tampering / Elevation | **SSRF via `provider.base_url`, `provider_credential.base_url`, `status_feed_url`**: a tenant points a fallback at `http://169.254.169.254/` or an internal api address and lets the gateway or worker fetch it with a vaulted credential attached | `is_allowlisted_base_url()` CHECK (https only outside dev-ollama; no loopback/link-local/RFC 1918/CGNAT/ULA) **plus** a handler-side DNS resolution check at write time recording `allowlist_basis`; the worker re-resolves before every probe and refuses if the answer moved into a private range (DNS rebinding); gateway outbound httpx has redirects disabled and a connect-time IP filter; probes run only in the worker, never inline in api; 422 `base_url_not_allowed` names the rule, not the resolved IP |
| T2 | CP | Information disclosure | **Prompt/completion exfiltration through audit read**: `audit:read` is wide (admin, auditor, engineer G) while payload read is narrow; if `detail` ever carried content, audit becomes the leak path | `audit_append()` rejects any `detail` key in `{prompt, completion, messages, body, content, headers, input, output}` (function CHECK, Step 3 §2.14); `detail ≤ 8 KB`; cross-references are `payload_sha256`/`payload_ref_id` that still require `payloads:read` to dereference; `GET /audit/events` has no "expand" parameter; test 3 canaries cover `audit_events.detail` |
| T3 | CP, IN | Spoofing / Tampering | **Idempotency-key replay and cross-principal reuse**: an attacker who learns a key replays a `kill` or `approve`, or reuses another user's key to read their stored response | Idempotency store keyed `(tenant_id, principal_id, Idempotency-Key)`, 24 h TTL; replay by the same principal returns the stored response with `Idempotent-Replayed: true`; a different principal gets 404; same key + different body → 422; keys must be UUIDs (≥ 122 bits); `routing_apply()` additionally dedupes on its own `p_idempotency_key` so a replay past the TTL cannot double-transition |
| T4 | DP | Information disclosure | **SSE token leakage**: streaming relays bytes; a provider error chunk or a client-side `Authorization` echo could land in the stream, in the span, or in the telemetry spill file | Gateway strips `X-Sibyl-*` and never writes request headers into spans except the `header_allowlist` (CHECK excludes `authorization, cookie, x-api-key, api-key`); the unconditional scrubber (§5) runs over every chunk buffered for capture **before** enqueue; error bodies the gateway itself emits are fixed templates with `X-Sibyl-Reason`; the spill queue holds already-scrubbed `sibyl-event/1` documents only |
| T5 | IN | Denial of service | **OTLP amplification**: one key floods ingest with 5 MB gzip bombs or millions of 1-byte spans, starving other tenants and Postgres | Per-key and per-tenant limits (§6): `tenant.ingest_events_per_s` (default 1,000) enforced with 429 + `Retry-After`; body ≤ 5 MB compressed **and** ≤ 32 MB decompressed (streaming decompressor aborts past the cap, 413 `batch_too_large`); ≤ 1,000 spans/batch; per-payload `max_payload_bytes` from `capture_policy` (oversize → hash + head/tail); `events_rejected` has its own 3-day retention so rejects cannot fill `events` |
| T6 | DP | Spoofing | **API key brute force / enumeration at the gateway**, which verifies locally without a database | 256-bit secrets, HMAC compare in constant time; the 12-char prefix is looked up in a hash map so an unknown prefix costs the same as a bad secret; gateway rate-limits 401s per source IP (60/min) and reports `telemetry.dropped`-style counters; 401 body is identical for unknown prefix, bad secret, expired and revoked (`X-Sibyl-Reason: unauthorized`) |
| T7 | DP | Elevation | **Agent-binding widening**: a tenant-level key plus a forged `X-Sibyl-Agent` impersonates a tier-1 agent (its identity, its fallback credentials, its budget) | R13 in the contract: header may only narrow; agent-bound keys ignore the header (403 on mismatch, `access.denied`); the snapshot carries `key → agent_id` so the gateway enforces without api; tier-1 agents **require** agent-bound keys (snapshot builder refuses a tier-1 agent reachable only via tenant-level keys; 409 `tier1_requires_bound_key` on lifecycle approval) |
| T8 | DP, CP | Tampering | **Stale or forged policy snapshot** (rollback to a version where an agent is not killed; MITM replacing the snapshot) | Ed25519 signature over JCS body; `kid` pinning; strict monotonic version; killed state sticky on any staleness (ADR-9); `snapshot.rejected` audit (critical) on each refusal; TLS to api with certificate pinning optional via `SIBYL_API_CA` |
| T9 | CP | Elevation | **Approval self-dealing**: a rule proposes, the same person requests and approves, or a `security_admin` approves their own request | `trg_requester_not_approver()` on `approval`, `erasure_request`, `fallback_chain`; the actions route checks it before `routing_apply()` and returns 409 `self_approval`; tier-1 backup-agent failover requires a *second* human even when the first holds `routing:override` |
| T10 | CP | Repudiation | **Unattributable automated actions / audit gaps**: a worker action with no actor, or a handler that forgets to audit | Every route declares `x-sibyl-audit`; test 5 asserts `max(seq)` rises by exactly one per handler; `actor_type ∈ {human, rule, policy, system, agent}` with `actor_id`/`actor_key_id`/`actor_session_id` required by taxonomy; api returns `X-Sibyl-Audit-Receipt: <tenant>:<seq>:<hash>` on every audited response so the client can later verify |
| T11 | CP | Information disclosure | **Cross-tenant existence oracle** via 403 vs 404, timing, or `X-Sibyl-Tenant` | RLS yields zero rows → uniform 404; `X-Sibyl-Tenant` validated after a constant-time membership check; `prefix` lookup is the sole pre-tenant read and returns the same 401 for all failure kinds; the generated isolation test covers every table off the allowlist |
| T12 | CP | Elevation | **Role escalation through membership routes or JIT**: admin grants owner; `role_claim_map` maps a group to `owner`; break-glass key creation by admin | `users:manage` grants ≤ caller's rank; `owner` and `security_admin` grants need owner; `jit_default_role NOT IN (owner, admin, security_admin)` CHECK; `role_claim_map` values are validated against the same CHECK at `PUT /oidc-issuers`; break-glass key creation needs `killswitch:pull` S (owner/security_admin) |
| T13 | SDK | Tampering / Disclosure | **SDK as an exfil or injection path**: a compromised app process sends fabricated events for another agent, oversized checkpoints with secrets, or hostile `sibyl.*` attributes | SDK keys are agent-bound (quickstart default); ingest ignores `sibyl.agent_id` that widens beyond the binding (reject per event); SDK runs the scrubber before buffering; attributes ≤ 4 KB (R19); checkpoint `state` ≤ 64 KB inline; `sibyl.*` attribute allowlist from `sibyl-schemas`, unknown attributes dropped and counted in `ingest.rejected`; SDK never receives a `gateway:proxy` key in the quickstart |
| T14 | CP | Denial of service | **Operator-hold or kill-switch abuse to freeze a tenant's fleet** (insider or stolen session) | `kill` and `release_kill` require S (fresh IdP auth, so a stolen cookie alone is insufficient); `scope_kind = tenant` kills are limited to 1 per 10 min per tenant for OIDC principals (break-glass has its own limit); every kill writes `policy.decision` events and an SSE broadcast so other owners see it within seconds; undo of a human kill is `release_kill`, itself S and audited |
| T15 | IN, CP | Information disclosure | **Payload retention/erasure bypass**: a packet or checkpoint stored inline in Postgres (U3) outlives the crypto-shred; a legal hold silently keeps content the tenant believes erased | Erasure cascade hard-deletes inline rows (§6.5 of DATAMODEL); the certificate text states that inline rows and pre-shred backups expire at `backups_expire_at` (D26); `GET /erasure-requests/{id}` shows `blocking_hold_ids` so the requester sees exactly what holds back the request; `POST /legal-holds` is S and `hold.placed` is evidence-grade |

Residual (documented, not mitigated in Phase 1): an attacker holding both DB write and the anchor signing key can rewrite the current hour (ADR-12); the hosted multi-tenant gateway holds all tenants' fallback credentials in one process (sidecar keyless mode is Phase 2); no per-object keys, so subject-level erasure is deletion by reference (U3).

---

## 5. Secrets scrub contract (unconditional, D12)

"Unconditional" means: it runs regardless of `capture_mode`, regardless of tenant, before any byte is buffered for storage, and the database refuses a redaction profile that lacks it (`trg_redaction_profile_baseline()`).

### 5.1 Where it runs

| Stage | Component | Input | Guarantee |
|---|---|---|---|
| 1 | **SDK** (`sibyl-sdk`, in the agent process) | every `gen_ai.*` content attribute, tool arguments/results, checkpoint `state`, handoff packet fields, before the event enters the bounded buffer | a secret never leaves the tenant's process; `sibyl.redaction.profile_hash` stamped on the span |
| 2 | **Gateway** | request body (messages, tools), response chunks assembled for capture, the `header_allowlist` subset; **never** the forwarded request itself | a secret never enters the telemetry queue or the spill file |
| 3 | **Ingest** | every string leaf of every incoming event and payload, *again*, before BlobStore write; also `attrs` | defence in depth for third-party OTel SDKs and `/v1/events` callers that are not `sibyl-sdk`; the profile hash recorded on `payload_refs` is ingest's, and if ingest found anything stage 1/2 missed it records `sibyl.redaction.late_hits = n` on the event (metadata only) |
| — | **api** | `audit_append()` detail, `reason` fields, `outcome_note`, `summary`, exports | human-typed text is scrubbed before storage; export objects are scrubbed on assembly |

Nothing runs at read time: what is stored is what is served, so "did the operator see a secret" is answerable from the stored object's hash.

### 5.2 Baseline detectors (`secrets_only` system profile, `sibyl-schemas` detector registry v1)

| id | Pattern (summary) | Kind label |
|---|---|---|
| `sibyl_key` | `sbl_(live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}` | `SECRET` |
| `openai_key` | `sk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}` | `SECRET` |
| `anthropic_key` | `sk-ant-[A-Za-z0-9_-]{20,}` | `SECRET` |
| `aws_access_key` | `(AKIA|ASIA)[A-Z0-9]{16}` | `SECRET` |
| `aws_secret_key` | 40-char base64 adjacent to `aws_secret|secret_access_key` (context-gated) | `SECRET` |
| `gcp_sa_key` | `"private_key_id"` + PEM in JSON | `SECRET` |
| `azure_conn_string` | `AccountKey=[A-Za-z0-9+/=]{86,}`; `SharedAccessSignature=` | `SECRET` |
| `github_token` | `gh[pousr]_[A-Za-z0-9]{36,}`; `github_pat_[A-Za-z0-9_]{82}` | `SECRET` |
| `slack_token` | `xox[abprs]-[A-Za-z0-9-]{10,}` | `SECRET` |
| `stripe_key` | `(sk|rk)_(live|test)_[A-Za-z0-9]{24,}` | `SECRET` |
| `jwt` | `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}` | `TOKEN` |
| `bearer_header` | `(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}` | `TOKEN` |
| `basic_auth_url` | `[a-z][a-z0-9+.-]*://[^/\s:]+:[^@\s]+@` (credential in URL authority) | `SECRET` |
| `dsn` | `(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s"']+` with a password component | `SECRET` |
| `pem_block` | `-----BEGIN [A-Z ]*PRIVATE KEY-----` … `-----END` | `PRIVATE_KEY` |
| `ssh_key` | `ssh-(rsa|ed25519) AAAA[A-Za-z0-9+/=]{40,}` when followed by a private block; otherwise untouched (public) | `PRIVATE_KEY` |
| `generic_secret_kv` | `(?i)(api[_-]?key|secret|password|passwd|token|client_secret)\s*[:=]\s*["']?([^\s"']{12,})` → replaces the value only | `SECRET` |
| `high_entropy` | base64/hex runs ≥ 32 chars with Shannon entropy ≥ 4.5 bits/char, **only** inside headers, tool arguments and `state`, never in prose message content (false-positive control) | `ENTROPY` |

Replacement: `[{kind}:{hash8}]` where `hash8` = first 8 hex of `sha256(SIBYL_SCRUB_SALT ‖ match)`. The salt is a platform secret (not per tenant) so the same leaked key is recognisable across a tenant's traces for incident response without being recoverable. Length-preserving replacement is **not** used (it leaks length).

PII detectors (`pii_standard`: email, phone, IBAN, PAN/Aadhaar, credit card with Luhn, IP) are **conditional** on `capture_mode = redacted` and are outside this contract's unconditional set.

### 5.3 How the redaction profile is recorded

- Every stored object: `payload_refs.redaction_profile_hash` and `payload_refs.capture_mode` (R15); checkpoints and inline packets carry the same two columns in their own rows.
- Every event: `sibyl.redaction.profile_hash` (OTel attribute, stored in `attrs`) stamped by the emitter; ingest overwrites with its own hash if it applied a stricter profile and keeps the emitter's as `sibyl.redaction.emitter_profile_hash`.
- `content_hash = sha256(JCS(detectors ‖ replacement_format))` is tenant-independent, so an auditor comparing two tenants' exports sees the same hash for the same profile.
- `audit_events.detail.redaction_profile_hash` on `capture.policy_set`, `data.revealed`, `data.exported`, `audit.exported`.
- The gateway and SDK receive the effective profile inside the snapshot (`tenants.<id>.agents.<id>.capture {mode, profile_hash, detectors_ref}`); they refuse to run with a profile whose detector set is not a superset of the baseline (startup assert against `sibyl-schemas`).
- `GET /payloads/{id}` returns `X-Sibyl-Redaction-Profile: <hash>` and `X-Sibyl-Capture-Mode: <mode>` so the console can label what the viewer is seeing.

Test 3 of Step 3 (canaries in headers, body, prompt, tool args, checkpoint state, audit detail, logs, metrics, snapshot JSON, bundle) is the acceptance test for this section and is run against all three stages independently and in sequence.

---

## 6. Security headers, CORS, rate limits per surface

### 6.1 Response headers

| Header | Gateway DP | Control plane api | Console (BFF) | Ingest |
|---|---|---|---|---|
| `Strict-Transport-Security: max-age=31536000; includeSubDomains` | ✓ (behind Caddy/TLS) | ✓ | ✓ (+ `preload` once the domain is final) | ✓ |
| `X-Content-Type-Options: nosniff` | ✓ | ✓ | ✓ | ✓ |
| `Content-Security-Policy` | n/a (JSON only) | `default-src 'none'; frame-ancestors 'none'` | `default-src 'self'; script-src 'self' 'nonce-{r}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` | n/a |
| `X-Frame-Options: DENY` | ✓ | ✓ | ✓ | ✓ |
| `Referrer-Policy: no-referrer` | ✓ | ✓ | `strict-origin-when-cross-origin` | ✓ |
| `Permissions-Policy: camera=(), microphone=(), geolocation=()` | — | — | ✓ | — |
| `Cache-Control: no-store` | ✓ | ✓ (except `GET /v1/policy/keys`: `max-age=300`) | ✓ on HTML and API responses | ✓ |
| `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` | — | ✓ | ✓ | — |
| `X-Sibyl-Request-Id` | ✓ | ✓ | ✓ | ✓ |
| `Server` | removed | removed | removed | removed |

Error bodies: RFC 9457 everywhere on CP/IN; the gateway returns OpenAI-shaped `{"error": {"message", "type", "code"}}` on DP (D16) with `X-Sibyl-Origin: gateway` and `X-Sibyl-Reason`. No stack traces, no SQL, no file paths, no upstream `base_url` in any 4xx/5xx body (the upstream host is a secret-adjacent datum under D11).

### 6.2 CORS

| Surface | Policy |
|---|---|
| Gateway DP | **No CORS headers.** Browser-originated provider calls would expose provider credentials to the page; SDK and server callers do not need CORS. A preflight gets 403 with `X-Sibyl-Reason: cors-disabled`. |
| Control plane api | No wildcard. Allowed origins = the tenant's console origin(s) (platform config `SIBYL_CONSOLE_ORIGINS`); `Access-Control-Allow-Credentials: false` (bearer only); allowed headers `Authorization, Content-Type, Idempotency-Key, If-Match, X-Sibyl-Tenant, X-Sibyl-CSRF`; exposed headers `ETag, X-Sibyl-Audit-Receipt, X-Sibyl-Request-Id, Idempotent-Replayed`; `max-age 600`. In practice the BFF is same-origin and CORS matters only for CLI-from-browser tooling. |
| Ingest | No CORS (server-side callers only). |
| Console | same-origin; `Sec-Fetch-Site` check on mutations. |

### 6.3 Rate limits (token bucket; 429 with `Retry-After` and `X-RateLimit-Limit/Remaining/Reset`; counters in-process per replica in Phase 1, Valkey later per ARCHITECTURE §7)

| Surface | Key | Limit | Notes |
|---|---|---|---|
| DP `POST /v1/chat/completions`, `/v1/embeddings` | per `api_key`; per agent `continuity_plan.rps_limit` / `max_inflight` | tenant default 50 rps burst 200 per key; agent plan overrides | enforced from the snapshot; exceeding `max_inflight` → 429 `agent_inflight_limit`, counted as `fallback_pressure` leading indicator |
| DP 401s | per source IP | 60 / min | §4 T6 |
| IN all routes | per key and per tenant | `tenant.ingest_events_per_s` (1,000) events/s, 20 batches/s per key; 5 MB gz / 32 MB raw per batch | 429 `tenant_erasing` separately |
| CP reads | per principal | 600 / min | SSE streams: 4 concurrent per session |
| CP mutations | per principal | 60 / min | plus per-route: `POST /api-keys` 10/h, `POST /credentials` 10/h, `POST /erasure-requests` 5/day per tenant |
| CP `POST …/actions` with `kill` | per tenant | 1 tenant-scope kill / 10 min; agent/provider kills 30 / min | §4 T14 |
| CP `POST /killswitch` (break-glass) | per key; per tenant | 3 / 10 min; 6 / h | §2.5, every attempt audited |
| CP `POST /audit/verify`, `/audit/exports`, `/exports` | per tenant | 10 / h; one running export job at a time | heavy reads |
| Auth `GET /auth/*/login`, `/auth/callback`, `/auth/step-up` | per IP; per tenant | 30 / min; 300 / min | `access.login_failed` after each rejected callback |
| Platform `GET /v1/policy/snapshot` | per gateway token | 2 / s | fallback poll is every 2 s |

---

## 7. Erasure and legal-hold API safety rules (D17, D26)

1. **Two humans, two sessions.** `POST /erasure-requests` and `POST …/approve` must come from different `app_user` rows (`CHECK approved_by <> requested_by`) and the approve call requires step-up. Tenant scope: both must hold `owner`. A tenant with one active owner cannot approve a tenant-scope erasure (409 `second_owner_required`); the console says so before the request is filed.
2. **Hold check is server-side and visible.** The request response includes `state` and `blocking_hold_ids[]`; `hold_blocked` requests are re-evaluated automatically on every `hold.released` and never approved manually past a hold (the state machine has no `hold_blocked → approved` edge without a successful re-check).
3. **No erasure of the erasure.** `audit_events`, `audit_anchors`, `erasure_request`, `legal_hold`, `tenant_key` (shredded rows), `tenant` (id, slug, status) survive. The API exposes this list verbatim in the certificate and in `GET /erasure-requests/{id}` as `retained_tables[]`.
4. **Certificate content (D26)** — `GET /erasure-requests/{id}/certificate` returns a JCS JSON document plus its `sha256`: request id, scope, legal basis, requester/approver as hashed actor refs, `affected_objects` counts, every `tenant_key.shredded` `(purpose, version)`, the `erasure` anchor id and signature, `backups_expire_at = completed_at + tenant.backup_retention_days` (default 35, D26 states 7 for the backup window; the certificate prints the tenant's actual value), and the sentence that inline packet/checkpoint rows and identifiers inside `audit_events` are not claimed deleted (U3). The console download is a `payload_refs(kind=anchor_export)` object and is the only erasure artefact that is **not** encrypted under the tenant's `payload` DEK (that DEK is shredded); it is encrypted under the `config` DEK for agent/subject scope and stored plaintext-signed for tenant-offboarding scope, because the tenant no longer has keys.
5. **Ingest and gateway during erasure.** `tenant.status = erasing` → ingest 429 `tenant_erasing`; gateway continues to proxy (continuity is not revoked by an erasure) but the snapshot flips the tenant's agents to `capture_mode = metadata` so nothing new is stored; the SDK honours the same.
6. **Subject-scope requests** take the subject identifier in the body **once**, hash it server-side (`sha256(SIBYL_SUBJECT_SALT ‖ identifier)`), store only the hash, and never echo the identifier. Phase 1 resolves subject → payloads by operator-supplied `agent_ids` + time window (U4); the response says `resolution = agent_window` so nobody mistakes it for a content search.
7. **Legal hold placement is evidence-grade and bounded.** `POST /legal-holds` requires S, a `reason`, an explicit `scope_kind`, and either `expires_at ≤ now + 2 y` or an incident reference (incident holds end at `resolved_at`, extended by the worker while open). Auto-holds (`tenant.hold_on_incident`) are created by the worker with `placed_by = NULL` and audited `hold.placed` with `actor_type = system`; the console shows them distinctly.
8. **Hold release re-opens erasure, not retention.** Releasing a hold re-evaluates `hold_blocked` erasure requests immediately but does not trigger a retention sweep; the next scheduled sweep handles it, so a release followed by a mistaken `hold.placed` within minutes loses nothing.
9. **Reads during hold.** A hold never widens read access: `GET /payloads/{id}` under a hold obeys the same scopes; `audit:read` principals see the hold row, not the held content.
10. **No bulk delete routes exist.** There is no `DELETE /agents/{id}` (retire instead), no `DELETE /payloads/{id}`, no `DELETE /audit/*`. The only path that removes tenant content is the erasure state machine; the OpenAPI document is checked in CI for the absence of `DELETE` on content resources (allowed only on `api-keys`, `credentials`, `memberships`, `sessions`, all of which are revocations, not deletions).

---

## 8. SDK-specific contract points

- `sibyl.init(api_key=…)` refuses a key whose scopes include `gateway:proxy` or `killswitch:pull` with a clear error ("ingest-only key expected"); quickstart issues agent-bound `ingest:write + handoff:write + routing:read` keys.
- The SDK never reads provider credentials; it wraps the client and stamps `X-Sibyl-Call-Id`, `X-Sibyl-Agent`, `X-Sibyl-Task-Id`, `traceparent` on outbound requests only when the base URL is the Sibyl gateway (it must not leak call ids to a provider directly).
- Scrubber (§5 stage 1) runs synchronously in the instrumented call's thread before buffering; the buffer is bounded (default 10 k events / 32 MB), drop-oldest, and emits `telemetry.dropped` counters that ingest turns into one audit row per minute, never per drop.
- `resolve_route()` uses `GET /route?agent=` with a 10 s cache and treats any non-200 as "keep last route" — the SDK never fails the application on a control-plane error (the ARCHITECTURE governing rule).
- The TypeScript sketch shares the detector registry (`sibyl-schemas` publishes `detectors.v1.json`) so both SDKs produce identical `profile_hash` values.

---

## 9. Open questions for the chair

1. **Gateway identity to api (Q1).** I specified a platform credential (`SIBYL_GATEWAY_TOKEN`, scope `gateway:snapshot`) for the Phase 1 hosted gateway because a multi-tenant snapshot cannot be fetched with a tenant key. Confirm, or rule that even Phase 1 gateways fetch per-tenant snapshots with tenant keys (costs N fetches per refresh, buys sidecar parity now).
2. **`GET /v1/policy/keys` unauthenticated?** Public keys only; making it unauthenticated simplifies offline audit verification and the SDK's optional snapshot check. Default: unauthenticated, read-only, cached 5 min.
3. **`incidents` as a resource.** I treated an incident as the projection of `failover + approval + alert + handoff_task` and accepted both `POST /incidents/{id}/actions` and `POST /agents/{id}/actions` (when no saga is open). The backend-architect may have modelled it differently; the action→scope table (§3.4) must survive whatever the path is.
4. **Scope renames.** `telemetry:write → ingest:write`, `registry:* → agents:*`, `route:read → routing:read` change the `api_key.scopes` CHECK from Step 3 before any code exists. Accept, or keep Step 3 names and treat the catalogue as aliases.
5. **Break-glass anchor kind.** I added `audit_anchors.kind = 'break_glass'` and a worker `anchor_now` outbox topic. Accept as a Step 3 amendment (seed-row change, no migration churn).
6. **Tier-1 requires agent-bound keys (T7).** The snapshot builder refusing tier-1 agents reachable only through tenant-level keys is a new product constraint; it is the cheapest mitigation of agent impersonation. Confirm or downgrade to a warning.
7. **`backups_expire_at` arithmetic.** D26 says `backup_retention_days = 7` for erasure; the DATAMODEL `tenant.backup_retention_days` default is 35. The certificate must print one number. I used the tenant column; the chair should pick the default.
8. **Human kill-rate cap (T14).** 1 tenant-scope kill per 10 min per tenant for OIDC principals could block a legitimate second owner during a real incident. Alternative: no cap, but a second tenant-scope kill within 10 min requires a *different* owner. I lean to the alternative.
