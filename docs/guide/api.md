# API conventions

Sibyl exposes three HTTP surfaces:

| Surface | Base URL (compose) | Shape |
|---|---|---|
| Control plane | `https://localhost:8443/api/v1` | REST + Server-Sent Events, RFC 9457 errors |
| Ingest | `https://localhost:8445/v1` | `POST /otlp/traces`, `POST /otlp/logs` (OTLP/HTTP), `POST /events` (`sibyl-event/1`) |
| Gateway | `https://localhost:8444/v1` | OpenAI-compatible `POST /chat/completions`, `POST /embeddings`, `GET /models` |

The reference is the OpenAPI 3.1 document [`openapi/sibyl-api.v1.yaml`](../../openapi/sibyl-api.v1.yaml), contract version 1.1.0. It is generated from `openapi/sibyl_openapi/`, and CI fails if the two drift. Do not edit the YAML by hand.

Every operation carries extensions that state its contract:

| Extension | States |
|---|---|
| `x-sibyl-scope` | The scope required |
| `x-sibyl-step-up` | `never`, `conditional` or `always` |
| `x-sibyl-idempotency` | Whether an `Idempotency-Key` is required |
| `x-sibyl-if-match` | Whether `If-Match` is required |
| `x-sibyl-rate-limit` | The named rate policy |
| `x-sibyl-audit` | The audit actions it writes |
| `x-sibyl-problems` | The problem codes it can return, by status |
| `x-sibyl-key-scopes` | The API-key scopes it accepts |
| `x-sibyl-object-rules` | Object-level rules, such as group limits |

## Authentication

| Principal | Credential | Used by |
|---|---|---|
| API key | `Authorization: Bearer sbl_<env>_<prefix>_<secret>` | SDKs, the gateway, scripts |
| Console session | `Authorization: Bearer sibyl_sess_<value>`, where the value is the `__Host-sibyl_session` cookie set at login | The console BFF; humans using `curl` |
| OIDC bearer token | A JWT from the tenant's issuer with `aud=sibyl-api` and a lifetime of 1 hour or less, plus `X-Sibyl-Tenant: <slug>` | CLI and scripts |

**How a request is resolved.** The API tries an API key, then a session, then an OIDC token. Every failure is the same `401 unauthenticated`. For OIDC tokens the tenant is resolved first, and the token's issuer must be one of that tenant's issuers. A shared issuer such as dex therefore cannot reach across tenants.

**Rules for API keys:**

- Keys are scoped (see [Concepts](concepts.md#people-and-roles)).
- A key can be bound to one agent. A bound key acts only for that agent.
- An API key sent with an `Origin` header is refused with `403 key_from_browser`.
- A key's `env` must match the deployment's `SIBYL_ENV`.
- The secret is shown once, at creation (`201`). An `Idempotency-Key` replay of the creation returns `secret: null`.
- Rotation (`POST /api-keys/{id}/rotate`) issues a new key. The old one stays valid through `rotation_grace_until`: `grace_s` defaults to 3600 and is at most 24 hours.

**Human scopes** come from role memberships, re-read on every request. A group-limited grant sees only agents in its groups. Anything else is `404`, never `403`, so the response does not reveal that the object exists.

**Step-up** means signing in again at the identity provider within the last 5 minutes. Without it the response is `403 step_up_required`. Step-up exists only for console sessions: start it with `POST /auth/step-up` from the browser. Bearer tokens cannot step up.

**Getting a session token for `curl`:**

1. Sign in at `/api/v1/auth/login?tenant=<slug>`.
2. Copy the `__Host-sibyl_session` cookie.
3. Send it as `Authorization: Bearer sibyl_sess_<value>`.

Sessions last up to 8 hours and expire after 30 minutes idle.

## Errors

Every non-2xx response from the control plane and ingest is `application/problem+json` (RFC 9457):

```json
{
  "type": "https://sibyl.dev/problems/invalid_transition",
  "title": "Transition not allowed",
  "status": 409,
  "detail": "agent is killed; fail_back needs a failed_over agent",
  "code": "invalid_transition",
  "from_state": "killed",
  "action": "fail_back"
}
```

`code` is the stable identifier. Extension members depend on the code, for example `blocking_hold_ids`, `incident_id` or `retry_after_s`. The full registry of codes, statuses and titles is `packages/sibyl-schemas/src/sibyl_schemas/_problems.py`.

Codes you will meet often:

| Status | Codes |
|---|---|
| 400 | `invalid_cursor`, `cursor_filter_mismatch`, `invalid_scope`, `unsupported_schema`, `batch_too_large` |
| 401 | `unauthenticated`, `oidc_failed` |
| 403 | `forbidden`, `step_up_required`, `key_from_browser`, `break_glass_key_misuse`, `agent_binding_violation`, `capture_policy_missing` (ingest) |
| 404 | `not_found` (also returned for other tenants' objects), `payload_swept`, `tenant_unknown` |
| 409 | `invalid_transition`, `saga_in_flight`, `approval_not_pending`, `self_approval`, `already_undone`, `nothing_to_undo`, `operator_hold`, `stale_precondition`, `hold_blocked`, `erasure_in_progress`, `erasure_blocked_by_chain`, `second_owner_required`, `idempotency_in_progress`, `already_resolved` |
| 410 | `payload_shredded` |
| 412 | `precondition_failed` |
| 422 | `validation_failed`, `verdict_required`, `scope_mismatch`, `alt_provider_requires_credential`, `base_url_not_allowlisted`, `idempotency_key_reuse` |
| 428 | `idempotency_key_required`, `precondition_required`, `reveal_reason_required` |
| 429 | `rate_limited`, `break_glass_rate_limited`, `stream_limit`, `tenant_rate_limit`, `ingest_saturated`, `tenant_erasing` (each with `Retry-After`) |
| 501 | `not_implemented`: a contract operation that is mounted but not built yet |
| 503 | `database_unavailable`, `database_timeout`, `serialization_failure`, `service_unavailable` |

Database errors are raised as SQLSTATE class `SB` with the message `sibyl:<code>` and mapped onto these codes. A `detail` never contains secrets, other tenants' ids or upstream URLs.

**The gateway uses OpenAI's error shape.** It is OpenAI-compatible, so errors are `{"error": {"message", "type", "param", "code"}}`. Two headers mark errors the gateway itself produced: `X-Sibyl-Error: <code>` and `X-Sibyl-Origin: gateway`. Codes are listed in [Operations](operations.md#what-the-gateway-tells-a-client).

## Idempotency

Every `POST` that creates something or changes state requires `Idempotency-Key`: a client-generated string of up to 128 characters (a UUID is fine). Records are kept for 24 hours and keyed by tenant, route and key.

| Case | Response |
|---|---|
| First call | The normal response, stored |
| Same key, same request (method, path, query, normalised JSON body) | The stored response, with `Idempotency-Replayed: true` |
| Same key, different request | `422 idempotency_key_reuse` |
| Same key, still running | `409 idempotency_in_progress` |
| Same key from another principal | `404` |
| Stored response was larger than 64 KB | `409 idempotent_replay_unavailable` |
| Key missing | `428 idempotency_key_required` |

Routing changes also pass the key into the database transition, so a replay after the 24 hours cannot apply a transition twice.

## ETags and concurrency

Resources return a strong `ETag`. For versioned rows it is `"<row_version>"`; otherwise it is a 16-character hash.

- `PUT` and `PATCH` on policy objects (continuity plans, chains, capture policies, rules, tenant settings) require `If-Match`. A missing header is `428 precondition_required`. A mismatch is `412 precondition_failed`, with the current representation in the body.
- `If-Match: *` creates only. Against an existing row it is a `412`, so a client can never overwrite policy blindly.
- Reads honour `If-None-Match` and answer `304`.
- Incident actions accept `expected_routing_version`. If the agent's routing moved on, the response is `409 stale_precondition` with the current state and version.

## Paging

Lists use opaque keyset cursors:

```
GET /api/v1/alerts?state=resolved&limit=100&cursor=eyJ2Ijoy...
```
```json
{ "data": [ ... ], "next_cursor": "eyJ2Ijoy...", "has_more": true }
```

- `limit` defaults to 50; the maximum is 200.
- The next page is also given in a `Link` header.
- A cursor is bound to the route, the sort order and the filters. Replaying it with different filters is `400 cursor_filter_mismatch`. A damaged cursor is `400 invalid_cursor`.
- Unknown filter values are `422 validation_failed`. They are never ignored.

## Audit receipts

Any `2xx` that wrote an audit row carries `X-Sibyl-Audit-Receipt: <tenant>:<seq>:<hash>`. It points to the row, so a client can prove its action was recorded. Every response carries `X-Request-Id`.

## Server-Sent Events

One stream carries every outbox event a principal may see:

```bash
curl -sN "$SIBYL/api/v1/events/stream?topics=incident,approval,handoff" -H "Authorization: Bearer $SESSION"
```

| Parameter | Meaning |
|---|---|
| `topics` | Comma-separated topics or event names. Topics: `policy`, `killswitch`, `graph`, `health`, `alert`, `provider_incident`, `incident`, `approval`, `handoff`, `erasure`. Events include `alert.fired`, `incident.updated`, `approval.requested`, `handoff.queued`, `killswitch.pulled` and the others in `sibyl_schemas/_bus.py`. |
| `agent_id` | Only events about this agent |
| `since` | Start from a time within the last 7 days, instead of the head |
| `Last-Event-ID` (header) | Resume after a cursor. Cursors look like `<xid>\|<uuid>`. |

**What a stream sends:**

- Frames are `id:` (the cursor), `event:` (the event type) and `data:` (JSON).
- Payloads are references and versions only. Fetch the object through its authorised `GET`.
- A `: ping` heartbeat arrives every 15 seconds. Each heartbeat re-checks the credential, and a revoked session or key ends the stream.
- Connections end after 1 hour. The `retry: 3000` hint tells clients to reconnect with `Last-Event-ID`.
- A slow client whose 1,000-frame buffer fills receives `event: reset` `{"reason":"slow_consumer"}`, and the stream ends. Events are never dropped silently.
- A resume cursor that no longer exists gets `event: reset` `{"reason":"cursor_expired","oldest":...}`. Back-fill from the list routes, then reconnect.

**Who sees what.** Humans need `agents:read` and see every topic, filtered by their groups. API keys need `routing:read` and see only `policy` and `killswitch` events; a bound key sees only its own agent. A session may hold 20 open streams and a key 5. Beyond that the response is `429 stream_limit`.

Streams read only rows below the database's commit horizon. That ordering guarantee has an operational cost; see [SSE or outbox stalled](../../ops/runbooks/sse-outbox-stalled.md).

## Rate limits

Limits are token buckets, counted per replica in Phase 1. Responses carry IETF `RateLimit-Policy` and `RateLimit` headers, and `Retry-After` when refused.

| Policy | Quota |
|---|---|
| `read` | 600 / min |
| `mutation` | 60 / min |
| `apikeys_create` | 10 / h |
| `credentials_create` | 10 / h |
| `tenant_key_rotate` | 6 / h |
| `erasure_create` | 5 / day |
| `payload_reveal` | 10 / min |
| `killswitch` | 30 / min |
| `break_glass_key` | 3 / 10 min |
| `break_glass_tenant` | 6 / h |
| `audit_jobs` | 10 / h |
| `sse` | 600 / min |
| `ingest` | 500 / s, burst 5,000 per tenant |
| `ingest_key_batches` | 20 / s |

Ingest also refuses when it is saturated (`429 ingest_saturated`, with `X-Sibyl-Backpressure`). The SDK waits for exactly the `Retry-After` interval and keeps the batch.

## Ingest in one paragraph

Telemetry goes to ingest, authenticated with an `ingest:write` key:

- OTLP/HTTP traces and logs, protobuf or JSON, use the GenAI semantic conventions v1.37.
- Sibyl's own events go as `{"schema": "sibyl-event/1", "events": [...]}`.

A batch can be up to 16 MiB raw and may be gzipped. Send `X-Sibyl-Batch-Id` to make retries safe; a repeated batch is answered with `X-Sibyl-Replayed: true`. Payload bodies are scrubbed, sealed with the tenant's payload key, and written to the BlobStore. Until the tenant has a capture policy, ingest answers `403 capture_policy_missing`.
