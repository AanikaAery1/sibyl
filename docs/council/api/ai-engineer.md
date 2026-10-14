# AI Engineer: Step 4 — Ingest contract and SDK design

Product: Sibyl (D19). Date: 2026-10-10. Scope: the ingest surface (`/v1/otlp/traces`, `/v1/otlp/logs`, `/v1/events`), the `sibyl.*` OTel namespace and normaliser, the Python SDK `sibyl-sdk` (Apache-2, D15), a TypeScript interface sketch, SDK↔gateway interplay, the `sibyl-handoff/1` schema, and the SDK test plan. Inputs: CHAIR-INITIAL.md (followed), DECISIONS D1–D29, ARCHITECTURE.md ADR-11 (OTel GenAI as the sole wire contract), my Step 3 `datamodel/ai-engineer.md` (carried forward, renamed), DATAMODEL.md §2.3/§4.3/§6.1 (telemetry rows, `call_merge`, ingest write path) and §4.1 (`api_key`). Phase 1 only.

Rename applied throughout (D19): `vigil-event/1` → `sibyl-event/1`, `vigil.*` → `sibyl.*`, `vigil-schemas` → `sibyl-schemas`, `vigil-sdk` → `sibyl-sdk`, module `vigil` → `sibyl`, `X-Vigil-*` → `X-Sibyl-*`, `$id` base `https://sibyl.dev/schemas/`. Document names: `sibyl-checkpoint/1`, `sibyl-handoff/1` (was `vigil-handoff-packet/1`), `sibyl-health/1`, `sibyl-feature-snapshot/1`, `sibyl-label/1`. Nothing structural changes in the rename except the two additive items in §2.4 (U1 nullable `agent_id`; three new attributes).

Governing rule, unchanged from Step 3: **one canonical event, two encodings in, one authority per field.** OTLP is the contract (ADR-11); `/v1/events` is a thin JSON adapter into the same normaliser; nothing downstream reads raw spans; captured content is always a `PayloadRef` into BlobStore (R19). The SDK is a thin layer over the OpenTelemetry SDK and never blocks the caller.

---

## 1. Ingest contract

### 1.1 Routes

| Route | Body | Content types | Scope | Success | Who sends |
|---|---|---|---|---|---|
| `POST /v1/otlp/traces` | OTLP `ExportTraceServiceRequest` | `application/x-protobuf`, `application/json` (OTLP/JSON); `Content-Encoding: gzip` accepted | `ingest:write` | `200` with `ExportTraceServiceResponse` (empty or `partial_success`) | sibyl-sdk, gateway, any OTel collector / third-party GenAI instrumentor |
| `POST /v1/otlp/logs` | OTLP `ExportLogsServiceRequest` | same | `ingest:write` | `200` with `ExportLogsServiceResponse` | sibyl-sdk (buffer/gap reports), legacy instrumentors that emit `gen_ai.*` content as log events |
| `POST /v1/events` | `sibyl-event/1` JSON batch (§1.6) | `application/json`; gzip accepted | `ingest:write` (`handoff:write` additionally for `handoff.requested`) | `202` with `{accepted, rejected[], warnings[]}` | sibyl-sdk for non-span documents (checkpoints, handoff requests, feedback, outcomes); shells, cron jobs, languages without an OTel SDK |

Only these three. No metrics endpoint in Phase 1: the two SDK counters from Step 3 (`sibyl.sdk.dropped_spans`, `sibyl.sdk.buffer_bytes`) travel as a log record on `/v1/otlp/logs` (§1.7). `GET /v1/otlp/*` is 405. All routes are served by the `ingest` container (ARCHITECTURE §3), which has no database role beyond `sibyl_ingest`.

Scope name: DATAMODEL §4.1 freezes the `api_key.scopes` set as `{telemetry:write, gateway:proxy, route:read, handoff:write, registry:read, registry:write, killswitch:pull}` (pre-R21 names). The chair's brief says `ingest:write`. This document now uses **`ingest:write`** per chair ruling R21 (Step 3 names amended in `sibyl-schemas` value sets).

### 1.2 Authentication and identity

- `Authorization: Bearer <api_key>`. Key format `sbl_<env>_<prefix12>_<secret>` (R13 format with the D19 prefix; Q2). Ingest looks up `prefix12` globally, verifies HMAC-SHA-256 + pepper locally (R12), resolves `tenant_id`, `api_key_id`, bound `agent_id`, scopes, `env`. `401` on any failure, same body and timing for unknown prefix and bad secret.
- `X-Sibyl-Agent: <agent uuid | registered slug>` — optional; **narrows only** (R13): to the bound agent, or for a tenant-level key to any agent of that tenant. Widening → `403 agent_not_permitted`, batch rejected, `access.denied` audit row. Per-span `sibyl.agent_id` follows the same rule and overrides the header per span.
- `env` on the key must match `sibyl.env` on the resource (`live`/`test`) when present; mismatch is a per-event rejection `env_mismatch`, not a batch failure.
- Tenant gates (DATAMODEL §6.1 step 1): `tenant.status='erasing'` → `429 tenant_erasing` with `Retry-After: 3600`; no tenant-scope `capture_policy` row → `403 capture_policy_missing`. Both are RFC 9457 problem details.
- Key revocation takes effect within one snapshot refresh (≤ 2 s) because ingest subscribes to the same `policy_changed` outbox NOTIFY as api.

### 1.3 Request headers and limits

| Header | Required | Meaning |
|---|---|---|
| `Content-Type` | yes | as above |
| `Content-Encoding: gzip` | no | decompressed size enforced |
| `X-Sibyl-Batch-Id: <uuidv7>` | recommended | batch idempotency key (§1.5). SDK and gateway always send it |
| `X-Sibyl-Schema: sibyl-event/1` | `/v1/events` only | declared major; unsupported → `400 unsupported_schema` listing supported majors. For OTLP the scope attribute `sibyl.schema.version` plays this role |
| `X-Sibyl-Agent` | no | see §1.2 |
| `X-Sibyl-Capture-Owner: sdk\|gateway` | gateway only | which side carried the payload body for the call (§5) |
| `User-Agent` | yes | `sibyl-sdk/<ver> python/<ver>` or `sibyl-gateway/<ver>`; recorded as `ingest.instrumentor` when the OTel scope lacks a name |

Limits (per request; `413 payload_too_large` or `400 batch_too_large`, never partial):

| Limit | Value |
|---|---|
| Body, compressed | 4 MiB |
| Body, decompressed | 16 MiB |
| Spans per `/v1/otlp/traces` request | 2,000 |
| Log records per `/v1/otlp/logs` request | 1,000 |
| Events per `/v1/events` request | 1,000 (one `INSERT` statement, DATAMODEL §6.1 step 7) |
| Attributes per span | 256; a single string attribute 64 KiB |
| Content parts (`gen_ai.input.messages` etc.) per span, combined | 4 MiB after scrubbing; above that the body is truncated tail-first per part and `sibyl.payload.truncated=true` is set, original byte count kept in `payload.bytes_original` |
| Request timeout (server side) | 10 s; a batch that cannot commit in time returns `503` with `Retry-After` and **nothing is stored** (ack after commit only) |

### 1.4 Backpressure

Per-tenant token bucket at ingest: default 500 events/s sustained, burst 5,000, tunable per tenant (`tenant.ingest_rate_limit`, Phase 1 column request to database-architect; default applies if absent). Saturation of the ingest process (DB pool wait > 2 s, or in-flight batches > 64) is a second, global limiter.

| Condition | Status | Headers | Client behaviour |
|---|---|---|---|
| Tenant bucket empty | `429` | `Retry-After: <s>` (1–30), `X-Sibyl-Backpressure: tenant_rate_limit` | back off, keep batch, retry; SDK honours `Retry-After` exactly |
| Ingest saturated | `429` | `Retry-After: <s>`, `X-Sibyl-Backpressure: ingest_saturated` | same |
| Tenant erasing | `429` | `Retry-After: 3600`, `X-Sibyl-Backpressure: tenant_erasing` | SDK stops sending for this tenant until restart; logs once |
| Postgres unavailable | `503` | `Retry-After: 5` | retry with jitter |
| Malformed body / unsupported schema / widening agent | `400`/`403` | RFC 9457 body | never retried; SDK drops the batch and counts `dropped_spans{reason=rejected}` |

Retry semantics match the OTLP/HTTP spec (retryable: 429, 502, 503, 504; non-retryable: other 4xx). The SDK's exporter spools a 429/503 batch (§3.6) and emits an `observation.gap(cause=ingest_backpressure)` once the spool is non-empty for > 60 s.

### 1.5 Idempotency and dedupe keys

Three layers, all `ON CONFLICT DO NOTHING` shaped:

1. **Batch**: `X-Sibyl-Batch-Id` is cached per tenant for 24 h (Postgres `ingest_batch_seen(tenant_id, batch_id, response_sha256, received_at)`, small, 3-day partitions — column request to database-architect). A replayed batch returns the **cached response** with `X-Sibyl-Replayed: true` and does no writes. This is what makes spool replay after a timeout safe.
2. **Event**: `sibyl-event/1.event_id` is the `events` PK; per-type idempotency keys from Step 3 §1 are unchanged (e.g. `(tenant_id, task_id, phase)` for `agent.invoke`, `(tenant_id, task_id, seq)` for `checkpoint`, `(tenant_id, packet_id)` for `handoff.requested`). The normaliser derives `event_id` deterministically for spans: `uuidv7` whose random bits are `sha256(tenant_id ‖ trace_id ‖ span_id ‖ source)[0:10]` and whose time bits come from span end time, so the same span replayed twice yields the same `event_id`.
3. **Call**: `gen_ai.request` merges on `(tenant_id, call_id)` in `call_merge` (DATAMODEL §6.1 step 6). Contribution after flush → `events_rejected('late_contribution')`; raw span kept.

Raw spans: BlobStore path `tenant/{tenant_id}/{date}/raw_batch/{batch_id}.bin` (one object per batch), derivable, so a raw span's identity is `(tenant_id, trace_id, span_id)` with no separate row.

### 1.6 Partial success

OTLP (`/v1/otlp/*`): `200` with `ExportTraceServiceResponse.partial_success = {rejected_spans: N, error_message: "<json>"}` where `error_message` is a compact JSON array `[{"trace_id","span_id","reason"}]` (max 100 entries, then `"+K more"`), because the OTLP response has no structured per-item slot. Fully accepted → `200` with an empty body (spec).

`/v1/events`: `202`

```json
{
  "schema": "sibyl-ingest-response/1",
  "batch_id": "019276c0-0000-7000-8000-000000000001",
  "accepted": 412,
  "rejected": [
    { "index": 17, "event_id": "019276c0-…-0011", "reason": "schema_invalid", "detail": "attrs.latency_ms: -3 is less than the minimum of 0" },
    { "index": 90, "event_id": "019276c0-…-005a", "reason": "outside_retention" }
  ],
  "warnings": ["semconv 1.36 attribute gen_ai.system mapped to gen_ai.provider.name on 3 events"],
  "replayed": false
}
```

`reason` is the DATAMODEL `events_rejected.reason` set: `schema_invalid, missing_required, unknown_type, late_contribution, outside_retention, no_partition, capture_policy_missing, tenant_erasing`, plus two ingest-only values that I ask database-architect to add to the CHECK: `env_mismatch`, `agent_not_permitted`. Rejected events are written to `events_rejected` with a 2 KB `head` and the raw batch ref; they count into the loss SLI. A batch is never all-or-nothing except for the 4xx/413 conditions in §1.3.

### 1.7 What each endpoint carries

**`/v1/otlp/traces`** — every span kind the normaliser understands (Step 3 §3, unchanged): `gen_ai.operation.name ∈ {chat, text_completion, embeddings, generate_content}` → `gen_ai.request`; `execute_tool` → `tool.call`; `invoke_agent` → `agent.invoke`; plus Sibyl-only span names emitted by the SDK and gateway: `sibyl.checkpoint`, `sibyl.policy.decision`, `sibyl.handoff.requested`, `sibyl.feedback`, `sibyl.task.outcome`. Anything else is raw-only with a `dead_letter` reason.

**`/v1/otlp/logs`** — log records with `event.name` in:

| `event.name` | Normalises to | Notes |
|---|---|---|
| `gen_ai.client.inference.operation.details` (semconv 1.37) | merged into the `gen_ai.request` of the same `trace_id/span_id` as content parts | for instrumentors that put content on events, not spans |
| `gen_ai.content.prompt`, `gen_ai.content.completion` (≤ 1.36 legacy) | same | accepted, warned |
| `sibyl.sdk.buffer` | `observation.gap` synthesis | attrs: `sibyl.sdk.dropped_spans`, `sibyl.sdk.buffer_bytes`, `sibyl.sdk.spool_bytes`, `sibyl.emitter_id`, window start/end |
| `sibyl.sdk.replay` | closes an `observation.gap` | `events_replayed`, `events_dropped` |

Unknown `event.name` → raw-only, `dead_letter`.

**`/v1/events`** — `{"schema":"sibyl-event/1","events":[…]}` where each element is a full `sibyl-event/1` envelope **minus** the ingest-authored fields (`observed_at`, `ingest`), which the client must not send (`400` if present). Content is never inline: an event that needs a body carries `attrs.payload_inline` — a base64 or UTF-8 string ≤ 4 MiB plus `content_type` and `parts` — which ingest scrubs, encrypts, writes to BlobStore and replaces with the `PayloadRef` before the row is written. `payload_inline` exists only on the wire, never in `attrs` (R19 CHECK stands). Checkpoint documents and handoff packets ride as `payload_inline` with `content_type: application/vnd.sibyl.checkpoint+json` / `application/vnd.sibyl.handoff+json`.

### 1.8 How spans map to DATAMODEL rows

| OTel span field | `sibyl-event/1` | `events` column | Notes |
|---|---|---|---|
| `trace_id` (16 B) | `trace_id` hex32 | `trace_id uuid` | byte-identical cast |
| `span_id`, `parent_span_id` | hex16 | `span_id bytea(8)`, `parent_span_id` | |
| `end_time_unix_nano` | `ts` | `ts` (partition key) | span **end**; `is_late` generated from `received_at − ts > 120 s` |
| `end − start` | `attrs.latency_ms` | `latency_ms` | |
| `status.code=ERROR`, `error.type` | `attrs.status`, `attrs.error_type` | `status`, `error_type`, `error_class` | `error_class` derived: 429→`rate_limit`, 5xx→`server_error`, timeout→`timeout`, 4xx→`client_error`, policy rejections→`blocked` |
| `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model` | `attrs.provider`, `request_model`, `response_model` | `provider`, `model`, `response_model` | unseen `(provider, model)` → `model` row `is_discovered` |
| `gen_ai.usage.*` | `attrs.usage` | `tokens_in`, `tokens_out`; rest in `attrs` | cost computed at ingest → `cost_usd` |
| `sibyl.agent_id` / header / key | `agent_id` | `agent_id`, `agent_version_id`, `identity_version`, `tools_hash` | resolution order §2.3; version columns from the registry at commit |
| `sibyl.task_id`, `sibyl.call_id` | `task_id`, `call_id` | same | `call_id` is the `call_merge` key |
| `sibyl.emitter_id`, `sibyl.seq` | same | `emitter_id`, `seq` | |
| `sibyl.capture.mode`, `sibyl.redaction.*` | `capture_mode`, `redaction_profile` | `capture_mode`, `redaction_profile_hash` | hash = sha256 of the immutable tenant profile (R15) |
| `sibyl.policy.*` | `policy_state` | `policy_state`, `policy_version` | |
| `sibyl.route.decision` | `attrs.route.decision` | `route_decision` | |
| `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions`, `gen_ai.tool.*` bodies | `attrs.payload` (`PayloadRef`) | `payload_ref_id`, `payload_sha256`, `payload_bytes` | body → BlobStore, row in `payload_refs(kind=span_content, source_kind=event)` committed first |
| whole batch | `ingest.raw_span_refs` (derived, not stored) | `raw_ref_id` | one `payload_refs(kind=raw_batch)` per request |
| scope `name/version`, `schema_url`, `sibyl.semconv.version` | `ingest.instrumentor`, `ingest.semconv_version` | `ingest jsonb`, `semconv_version`, `normaliser_version` | |
| everything else | `attrs` | `attrs jsonb ≤ 4 KB` | no content keys (R19 CHECK) |

Order inside the transaction is DATAMODEL §6.1 steps 1–9 verbatim; this document adds step 0 (batch-id lookup) and step 2a (`payload_inline` extraction).

---

## 2. The `sibyl.*` namespace and the normaliser

### 2.1 GenAI semconv v1.37.0 attributes relied on (D25)

Required for a span to become an event (else raw-only): `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, valid ids, start+end timestamps. Expected (missing → `ingest.warnings`): `gen_ai.response.model`, `gen_ai.response.finish_reasons`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.conversation.id`, `gen_ai.agent.id|name`, `error.type`, `server.address|port`. Optional: `gen_ai.response.id`, `gen_ai.request.{temperature,top_p,top_k,max_tokens,seed,stop_sequences,frequency_penalty,presence_penalty,choice.count}`, `gen_ai.output.type`, `gen_ai.openai.request.service_tier`, `gen_ai.data_source.id`. Tool spans: `gen_ai.tool.name` (required), `gen_ai.tool.call.id`, `gen_ai.tool.type`, `gen_ai.tool.description`. Content: `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions` (span attributes in 1.37) or the `gen_ai.client.inference.operation.details` log event. The full translation table including legacy spellings (`gen_ai.system`, OpenLLMetry `gen_ai.prompt.N.*`, OpenInference `llm.*`) is Step 3 §3 and moves unchanged into `sibyl-schemas/normaliser/semconv-1.37.0.yaml`.

### 2.2 `sibyl.*` attributes (renamed from `vigil.*`; three additions marked +)

| Attribute | Type | Lands in |
|---|---|---|
| `sibyl.tenant_id` | string(uuid) | ignored for authority (key wins); mismatch → `access.tenant_mismatch` audit |
| `sibyl.agent_id` | string(uuid or slug) | `agent_id` after resolution |
| `sibyl.task_id` | string(uuid) | `task_id` |
| `sibyl.call_id` | string(uuid) | `call_id` (merge key) |
| `sibyl.source` | `sdk\|gateway\|otel` | `source` |
| `sibyl.emitter_id`, `sibyl.seq` | string, int | `emitter_id`, `seq` |
| `sibyl.env` + | `live\|test` | checked against key `env` |
| `sibyl.capture.mode` | `full\|redacted\|metadata` | `capture_mode` |
| `sibyl.redaction.profile`, `.version`, `.rules` (string[]), `.secrets_scrubbed` (int) | — | `redaction_profile` |
| `sibyl.policy.state`, `.version`, `.fail_mode`, `.snapshot_age_s` | string, int, string, double | `policy_state` |
| `sibyl.route.decision`, `.reason`, `.from.provider`, `.from.model`, `.to.*`, `.transition_id` | strings | `attrs.route` |
| `sibyl.retry.attempt`, `.inline_fallback_used`, `.breaker_state` | int, bool, string | `attrs.retry` |
| `sibyl.ratelimit.{limit,remaining,reset}_{requests,tokens}` | int ×6 | `attrs.ratelimit` |
| `sibyl.ttfb_ms`, `sibyl.streamed` | double, bool | `attrs.ttfb_ms`, `attrs.streamed` |
| `sibyl.model.context_limit` | int | `attrs.context.model_context_limit` |
| `sibyl.checkpoint.{id,seq,step_index,step_name,state_bytes,state_schema,ref}` | — | `checkpoint` attrs |
| `sibyl.tool.side_effect_class`, `sibyl.mcp.server` | string | `tool.call` attrs |
| `sibyl.prompt.version`, `sibyl.task.outcome`, `sibyl.feedback.score`, `sibyl.feedback.scale`, `sibyl.eval.sample` | string, string, double, string, bool | as named |
| `sibyl.payload.truncated` +, `sibyl.payload.bytes_original` + | bool, int | `attrs.payload` |
| `sibyl.sdk.version` + | string | `ingest.instrumentor` when scope name is absent |
| Scope attributes: `sibyl.schema.version`, `sibyl.semconv.version` | string | declared major; `ingest.semconv_version` |
| Log attributes: `sibyl.sdk.dropped_spans`, `sibyl.sdk.buffer_bytes`, `sibyl.sdk.spool_bytes` | int | `observation.gap` synthesis |

Cost is never on the wire. `sibyl.tenant_id` is never trusted.

### 2.3 Normaliser rules (ordered, deterministic, versioned `normaliser/1.x`)

1. **Decode** OTLP (protobuf or JSON) or the `/v1/events` batch; write the raw batch object first (`payload_refs.kind=raw_batch`).
2. **Classify each span** by `gen_ai.operation.name` after applying the legacy map for the scope's `(name, version, schema_url)`; unknown → raw-only, `dead_letter{reason}` metric.
3. **Resolve identity**, in order: per-span `sibyl.agent_id` → `gen_ai.agent.id` → `X-Sibyl-Agent` header → key's bound agent → auto-register `unclaimed/<hash8>` provisional agent and emit `agent.discovered(discovered_via=span_attr|gateway_header|api_key_default)`. Any resolution that widens beyond the key's permission → reject `agent_not_permitted`.
4. **Nullable `agent_id`** (DATAMODEL U1, adopted): `provider.status` and `observation.gap` may carry `agent_id: null`; every other type requires it. Additive within `/1`.
5. **Scrub** every content part with the unconditional secrets profile (cloud keys, bearer tokens, private keys, connection strings → `[SECRET:<hash8>]`), then the tenant's active `redaction_profile`; record `rules_fired`, `secrets_scrubbed`. Scrubbing runs at ingest **even if** the SDK already scrubbed (idempotent on already-replaced tokens).
6. **Apply capture policy**: effective mode = most restrictive of (span's `sibyl.capture.mode`, tenant/agent `capture_policy`). `metadata` → drop bodies, keep `content_hashes` and `output_chars`; `redacted` → store after profile; `full` → store after the secrets floor.
7. **Hash and store** content (`sha256` of post-redaction plaintext), encrypt under the tenant payload DEK, write `payload_refs`, emit `PayloadRef`.
8. **Derive**: `latency_ms`, `error_class`, `context.utilisation`, `ratelimit.headroom`, `output_chars`, `content_hashes`, `cost_usd` + `cost_source` from the tenant price table.
9. **Build the envelope**: deterministic `event_id` (§1.5), `observed_at = clock_timestamp()`, `ingest{normaliser_version, semconv_version, instrumentor, warnings}`.
10. **Validate** against `sibyl-event/1` (`additionalProperties: false`); fail → `events_rejected(schema_invalid)`.
11. **Route**: `gen_ai.request` → `call_merge` upsert; everything else → `events` multi-row insert. Commit; respond.

Legacy acceptance is additive and never changes `/1`; a semconv bump at freeze (D25) is a new YAML table and a `normaliser_version` bump, with conformance fixtures per instrumentor version.

### 2.4 Changes to `sibyl-event/1` versus Step 3 (all additive)

- `agent_id`: `oneOf [uuid, null]`, with `if type ∈ {provider.status, observation.gap} … else required non-null` (U1).
- `attrs_gen_ai_request.payload`: `PayloadRef` gains optional `truncated: boolean`, `bytes_original: integer`.
- Envelope `ingest.instrumentor` examples now read `sibyl-sdk/0.1.0`, `gateway/0.1.0`.
- `agent.discovered.discovered_via` enum unchanged.
Everything else in Step 3 §2 stands with the `$id` renamed to `https://sibyl.dev/schemas/sibyl-event/1`.

---

## 3. Python SDK `sibyl-sdk`

### 3.1 Principles

Thin layer on `opentelemetry-sdk`; OTLP/HTTP exporter to `/v1/otlp/traces`; non-span documents via `/v1/events`. Dependencies: `opentelemetry-sdk`, `opentelemetry-exporter-otlp-proto-http`, `httpx`, `pydantic>=2`, `cryptography` (Ed25519 verify), `sibyl-schemas` (the only shared package, ADR-13). Python ≥ 3.10, sync and asyncio. Apache-2 (D15). Zero config beyond `init()`; env vars `SIBYL_API_KEY`, `SIBYL_ENDPOINT`, `SIBYL_AGENT_ID`, `SIBYL_CAPTURE_MODE`, `SIBYL_ENV` are read when the argument is omitted. Never raises into application code except `SibylKilled` / `SibylPolicyUnavailable` (fail-closed agents only) and `SibylConfigError` at `init()`.

### 3.2 Public API stub

```python
# sibyl/__init__.pyi — public surface of sibyl-sdk 0.1 (Phase 1)
from __future__ import annotations
from contextlib import AbstractContextManager, AbstractAsyncContextManager
from datetime import datetime, timedelta
from typing import (
    Any,
    Awaitable,
    Callable,
    Iterable,
    Literal,
    Mapping,
    ParamSpec,
    Sequence,
    TypeVar,
    overload,
)
from uuid import UUID

__version__: str

CaptureMode = Literal["full", "redacted", "metadata"]
FailMode = Literal["open", "closed"]
SideEffectClass = Literal["none", "read", "write", "external", "unknown"]
ToolType = Literal["function", "mcp", "a2a", "http", "retrieval", "code", "extension", "datastore"]
Outcome = Literal["success", "partial", "failure", "abandoned", "handed_off"]
FailureMode = Literal[
    "provider_outage",
    "latency_degradation",
    "quality_collapse",
    "prompt_injection",
    "policy_violation",
    "tool_failure",
    "data_source_failure",
    "infinite_loop",
    "cost_runaway",
    "permission_error",
    "model_deprecation",
    "silent_drift",
]
P = ParamSpec("P")
R = TypeVar("R")


class SibylError(Exception): ...


class SibylConfigError(SibylError): ...


class SibylKilled(SibylError):
    """Raised by wrapped clients when the agent's policy state is `killed` (kill beats fail-open)."""

    agent_id: UUID
    policy_version: int
    reason: str


class SibylPolicyUnavailable(SibylError):
    """Raised only for fail-closed agents when no snapshot is fresh within max_stale."""


class ScrubContext:
    part: Literal[
        "input_messages",
        "output_messages",
        "system_instructions",
        "tool_definitions",
        "tool_args",
        "tool_result",
        "state",
        "comment",
    ]
    agent_id: UUID
    task_id: UUID | None
    call_id: UUID | None


ScrubHook = Callable[[str, ScrubContext], str]


class ExporterConfig:
    def __init__(
        self,
        *,
        max_queue_spans: int = 10_000,  # in-memory ring, drop-oldest
        max_queue_bytes: int = 32 * 1024 * 1024,
        batch_size: int = 512,
        schedule_delay: timedelta = ...,  # 2 s
        export_timeout: timedelta = ...,  # 10 s
        spool_dir: str | None = None,  # local disk spool, off by default
        spool_max_bytes: int = 256 * 1024 * 1024,
        spool_max_age: timedelta = ...,  # 7 d
        critical_lane: bool = True,  # checkpoints / handoffs / policy decisions drain first
        shutdown_flush_timeout: timedelta = ...,  # 2 s, bounded
    ) -> None: ...


class PolicyConfig:
    def __init__(
        self,
        *,
        poll_interval: timedelta = ...,  # ttl/3 → 20 s
        max_stale: timedelta = ...,  # 15 min
        public_key: str
        | None = None,  # base64 Ed25519; None → fetched once at init and pinned (TOFU, Q3)
        cache_dir: str | None = None,  # ~/.sibyl/policy/<agent_id>.json
        enforce_kill_switch: bool = True,
    ) -> None: ...


class Client:
    """Returned by init(); module-level functions delegate to the default client."""

    agent_id: UUID
    tenant_id: UUID | None
    capture_mode: CaptureMode
    endpoint: str

    def flush(self, timeout: timedelta | None = None) -> bool: ...
    def shutdown(self, timeout: timedelta | None = None) -> None: ...
    def stats(self) -> ExporterStats: ...


class ExporterStats:
    queued_spans: int
    queued_bytes: int
    dropped_spans: int
    spooled_bytes: int
    last_export_at: datetime | None
    last_error: str | None
    backpressure_until: datetime | None


def init(
    api_key: str | None = None,
    *,
    endpoint: str | None = None,  # https://ingest.<tenant-host>  (no path)
    agent_id: str
    | UUID
    | None = None,  # uuid or registered slug; may be omitted if the key is agent-bound
    capture_mode: CaptureMode = "full",  # D12: explicit; tenant policy may further restrict
    env: Literal["live", "test"] | None = None,
    instrument: Sequence[Literal["openai", "anthropic", "mcp", "httpx"]] | Literal["auto"] = "auto",
    scrub: ScrubHook
    | Sequence[ScrubHook]
    | None = None,  # runs AFTER the unconditional secrets scrubber
    exporter: ExporterConfig | None = None,
    policy: PolicyConfig | None = None,
    resource_attributes: Mapping[str, str] | None = None,
    tracer_provider: Any | None = None,  # reuse an existing OTel TracerProvider
    fail_mode: FailMode | None = None,  # override only for local dev; registry wins in production
) -> Client: ...


def get_client() -> Client: ...
def flush(timeout: timedelta | None = None) -> bool: ...
def shutdown(timeout: timedelta | None = None) -> None: ...


# ---- identity + task boundary -------------------------------------------------
class AgentRun(AbstractContextManager["AgentRun"], AbstractAsyncContextManager["AgentRun"]):
    agent_id: UUID
    task_id: UUID
    parent_task_id: UUID | None
    trace_id: str
    goal: str | None
    steps: int
    tool_calls: int
    model_calls: int
    cost_usd: float

    def set_goal(self, goal: str) -> None: ...
    def outcome(
        self, outcome: Outcome, *, reason: str | None = None, rework: bool | None = None
    ) -> None: ...
    def handoff(
        self, packet: HandoffPacket
    ) -> UUID: ...  # emits handoff.requested; returns packet_id
    def cancel(self, reason: str | None = None) -> None: ...


def agent(
    name: str | None = None,
    *,
    agent_id: str
    | UUID
    | None = None,  # defaults to init() agent; another id must be permitted by the key
    task_id: str | UUID | None = None,  # resume an existing task
    goal: str | None = None,
    conversation_id: str | None = None,
    attributes: Mapping[str, Any] | None = None,
) -> AgentRun: ...


"""Opens an `invoke_agent` span: agent.invoke(phase=start) on enter, phase=end on exit with
status ok|error|handed_off|cancelled. Nested use sets parent_task_id. Sync and async."""


def current_run() -> AgentRun | None: ...


# ---- tools -------------------------------------------------------------------
@overload
def tool(fn: Callable[P, R], /) -> Callable[P, R]: ...
@overload
def tool(
    *,
    name: str | None = None,
    tool_type: ToolType = "function",
    side_effect: SideEffectClass = "unknown",
    capture_args: bool | None = None,
    capture_result: bool | None = None,
    mcp_server: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


"""Wraps sync or async callables in an `execute_tool` span (tool.call). Exceptions propagate
unchanged and mark status=error with error.type = exception class name."""


def instrument(client: Any, *, capture_mode: CaptureMode | None = None) -> Any: ...


"""Explicitly wrap an openai.OpenAI / AsyncOpenAI / anthropic.Anthropic / AsyncAnthropic instance,
or an mcp ClientSession. Idempotent: detects existing OTel instrumentation and adds only the
Sibyl span processor + headers, never a second wrapper."""


# ---- checkpoints -------------------------------------------------------------
class Step:  # declared step
    def __init__(
        self,
        step: str,
        *,
        index: int | None = None,
        description: str | None = None,
        output: Any | None = None,
        inputs_needed: Sequence[str] = (),
        blocked_on: str | None = None,
        tool_name: str | None = None,
    ) -> None: ...


class SideEffect:
    def __init__(
        self,
        kind: Literal[
            "external_write",
            "message_sent",
            "payment",
            "file_written",
            "db_write",
            "ticket_created",
            "api_call",
            "unknown",
        ],
        *,
        target: str | None = None,
        idempotency_key: str | None = None,
        reversible: bool | None = None,
    ) -> None: ...


def checkpoint(
    state: Mapping[str, Any] | Any,  # JSON-serialisable or pydantic model
    *,
    step: str | None = None,
    step_index: int | None = None,
    completed: Sequence[Step | str] = (),
    pending: Sequence[Step | str] = (),
    side_effects: Sequence[SideEffect] = (),
    state_schema: str | None = None,  # 'app:<name>/v<n>' | 'pydantic:<module.Class>' | 'json'
    run: AgentRun | None = None,
) -> UUID: ...


"""Emits a sibyl-checkpoint/1 document via /v1/events (critical lane) and a `checkpoint` span.
State ≤ 64 KiB post-scrub is inline; larger state ships as payload_inline. Returns checkpoint_id."""


# ---- handoff -----------------------------------------------------------------
class HandoffPacket:  # pydantic model generated from sibyl-handoff/1; validates on construction
    packet_id: UUID
    fidelity: Literal["checkpoint", "request_only"]

    def model_dump_json(self) -> str: ...


class handoff:
    @staticmethod
    def packet(
        *,
        reason: str,  # plain language, 20–1000 chars
        failure_mode: FailureMode,
        next_action: str,  # one imperative sentence
        goal: str | None = None,  # defaults to run.goal
        pending: Sequence[Step | str] | None = None,  # defaults to last checkpoint's pending
        deadline: datetime | None = None,  # None → tier RTO at the control plane (D23)
        run: AgentRun | None = None,
        from_checkpoint: UUID | Literal["latest", None] = "latest",
    ) -> HandoffPacket: ...
    @staticmethod
    def request(packet: HandoffPacket, *, run: AgentRun | None = None) -> UUID: ...

    """Emits handoff.requested(trigger=sdk_explicit, assembled_by=sdk) with the packet as payload.
    Requires handoff:write on the key; otherwise the SDK logs once and emits only the event (Q4)."""


# ---- labels ------------------------------------------------------------------
def feedback(
    score: float,
    *,
    scale: str = "thumbs",
    target: Literal["trace", "task", "call", "packet"] = "task",
    target_id: str | UUID | None = None,
    rater: Literal["end_user", "operator"] = "end_user",
    comment: str | None = None,
    tags: Sequence[str] = (),
) -> UUID: ...
def outcome(
    outcome: Outcome,
    *,
    reason: str | None = None,
    rework: bool | None = None,
    run: AgentRun | None = None,
) -> None: ...


# ---- policy / kill switch ------------------------------------------------------
class PolicySnapshot:
    agent_id: UUID
    policy_version: int
    issued_at: datetime
    ttl_s: int
    state: Literal["active", "degraded", "failover", "quarantined", "killed", "held"]
    fail_mode: FailMode
    capture_mode: CaptureMode
    tier: int
    primary: dict[str, str]
    fallback_chain: list[dict[str, str]]

    @property
    def freshness(self) -> Literal["fresh", "stale", "expired", "unavailable"]: ...


class policy:
    @staticmethod
    def current(agent_id: str | UUID | None = None) -> PolicySnapshot | None: ...
    @staticmethod
    def check(agent_id: str | UUID | None = None) -> None: ...

    """Raises SibylKilled if state == killed (any freshness). Raises SibylPolicyUnavailable only
    when fail_mode == closed and freshness == unavailable. Called automatically before every
    wrapped provider call; exposed for apps that call providers through their own HTTP client."""

    @staticmethod
    def on_change(callback: Callable[[PolicySnapshot], None]) -> Callable[[], None]: ...
```

### 3.3 Usage example (30 lines)

```python
import os, sibyl
from openai import OpenAI

sibyl.init(
    os.environ["SIBYL_API_KEY"],
    endpoint="https://ingest.meridian.example",
    agent_id="quote-assistant",
    capture_mode="full",
    scrub=lambda text, ctx: text.replace(os.environ.get("CRM_TENANT", "\0"), "[CRM]"),
)
client = OpenAI()  # auto-instrumented: sibyl.* headers + gen_ai span on every call


@sibyl.tool(side_effect="read")
def lookup_order(order_id: str) -> dict:
    return crm.get_order(order_id)


@sibyl.tool(side_effect="external", name="send_email")
def send_email(to: str, body: str) -> None:
    mailer.send(to, body)


def run_quote(rfq: dict) -> None:
    with sibyl.agent(goal=f"Quote order {rfq['order_id']}") as run:
        order = lookup_order(rfq["order_id"])
        sibyl.checkpoint(
            {"rfq": rfq, "order": order},
            step="lookup_order",
            completed=["parse_rfq", "lookup_order"],
            pending=["price_quote", "send_quote"],
        )
        try:
            draft = client.chat.completions.create(
                model="gpt-5-mini",
                messages=[{"role": "user", "content": f"Draft a quote for {order}"}],
            )
        except sibyl.SibylKilled:
            run.cancel("kill switch")
            raise
        except Exception as e:
            pkt = sibyl.handoff.packet(
                reason=f"Provider call failed while drafting the quote: {e}",
                failure_mode="provider_outage",
                next_action="Review the order and send the quote manually.",
            )
            run.handoff(pkt)
            return
        send_email(order["contact"], draft.choices[0].message.content)
        run.outcome("success")
```

### 3.4 Auto-instrumentation

`init(instrument="auto")` patches, if importable: `openai` (`chat.completions.create`, `embeddings.create`, `responses.create`, sync/async, streaming), `anthropic` (`messages.create`, `messages.stream`), `mcp` (`ClientSession.call_tool/list_tools/read_resource`), and the `httpx` transport those clients use (for header injection, §5). Each wrapped call: `policy.check()` → open `gen_ai.*` span with 1.37 attributes → inject `X-Sibyl-*` + `traceparent` into the outgoing request → on completion (last streamed chunk consumed, or exception) set usage/finish reasons/content per capture mode → end span. Streaming content is reassembled from chunks; `sibyl.ttfb_ms` is the first-chunk latency. If the client is already instrumented by OpenLLMetry/OpenInference (`_is_instrumented_by_opentelemetry` or a known wrapper type), Sibyl only adds its span processor (stamps `sibyl.*` from context onto their spans) and the header hook. Frameworks (LangGraph, OpenAI Agents SDK, CrewAI) are covered through their OTel exporters pointed at the Sibyl tracer provider; no framework-specific code in Phase 1.

### 3.5 Secrets scrub hook

Pipeline per content part: (1) **unconditional secrets scrubber** from `sibyl-schemas` (same regex set as ingest and gateway; replaces with `[SECRET:<hash8>]`; cannot be disabled or reordered); (2) user `scrub` hooks in order; (3) capture-mode gate (`metadata` → hashes only). Hooks receive the post-scrub text and a `ScrubContext`; exceptions in a hook are caught, counted (`scrub_hook_errors`), and the part is downgraded to `metadata` for that span (fail safe: never ship unscrubbed on hook failure). The SDK records `sibyl.redaction.rules` = `["secrets.*", "sdk.hook:<name>"]`. Ingest scrubs again (§2.3 step 5), which is idempotent.

### 3.6 Bounded non-blocking exporter

Two lanes over one OTLP exporter and one `/v1/events` client:

- **Telemetry lane**: `BatchSpanProcessor`-shaped ring buffer, `max_queue_spans` / `max_queue_bytes`, **drop-oldest** on overflow, counting `dropped_spans{reason=overflow}`.
- **Critical lane**: checkpoints, `handoff.requested`, `policy.decision`, `agent.invoke(end)`; bounded at 1,000 items, drop-oldest as well (but spooled first if a spool is configured); drains before the telemetry lane.
- Export loop: every `schedule_delay` or `batch_size`, one HTTP call per lane, gzip, `X-Sibyl-Batch-Id`; on 429/503 honour `Retry-After` and pause both lanes; on 4xx drop and count; on timeout keep the batch for replay (safe through §1.5 batch dedupe).
- **Disk spool (optional)**: when `spool_dir` is set, batches that fail export are appended as segment files (`<ts>-<batch_id>.otlp.gz`), capped by bytes and age, oldest segments deleted first; replay at startup and whenever the endpoint recovers, original timestamps preserved; the SDK emits `sibyl.sdk.replay` logs so ingest can close the gap. No spool → batches that cannot be exported are dropped after `export_timeout × 3`.
- Every 60 s, and whenever `dropped_spans` increments by ≥ 100, a `sibyl.sdk.buffer` log record is sent (critical lane).
- The application thread does **O(1)** work per span end (enqueue). `shutdown()` flushes for at most `shutdown_flush_timeout` (2 s default) then returns; an `atexit` hook calls it. Fork-safe: a `os.register_at_fork` hook re-creates the worker thread in the child.

### 3.7 Kill-switch check via signed snapshot poll

The SDK polls `GET /v1/policy/snapshot?agent_id=<id>` on the api with `If-None-Match` every `poll_interval` (20 s, ttl/3), using the same API key (requires `routing:read`; agent-bound telemetry keys are issued with `ingest:write routing:read handoff:write` by default — Q4). Response: the Ed25519-signed snapshot the gateway uses (ARCHITECTURE §4), filtered to one agent. The SDK verifies the signature against the pinned public key, rejects lower `policy_version`, caches to `cache_dir`, and derives `freshness` from `issued_at + ttl` (60 s) with grace 300 s then `max_stale` 15 min.

Semantics on every wrapped call (and on explicit `policy.check()`):

| Snapshot `state` | freshness | fail_mode | Result |
|---|---|---|---|
| `killed` | any (incl. expired/unavailable-after-killed) | any | `SibylKilled` raised; no provider request. **Kill beats fail-open** (ADR-9): a cached `killed` persists until a fresh snapshot says otherwise |
| `quarantined` | any | any | proceed; spans stamped `sibyl.policy.state`; `policy.decision(action=reject_quarantined)` only if the gateway rejects |
| other | fresh/stale | any | proceed; `sibyl.policy.*` stamped |
| other | expired | open | proceed; `policy.decision(action=forward_stale)` emitted once per minute per agent |
| other | expired/unavailable | closed | `SibylPolicyUnavailable` |
| none ever | — | open | proceed with `policy_state=unavailable`; one warning log |

The SDK does **not** route (no inline fallback in Phase 1; the gateway does that). `policy.on_change` lets apps react (e.g. pause a worker loop) when state moves to `killed` or `held`.

---

## 4. TypeScript SDK — interface sketch (Phase 1 types only, implementation Phase 2)

```ts
// @sibyl/sdk — on @opentelemetry/sdk-node; AsyncLocalStorage context; Node ≥ 20; no browser target
export type CaptureMode = "full" | "redacted" | "metadata";
export type FailMode = "open" | "closed";
export type SideEffectClass = "none" | "read" | "write" | "external" | "unknown";
export type Outcome = "success" | "partial" | "failure" | "abandoned" | "handed_off";
export type FailureMode = "provider_outage" | "latency_degradation" | "quality_collapse" | "prompt_injection"
  | "policy_violation" | "tool_failure" | "data_source_failure" | "infinite_loop" | "cost_runaway"
  | "permission_error" | "model_deprecation" | "silent_drift";

export interface ScrubContext { part: string; agentId: string; taskId?: string; callId?: string }
export type ScrubHook = (text: string, ctx: ScrubContext) => string;

export interface ExporterOptions {
  maxQueueSpans?: number; maxQueueBytes?: number; batchSize?: number; scheduleDelayMs?: number;
  exportTimeoutMs?: number; spoolDir?: string; spoolMaxBytes?: number; spoolMaxAgeMs?: number;
  shutdownFlushTimeoutMs?: number;
}
export interface PolicyOptions { pollIntervalMs?: number; maxStaleMs?: number; publicKey?: string; cacheDir?: string; enforceKillSwitch?: boolean }

export interface InitOptions {
  apiKey?: string; endpoint?: string; agentId?: string; captureMode?: CaptureMode; env?: "live" | "test";
  instrument?: Array<"openai" | "anthropic" | "mcp" | "fetch"> | "auto";
  scrub?: ScrubHook | ScrubHook[]; exporter?: ExporterOptions; policy?: PolicyOptions;
  resourceAttributes?: Record<string, string>; tracerProvider?: unknown;
}
export interface SibylClient {
  readonly agentId: string; readonly captureMode: CaptureMode;
  flush(timeoutMs?: number): Promise<boolean>; shutdown(timeoutMs?: number): Promise<void>; stats(): ExporterStats;
}
export interface ExporterStats { queuedSpans: number; queuedBytes: number; droppedSpans: number; spooledBytes: number; lastExportAt?: Date; lastError?: string }

export function init(options?: InitOptions): SibylClient;
export function instrument<T>(client: T, opts?: { captureMode?: CaptureMode }): T;

export interface AgentRun {
  readonly agentId: string; readonly taskId: string; readonly parentTaskId?: string; readonly traceId: string;
  setGoal(goal: string): void; outcome(o: Outcome, opts?: { reason?: string; rework?: boolean }): void;
  handoff(packet: HandoffPacket): Promise<string>; cancel(reason?: string): void;
}
export interface AgentOptions { name?: string; agentId?: string; taskId?: string; goal?: string; conversationId?: string; attributes?: Record<string, unknown> }
export function agent<T>(opts: AgentOptions, fn: (run: AgentRun) => Promise<T> | T): Promise<T>;
export function currentRun(): AgentRun | undefined;

export interface ToolOptions { name?: string; toolType?: string; sideEffect?: SideEffectClass; captureArgs?: boolean; captureResult?: boolean; mcpServer?: string }
export function tool<F extends (...a: any[]) => any>(fn: F, opts?: ToolOptions): F;

export interface Step { step: string; index?: number; description?: string; output?: unknown; inputsNeeded?: string[]; blockedOn?: string; toolName?: string }
export interface SideEffect { kind: string; target?: string; idempotencyKey?: string; reversible?: boolean }
export function checkpoint(state: unknown, opts?: { step?: string; stepIndex?: number; completed?: (Step | string)[]; pending?: (Step | string)[]; sideEffects?: SideEffect[]; stateSchema?: string; run?: AgentRun }): Promise<string>;

export interface HandoffPacket { readonly packetId: string; readonly fidelity: "checkpoint" | "request_only"; toJSON(): object }
export const handoff: {
  packet(opts: { reason: string; failureMode: FailureMode; nextAction: string; goal?: string; pending?: (Step | string)[]; deadline?: Date; run?: AgentRun; fromCheckpoint?: string | "latest" | null }): HandoffPacket;
  request(packet: HandoffPacket, opts?: { run?: AgentRun }): Promise<string>;
};
export function feedback(score: number, opts?: { scale?: string; target?: "trace" | "task" | "call" | "packet"; targetId?: string; rater?: "end_user" | "operator"; comment?: string; tags?: string[] }): Promise<string>;

export interface PolicySnapshot { agentId: string; policyVersion: number; issuedAt: Date; ttlS: number; state: "active" | "degraded" | "failover" | "quarantined" | "killed" | "held"; failMode: FailMode; captureMode: CaptureMode; tier: 1 | 2 | 3; freshness: "fresh" | "stale" | "expired" | "unavailable" }
export const policy: { current(agentId?: string): PolicySnapshot | undefined; check(agentId?: string): void; onChange(cb: (s: PolicySnapshot) => void): () => void };
export class SibylKilled extends Error { agentId: string; policyVersion: number }
export class SibylPolicyUnavailable extends Error {}
```

---

## 5. SDK ↔ gateway interplay (no double capture)

Both are Phase 1 (D2). An agent may run with SDK only, gateway only (`base_url` pointed at the gateway, raw OpenAI client), or both. The design makes "both" cost one event and one payload body.

**Outbound headers injected by the SDK** on every wrapped provider request (and stripped by the gateway before forwarding upstream; the gateway never forwards `X-Sibyl-*` or Sibyl's `traceparent` to a provider):

| Header | Value | Purpose |
|---|---|---|
| `traceparent` (W3C) | SDK span context | gateway span becomes a **child** of the SDK's `gen_ai` span; same `trace_id` |
| `X-Sibyl-Call-Id` | uuid, minted by the SDK | `call_merge` key; the gateway reuses it instead of minting |
| `X-Sibyl-Agent` | agent uuid/slug | narrows only (R13); gateway resolves identity identically to ingest |
| `X-Sibyl-Task-Id` | uuid | gateway stamps `sibyl.task_id` so a gateway-only contribution still joins the task |
| `X-Sibyl-Capture-Owner` | `sdk` when SDK `capture_mode ∈ {full, redacted}`, else `gateway` | tells the gateway whether to ship the body |
| `X-Sibyl-Policy-Version` | int the SDK last saw | gateway reports `sibyl.policy.version` divergence as an `ingest.warnings` entry (debugging aid, no enforcement) |

**Gateway behaviour on seeing `X-Sibyl-Call-Id`**: emit its `gen_ai` span with `sibyl.call_id` from the header, `sibyl.source=gateway`, parent = `traceparent`; carry `X-Sibyl-Capture-Owner` to ingest on the batch so the normaliser knows which contribution owns `payload`. When owner is `sdk`, the gateway still records `content_hashes` (sha256 of the bytes it saw after scrubbing) so ingest can verify the two sides saw the same content; mismatch → `ingest.warnings: content_hash_mismatch`, SDK body wins (authority table, Step 3 §1). When owner is `gateway` (SDK in `metadata` or absent), the gateway ships the body.

**Ingest merge** (unchanged authority table): SDK owns `task_id`, hierarchy, `conversation_id`, `prompt_version`; gateway owns `latency_ms`, `ttfb_ms`, `http_status`, `ratelimit.*`, `route.*`, `retry.*`, `server.*`, `response_id`, `usage.*`, `response_model`, `finish_reasons`, `error_type`; `capture_mode` and `redaction_profile` = the more restrictive. Health counts one call. A single-author call completes after the 5 s merge window.

**Without the headers** (raw client through the gateway, or SDK talking straight to the provider): each side is a single author; the gateway mints `call_id`; identity comes from key/header. No duplication is possible because there is only one span per call.

**Third-party instrumentors plus gateway**: an OpenLLMetry span and a gateway span for the same HTTP call share no `call_id`. Ingest links them by `(tenant_id, trace_id)` **and** parent/child relationship when the instrumentor propagates `traceparent` (OpenLLMetry and OpenInference both do through the HTTP client): the gateway span's parent is the instrumentor's `gen_ai` span → ingest treats the parent as the `otel` contribution, assigns the gateway's `call_id` to it, and merges. If no propagation, both are stored as separate `gen_ai.request` events with `ingest.warnings: possible_duplicate` and the worker's request count uses `source=gateway` rows only for agents that have a gateway route configured (registry flag `agent.via_gateway`). This is the one heuristic in the system; it is logged and visible.

**Policy state**: both sides stamp `sibyl.policy.*` from their own snapshot; the merged event keeps the gateway's (it enforced) and records the SDK's version in `attrs.policy_sdk_version` when they differ.

---

## 6. Handoff packet schema `sibyl-handoff/1`

Renamed from Step 3 `vigil-handoff-packet/1` with the step/side-effect `$defs` inlined so the schema validates standalone (contract tests load one file). Content is unchanged except `schema` const and `$id`s. Health `factor` is referenced from `sibyl-health/1`.

```json schema:sibyl-handoff
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sibyl.dev/schemas/sibyl-handoff/1",
  "title": "sibyl-handoff/1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "packet_id", "tenant_id", "agent_id", "task_id", "created_at", "fidelity", "goal", "original_input", "completed_steps", "pending_steps", "reason", "next_action", "deadline", "accountability", "redaction", "provenance"],
  "properties": {
    "schema": { "const": "sibyl-handoff/1" },
    "packet_id": { "$ref": "#/$defs/uuidv7" },
    "tenant_id": { "$ref": "#/$defs/uuid" },
    "agent_id": { "$ref": "#/$defs/uuid" },
    "agent_name": { "type": "string", "maxLength": 128 },
    "task_id": { "$ref": "#/$defs/uuid" },
    "created_at": { "type": "string", "format": "date-time" },
    "fidelity": { "enum": ["checkpoint", "request_only"] },
    "goal": { "type": "string", "minLength": 1, "maxLength": 2000 },
    "original_input": { "$ref": "#/$defs/output_ref" },
    "completed_steps": { "type": "array", "items": { "$ref": "#/$defs/completed_step" } },
    "pending_steps": { "type": "array", "items": { "$ref": "#/$defs/pending_step" } },
    "side_effects": { "type": "array", "items": { "$ref": "#/$defs/side_effect" } },
    "reason": {
      "type": "object", "additionalProperties": false,
      "required": ["plain_language", "trigger", "failure_mode"],
      "properties": {
        "plain_language": { "type": "string", "minLength": 20, "maxLength": 1000 },
        "failure_mode": { "$ref": "#/$defs/failure_mode" },
        "trigger": {
          "type": "object", "additionalProperties": false, "required": ["kind"],
          "properties": {
            "kind": { "enum": ["sdk_explicit", "rule", "a2a_state", "operator", "approval_timeout"] },
            "rule_id": { "type": "string", "pattern": "^[a-z][a-z0-9_]{2,40}$" },
            "alert_id": { "$ref": "#/$defs/uuid" },
            "health_snapshot_id": { "$ref": "#/$defs/uuidv7" },
            "factors": { "type": "array", "items": { "$ref": "https://sibyl.dev/schemas/sibyl-health/1#/$defs/factor" } },
            "span_ids": { "type": "array", "items": { "$ref": "#/$defs/span_id" } },
            "call_ids": { "type": "array", "items": { "$ref": "#/$defs/uuid" } }
          }
        }
      }
    },
    "next_action": { "type": "string", "minLength": 5, "maxLength": 300 },
    "deadline": {
      "type": "object", "additionalProperties": false, "required": ["at", "derived_from"],
      "properties": {
        "at": { "type": "string", "format": "date-time" },
        "derived_from": { "enum": ["task_deadline", "tier_rto", "operator"] },
        "tier": { "type": "integer", "minimum": 1, "maximum": 3 },
        "rto_s": { "type": "integer", "minimum": 0 }
      }
    },
    "accountability": {
      "type": "object", "additionalProperties": false, "required": ["owner", "line"],
      "properties": {
        "owner": { "type": "string" }, "on_call": { "type": "string" }, "escalation": { "type": "string" },
        "business_process": { "type": "string" },
        "line": { "type": "string", "maxLength": 300 }
      }
    },
    "redaction": {
      "type": "object", "additionalProperties": false, "required": ["capture_mode", "profile"],
      "properties": {
        "capture_mode": { "enum": ["full", "redacted", "metadata"] },
        "profile": { "$ref": "https://sibyl.dev/schemas/sibyl-event/1#/$defs/redaction_profile" },
        "fields_redacted": { "type": "array", "items": { "type": "string" } }
      }
    },
    "provenance": {
      "type": "object", "additionalProperties": false, "required": ["assembled_by", "policy_version", "trace_ids"],
      "properties": {
        "assembled_by": { "enum": ["sdk", "control_plane"] },
        "sdk_version": { "type": "string" },
        "checkpoint_id": { "$ref": "#/$defs/uuidv7" },
        "checkpoint_seq": { "type": "integer", "minimum": 0 },
        "checkpoint_age_s": { "type": "number", "minimum": 0 },
        "trace_ids": { "type": "array", "items": { "type": "string", "pattern": "^[0-9a-f]{32}$" } },
        "policy_version": { "type": "integer", "minimum": 0 },
        "transition_id": { "$ref": "#/$defs/uuid" },
        "normaliser_version": { "type": "string" }
      }
    },
    "sidecar": {
      "type": "object", "additionalProperties": false,
      "properties": {
        "route_history": { "type": "array", "items": { "type": "object", "required": ["at", "to"], "properties": { "at": { "type": "string", "format": "date-time" }, "to": { "$ref": "#/$defs/target" }, "decision": { "type": "string" } } } },
        "cost_so_far_usd": { "type": "number", "minimum": 0 },
        "attempts": { "type": "integer", "minimum": 0 },
        "model_calls": { "type": "integer", "minimum": 0 },
        "tool_calls": { "type": "integer", "minimum": 0 }
      }
    },
    "summary": { "type": "string", "maxLength": 500 }
  },
  "allOf": [
    { "if": { "properties": { "fidelity": { "const": "request_only" } } }, "then": { "properties": { "pending_steps": { "maxItems": 0 } } } },
    { "if": { "properties": { "provenance": { "properties": { "assembled_by": { "const": "sdk" } }, "required": ["assembled_by"] } } }, "then": { "properties": { "reason": { "properties": { "trigger": { "properties": { "kind": { "const": "sdk_explicit" } } } } } } } }
  ],
  "$defs": {
    "uuid": { "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" },
    "uuidv7": { "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
    "span_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
    "failure_mode": { "enum": ["provider_outage", "latency_degradation", "quality_collapse", "prompt_injection", "policy_violation", "tool_failure", "data_source_failure", "infinite_loop", "cost_runaway", "permission_error", "model_deprecation", "silent_drift"] },
    "target": {
      "type": "object", "additionalProperties": false, "required": ["provider", "model"],
      "properties": { "provider": { "type": "string" }, "model": { "type": "string" }, "base_url_hash": { "type": "string" }, "agent_id": { "$ref": "#/$defs/uuid" } }
    },
    "payload_ref": { "$ref": "https://sibyl.dev/schemas/sibyl-event/1#/$defs/payload_ref" },
    "output_ref": {
      "type": "object", "additionalProperties": false,
      "properties": {
        "preview": { "type": "string", "maxLength": 4096 },
        "ref": { "$ref": "#/$defs/payload_ref" },
        "content_type": { "type": "string" }
      }
    },
    "completed_step": {
      "type": "object", "additionalProperties": false,
      "required": ["index", "step", "started_at", "ended_at", "assumed"],
      "properties": {
        "index": { "type": "integer", "minimum": 0 },
        "step": { "type": "string", "maxLength": 128 },
        "started_at": { "type": "string", "format": "date-time" },
        "ended_at": { "type": "string", "format": "date-time" },
        "tool_name": { "type": "string" },
        "call_id": { "$ref": "#/$defs/uuid" },
        "span_id": { "$ref": "#/$defs/span_id" },
        "output": { "$ref": "#/$defs/output_ref" },
        "assumed": { "type": "boolean" }
      }
    },
    "pending_step": {
      "type": "object", "additionalProperties": false, "required": ["index", "step"],
      "properties": {
        "index": { "type": "integer", "minimum": 0 },
        "step": { "type": "string", "maxLength": 128 },
        "description": { "type": "string", "maxLength": 1000 },
        "inputs_needed": { "type": "array", "items": { "type": "string" } },
        "blocked_on": { "type": "string" }
      }
    },
    "side_effect": {
      "type": "object", "additionalProperties": false, "required": ["kind", "at", "assumed"],
      "properties": {
        "kind": { "enum": ["external_write", "message_sent", "payment", "file_written", "db_write", "ticket_created", "api_call", "unknown"] },
        "target": { "type": "string", "maxLength": 256 },
        "at": { "type": "string", "format": "date-time" },
        "idempotency_key": { "type": "string", "maxLength": 256 },
        "reversible": { "type": "boolean" },
        "assumed": { "type": "boolean" },
        "evidence_span_id": { "$ref": "#/$defs/span_id" }
      }
    }
  }
}
```

The Step 3 §5 example passes this schema after changing `"schema"` to `"sibyl-handoff/1"` (and `blob://` refs are unchanged). SDK-assembled packets: `assembled_by=sdk`, `trigger.kind=sdk_explicit`, `deadline` either from `deadline=` or placeholder `derived_from=tier_rto` with `at` = `created_at` (the control plane rewrites `at` to `created_at + RTO` per D23 when it stores the `handoff_task`; the rewritten packet keeps the SDK's `packet_id`). `accountability` is filled by the control plane from the registry; the SDK sends `{"owner": "<agent slug>", "line": "pending"}`. `original_input` on SDK packets is the first `input_messages` payload of the run (preview ≤ 4 KiB + ref). Content remains `PayloadRef`s so the erasure cascade covers packets (D17).

---

## 7. SDK test plan

Target: 85 % line coverage on `sibyl-sdk`; contract tests gate the release. Everything runs offline (D10: no paid APIs); provider SDKs are exercised against `respx`/`pytest-httpx` mocks and the openai/anthropic libraries' own fake transports.

### 7.1 Unit tests

| Area | Cases |
|---|---|
| `init()` | env-var fallback; missing key → `SibylConfigError`; agent-bound key with mismatched `agent_id` → `SibylConfigError`; `instrument="auto"` with openai absent → skip silently; reuse of an external `TracerProvider` |
| `agent()` | start/end spans with `agent.invoke` attrs; nested runs → `parent_task_id`; exception → `status=error`, `error_type`; `cancel()` → `cancelled`; `handoff()` → `handed_off`; async + sync; `steps/tool_calls/model_calls/cost_usd` counters |
| `tool()` | sync/async/generator; `side_effect` attr; `capture_args/result` honour capture mode; exception propagates unchanged; MCP path sets `gen_ai.tool.type=mcp` and `sibyl.mcp.server` |
| Auto-instrumentation | openai chat/embeddings/responses, streaming reassembly, `ttfb_ms`; anthropic messages + stream; usage mapping incl. cache tokens; `error.type` from HTTP 429/500/timeout; idempotent when already instrumented (one span, no double headers) |
| Headers | `traceparent`, `X-Sibyl-Call-Id/Agent/Task-Id/Capture-Owner/Policy-Version` present and correct per capture mode; not injected when `base_url` is not a Sibyl gateway? → **always injected** (gateway strips); test that provider-bound requests still succeed with extra headers in mocks |
| Scrubber | fixture corpus of 60 secrets (AWS, GCP, Azure, GitHub, Slack, Bearer JWT, PEM, DSNs) → all replaced with `[SECRET:<hash8>]`; false-positive corpus (UUIDs, base64 images) untouched; hook ordering; hook raising → part downgraded to `metadata`, counter incremented, call unaffected |
| Capture modes | `full` ships bodies; `redacted` applies profile; `metadata` ships hashes + `output_chars` only; tenant-restricted mode from snapshot overrides a looser `init()` value |
| Exporter | ring overflow drops oldest and counts; critical lane drains first; 429 `Retry-After` pauses both lanes exactly N s; 400 drops; timeout keeps batch and replays with the **same** `X-Sibyl-Batch-Id`; `shutdown()` returns within the bound even when the endpoint hangs; fork safety; `sibyl.sdk.buffer` log cadence |
| Spool | segment write/rotate/cap by bytes and age; replay order oldest-first; corrupted segment skipped and counted; replay emits `sibyl.sdk.replay` |
| Checkpoint | ≤ 64 KiB inline vs `payload_inline` above; scrub runs before size check; `(task_id, seq)` monotonic; pydantic state serialisation; `state_schema` inference |
| Handoff builder | validates against `sibyl-handoff/1` on construction (positive + 12 negative mutations); `from_checkpoint="latest"` pulls pending steps; `request_only` when no checkpoint; `request()` without `handoff:write` → event still emitted, warning once |
| Policy | Ed25519 verify (good/bad sig/wrong key); monotonic version rejection; freshness transitions at ttl/grace/max_stale boundaries (frozen clock); `killed` → `SibylKilled` even after cache expiry; fail-closed + unavailable → `SibylPolicyUnavailable`; fail-open + expired → proceed + one `policy.decision` per minute; `on_change` fired once per version |

### 7.2 Contract tests against recorded ingest fixtures

`sibyl-schemas/fixtures/ingest/` holds recorded request/response pairs produced by the real ingest service in CI (docker-compose, `sandbox` tenant, D29) and committed; the SDK tests replay them with a fake server (`pytest-httpserver`):

1. **Golden OTLP**: each SDK scenario (chat ok, chat error 429, streaming, tool call, nested agent run, checkpoint, handoff, feedback) produces a protobuf batch; test decodes it and asserts the normaliser (imported from `sibyl-schemas`, pure function) yields `sibyl-event/1` documents equal to the committed golden JSON modulo `event_id/ts/observed_at`.
2. **Response handling**: fixtures for `200 empty`, `200 partial_success`, `202 /v1/events` with rejects, `400 unsupported_schema`, `401`, `403 agent_not_permitted`, `413`, `429` each backpressure reason, `503`; assert exporter state machine transitions and counters.
3. **Batch replay**: send, receive timeout, resend → fixture returns `X-Sibyl-Replayed: true`; assert no double counting in SDK stats.
4. **Schema conformance**: every JSON the SDK emits on `/v1/events` validates against `sibyl-event/1` with `payload_inline` allowed by the wire-variant schema `sibyl-event-wire/1`; every packet validates against `sibyl-handoff/1`; every checkpoint against `sibyl-checkpoint/1`.
5. **Merge contract**: SDK span + a recorded gateway span for the same `call_id` → run the merge function from `sibyl-schemas` → assert the authority table (SDK ids, gateway latency/usage, body from `Capture-Owner`).
6. **Semconv pin**: all emitted attribute names ⊆ the 1.37.0 registry + `sibyl.*`; a CI job diffs against the pinned semconv YAML (D25).

### 7.3 Integration (compose, nightly)

Simulator agents (D3) run with the SDK against the real stack: 10 min soak at 200 calls/s with chaos knobs (ingest paused 2 min → spool fills → replay closes `observation.gap`; kill switch pulled → `SibylKilled` within 20 s; snapshot server down → fail-open proceeds, fail-closed stops). Asserts on `events` row counts (no duplicates by `call_id`), `events_rejected` empty, `observation.gap` closed, and p99 added latency of the SDK wrapper < 1 ms per call (benchmark job).

---

## 8. Open questions for the chair

| # | Question | My default |
|---|---|---|
| Q1 | Scope spelling: brief says `ingest:write`; DATAMODEL §4.1 freezes `ingest:write`. | Keep `ingest:write`; one value set, no rename churn. |
| Q2 | API key prefix: `vgl_` (R13) → `sbl_` under D19? | Yes, `sbl_<env>_<prefix12>_<secret>`; prefix is cosmetic to the HMAC. |
| Q3 | Policy snapshot public key distribution to SDKs: pin via `init(policy.public_key=…)` vs fetch-once-and-pin from `GET /.well-known/sibyl-keys.json`. | Fetch-once over TLS and pin to disk; explicit pin optional; key rotation via a `next_key` field in the snapshot. |
| Q4 | Default scopes on agent-bound telemetry keys: `ingest:write` alone, or `ingest:write routing:read handoff:write` so the SDK can poll the snapshot and request handoffs without a second key. | The three; onboarding wizard shows them. |
| Q5 | OTLP status: spec says `200` for OTLP success; DATAMODEL §6.1 says `202`. | `200` on `/v1/otlp/*` (collectors expect it), `202` on `/v1/events`. |
| Q6 | `/v1/otlp/logs` in Phase 1: needed for 1.37 content events and SDK buffer reports, but adds a code path. | Keep, scoped to the four `event.name`s in §1.7; everything else raw-only. |
| Q7 | Two ingest-side tables/columns requested from database-architect: `ingest_batch_seen` (batch dedupe) and `tenant.ingest_rate_limit`; plus two `events_rejected.reason` values. | Approve as Step 4 amendments to DATAMODEL. |
| Q8 | `sibyl.checkpoint()` is Phase 1 (handoff `fidelity=checkpoint` depends on it); confirm it is not deferred with the LangGraph mirror (Phase 2). | Phase 1, explicit API only. |
