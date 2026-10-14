# AI Engineer: Data model (Step 3, wave 1) — event schemas and wire documents

Codename: Vigil. Date: 2026-10-09. Scope: `vigil-event/1` and every JSON document that crosses the wire: events, checkpoint, handoff packet v1, health response, feature snapshot, labels. Inputs: DECISIONS D1–D18, ARCHITECTURE.md, my Step 2 report. Tables are not mine; §9 tells database-architect and backend-architect how to map these documents onto theirs.

Governing rule: **one canonical event, two encodings in, one authority per field.** Everything arrives as OTLP (or the `/v1/events` JSON adapter), is normalised once into `vigil-event/1`, and nothing downstream reads raw spans. Captured content never lives in an event: it is always a `PayloadRef` into BlobStore (ADR-5), which is what makes crypto-shred (D17) and unconditional secrets scrubbing (D12) enforceable in one place.

Schemas are JSON Schema draft 2020-12 under `$id: https://vigil.dev/schemas/<name>/1`. Fenced blocks are tagged `schema:<name>` and `example:<name>` so a conformance test in `vigil-schemas` can extract and validate them; every example here passes its schema (validated with `jsonschema` 4.26, including negative mutations).

## 1. Event type catalogue

Fourteen types. `idempotency key` is the `ON CONFLICT DO NOTHING` target; "health derives" names what the rule engine (backend-architect's R1–R5, L1–L5) and the Phase 2 feature store compute from it.

| Type | Emitted when | By | Required attrs | Notable optional attrs | Idempotency key | Health derives |
|---|---|---|---|---|---|---|
| `gen_ai.request` | One per provider call, after the response has flushed (or errored) | sdk, gateway; merged by ingest | `operation`, `provider`, `request_model`, `status`, `latency_ms`, `contributions` | `response_model`, `usage`, `cost_usd`, `finish_reasons`, `error_type`, `http_status`, `ratelimit`, `route`, `retry`, `tool_calls_requested`, `context`, `payload`, `conversation_id`, `prompt_version` | `(tenant_id, call_id)`; raw spans `(tenant_id, trace_id, span_id)` | R1 error rate, R2 p95, R3 consecutive failures, R5/L4 spend, L1/L2 trends, L3 ratelimit headroom and 429 share, L5 inline fallbacks, context saturation, finish-reason mix, token and output-length baselines |
| `tool.call` | One per tool execution the agent process performs | sdk (incl. MCP hook, third-party instrumentors) | `tool_name`, `tool_type`, `status`, `latency_ms` | `tool_call_id`, `mcp_server`, `error_type`, `side_effect_class`, `payload`, `args_bytes`, `result_bytes` | `(tenant_id, trace_id, span_id)` | Tool failure rate, tool-sequence n-gram entropy (loop and drift signals), side-effect inventory for packets, tool AI-BOM |
| `agent.invoke` | Task boundary: `phase=start` when `@vigil.task` opens, `phase=end` when it closes | sdk | `phase`, `agent_name` | `parent_task_id`, `status`, `duration_ms`, `steps`, `tool_calls`, `model_calls`, `cost_usd`, `a2a` | `(tenant_id, task_id, phase)` | Tasks in flight (handoff blast radius), task duration baseline, step-count ceiling (infinite loop), hierarchy edges |
| `checkpoint` | `vigil.checkpoint()` call; also on framework mirror (Phase 2) | sdk | `checkpoint_id`, `seq`, `step_index`, `state_bytes`, `completed_count`, `pending_count` | `step_name`, `state_ref`, `state_schema`, `side_effects_count`, `prev_checkpoint_id` | `(tenant_id, task_id, seq)` | Checkpoint age per task → packet fidelity; tasks without checkpoints → `request_only` warning on the asset |
| `handoff.requested` | SDK `handoff()`, worker rule trigger, A2A `failed`/`input-required`, operator | sdk, worker, api | `packet_id`, `trigger`, `fidelity`, `assembled_by`, `failure_mode` | `packet_ref`, `rule_id`, `alert_id`, `transition_id`, `reason_preview` | `(tenant_id, packet_id)` | Handoff rate per agent, trigger mix (explicit vs rule), fidelity ratio |
| `handoff.completed` / `handoff.returned` | Operator resolves a queue task | api | `packet_id`, `outcome`, `operator_ref`, `claimed_at`, `resolved_at` | `rework`, `rating`, `returned_to_agent_id`, `note_ref`, `time_to_claim_s` | `(tenant_id, packet_id, outcome)` | Label (§7); operator load; packet usefulness |
| `feedback` | End-user or operator rates an output; LLM judge (Phase 3) | sdk, api | `feedback_id`, `target`, `score`, `scale`, `rater` | `comment_ref`, `tags` | `(tenant_id, feedback_id)` | Quality baseline, outcome label independent of rules |
| `task.outcome` | Task ends with a declared business outcome | sdk, api | `outcome`, `declared_by` | `reason`, `metrics`, `rework` | `(tenant_id, task_id, declared_by)` | Task success rate, cost per successful task, primary training label |
| `agent.discovered` | Unknown agent identity seen (header, span attr, A2A card, MCP server) | gateway, ingest | `discovered_via`, `candidate`, `candidate_hash`, `resolved_agent_id`, `fail_mode_applied` | `first_call_id`, `first_trace_id`, `server_address` | `(tenant_id, candidate_hash, day)` | Registry completeness, shadow-AI count; never a health penalty on the unclaimed agent itself |
| `policy.decision` | Only non-default decisions: stale/expired/unavailable snapshot, fail-closed or kill rejection, inline fallback, breaker open, throttle, unknown-agent default | gateway, sdk | `action`, `state`, `fail_mode`, `reason` | `from_target`, `to_target`, `snapshot_issued_at`, `attempt`, `http_status_returned` | `(tenant_id, call_id, action)`; `event_id` when no call | L5 fallback pressure, breaker state feature, audit of every stale decision (ADR-9), fail-closed rejection count |
| `observation.gap` | Worker detects a missing heartbeat run, or an SDK/gateway replay reports drops | worker (synthesised), ingest (from `vigil.sdk.dropped_spans`) | `emitter_id`, `gap_start`, `cause`, `status` | `gap_end`, `events_replayed`, `events_dropped`, `affected_agent_ids` | `(tenant_id, emitter_id, gap_start)` | `observation_coverage` feature; windows inside a gap are excluded from baselines and marked low-confidence; forces `provisional` if coverage < 0.8 |
| `provider.status` | Status feed or probe changes state | worker | `provider`, `status`, `feed` | `component`, `incident_id`, `incident_url`, `started_at`, `resolved_at`, `probe_latency_ms` | `(tenant_id, provider, component, status, started_at)` | R4 provider status, provider-incident collapse, post-hoc label windows (§7) |
| `health.transition` | Agent status band changes | worker | `from_status`, `to_status`, `score`, `health_snapshot_id`, `feature_snapshot_ref`, `rules_fired` | `alert_id`, `recommended_action` | `(tenant_id, health_snapshot_id)` | The join point for every label |

`provider.status` is platform-scoped: it is stored under the reserved platform tenant `00000000-0000-7000-8000-000000000000` and fanned into per-tenant features by the worker, so RLS still has a tenant on every row.

### `gen_ai.request` merge rules (the one event with two authors)

Ingest upserts on `(tenant_id, call_id)`. First contribution creates the event with `contributions=[source]` and `merge_state=partial`; the second merges and sets `merge_state=complete`. A contribution arriving more than 24 h after the first is stored as a raw span only. Field authority:

| Field group | Authority | Fallback |
|---|---|---|
| `task_id`, `trace_id`/`span_id` (envelope), `conversation_id`, hierarchy, `prompt_version` | sdk | gateway header values |
| `latency_ms`, `ttfb_ms`, `http_status`, `ratelimit.*`, `route.*`, `retry.*`, `server.*`, `response_id` | gateway | sdk measured values |
| `usage.*`, `response_model`, `finish_reasons`, `error_type` | gateway | sdk |
| `payload` (content) | sdk when `capture_mode=full`; gateway when the SDK is in `metadata` or absent | whichever exists |
| `capture_mode`, `redaction_profile` | the more restrictive of the two (metadata < redacted < full) | — |

A single-author call (gateway-only or SDK-only) reaches `merge_state=complete` after a 5 s merge window. Health counts one call either way.

## 2. Common envelope and per-type `attrs`

Envelope decisions: `source` adds `api` to the brief's four values (operator actions are first-class events); `emitter_id` + `seq` give per-process ordering so gaps and out-of-order replay are detectable without trusting clocks; `policy_state` is on every event, so a stale-snapshot decision is visible from whichever side made it.

```json schema:vigil-event
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://vigil.dev/schemas/vigil-event/1",
  "title": "vigil-event/1 envelope",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "event_id", "type", "tenant_id", "agent_id", "ts", "observed_at", "source", "emitter_id", "seq", "capture_mode", "redaction_profile", "policy_state", "attrs"],
  "properties": {
    "schema": { "const": "vigil-event/1" },
    "event_id": { "$ref": "#/$defs/uuidv7" },
    "type": { "enum": ["gen_ai.request", "tool.call", "agent.invoke", "checkpoint", "handoff.requested", "handoff.completed", "handoff.returned", "feedback", "task.outcome", "agent.discovered", "policy.decision", "observation.gap", "provider.status", "health.transition"] },
    "tenant_id": { "$ref": "#/$defs/uuid" },
    "agent_id": { "$ref": "#/$defs/uuid" },
    "task_id": { "oneOf": [{ "$ref": "#/$defs/uuid" }, { "type": "null" }] },
    "call_id": { "oneOf": [{ "$ref": "#/$defs/uuid" }, { "type": "null" }] },
    "trace_id": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
    "span_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
    "parent_span_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
    "ts": { "type": "string", "format": "date-time", "description": "Emitter clock; for spans, the span end time" },
    "observed_at": { "type": "string", "format": "date-time", "description": "Ingest clock at commit" },
    "source": { "enum": ["sdk", "gateway", "ingest", "worker", "api"] },
    "emitter_id": { "type": "string", "maxLength": 128, "description": "Stable per process instance: '<source>:<host>:<pid>' or gateway replica id" },
    "seq": { "type": "integer", "minimum": 0, "description": "Monotonic per emitter_id; replay keeps original seq" },
    "capture_mode": { "enum": ["full", "redacted", "metadata"] },
    "redaction_profile": { "$ref": "#/$defs/redaction_profile" },
    "policy_state": { "$ref": "#/$defs/policy_state" },
    "ingest": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "normaliser_version": { "type": "string" },
        "semconv_version": { "type": "string" },
        "instrumentor": { "type": "string", "description": "e.g. vigil-sdk/0.1.0, openllmetry/0.47, openinference/0.1, gateway/0.1.0" },
        "raw_span_refs": { "type": "array", "items": { "$ref": "#/$defs/raw_span_ref" } },
        "warnings": { "type": "array", "items": { "type": "string" } }
      }
    },
    "attrs": { "type": "object" }
  },
  "allOf": [
    { "if": { "properties": { "type": { "const": "gen_ai.request" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_gen_ai_request" } } } },
    { "if": { "properties": { "type": { "const": "tool.call" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_tool_call" } } } },
    { "if": { "properties": { "type": { "const": "agent.invoke" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_agent_invoke" } } } },
    { "if": { "properties": { "type": { "const": "checkpoint" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_checkpoint" } } } },
    { "if": { "properties": { "type": { "const": "handoff.requested" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_handoff_requested" } } } },
    { "if": { "properties": { "type": { "enum": ["handoff.completed", "handoff.returned"] } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_handoff_resolved" } } } },
    { "if": { "properties": { "type": { "const": "feedback" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_feedback" } } } },
    { "if": { "properties": { "type": { "const": "task.outcome" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_task_outcome" } } } },
    { "if": { "properties": { "type": { "const": "agent.discovered" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_agent_discovered" } } } },
    { "if": { "properties": { "type": { "const": "policy.decision" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_policy_decision" } } } },
    { "if": { "properties": { "type": { "const": "observation.gap" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_observation_gap" } } } },
    { "if": { "properties": { "type": { "const": "provider.status" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_provider_status" } } } },
    { "if": { "properties": { "type": { "const": "health.transition" } } }, "then": { "properties": { "attrs": { "$ref": "#/$defs/attrs_health_transition" } } } }
  ],
  "$defs": {
    "uuid": { "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" },
    "uuidv7": { "type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
    "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "money": { "type": "number", "minimum": 0 },
    "failure_mode": { "enum": ["provider_outage", "latency_degradation", "quality_collapse", "prompt_injection", "policy_violation", "tool_failure", "data_source_failure", "infinite_loop", "cost_runaway", "permission_error", "model_deprecation", "silent_drift"] },
    "rule_id": { "type": "string", "pattern": "^[a-z][a-z0-9_]{2,40}$", "description": "Registered rule ids: error_rate, p95_latency, consecutive_failures, provider_status, budget_breach, error_trend, latency_trend, ratelimit_proximity, budget_proximity, fallback_pressure, context_saturation, credential_expiry, model_deprecation; registry is additive" },
    "redaction_profile": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "version", "secrets_scrubbed"],
      "properties": {
        "id": { "type": "string", "description": "'secrets' is the unconditional floor; tenant profiles add PII rules" },
        "version": { "type": "integer", "minimum": 1 },
        "rules_fired": { "type": "array", "items": { "type": "string" }, "default": [] },
        "secrets_scrubbed": { "type": "integer", "minimum": 0 },
        "fields_redacted": { "type": "array", "items": { "type": "string" } }
      }
    },
    "policy_state": {
      "type": "object",
      "additionalProperties": false,
      "required": ["state"],
      "properties": {
        "state": { "enum": ["fresh", "stale", "expired", "unavailable", "not_applicable"] },
        "policy_version": { "type": ["integer", "null"], "minimum": 0 },
        "fail_mode": { "enum": ["open", "closed", null] },
        "snapshot_age_s": { "type": "number", "minimum": 0 }
      }
    },
    "payload_ref": {
      "type": "object",
      "additionalProperties": false,
      "required": ["ref", "sha256", "bytes", "content_type"],
      "properties": {
        "ref": { "type": "string", "pattern": "^blob://[0-9a-f-]{36}/\\d{4}-\\d{2}-\\d{2}/[A-Za-z0-9_./-]+$" },
        "sha256": { "$ref": "#/$defs/sha256", "description": "Of the plaintext after redaction, before compression and encryption" },
        "bytes": { "type": "integer", "minimum": 0 },
        "content_type": { "type": "string" },
        "parts": { "type": "array", "items": { "enum": ["input_messages", "output_messages", "system_instructions", "tool_definitions", "tool_args", "tool_result", "state", "raw_span", "comment", "original_input"] } },
        "redaction_profile": { "$ref": "#/$defs/redaction_profile" }
      }
    },
    "raw_span_ref": {
      "type": "object",
      "required": ["source", "trace_id", "span_id", "ref"],
      "properties": {
        "source": { "enum": ["sdk", "gateway", "otel"] },
        "trace_id": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
        "span_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
        "ref": { "type": "string" }
      }
    },
    "target": {
      "type": "object",
      "additionalProperties": false,
      "required": ["provider", "model"],
      "properties": {
        "provider": { "type": "string" },
        "model": { "type": "string" },
        "base_url_hash": { "type": "string", "description": "sha256 prefix of the allowlisted base_url; never the URL" },
        "agent_id": { "$ref": "#/$defs/uuid", "description": "Set when the target is a backup agent" }
      }
    },
    "usage": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "input_tokens": { "type": "integer", "minimum": 0 },
        "output_tokens": { "type": "integer", "minimum": 0 },
        "cached_input_tokens": { "type": "integer", "minimum": 0 },
        "cache_creation_input_tokens": { "type": "integer", "minimum": 0 },
        "reasoning_tokens": { "type": "integer", "minimum": 0 },
        "source": { "enum": ["provider", "estimated"] }
      }
    },
    "attrs_gen_ai_request": {
      "type": "object",
      "additionalProperties": false,
      "required": ["operation", "provider", "request_model", "status", "latency_ms", "contributions", "merge_state"],
      "properties": {
        "operation": { "enum": ["chat", "text_completion", "embeddings", "generate_content"] },
        "provider": { "type": "string", "description": "gen_ai.provider.name value, e.g. openai, anthropic, ollama" },
        "request_model": { "type": "string" },
        "response_model": { "type": "string" },
        "response_id": { "type": "string" },
        "status": { "enum": ["ok", "error"] },
        "error_type": { "type": "string", "description": "OTel error.type: HTTP status as string, exception class, or 'timeout'" },
        "http_status": { "type": "integer", "minimum": 100, "maximum": 599 },
        "latency_ms": { "type": "number", "minimum": 0 },
        "ttfb_ms": { "type": "number", "minimum": 0 },
        "streamed": { "type": "boolean" },
        "usage": { "$ref": "#/$defs/usage" },
        "cost_usd": { "$ref": "#/$defs/money" },
        "cost_source": { "type": "string", "description": "price table id and version, e.g. prices/2026-10-01" },
        "finish_reasons": { "type": "array", "items": { "type": "string" } },
        "request": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "temperature": { "type": "number" }, "top_p": { "type": "number" }, "top_k": { "type": "integer" },
            "max_tokens": { "type": "integer" }, "seed": { "type": "integer" }, "stop_sequences": { "type": "array", "items": { "type": "string" } },
            "frequency_penalty": { "type": "number" }, "presence_penalty": { "type": "number" },
            "choice_count": { "type": "integer" }, "output_type": { "enum": ["text", "json", "image", "speech"] },
            "service_tier": { "type": "string" }, "tool_definitions_count": { "type": "integer", "minimum": 0 }
          }
        },
        "tool_calls_requested": { "type": "array", "items": { "type": "object", "required": ["name"], "properties": { "id": { "type": "string" }, "name": { "type": "string" } } } },
        "context": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "model_context_limit": { "type": "integer", "minimum": 1 },
            "utilisation": { "type": "number", "minimum": 0, "maximum": 1, "description": "Derived: input_tokens / model_context_limit" }
          }
        },
        "ratelimit": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "limit_requests": { "type": "integer" }, "remaining_requests": { "type": "integer" }, "reset_requests_ms": { "type": "integer" },
            "limit_tokens": { "type": "integer" }, "remaining_tokens": { "type": "integer" }, "reset_tokens_ms": { "type": "integer" },
            "headroom": { "type": "number", "minimum": 0, "maximum": 1, "description": "Derived: min(remaining/limit) across requests and tokens" }
          }
        },
        "retry": {
          "type": "object",
          "additionalProperties": false,
          "required": ["attempt"],
          "properties": {
            "attempt": { "type": "integer", "minimum": 1 },
            "inline_fallback_used": { "type": "boolean" },
            "fallback_target": { "$ref": "#/$defs/target" },
            "breaker_state": { "enum": ["closed", "open", "half_open"] }
          }
        },
        "route": {
          "type": "object",
          "additionalProperties": false,
          "required": ["decision"],
          "properties": {
            "decision": { "enum": ["primary", "failover", "inline_fallback", "canary", "stale_primary"] },
            "reason": { "type": "string" },
            "from": { "$ref": "#/$defs/target" },
            "to": { "$ref": "#/$defs/target" },
            "transition_id": { "$ref": "#/$defs/uuid" }
          }
        },
        "server": { "type": "object", "properties": { "address": { "type": "string" }, "port": { "type": "integer" } } },
        "conversation_id": { "type": "string" },
        "prompt_version": { "type": "string", "description": "Declared version, else sha256 prefix of system instructions" },
        "data_source_ids": { "type": "array", "items": { "type": "string" } },
        "payload": { "$ref": "#/$defs/payload_ref" },
        "content_hashes": { "type": "object", "properties": { "input": { "$ref": "#/$defs/sha256" }, "output": { "$ref": "#/$defs/sha256" }, "system": { "$ref": "#/$defs/sha256" } } },
        "output_chars": { "type": "integer", "minimum": 0 },
        "eval_sample": { "type": "boolean" },
        "contributions": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "enum": ["sdk", "gateway", "otel"] } },
        "merge_state": { "enum": ["partial", "complete"] }
      }
    },
    "attrs_tool_call": {
      "type": "object",
      "additionalProperties": false,
      "required": ["tool_name", "tool_type", "status", "latency_ms"],
      "properties": {
        "tool_name": { "type": "string" },
        "tool_type": { "enum": ["function", "mcp", "a2a", "http", "retrieval", "code", "extension", "datastore"] },
        "tool_call_id": { "type": "string" },
        "mcp_server": { "type": "string" },
        "status": { "enum": ["ok", "error"] },
        "error_type": { "type": "string" },
        "latency_ms": { "type": "number", "minimum": 0 },
        "side_effect_class": { "enum": ["none", "read", "write", "external", "unknown"], "default": "unknown" },
        "args_bytes": { "type": "integer", "minimum": 0 },
        "result_bytes": { "type": "integer", "minimum": 0 },
        "payload": { "$ref": "#/$defs/payload_ref" }
      }
    },
    "attrs_agent_invoke": {
      "type": "object",
      "additionalProperties": false,
      "required": ["phase", "agent_name"],
      "properties": {
        "phase": { "enum": ["start", "end"] },
        "agent_name": { "type": "string" },
        "parent_task_id": { "$ref": "#/$defs/uuid" },
        "status": { "enum": ["ok", "error", "handed_off", "cancelled"] },
        "error_type": { "type": "string" },
        "duration_ms": { "type": "number", "minimum": 0 },
        "steps": { "type": "integer", "minimum": 0 },
        "tool_calls": { "type": "integer", "minimum": 0 },
        "model_calls": { "type": "integer", "minimum": 0 },
        "cost_usd": { "$ref": "#/$defs/money" },
        "a2a": { "type": "object", "properties": { "remote_task_id": { "type": "string" }, "state": { "type": "string" }, "callee_agent_id": { "$ref": "#/$defs/uuid" } } }
      }
    },
    "attrs_checkpoint": {
      "type": "object",
      "additionalProperties": false,
      "required": ["checkpoint_id", "seq", "step_index", "state_bytes", "completed_count", "pending_count"],
      "properties": {
        "checkpoint_id": { "$ref": "#/$defs/uuidv7" },
        "seq": { "type": "integer", "minimum": 1 },
        "step_index": { "type": "integer", "minimum": 0 },
        "step_name": { "type": "string" },
        "state_bytes": { "type": "integer", "minimum": 0 },
        "state_ref": { "$ref": "#/$defs/payload_ref", "description": "Present when state_bytes > 65536" },
        "state_schema": { "type": "string" },
        "completed_count": { "type": "integer", "minimum": 0 },
        "pending_count": { "type": "integer", "minimum": 0 },
        "side_effects_count": { "type": "integer", "minimum": 0 },
        "prev_checkpoint_id": { "$ref": "#/$defs/uuidv7" }
      }
    },
    "attrs_handoff_requested": {
      "type": "object",
      "additionalProperties": false,
      "required": ["packet_id", "trigger", "fidelity", "assembled_by", "failure_mode"],
      "properties": {
        "packet_id": { "$ref": "#/$defs/uuidv7" },
        "trigger": { "enum": ["sdk_explicit", "rule", "a2a_state", "operator", "approval_timeout"] },
        "rule_id": { "$ref": "#/$defs/rule_id" },
        "alert_id": { "$ref": "#/$defs/uuid" },
        "transition_id": { "$ref": "#/$defs/uuid" },
        "fidelity": { "enum": ["checkpoint", "request_only"] },
        "assembled_by": { "enum": ["sdk", "control_plane"] },
        "failure_mode": { "$ref": "#/$defs/failure_mode" },
        "checkpoint_seq": { "type": "integer", "minimum": 0 },
        "packet_ref": { "$ref": "#/$defs/payload_ref" },
        "reason_preview": { "type": "string", "maxLength": 280 }
      }
    },
    "attrs_handoff_resolved": {
      "type": "object",
      "additionalProperties": false,
      "required": ["packet_id", "outcome", "operator_ref", "claimed_at", "resolved_at"],
      "properties": {
        "packet_id": { "$ref": "#/$defs/uuidv7" },
        "outcome": { "enum": ["completed", "returned", "abandoned"] },
        "operator_ref": { "$ref": "#/$defs/uuid", "description": "User id, never email" },
        "claimed_at": { "type": "string", "format": "date-time" },
        "resolved_at": { "type": "string", "format": "date-time" },
        "time_to_claim_s": { "type": "number", "minimum": 0 },
        "rework": { "type": "boolean" },
        "rating": { "type": "integer", "minimum": 1, "maximum": 5 },
        "returned_to_agent_id": { "$ref": "#/$defs/uuid" },
        "note_ref": { "$ref": "#/$defs/payload_ref" }
      }
    },
    "attrs_feedback": {
      "type": "object",
      "additionalProperties": false,
      "required": ["feedback_id", "target", "score", "scale", "rater"],
      "properties": {
        "feedback_id": { "$ref": "#/$defs/uuidv7" },
        "target": { "type": "object", "required": ["kind", "id"], "properties": { "kind": { "enum": ["trace", "task", "call", "packet"] }, "id": { "type": "string" } } },
        "score": { "type": "number", "minimum": -1, "maximum": 1, "description": "Normalised; raw value kept in scale" },
        "scale": { "type": "string", "description": "thumbs | 1-5 | 0-100 | judge:<name>" },
        "raw_value": { "type": ["number", "string"] },
        "rater": { "enum": ["end_user", "operator", "judge"] },
        "comment_ref": { "$ref": "#/$defs/payload_ref" },
        "tags": { "type": "array", "items": { "type": "string" } }
      }
    },
    "attrs_task_outcome": {
      "type": "object",
      "additionalProperties": false,
      "required": ["outcome", "declared_by"],
      "properties": {
        "outcome": { "enum": ["success", "partial", "failure", "abandoned", "handed_off"] },
        "declared_by": { "enum": ["sdk", "operator", "judge"] },
        "reason": { "type": "string", "maxLength": 500 },
        "rework": { "type": "boolean" },
        "metrics": { "type": "object", "properties": { "steps": { "type": "integer" }, "tool_calls": { "type": "integer" }, "model_calls": { "type": "integer" }, "cost_usd": { "$ref": "#/$defs/money" }, "duration_ms": { "type": "number" } } }
      }
    },
    "attrs_agent_discovered": {
      "type": "object",
      "additionalProperties": false,
      "required": ["discovered_via", "candidate", "candidate_hash", "resolved_agent_id", "fail_mode_applied"],
      "properties": {
        "discovered_via": { "enum": ["gateway_header", "api_key_default", "span_attr", "a2a_card", "mcp_list_tools", "egress_log"] },
        "candidate": { "type": "string", "maxLength": 256 },
        "candidate_hash": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
        "resolved_agent_id": { "$ref": "#/$defs/uuid" },
        "fail_mode_applied": { "enum": ["open", "closed"] },
        "first_call_id": { "$ref": "#/$defs/uuid" },
        "first_trace_id": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
        "server_address": { "type": "string" }
      }
    },
    "attrs_policy_decision": {
      "type": "object",
      "additionalProperties": false,
      "required": ["action", "state", "fail_mode", "reason"],
      "properties": {
        "action": { "enum": ["forward_stale", "inline_fallback", "reject_closed", "reject_killed", "reject_quarantined", "throttle", "breaker_open", "unknown_agent_default", "local_breaker_prefer_fallback"] },
        "state": { "enum": ["fresh", "stale", "expired", "unavailable", "none"] },
        "fail_mode": { "enum": ["open", "closed"] },
        "reason": { "type": "string", "maxLength": 200 },
        "snapshot_issued_at": { "type": "string", "format": "date-time" },
        "from_target": { "$ref": "#/$defs/target" },
        "to_target": { "$ref": "#/$defs/target" },
        "attempt": { "type": "integer", "minimum": 1 },
        "http_status_returned": { "type": "integer" }
      }
    },
    "attrs_observation_gap": {
      "type": "object",
      "additionalProperties": false,
      "required": ["emitter_id", "gap_start", "cause", "status"],
      "properties": {
        "emitter_id": { "type": "string" },
        "gap_start": { "type": "string", "format": "date-time" },
        "gap_end": { "type": "string", "format": "date-time" },
        "cause": { "enum": ["control_plane_unreachable", "emitter_silent", "buffer_dropped", "ingest_backpressure", "clock_skew"] },
        "status": { "enum": ["open", "closed", "closed_with_loss"] },
        "events_replayed": { "type": "integer", "minimum": 0 },
        "events_dropped": { "type": "integer", "minimum": 0 },
        "affected_agent_ids": { "type": "array", "items": { "$ref": "#/$defs/uuid" } }
      }
    },
    "attrs_provider_status": {
      "type": "object",
      "additionalProperties": false,
      "required": ["provider", "status", "feed"],
      "properties": {
        "provider": { "type": "string" },
        "component": { "type": "string" },
        "status": { "enum": ["operational", "degraded_performance", "partial_outage", "major_outage", "maintenance", "unknown"] },
        "feed": { "enum": ["statuspage_json", "probe", "manual"] },
        "incident_id": { "type": "string" },
        "incident_url": { "type": "string" },
        "started_at": { "type": "string", "format": "date-time" },
        "resolved_at": { "type": "string", "format": "date-time" },
        "probe_latency_ms": { "type": "number", "minimum": 0 }
      }
    },
    "attrs_health_transition": {
      "type": "object",
      "additionalProperties": false,
      "required": ["from_status", "to_status", "score", "health_snapshot_id", "feature_snapshot_ref", "rules_fired"],
      "properties": {
        "from_status": { "enum": ["healthy", "watch", "degraded", "failed", "unknown"] },
        "to_status": { "enum": ["healthy", "watch", "degraded", "failed"] },
        "score": { "type": "integer", "minimum": 0, "maximum": 100 },
        "health_snapshot_id": { "$ref": "#/$defs/uuidv7" },
        "feature_snapshot_ref": { "type": "string", "pattern": "^fs_[0-9a-f-]{36}$" },
        "rules_fired": { "type": "array", "items": { "$ref": "#/$defs/rule_id" } },
        "alert_id": { "$ref": "#/$defs/uuid" },
        "recommended_action": { "type": "string" }
      }
    }
  }
}
```

### Example: `gen_ai.request` (merged, SDK + gateway, inline fallback used)

```json example:vigil-event
{
  "schema": "vigil-event/1",
  "event_id": "019276a1-5b3c-7d2e-8f41-0a1b2c3d4e5f",
  "type": "gen_ai.request",
  "tenant_id": "0192767f-0000-7000-8000-00000000a001",
  "agent_id": "0192767f-0000-7000-8000-00000000c010",
  "task_id": "019276a0-9c1d-7e3f-9a52-1b2c3d4e5f60",
  "call_id": "019276a1-4a2b-7c1d-8e30-f1e2d3c4b5a6",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "parent_span_id": "53995c3f42cd8ad8",
  "ts": "2026-10-09T09:14:32.418Z",
  "observed_at": "2026-10-09T09:14:33.102Z",
  "source": "gateway",
  "emitter_id": "gateway:gw-1:4211",
  "seq": 88213,
  "capture_mode": "full",
  "redaction_profile": { "id": "secrets", "version": 1, "rules_fired": ["secrets.bearer_token"], "secrets_scrubbed": 1 },
  "policy_state": { "state": "fresh", "policy_version": 42, "fail_mode": "open", "snapshot_age_s": 7.4 },
  "ingest": {
    "normaliser_version": "normaliser/1.3.0",
    "semconv_version": "1.37.0",
    "instrumentor": "gateway/0.1.0",
    "raw_span_refs": [
      { "source": "sdk", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "53995c3f42cd8ad8", "ref": "blob://0192767f-0000-7000-8000-00000000a001/2026-10-09/4bf92f3577b34da6a3ce929d0e0e4736/53995c3f42cd8ad8.raw.bin" },
      { "source": "gateway", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "00f067aa0ba902b7", "ref": "blob://0192767f-0000-7000-8000-00000000a001/2026-10-09/4bf92f3577b34da6a3ce929d0e0e4736/00f067aa0ba902b7.raw.bin" }
    ]
  },
  "attrs": {
    "operation": "chat",
    "provider": "openai",
    "request_model": "gpt-5-mini",
    "response_model": "gpt-5-mini-2026-08-01",
    "response_id": "chatcmpl-9x2Kq",
    "status": "ok",
    "http_status": 200,
    "latency_ms": 1843.2,
    "ttfb_ms": 412.0,
    "streamed": true,
    "usage": { "input_tokens": 2310, "output_tokens": 418, "cached_input_tokens": 1024, "source": "provider" },
    "cost_usd": 0.001419,
    "cost_source": "prices/2026-10-01",
    "finish_reasons": ["tool_calls"],
    "request": { "temperature": 0.2, "max_tokens": 1024, "tool_definitions_count": 4, "output_type": "text" },
    "tool_calls_requested": [{ "id": "call_8f1", "name": "lookup_order" }],
    "context": { "model_context_limit": 128000, "utilisation": 0.018 },
    "ratelimit": { "limit_requests": 10000, "remaining_requests": 612, "reset_requests_ms": 4200, "limit_tokens": 2000000, "remaining_tokens": 91000, "reset_tokens_ms": 4200, "headroom": 0.0455 },
    "retry": { "attempt": 2, "inline_fallback_used": true, "fallback_target": { "provider": "openai", "model": "gpt-5-mini" }, "breaker_state": "half_open" },
    "route": { "decision": "inline_fallback", "reason": "primary 429 on attempt 1; snapshot inline_fallback=true (tier 3)", "from": { "provider": "openai", "model": "gpt-5.4" }, "to": { "provider": "openai", "model": "gpt-5-mini" } },
    "server": { "address": "api.openai.com", "port": 443 },
    "conversation_id": "conv_7731",
    "prompt_version": "sha256:3e1a9c0b",
    "payload": {
      "ref": "blob://0192767f-0000-7000-8000-00000000a001/2026-10-09/4bf92f3577b34da6a3ce929d0e0e4736/53995c3f42cd8ad8.bin",
      "sha256": "9b74c9897bac770ffc029102a200c5de3c5d87d6b8d7a3c2f5a0b1c2d3e4f5a6",
      "bytes": 18422,
      "content_type": "application/vnd.vigil.genai-content+json",
      "parts": ["input_messages", "output_messages", "system_instructions", "tool_definitions"],
      "redaction_profile": { "id": "secrets", "version": 1, "rules_fired": ["secrets.bearer_token"], "secrets_scrubbed": 1 }
    },
    "content_hashes": { "input": "0c3a2e1f9d8b7a6c5e4d3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c", "output": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90" },
    "output_chars": 1612,
    "eval_sample": false,
    "contributions": ["sdk", "gateway"],
    "merge_state": "complete"
  }
}
```

### Example: `checkpoint` event (the state lives in the Checkpoint document, §4)

```json example:vigil-event
{
  "schema": "vigil-event/1",
  "event_id": "019276a2-0c4d-7e5f-8a61-2b3c4d5e6f70",
  "type": "checkpoint",
  "tenant_id": "0192767f-0000-7000-8000-00000000a001",
  "agent_id": "0192767f-0000-7000-8000-00000000c010",
  "task_id": "019276a0-9c1d-7e3f-9a52-1b2c3d4e5f60",
  "call_id": null,
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "7a1b2c3d4e5f6071",
  "ts": "2026-10-09T09:14:35.001Z",
  "observed_at": "2026-10-09T09:14:36.420Z",
  "source": "sdk",
  "emitter_id": "sdk:quote-worker-3:7719",
  "seq": 1042,
  "capture_mode": "full",
  "redaction_profile": { "id": "secrets", "version": 1, "rules_fired": [], "secrets_scrubbed": 0 },
  "policy_state": { "state": "fresh", "policy_version": 42, "fail_mode": "open" },
  "attrs": {
    "checkpoint_id": "019276a2-0c4d-7e5f-8a61-2b3c4d5e6f71",
    "seq": 2,
    "step_index": 3,
    "step_name": "price_quote",
    "state_bytes": 9120,
    "state_schema": "app:quote_pipeline/v3",
    "completed_count": 3,
    "pending_count": 2,
    "side_effects_count": 1,
    "prev_checkpoint_id": "019276a1-0000-7000-8000-000000000001"
  }
}
```

## 3. OTel GenAI mapping

Pinned conventions: **OpenTelemetry Semantic Conventions v1.37.0, GenAI namespace (status Development).** That is the release that renamed `gen_ai.system` to `gen_ai.provider.name` and introduced `gen_ai.input.messages`, `gen_ai.output.messages` and `gen_ai.system_instructions` as span attributes; every name below is a 1.37 name. If a newer release is current at freeze, the normaliser table bumps and the "legacy" column grows; `vigil-event/1` does not change (§8). The translation table is YAML in `vigil-schemas`, keyed on the scope `schema_url`, the instrumentor name/version from the scope, and `vigil.semconv.version`.

**A span becomes a `gen_ai.request` event only if all of** `gen_ai.operation.name` ∈ {chat, text_completion, embeddings, generate_content}, `gen_ai.provider.name` (after renames), `gen_ai.request.model`, valid `trace_id`/`span_id`, start and end timestamps, and tenant from the API key are present. `execute_tool` → `tool.call` needs `gen_ai.tool.name`. `invoke_agent` → `agent.invoke` needs `gen_ai.agent.name` or `vigil.agent_id`. Anything else (`create_agent`, unknown kinds, spans failing the required set) is **stored raw-only** in BlobStore with a `dead_letter` counter and reason; it is replayable after a normaliser fix. Everything is stored raw regardless (ADR-11).

| OTel attribute (v1.37) | `vigil-event/1` field | Req | Legacy spellings the normaliser accepts |
|---|---|---|---|
| `gen_ai.operation.name` | `type` + `attrs.operation` | yes | OpenLLMetry `llm.request.type`; OpenInference `openinference.span.kind` (LLM→chat, TOOL→tool.call, AGENT/CHAIN→agent.invoke, EMBEDDING→embeddings) |
| `gen_ai.provider.name` | `attrs.provider` | yes | `gen_ai.system` (≤1.36); OpenInference `llm.provider`, `llm.system`; OpenLLMetry `gen_ai.system` |
| `gen_ai.request.model` | `attrs.request_model` | yes | OpenInference `llm.model_name` |
| `gen_ai.response.model` | `attrs.response_model` | exp | — |
| `gen_ai.response.id` | `attrs.response_id` | opt | — |
| `gen_ai.response.finish_reasons` | `attrs.finish_reasons` | exp | OpenLLMetry `gen_ai.completion.N.finish_reason` |
| `gen_ai.usage.input_tokens` / `output_tokens` | `attrs.usage.input_tokens` / `output_tokens` | exp | `gen_ai.usage.prompt_tokens` / `completion_tokens` (≤1.26); OpenInference `llm.token_count.prompt` / `completion`; `llm.usage.total_tokens` (split only if one side present) |
| vendor cache counters (`gen_ai.usage.cache_read_input_tokens`, `...cache_creation_input_tokens`, OpenInference `llm.token_count.prompt_details.cache_read`) | `attrs.usage.cached_input_tokens`, `cache_creation_input_tokens` | opt | all of the listed spellings |
| `gen_ai.request.temperature/top_p/top_k/max_tokens/seed/stop_sequences/frequency_penalty/presence_penalty/choice.count` | `attrs.request.*` | opt | OpenInference `llm.invocation_parameters` (JSON string, parsed) |
| `gen_ai.output.type` | `attrs.request.output_type` | opt | — |
| `gen_ai.openai.request.service_tier`, `gen_ai.openai.response.service_tier` | `attrs.request.service_tier` | opt | — |
| `gen_ai.conversation.id` | `attrs.conversation_id` | exp | OpenInference `session.id` |
| `gen_ai.agent.id` / `gen_ai.agent.name` | identity resolution → `agent_id`; `attrs.agent_name` | exp | OpenLLMetry `traceloop.entity.name` when `traceloop.span.kind=agent` |
| `gen_ai.tool.name` / `gen_ai.tool.call.id` / `gen_ai.tool.type` / `gen_ai.tool.description` | `attrs.tool_name` / `tool_call_id` / `tool_type` / payload | yes for tool.call | OpenInference `tool.name`, `tool_call.function.name`; OpenLLMetry `traceloop.entity.name` with kind `tool` |
| `gen_ai.input.messages` / `gen_ai.output.messages` / `gen_ai.system_instructions` | `attrs.payload` (parts) + `content_hashes` + `output_chars` | content | `gen_ai.prompt.N.role/content`, `gen_ai.completion.N.role/content` (OpenLLMetry); `llm.input_messages.N.message.*`, `llm.output_messages.N.message.*`, `input.value`, `output.value` (OpenInference); `gen_ai.content.prompt`/`completion` events |
| `gen_ai.data_source.id` | `attrs.data_source_ids[]` | opt | OpenInference `retrieval.documents.N.document.id` |
| `error.type` | `attrs.error_type`, `status=error` | exp | span status ERROR with no attribute → `error_type="unknown"` |
| `server.address` / `server.port` | `attrs.server.*` | exp | OpenLLMetry `gen_ai.openai.api_base` (host only) |
| OTel span `start/end`, status | `ts`, `latency_ms`, `status` | yes | — |

`vigil.*` extension attributes (all optional on the wire; types as declared):

| Attribute | Type | Lands in |
|---|---|---|
| `vigil.tenant_id` | string(uuid) | Ignored for authority (key wins); mismatch → audit event |
| `vigil.agent_id` | string(uuid or registered slug) | `agent_id` after resolution |
| `vigil.task_id` | string(uuid) | `task_id` |
| `vigil.call_id` | string(uuid) | `call_id` (merge key) |
| `vigil.source` | string enum | `source` |
| `vigil.emitter_id`, `vigil.seq` | string, int | `emitter_id`, `seq` |
| `vigil.capture.mode` | string enum | `capture_mode` |
| `vigil.redaction.profile`, `vigil.redaction.version`, `vigil.redaction.rules` (string[]), `vigil.redaction.secrets_scrubbed` (int) | — | `redaction_profile` |
| `vigil.policy.state`, `vigil.policy.version`, `vigil.policy.fail_mode`, `vigil.policy.snapshot_age_s` | string, int, string, double | `policy_state` |
| `vigil.route.decision`, `vigil.route.reason`, `vigil.route.from.provider`, `vigil.route.from.model`, `vigil.route.to.*`, `vigil.route.transition_id` | strings | `attrs.route` |
| `vigil.retry.attempt`, `vigil.retry.inline_fallback_used`, `vigil.retry.breaker_state` | int, bool, string | `attrs.retry` |
| `vigil.ratelimit.*` (six ints mirroring the `x-ratelimit-*` headers) | int | `attrs.ratelimit` |
| `vigil.ttfb_ms`, `vigil.streamed` | double, bool | `attrs.ttfb_ms`, `attrs.streamed` |
| `vigil.model.context_limit` | int | `attrs.context.model_context_limit` |
| `vigil.checkpoint.id`, `vigil.checkpoint.seq`, `vigil.checkpoint.step_index`, `vigil.checkpoint.step_name`, `vigil.checkpoint.state_bytes`, `vigil.checkpoint.state_schema`, `vigil.checkpoint.ref` | — | `checkpoint` attrs |
| `vigil.tool.side_effect_class`, `vigil.mcp.server` | string | `tool.call` attrs |
| `vigil.prompt.version`, `vigil.task.outcome`, `vigil.feedback.score`, `vigil.feedback.scale`, `vigil.eval.sample` | string, string, double, string, bool | `attrs.prompt_version`; `task.outcome` and `feedback` events; `attrs.eval_sample` |
| `vigil.semconv.version`, `vigil.schema.version` | string | `ingest.semconv_version`; client schema declaration (§8) |
| `vigil.sdk.dropped_spans`, `vigil.sdk.buffer_bytes` (metrics) | int | `observation.gap` synthesis |

Cost is never on the wire: the normaliser prices `usage` against the tenant price table and records `cost_source`. Derived fields (`context.utilisation`, `ratelimit.headroom`, `output_chars`, `content_hashes`) are computed at ingest; the feature store never re-reads payloads.

## 4. Checkpoint document

A `Checkpoint` is a document the SDK produces and the control plane stores (backend-architect's `checkpoint` entity); the `checkpoint` event is its receipt. State up to 64 KB is inline in the document (JSONB in the row); above that, `state` is omitted and `state_ref` points to BlobStore. The 64 KB cap is on the post-redaction, serialised state. `completed_steps[].output` follows the same rule at 4 KB per step preview.

```json schema:checkpoint
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://vigil.dev/schemas/checkpoint/1",
  "title": "Checkpoint v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "checkpoint_id", "tenant_id", "agent_id", "task_id", "seq", "step_index", "created_at", "state_bytes", "state_schema", "completed_steps", "pending_steps", "side_effects", "redaction", "provenance"],
  "properties": {
    "schema": { "const": "vigil-checkpoint/1" },
    "checkpoint_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuidv7" },
    "tenant_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "agent_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "task_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "seq": { "type": "integer", "minimum": 1, "description": "Monotonic per task; gaps allowed, order is authoritative" },
    "step_index": { "type": "integer", "minimum": 0 },
    "step_name": { "type": "string", "maxLength": 128 },
    "created_at": { "type": "string", "format": "date-time" },
    "goal": { "type": "string", "maxLength": 2000 },
    "state": { "type": "object", "description": "Inline when state_bytes <= 65536" },
    "state_ref": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/payload_ref" },
    "state_bytes": { "type": "integer", "minimum": 0 },
    "state_sha256": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/sha256" },
    "state_schema": { "type": "string", "description": "Hint for the consumer: 'json' | 'app:<name>/v<n>' | 'langgraph/StateSnapshot@1' | 'pydantic:<module.Class>'" },
    "completed_steps": { "type": "array", "items": { "$ref": "#/$defs/completed_step" } },
    "pending_steps": { "type": "array", "items": { "$ref": "#/$defs/pending_step" } },
    "side_effects": { "type": "array", "items": { "$ref": "#/$defs/side_effect" } },
    "redaction": { "$ref": "#/$defs/redaction_state" },
    "provenance": {
      "type": "object",
      "additionalProperties": false,
      "required": ["sdk_version", "trace_id", "span_id"],
      "properties": {
        "sdk_version": { "type": "string" },
        "trace_id": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
        "span_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
        "prev_checkpoint_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuidv7" },
        "framework_checkpoint_id": { "type": "string", "description": "LangGraph thread/checkpoint id when mirrored" }
      }
    }
  },
  "allOf": [
    { "if": { "properties": { "state_bytes": { "maximum": 65536 } } }, "then": { "required": ["state"] }, "else": { "required": ["state_ref"], "not": { "required": ["state"] } } }
  ],
  "$defs": {
    "output_ref": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "preview": { "type": "string", "maxLength": 4096 },
        "ref": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/payload_ref" },
        "content_type": { "type": "string" }
      }
    },
    "completed_step": {
      "type": "object",
      "additionalProperties": false,
      "required": ["index", "step", "started_at", "ended_at", "assumed"],
      "properties": {
        "index": { "type": "integer", "minimum": 0 },
        "step": { "type": "string", "maxLength": 128 },
        "started_at": { "type": "string", "format": "date-time" },
        "ended_at": { "type": "string", "format": "date-time" },
        "tool_name": { "type": "string" },
        "call_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
        "span_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
        "output": { "$ref": "#/$defs/output_ref" },
        "assumed": { "type": "boolean", "description": "true when inferred from the trace rather than declared by the app" }
      }
    },
    "pending_step": {
      "type": "object",
      "additionalProperties": false,
      "required": ["index", "step"],
      "properties": {
        "index": { "type": "integer", "minimum": 0 },
        "step": { "type": "string", "maxLength": 128 },
        "description": { "type": "string", "maxLength": 1000 },
        "inputs_needed": { "type": "array", "items": { "type": "string" } },
        "blocked_on": { "type": "string" }
      }
    },
    "side_effect": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kind", "at", "assumed"],
      "properties": {
        "kind": { "enum": ["external_write", "message_sent", "payment", "file_written", "db_write", "ticket_created", "api_call", "unknown"] },
        "target": { "type": "string", "maxLength": 256 },
        "at": { "type": "string", "format": "date-time" },
        "idempotency_key": { "type": "string", "maxLength": 256 },
        "reversible": { "type": "boolean" },
        "assumed": { "type": "boolean" },
        "evidence_span_id": { "type": "string", "pattern": "^[0-9a-f]{16}$" }
      }
    },
    "redaction_state": {
      "type": "object",
      "additionalProperties": false,
      "required": ["capture_mode", "profile"],
      "properties": {
        "capture_mode": { "enum": ["full", "redacted", "metadata"] },
        "profile": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/redaction_profile" },
        "fields_redacted": { "type": "array", "items": { "type": "string" } }
      }
    }
  }
}
```

**Assembly rules.** The SDK writes the checkpoint from what the app declares (`vigil.checkpoint(task_id, state, step=..., completed=[...], pending=[...])`): `completed_steps[].assumed=false`; `side_effects` only when declared, or when a `vigil.tool()` with `side_effect_class` write/external returned (then `assumed=false`, the SDK saw it). Secrets scrubbing runs over the serialised state before the size check. The control plane never modifies a stored checkpoint; assembling a packet (§5) it **overlays** the trace tail: `tool.call`s after `checkpoint.ts` with `side_effect_class ∈ {write, external}` become `side_effects` with `assumed=true`; completed `tool.call`/`gen_ai.request` events after it become `completed_steps` with `assumed=true` and `output.ref` on the event payload. `pending_steps` are never inferred. No checkpoint → `fidelity=request_only`.

## 5. Handoff packet v1

```json schema:handoff-packet
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://vigil.dev/schemas/handoff-packet/1",
  "title": "HandoffPacket v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "packet_id", "tenant_id", "agent_id", "task_id", "created_at", "fidelity", "goal", "original_input", "completed_steps", "pending_steps", "reason", "next_action", "deadline", "accountability", "redaction", "provenance"],
  "properties": {
    "schema": { "const": "vigil-handoff-packet/1" },
    "packet_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuidv7" },
    "tenant_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "agent_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "agent_name": { "type": "string" },
    "task_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "created_at": { "type": "string", "format": "date-time" },
    "fidelity": { "enum": ["checkpoint", "request_only"] },
    "goal": { "type": "string", "minLength": 1, "maxLength": 2000 },
    "original_input": { "$ref": "https://vigil.dev/schemas/checkpoint/1#/$defs/output_ref" },
    "completed_steps": { "type": "array", "items": { "$ref": "https://vigil.dev/schemas/checkpoint/1#/$defs/completed_step" } },
    "pending_steps": { "type": "array", "items": { "$ref": "https://vigil.dev/schemas/checkpoint/1#/$defs/pending_step" } },
    "side_effects": { "type": "array", "items": { "$ref": "https://vigil.dev/schemas/checkpoint/1#/$defs/side_effect" } },
    "reason": {
      "type": "object",
      "additionalProperties": false,
      "required": ["plain_language", "trigger", "failure_mode"],
      "properties": {
        "plain_language": { "type": "string", "minLength": 20, "maxLength": 1000 },
        "failure_mode": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/failure_mode" },
        "trigger": {
          "type": "object",
          "additionalProperties": false,
          "required": ["kind"],
          "properties": {
            "kind": { "enum": ["sdk_explicit", "rule", "a2a_state", "operator", "approval_timeout"] },
            "rule_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/rule_id" },
            "alert_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
            "health_snapshot_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuidv7" },
            "factors": { "type": "array", "items": { "$ref": "https://vigil.dev/schemas/health/1#/$defs/factor" } },
            "span_ids": { "type": "array", "items": { "type": "string", "pattern": "^[0-9a-f]{16}$" } },
            "call_ids": { "type": "array", "items": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" } }
          }
        }
      }
    },
    "next_action": { "type": "string", "minLength": 5, "maxLength": 300, "description": "One imperative sentence" },
    "deadline": {
      "type": "object",
      "additionalProperties": false,
      "required": ["at", "derived_from"],
      "properties": {
        "at": { "type": "string", "format": "date-time" },
        "derived_from": { "enum": ["task_deadline", "tier_rto", "operator"] },
        "tier": { "type": "integer", "minimum": 1, "maximum": 3 },
        "rto_s": { "type": "integer", "minimum": 0 }
      }
    },
    "accountability": {
      "type": "object",
      "additionalProperties": false,
      "required": ["owner", "line"],
      "properties": {
        "owner": { "type": "string" },
        "on_call": { "type": "string" },
        "escalation": { "type": "string" },
        "business_process": { "type": "string" },
        "line": { "type": "string", "maxLength": 300, "description": "Rendered: 'Owned by <owner> (<process>); on call <on_call>; escalate to <escalation>'" }
      }
    },
    "redaction": { "$ref": "https://vigil.dev/schemas/checkpoint/1#/$defs/redaction_state" },
    "provenance": {
      "type": "object",
      "additionalProperties": false,
      "required": ["assembled_by", "policy_version", "trace_ids"],
      "properties": {
        "assembled_by": { "enum": ["sdk", "control_plane"] },
        "checkpoint_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuidv7" },
        "checkpoint_seq": { "type": "integer", "minimum": 0 },
        "checkpoint_age_s": { "type": "number", "minimum": 0 },
        "trace_ids": { "type": "array", "items": { "type": "string", "pattern": "^[0-9a-f]{32}$" } },
        "policy_version": { "type": "integer", "minimum": 0 },
        "transition_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
        "normaliser_version": { "type": "string" }
      }
    },
    "sidecar": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "route_history": { "type": "array", "items": { "type": "object", "required": ["at", "to"], "properties": { "at": { "type": "string", "format": "date-time" }, "to": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/target" }, "decision": { "type": "string" } } } },
        "cost_so_far_usd": { "type": "number", "minimum": 0 },
        "attempts": { "type": "integer", "minimum": 0 },
        "model_calls": { "type": "integer", "minimum": 0 },
        "tool_calls": { "type": "integer", "minimum": 0 }
      }
    },
    "summary": { "type": "string", "maxLength": 500, "description": "One-paragraph text written at creation for search (database-architect §7)" }
  }
}
```

```json example:handoff-packet
{
  "schema": "vigil-handoff-packet/1",
  "packet_id": "019276a3-1d5e-7f60-8b72-3c4d5e6f7081",
  "tenant_id": "0192767f-0000-7000-8000-00000000a001",
  "agent_id": "0192767f-0000-7000-8000-00000000c010",
  "agent_name": "quote-assistant",
  "task_id": "019276a0-9c1d-7e3f-9a52-1b2c3d4e5f60",
  "created_at": "2026-10-09T09:16:02.000Z",
  "fidelity": "checkpoint",
  "goal": "Produce and send a price quote for order #A-88213 to the customer contact on file",
  "original_input": {
    "preview": "Customer: Meridian Logistics. Request: quote for 40 pallets, delivery Pune, by 15 Oct. Attachments: RFQ-7731.pdf",
    "ref": { "ref": "blob://0192767f-0000-7000-8000-00000000a001/2026-10-09/4bf92f3577b34da6a3ce929d0e0e4736/a0a0a0a0a0a0a0a0.bin", "sha256": "0c3a2e1f9d8b7a6c5e4d3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c", "bytes": 3120, "content_type": "application/vnd.vigil.genai-content+json", "parts": ["input_messages"] },
    "content_type": "application/vnd.vigil.genai-content+json"
  },
  "completed_steps": [
    { "index": 0, "step": "parse_rfq", "started_at": "2026-10-09T09:14:10.000Z", "ended_at": "2026-10-09T09:14:12.400Z", "output": { "preview": "{\"sku\":\"PAL-40\",\"qty\":40,\"city\":\"Pune\",\"by\":\"2026-10-15\"}" }, "assumed": false },
    { "index": 1, "step": "lookup_order", "started_at": "2026-10-09T09:14:30.000Z", "ended_at": "2026-10-09T09:14:32.600Z", "tool_name": "lookup_order", "call_id": "019276a1-4a2b-7c1d-8e30-f1e2d3c4b5a6", "output": { "preview": "order A-88213: credit ok, pricing tier B" }, "assumed": false },
    { "index": 2, "step": "price_quote", "started_at": "2026-10-09T09:14:33.000Z", "ended_at": "2026-10-09T09:14:34.900Z", "output": { "preview": "INR 4,18,000 incl. freight; validity 7 days" }, "assumed": false },
    { "index": 3, "step": "draft_email", "started_at": "2026-10-09T09:15:40.000Z", "ended_at": "2026-10-09T09:15:58.200Z", "span_id": "8b2c3d4e5f607182", "output": { "preview": "Subject: Quote A-88213 ...", "ref": { "ref": "blob://0192767f-0000-7000-8000-00000000a001/2026-10-09/4bf92f3577b34da6a3ce929d0e0e4736/8b2c3d4e5f607182.bin", "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", "bytes": 2210, "content_type": "application/vnd.vigil.genai-content+json", "parts": ["output_messages"] } }, "assumed": true }
  ],
  "pending_steps": [
    { "index": 4, "step": "send_quote", "description": "Send the drafted email via CRM send_email tool", "inputs_needed": ["approved draft"] },
    { "index": 5, "step": "log_crm", "description": "Record quote in CRM opportunity 7731" }
  ],
  "side_effects": [
    { "kind": "api_call", "target": "crm.lookup_order", "at": "2026-10-09T09:14:32.600Z", "reversible": true, "assumed": false, "evidence_span_id": "00f067aa0ba902b7" }
  ],
  "reason": {
    "plain_language": "OpenAI returned rate-limit errors on 8 of the last 10 calls from this agent and the inline fallback model also failed on step 'send_quote'. The task was stopped before any email was sent.",
    "failure_mode": "provider_outage",
    "trigger": {
      "kind": "rule",
      "rule_id": "ratelimit_proximity",
      "alert_id": "0192767f-0000-7000-8000-00000000e501",
      "health_snapshot_id": "019276a2-7f00-7000-8000-000000000042",
      "factors": [
        { "rule": "ratelimit_proximity", "weight": 0.15, "value": 0.045, "threshold": 0.10, "direction": "below", "penalty": 10, "explanation": "Rate-limit headroom 4.5% (threshold 10%)" },
        { "rule": "error_rate", "weight": 0.30, "value": 0.8, "threshold": 0.05, "direction": "above", "penalty": 30, "explanation": "Error rate 80% over the last 5 minutes (threshold 5%)" }
      ],
      "span_ids": ["9c3d4e5f60718293"],
      "call_ids": ["019276a2-5a2b-7c1d-8e30-f1e2d3c4b5a9"]
    }
  },
  "next_action": "Review the drafted email in step 3, then send it to the customer and log the quote in CRM opportunity 7731.",
  "deadline": { "at": "2026-10-09T10:16:02.000Z", "derived_from": "tier_rto", "tier": 2, "rto_s": 3600 },
  "accountability": {
    "owner": "sales-ops@tenant",
    "on_call": "r.iyer",
    "escalation": "head-of-sales",
    "business_process": "Quote-to-cash",
    "line": "Owned by sales-ops@tenant (Quote-to-cash); on call r.iyer; escalate to head-of-sales"
  },
  "redaction": { "capture_mode": "full", "profile": { "id": "secrets", "version": 1, "rules_fired": [], "secrets_scrubbed": 0 }, "fields_redacted": [] },
  "provenance": {
    "assembled_by": "control_plane",
    "checkpoint_id": "019276a2-0c4d-7e5f-8a61-2b3c4d5e6f71",
    "checkpoint_seq": 2,
    "checkpoint_age_s": 87,
    "trace_ids": ["4bf92f3577b34da6a3ce929d0e0e4736"],
    "policy_version": 42,
    "transition_id": "0192767f-0000-7000-8000-00000000f777",
    "normaliser_version": "normaliser/1.3.0"
  },
  "sidecar": {
    "route_history": [
      { "at": "2026-10-09T09:14:31.000Z", "to": { "provider": "openai", "model": "gpt-5-mini" }, "decision": "inline_fallback" },
      { "at": "2026-10-09T09:15:59.000Z", "to": { "provider": "anthropic", "model": "claude-sonnet-5" }, "decision": "failover" }
    ],
    "cost_so_far_usd": 0.0412,
    "attempts": 6,
    "model_calls": 5,
    "tool_calls": 1
  },
  "summary": "Quote for Meridian Logistics order A-88213 drafted but not sent; OpenAI rate-limited, fallback failed at send_quote. Operator to review draft and send."
}
```

Rules: `deadline.derived_from=tier_rto` means `created_at + RTO` of the agent's tier (defaults 15 min / 1 h / 4 h for tiers 1/2/3 until the continuity plan says otherwise); `next_action` and `reason.plain_language` come from per-rule templates filled with `factors[]`; `request_only` packets have `completed_steps` built entirely from the trace tail (`assumed=true`), `pending_steps=[]`, and a console label "cannot resume, context only". Step content is always a `PayloadRef`, so packets stay small and the erasure cascade covers them.

## 6. Health response, feature snapshot, predictor interface

```json schema:health
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://vigil.dev/schemas/health/1",
  "title": "GET /agents/{id}/health",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "health_snapshot_id", "tenant_id", "agent_id", "computed_at", "window", "score", "status", "provisional", "factors", "horizons", "predicted_failure_mode", "feature_snapshot_ref", "policy_version"],
  "properties": {
    "schema": { "const": "vigil-health/1" },
    "health_snapshot_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuidv7" },
    "tenant_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "agent_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "computed_at": { "type": "string", "format": "date-time" },
    "window": {
      "type": "object", "additionalProperties": false, "required": ["start", "end", "grain_s"],
      "properties": { "start": { "type": "string", "format": "date-time" }, "end": { "type": "string", "format": "date-time" }, "grain_s": { "enum": [60, 300, 900, 3600] } }
    },
    "score": { "type": "integer", "minimum": 0, "maximum": 100 },
    "status": { "enum": ["healthy", "watch", "degraded", "failed"] },
    "provisional": {
      "type": "object", "additionalProperties": false, "required": ["flag", "events_seen", "events_needed"],
      "properties": { "flag": { "type": "boolean" }, "events_seen": { "type": "integer", "minimum": 0 }, "events_needed": { "type": "integer", "minimum": 1 }, "observation_coverage": { "type": "number", "minimum": 0, "maximum": 1 } }
    },
    "factors": { "type": "array", "items": { "$ref": "#/$defs/factor" } },
    "horizons": {
      "type": "object", "additionalProperties": false, "required": ["15m", "1h", "24h"],
      "properties": { "15m": { "$ref": "#/$defs/prediction" }, "1h": { "$ref": "#/$defs/prediction" }, "24h": { "$ref": "#/$defs/prediction" } }
    },
    "predicted_failure_mode": { "oneOf": [{ "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/failure_mode" }, { "type": "null" }] },
    "recommended_action": { "enum": ["none", "watch", "reroute_to_fallback", "reroute_to_backup_agent", "throttle", "trim_context", "quarantine", "handoff", "await_approval", null] },
    "feature_snapshot_ref": { "type": "string", "pattern": "^fs_[0-9a-f-]{36}$" },
    "policy_version": { "type": "integer", "minimum": 0 },
    "routing_state": { "type": "string" }
  },
  "$defs": {
    "factor": {
      "type": "object", "additionalProperties": false,
      "required": ["rule", "weight", "value", "threshold", "direction", "explanation"],
      "properties": {
        "rule": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/rule_id" },
        "weight": { "type": "number", "minimum": 0, "maximum": 1 },
        "penalty": { "type": "number", "minimum": 0, "maximum": 100 },
        "value": { "type": ["number", "string", "boolean"] },
        "threshold": { "type": ["number", "string", "boolean"] },
        "direction": { "enum": ["above", "below", "equals", "rising", "falling"] },
        "explanation": { "type": "string", "maxLength": 300 },
        "evidence": { "type": "string", "description": "Console deep link or query" },
        "kind": { "enum": ["detected", "leading"] },
        "horizon_s": { "type": "integer" }
      }
    },
    "prediction": {
      "type": "object", "additionalProperties": false,
      "required": ["probability_band", "source", "confidence"],
      "properties": {
        "probability_band": { "enum": ["0.05", "0.25", "0.60", "0.90"] },
        "probability": { "type": "number", "minimum": 0, "maximum": 1, "description": "Only from a calibrated model source" },
        "predicted_failure_mode": { "oneOf": [{ "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/failure_mode" }, { "type": "null" }] },
        "source": { "type": "string", "pattern": "^(rules/v\\d+|model/[a-z0-9_-]+:[A-Za-z0-9._-]+)$" },
        "confidence": { "enum": ["low", "medium", "high"] },
        "contributing_rules": { "type": "array", "items": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/rule_id" } },
        "abstained": { "type": "boolean", "description": "Model abstained; rules filled this horizon" }
      }
    }
  }
}
```

```json example:health
{
  "schema": "vigil-health/1",
  "health_snapshot_id": "019276a2-7f00-7000-8000-000000000042",
  "tenant_id": "0192767f-0000-7000-8000-00000000a001",
  "agent_id": "0192767f-0000-7000-8000-00000000c010",
  "computed_at": "2026-10-09T09:15:50.000Z",
  "window": { "start": "2026-10-09T09:10:50.000Z", "end": "2026-10-09T09:15:50.000Z", "grain_s": 300 },
  "score": 42,
  "status": "degraded",
  "provisional": { "flag": false, "events_seen": 1840, "events_needed": 50, "observation_coverage": 1.0 },
  "factors": [
    { "rule": "error_rate", "weight": 0.30, "penalty": 30, "value": 0.12, "threshold": 0.05, "direction": "above", "explanation": "Error rate 12% over the last 5 minutes (threshold 5%)", "evidence": "/traces?agent=c010&error=true", "kind": "detected" },
    { "rule": "ratelimit_proximity", "weight": 0.15, "penalty": 10, "value": 0.045, "threshold": 0.10, "direction": "below", "explanation": "Rate-limit headroom 4.5% (threshold 10%)", "kind": "leading", "horizon_s": 900 },
    { "rule": "fallback_pressure", "weight": 0.15, "penalty": 18, "value": 0.34, "threshold": 0.20, "direction": "above", "explanation": "Inline fallbacks on 34% of calls (threshold 20%)", "kind": "leading", "horizon_s": 900 }
  ],
  "horizons": {
    "15m": { "probability_band": "0.60", "predicted_failure_mode": "provider_outage", "source": "rules/v1", "confidence": "low", "contributing_rules": ["ratelimit_proximity", "fallback_pressure"] },
    "1h": { "probability_band": "0.25", "predicted_failure_mode": "latency_degradation", "source": "rules/v1", "confidence": "low", "contributing_rules": ["fallback_pressure"] },
    "24h": { "probability_band": "0.05", "predicted_failure_mode": null, "source": "rules/v1", "confidence": "low", "contributing_rules": [] }
  },
  "predicted_failure_mode": "provider_outage",
  "recommended_action": "reroute_to_fallback",
  "feature_snapshot_ref": "fs_019276a2-7e00-7000-8000-000000000042",
  "policy_version": 42,
  "routing_state": "degraded"
}
```

### FeatureSnapshot (frozen at prediction time)

One document per health computation, immutable, referenced by `feature_snapshot_ref`, written by the worker to backend-architect's `health_snapshot` (or its own `feature_snapshot` table, their call). Features are a flat map per grain so a new feature is an additive key, never a schema change. Static features are the registry facts as they were at `as_of`.

```json schema:feature-snapshot
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://vigil.dev/schemas/feature-snapshot/1",
  "title": "FeatureSnapshot v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "feature_snapshot_ref", "tenant_id", "agent_id", "as_of", "feature_set", "grains", "static", "observation_coverage"],
  "properties": {
    "schema": { "const": "vigil-feature-snapshot/1" },
    "feature_snapshot_ref": { "type": "string", "pattern": "^fs_[0-9a-f-]{36}$" },
    "tenant_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "agent_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "as_of": { "type": "string", "format": "date-time", "description": "No event with ts > as_of contributed" },
    "feature_set": { "type": "string", "pattern": "^features/v\\d+$" },
    "grains": {
      "type": "object", "additionalProperties": false, "required": ["1m", "5m", "15m", "1h"],
      "properties": { "1m": { "$ref": "#/$defs/grain" }, "5m": { "$ref": "#/$defs/grain" }, "15m": { "$ref": "#/$defs/grain" }, "1h": { "$ref": "#/$defs/grain" } }
    },
    "static": {
      "type": "object", "additionalProperties": false,
      "required": ["tier", "provider", "model", "fail_mode", "hour_of_day_utc", "day_of_week_utc"],
      "properties": {
        "tier": { "type": "integer", "minimum": 1, "maximum": 3 },
        "provider": { "type": "string" }, "model": { "type": "string" },
        "fail_mode": { "enum": ["open", "closed"] },
        "routing_state": { "type": "string" },
        "breaker_state": { "enum": ["closed", "open", "half_open"] },
        "provider_status": { "type": "string" },
        "budget_headroom": { "type": "number" },
        "model_context_limit": { "type": "integer" },
        "days_to_model_deprecation": { "type": ["integer", "null"] },
        "days_to_credential_expiry": { "type": ["integer", "null"] },
        "hour_of_day_utc": { "type": "integer", "minimum": 0, "maximum": 23 },
        "day_of_week_utc": { "type": "integer", "minimum": 0, "maximum": 6 },
        "agent_age_days": { "type": "number" },
        "peer_group": { "type": "string", "description": "Cold-start baseline group id" }
      }
    },
    "observation_coverage": { "type": "number", "minimum": 0, "maximum": 1 },
    "baseline_ref": { "type": "string", "description": "Which learned or peer baseline was used for *_vs_baseline features" }
  },
  "$defs": {
    "grain": {
      "type": "object",
      "description": "Flat numeric feature map; keys registered in features/vN. Missing key = not computable in this grain.",
      "propertyNames": { "pattern": "^[a-z][a-z0-9_]{1,60}$" },
      "additionalProperties": { "type": ["number", "null"] },
      "properties": {
        "request_count": {}, "error_rate": {}, "error_rate_429": {}, "error_rate_5xx": {}, "error_rate_timeout": {},
        "latency_p50_ms": {}, "latency_p95_ms": {}, "latency_p99_ms": {}, "latency_p95_vs_baseline": {}, "ttfb_p95_ms": {},
        "tokens_in_mean": {}, "tokens_out_mean": {}, "tokens_out_cv": {}, "output_chars_mean": {}, "cost_usd": {}, "cost_per_task_usd": {},
        "ratio_429": {}, "retry_mean": {}, "inline_fallback_ratio": {}, "ratelimit_headroom_min": {},
        "finish_length_ratio": {}, "finish_tool_calls_ratio": {}, "context_utilisation_p95": {},
        "tool_call_count": {}, "tool_error_rate": {}, "tool_seq_entropy": {}, "tool_seq_repeat_ratio": {},
        "task_count": {}, "task_success_rate": {}, "task_steps_p95": {}, "handoff_count": {}, "checkpoint_age_p95_s": {},
        "feedback_mean": {}, "route_changes": {}, "policy_stale_ratio": {},
        "error_rate_slope": {}, "latency_p95_slope": {}, "cost_slope": {}
      }
    }
  }
}
```

### `HealthPredictor` interface (Phase 2 plug-in; the rules engine is the default implementation)

Interface, not code:

- `name`, `version` → rendered as `source` (`rules/v1` or `model/<name>:<version>`).
- `required_feature_set` → must equal `FeatureSnapshot.feature_set` or a lower minor, else the registry refuses to select it.
- `predict(snapshot: FeatureSnapshot, horizons_s: [900, 3600, 86400]) -> list[Prediction]`, `Prediction` = `health/1#/$defs/prediction` plus `horizon_s`. Fewer horizons or `abstained=true` are allowed; the worker fills gaps from rules and marks them.
- `explain(snapshot, horizon_s) -> list[factor]`, optional; absent → rules' factors are shown.
- Selected per tenant/agent by config; `provisional.flag=true` or `observation_coverage < 0.8` forces `rules/vN`.
- Pure function of the snapshot, no DB reads inside `predict`: offline replay against stored snapshots then equals production.

## 7. Labels

Every label is a document (backend owns the table) **and** carries a `judges` pointer to exactly one of: a `health_snapshot_id`, an `event_id`, an `alert_id`, a `packet_id`, a `transition_id`, or a time window on an agent. The pointer plus `judged_as_of` (the `computed_at`/`ts` of the thing judged) is what Step 5 joins on; `labelled_at` is always later. Training joins `FeatureSnapshot.as_of ≤ judged_as_of < outcome`; nothing after `as_of` may enter the feature side.

```json schema:label
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://vigil.dev/schemas/label/1",
  "title": "Label v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "label_id", "tenant_id", "agent_id", "kind", "judges", "judged_as_of", "labelled_at", "labeller", "value"],
  "properties": {
    "schema": { "const": "vigil-label/1" },
    "label_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuidv7" },
    "tenant_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "agent_id": { "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/uuid" },
    "kind": { "enum": ["alert_verdict", "task_outcome", "feedback", "failover_outcome", "handoff_outcome", "provider_incident"] },
    "judges": {
      "type": "object", "additionalProperties": false, "required": ["kind", "id"],
      "properties": {
        "kind": { "enum": ["health_snapshot", "event", "alert", "packet", "transition", "window"] },
        "id": { "type": "string" },
        "window": { "type": "object", "required": ["start", "end"], "properties": { "start": { "type": "string", "format": "date-time" }, "end": { "type": "string", "format": "date-time" } } },
        "feature_snapshot_ref": { "type": "string", "pattern": "^fs_[0-9a-f-]{36}$" }
      }
    },
    "judged_as_of": { "type": "string", "format": "date-time" },
    "labelled_at": { "type": "string", "format": "date-time" },
    "labeller": { "type": "object", "required": ["kind"], "properties": { "kind": { "enum": ["operator", "end_user", "sdk", "judge", "worker"] }, "ref": { "type": "string" } } },
    "value": { "type": "object" },
    "reason": { "type": "string", "maxLength": 500 }
  },
  "allOf": [
    { "if": { "properties": { "kind": { "const": "alert_verdict" } } }, "then": { "properties": { "value": { "type": "object", "required": ["verdict"], "properties": { "verdict": { "enum": ["tp", "fp", "unsure"] }, "actual_failure_mode": { "oneOf": [{ "$ref": "https://vigil.dev/schemas/vigil-event/1#/$defs/failure_mode" }, { "type": "null" }] }, "lead_time_s": { "type": ["integer", "null"] } } } } } },
    { "if": { "properties": { "kind": { "const": "task_outcome" } } }, "then": { "properties": { "value": { "type": "object", "required": ["outcome"], "properties": { "outcome": { "enum": ["success", "partial", "failure", "abandoned", "handed_off"] }, "rework": { "type": "boolean" } } } } } },
    { "if": { "properties": { "kind": { "const": "feedback" } } }, "then": { "properties": { "value": { "type": "object", "required": ["score"], "properties": { "score": { "type": "number", "minimum": -1, "maximum": 1 }, "scale": { "type": "string" } } } } } },
    { "if": { "properties": { "kind": { "const": "failover_outcome" } } }, "then": { "properties": { "value": { "type": "object", "required": ["fallback_succeeded"], "properties": { "fallback_succeeded": { "type": "boolean" }, "time_to_recover_s": { "type": "integer" }, "failback_verified": { "type": "boolean" }, "undone_by_operator": { "type": "boolean" } } } } } },
    { "if": { "properties": { "kind": { "const": "handoff_outcome" } } }, "then": { "properties": { "value": { "type": "object", "required": ["outcome"], "properties": { "outcome": { "enum": ["completed", "returned", "abandoned"] }, "rework": { "type": "boolean" }, "rating": { "type": "integer", "minimum": 1, "maximum": 5 }, "packet_useful": { "type": "boolean" } } } } } },
    { "if": { "properties": { "kind": { "const": "provider_incident" } } }, "then": { "properties": { "value": { "type": "object", "required": ["provider", "status", "rule_fired_before"], "properties": { "provider": { "type": "string" }, "status": { "type": "string" }, "incident_id": { "type": "string" }, "rule_fired_before": { "type": "boolean" }, "lead_time_s": { "type": ["integer", "null"] } } } } } }
  ]
}
```

```json example:label
{
  "schema": "vigil-label/1",
  "label_id": "019276b0-0000-7000-8000-000000000101",
  "tenant_id": "0192767f-0000-7000-8000-00000000a001",
  "agent_id": "0192767f-0000-7000-8000-00000000c010",
  "kind": "alert_verdict",
  "judges": { "kind": "health_snapshot", "id": "019276a2-7f00-7000-8000-000000000042", "feature_snapshot_ref": "fs_019276a2-7e00-7000-8000-000000000042" },
  "judged_as_of": "2026-10-09T09:15:50.000Z",
  "labelled_at": "2026-10-09T09:41:12.000Z",
  "labeller": { "kind": "operator", "ref": "0192767f-0000-7000-8000-00000000u001" },
  "value": { "verdict": "tp", "actual_failure_mode": "provider_outage", "lead_time_s": 610 },
  "reason": "OpenAI status page confirmed elevated 429s from 09:25"
}
```

Production: `alert_verdict` is mandatory on alert close (judges the `health_snapshot` that raised it); `task_outcome` and `feedback` mirror the events of the same name (judge the `agent.invoke` end event or trace); `failover_outcome` is written by the worker when a transition returns to `active` or is undone (judges the `transition`); `handoff_outcome` comes from `handoff.completed|returned` (judges the `packet`); `provider_incident` is synthesised from `provider.status` for every agent on that provider, judging the **window [started_at − 1 h, started_at]** with `rule_fired_before` from `health.transition` history. That last label exists whether or not a rule fired; it is what stops Phase 2 from imitating Phase 1 rules.

## 8. Versioning policy

- `vigil-event/1` is a major. Within it, changes are **additive only**: new event types, new optional attrs keys, new enum values on fields documented as open (`rule_id`, `provider`, feature keys). Removing a field, changing a type, tightening a required set, or changing an idempotency key is `vigil-event/2`.
- Consumers ignore unknown keys and unknown event types (the worker's rule set lists the types it reads).
- The normaliser carries **N and N−1**: when `vigil-event/2` ships, ingest writes `/2` and a view (or a re-normalisation job from raw spans) serves `/1` readers for one release; the row's `schema` field says which it is.
- The OTel conventions version is pinned independently (§3); bumps are normaliser table revisions with conformance fixtures per instrumentor version. `ingest.semconv_version` and `ingest.normaliser_version` let a re-normalisation target rows by version.
- Clients declare their schema version on the wire: OTLP scope attribute `vigil.schema.version` (e.g. `vigil-event/1`) and `vigil.semconv.version`; `/v1/events` JSON batches declare `{"schema": "vigil-event/1", "events": [...]}`; the gateway stamps its own. A declared major the ingest does not support → 400 with the supported list; undeclared → assumed current, with an `ingest.warnings` entry.
- Documents (`checkpoint`, `handoff-packet`, `health`, `feature-snapshot`, `label`) version independently on the same rule; `feature_set` (`features/vN`) versions the feature key registry and gates predictor selection.

## 9. Mapping note for database-architect and backend-architect

`events` (database-architect): first-class columns, in this order of importance for the indexes you already proposed: `tenant_id`, `ts`, `event_id` (PK), `agent_id`, `type` (your `kind`), `task_id`, `call_id`, `trace_id`, `span_id`, `source`, `emitter_id`, `seq`, `capture_mode`, `policy_state.state` (as `policy_state TEXT`), `policy_state.policy_version` (`policy_version INT`), `observed_at`. From `gen_ai.request` attrs, hoist as columns because every rule and rollup reads them: `status`, `error_type`, `latency_ms`, `provider`, `model` (=`request_model`), `tokens_in`, `tokens_out`, `cost_usd`, `route_decision`, `merge_state`. `payload_ref`, `payload_sha256`, `payload_bytes` are your columns, populated from `attrs.payload`. Everything else in `attrs` stays JSONB and must fit your 4 KB cap (the example above is 2.0 KB); `ingest` (raw span refs, warnings; 0.5 KB in the example) is JSONB and may be a separate narrow table if the cap bites. `redaction_profile` is JSONB on the row; `redaction_profile.id` could be a column if the compliance view groups by it. Idempotency keys per type (§1) are the `ON CONFLICT` targets. `gen_ai.request` merging needs an update path: either `events` allows updating `attrs`/`merge_state` within 24 h of `ts`, or ingest stages in a small `call_merge` table and emits the final row once. I prefer the second; `events` stays append-only.

`payload_refs` (database-architect): one row per `PayloadRef` with `ref`, `sha256`, `bytes`, `content_type`, `parts[]`, `redaction_profile_id`, `tenant_id`, `created_at`, `derived_from (event_id | checkpoint_id | packet_id)`, which is also your derived-data registry for erasure cascades.

`checkpoint`, `handoff_task` (backend-architect): the Checkpoint document is one JSONB column plus hoisted `tenant_id, agent_id, task_id, seq, step_index, created_at, state_bytes, state_ref` and a `UNIQUE (tenant_id, task_id, seq)`. The packet is one JSONB column plus `packet_id, tenant_id, agent_id, task_id, created_at, fidelity, failure_mode, deadline_at, trigger_kind, rule_id, alert_id, transition_id, assembled_by, summary`; packets over 64 KB (rare, only with many inline previews) spill to BlobStore and the row keeps `packet_ref`.

`health_snapshot` (backend-architect): the health response as JSONB plus `health_snapshot_id, tenant_id, agent_id, computed_at, score, status, provisional, predicted_failure_mode, feature_snapshot_ref, policy_version`; the FeatureSnapshot as its own JSONB row keyed by `feature_snapshot_ref`, immutable, retained as long as labels reference it (not swept with events). Labels: one table, `kind`, `judges_kind`, `judges_id`, `judged_as_of`, `labelled_at`, `value JSONB`, with an index on `(tenant_id, judges_kind, judges_id)`.

`provider.status` rows use the platform tenant id; add it to the RLS policy as readable by all tenants.
