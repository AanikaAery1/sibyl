# Step 4 — APIs + SDK: technical-writer

Date: 2026-10-10. Inputs: `CHAIR-INITIAL.md`, `DECISIONS.md` (D1–D29), `architect/ARCHITECTURE.md`, `datamodel/ai-engineer.md` (event and document schemas), `datamodel/security-auditor.md` (scopes, roles, audit taxonomy).

Scope of this report: the *documentation* of the three surfaces and the SDK, not their definition. Route paths, header names, enum values and SDK signatures below follow the chair position and the Step 3 contracts; anything I had to invent is marked `<!-- TBC -->` so the chair can reconcile against backend-architect and ai-engineer. All identifiers use the `sibyl*` family (D19); `vigil*` does not appear in user-facing text anywhere.

Conventions used in every page: second person, present tense, one task per heading, every code block runnable against the compose stack, every persona page starts with "who this is for". Readability target: Flesch > 60 on prose paragraphs; reference tables are exempt.

---

## 1. Quickstart: "Sibyl in 10 minutes"

> **Who this is for.** The Platform Admin, a platform engineer who already has an agent calling an OpenAI-compatible model and wants to see it governed, monitored and failed over without changing its code. Time to first value: about 10 minutes on a laptop with Docker.
>
> **What you will have at the end.** One agent registered in Sibyl, a simulated provider outage, an automatic failover you can watch, a handoff packet in the On-call Operator's queue, and an audit chain the Compliance Auditor can verify offline.

### 1.1 Start the stack

```bash
git clone https://github.com/sibyl-ai/sibyl && cd sibyl      # <!-- TBC: repo URL -->
cp .env.example .env
docker compose up -d
docker compose ps        # gateway, api, ingest, worker, console, postgres, dex, simulator all "healthy"
```

Ports on the compose default profile:

| Service | URL | Notes |
|---|---|---|
| Console | http://localhost:3000 | Sign in via dex with a demo persona |
| Gateway (data plane) | http://localhost:8080 | OpenAI-compatible; point clients here |
| Control-plane API | http://localhost:8000/api/v1 | REST + SSE |
| Ingest | http://localhost:8001/v1/otlp | OTLP/HTTP and `sibyl-event/1` batches |
| dex (demo IdP) | http://localhost:5556 | Static personas, see below |

<!-- TBC: port numbers are placeholders until compose is written. -->

Demo identities (D29). Passwords are in `.env.example`; they are for the local stack only.

| Persona | Role | Use for |
|---|---|---|
| Platform Admin | `admin` (engineer) | Creating keys, registering agents, chaos knobs |
| On-call Operator | `operator` | Operator queue, approvals, undo, hold |
| Compliance Auditor | `auditor` | Audit viewer, anchor verification, exports |

The compose stack seeds three tenants: `meridian` (20 synthetic agents already running), `northstar` (3 agents, used by the isolation test), `sandbox` (empty). This quickstart uses **`sandbox`** so you see your own agent appear from nothing; switch to `meridian` when you want a busy fleet map.

### 1.2 Create a tenant API key

Sign in to the console as the Platform Admin, pick tenant `sandbox`, and complete the one onboarding step Sibyl refuses to skip: the **capture policy** (D12). `full` is pre-selected; secrets scrubbing is on regardless of what you choose. Until the policy exists the ingest answers `403 capture_policy_missing` and you cannot mint a key.

Then mint a key from the CLI or the console. From the CLI:

```bash
export SIBYL_SESSION=...   # paste from Console → Settings → "CLI session" <!-- TBC -->
curl -s -X POST http://localhost:8000/api/v1/api-keys \
  -H "Authorization: Bearer $SIBYL_SESSION" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "admin-laptop",
    "scopes": ["gateway:proxy", "ingest:write", "handoff:write", "agents:read", "agents:write"]
  }'
```

```json
{
  "key_id": "0192a0f1-7b3c-7d2e-9a1b-0c4d5e6f7a8b",
  "prefix": "sbl_live_9f2k",
  "secret": "sbl_live_9f2k_…",            // shown once; Sibyl stores only a hash
  "scopes": ["gateway:proxy", "ingest:write", "handoff:write", "agents:read", "agents:write"],
  "tenant": "sandbox",
  "expires_at": null
}
```

<!-- TBC: key prefix `sb_` (Step 2 used `vg_`); whether `agent_id` binding is required at creation or optional. -->

```bash
export SIBYL_API_KEY="sbl_live_9f2k_…"
```

The key is tenant-scoped. A key can be **bound to one agent** at creation (`"agent_id": "..."`); a bound key may only speak for that agent. `killswitch:pull` is *not* on this key and should never be on a developer key; it is the break-glass scope (D20) and lives on a separately minted key kept offline.

### 1.3 Connect an agent, two ways

Pick one. Both produce the same `gen_ai.request` events; (b) additionally gives you checkpoints and task boundaries, which is what makes a handoff packet worth reading.

#### (a) Zero code: point an existing OpenAI client at the gateway

Change two things: the base URL and the Authorization header. Add one header, `X-Sibyl-Agent`, so Sibyl knows which registered agent this traffic belongs to.

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="sbl_live_9f2k_…",  # the Sibyl key, not your provider key
    default_headers={
        "X-Sibyl-Agent": "quote-worker",  # slug; auto-registered on first call
        "X-Sibyl-Upstream-Authorization": "Bearer sk-…",  # <!-- TBC --> passthrough of your provider key (D11)
    },
)

resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Quote me 40 tonnes of OPC 43 to Jaipur."}],
)
print(resp.choices[0].message.content)
```

What happened on the wire:

- The request body is byte-for-byte OpenAI. Sibyl adds **no JSON fields** (D16). All Sibyl behaviour rides on `X-Sibyl-*` headers.
- The gateway looked up `quote-worker` in its signed policy snapshot, did not find it, served the call with the tenant default (`unknown_agent_fail_mode`, `open` by default) and enqueued an `agent.discovered` event.
- Response headers you will see: `X-Sibyl-Agent-Id`, `X-Sibyl-Route` (`primary` or the fallback target that answered), `X-Sibyl-Policy-State` (`fresh|stale|expired`), `X-Sibyl-Call-Id`. <!-- TBC: exact response header set -->

Honest limit: a gateway-only agent can only ever get a **`request_only`** handoff packet. Sibyl knows the last request, not the agent's state. The console says so on the agent card. Use (b) when the agent does multi-step work.

#### (b) SDK: `pip install sibyl-sdk`

```bash
pip install sibyl-sdk          # Apache-2 (D15)
export SIBYL_API_KEY="sbl_live_9f2k_…"
export SIBYL_ENDPOINT="http://localhost:8001"     # ingest; defaults to the cloud endpoint when unset <!-- TBC -->
```

```python
import sibyl
from openai import OpenAI

sibyl.init(agent="quote-worker")  # wraps OpenAI/Anthropic clients via OTel GenAI instrumentation
client = OpenAI(
    base_url="http://localhost:8080/v1", api_key=sibyl.gateway_key()
)  # optional: also go through the gateway


@sibyl.task(name="prepare_quote")
def prepare_quote(request: dict) -> dict:
    rate = lookup_rate(request["destination"])  # a tool call; auto-captured as tool.call
    sibyl.checkpoint(step="rate_looked_up", state={"request": request, "rate": rate})

    draft = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": f"Draft a quote: {request} at {rate}"}],
    )
    sibyl.checkpoint(
        step="draft_written",
        state={"draft": draft.choices[0].message.content},
        pending=["send_to_customer"],
    )
    return {"draft": draft.choices[0].message.content}
```

Rules the SDK keeps for you, so you do not have to:

- `sibyl.init()` never blocks the caller. Telemetry goes into a bounded in-process buffer (drop-oldest) and is flushed every 500 ms or 200 spans; `sibyl.sdk.dropped_spans` is reported so the control plane can mark an observation gap instead of silently losing data.
- Secrets scrubbing is unconditional (`[SECRET:<hash8>]`), even under `capture_mode=full`.
- `sibyl.checkpoint()` state is capped at 64 KB after redaction; larger state goes to BlobStore by reference.
- Going through the gateway *and* the SDK is the recommended shape: the SDK owns task and checkpoint context, the gateway owns latency, usage and routing, and ingest merges the two views of one call within 5 s.

### 1.4 See the agent in the registry

Console → **Registry**. `quote-worker` appears within ~5 s with lifecycle `discovered`, tier **3** (the default for discovered agents) and, for path (a), a yellow "request-only handoff" badge.

Or from the API:

```bash
curl -s http://localhost:8000/api/v1/agents?slug=quote-worker \
  -H "Authorization: Bearer $SIBYL_API_KEY"
```

```json
{
  "data": [{
    "id": "0192a0f2-…", "slug": "quote-worker", "lifecycle": "discovered", "tier": 3,
    "fail_mode": "open", "handoff_fidelity": "checkpoint",
    "continuity_plan": null, "owner": null, "last_seen_at": "2026-10-10T09:12:41Z"
  }],
  "next_cursor": null
}
```

Promote it to a governed asset by giving it an owner, a tier and a continuity plan. The plan is what failover reads:

```bash
curl -s -X PUT http://localhost:8000/api/v1/agents/0192a0f2-…/continuity-plan \
  -H "Authorization: Bearer $SIBYL_API_KEY" -H "If-Match: \"0\"" \
  -H "Content-Type: application/json" \
  -d '{
    "tier": 2,
    "rto_minutes": 60,
    "fallback_chain": [
      {"kind": "alternate_model",    "provider": "openai",    "model": "gpt-4o"},
      {"kind": "alternate_provider", "provider": "anthropic", "model": "claude-sonnet-4-5", "credential_id": "0192…"},
      {"kind": "human_queue",        "queue": "default"}
    ],
    "degraded_mode": "serve_cached_rates"
  }'
```

<!-- TBC: continuity plan is a sub-resource (`PUT .../continuity-plan`) vs a field on `PATCH /agents/{id}`; `credential_id` references a vaulted `provider_credential` (D11). -->

Tier 2 means: alternate-model and alternate-provider failover are automatic on detected failure; predicted-only failover degrades first and goes automatic after two windows; failover to a backup agent is automatic; kill is operator-only (ARCHITECTURE §5).

### 1.5 Trigger a simulated failure (chaos knob)

The compose stack ships a provider simulator. Turn on a 5xx storm for the OpenAI stub:

```bash
curl -s -X POST http://localhost:8000/api/v1/simulator/chaos \
  -H "Authorization: Bearer $SIBYL_API_KEY" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"provider": "openai", "fault": "error_rate", "value": 0.8, "duration_s": 300}'
```

<!-- TBC: simulator control is a control-plane route or a separate `simulator:9000` admin port; fault enum (`error_rate | latency_ms | rate_limit | status_incident | budget_burn`). -->

Then run `prepare_quote()` in a loop (or let the simulator's own `quote-worker` traffic do it). Within one or two 1-minute windows the detected rules fire: error rate crosses threshold, consecutive failures, and the inline-fallback pressure leading indicator.

### 1.6 Watch the automatic failover

Open a second terminal and follow the incident stream:

```bash
curl -N http://localhost:8000/api/v1/incidents/stream \
  -H "Authorization: Bearer $SIBYL_API_KEY" -H "Accept: text/event-stream"
```

```
event: incident.opened
data: {"incident_id":"0192a0f9-…","agent_id":"0192a0f2-…","trigger":"detected","rules":["error_rate","consecutive_failures"],"state":"degraded"}

event: incident.transition
data: {"incident_id":"0192a0f9-…","from":"degraded","to":"failed_over","action":"failover.alternate_model","target":{"provider":"openai","model":"gpt-4o"},"transition_id":"0192a0fa-…","actor":"worker:rule_engine"}

event: incident.transition
data: {"incident_id":"0192a0f9-…","from":"failed_over","to":"failed_over","action":"failover.alternate_provider","target":{"provider":"anthropic","model":"claude-sonnet-4-5"},"actor":"worker:rule_engine"}

event: handoff.requested
data: {"packet_id":"0192a0fb-…","fidelity":"checkpoint","trigger":"rule","queue":"default"}
```

In the console the agent card moves from green to amber to "failed over → anthropic/claude-sonnet-4-5". The gateway honoured the new route in under 2 s; your client code did not change and did not fail: `X-Sibyl-Route: fallback:anthropic/claude-sonnet-4-5` is now on every response.

If you set the agent to **tier 1** instead, the alternate-provider step would still be automatic on *detected* failure, but a *predicted-only* trigger would park the incident in `awaiting_approval` (D13) and the On-call Operator would see an approval card with a 10-minute timeout that forces `hold` (D22).

### 1.7 On-call Operator: the handoff packet lands in the operator queue

Sign in as the **On-call Operator**. Console → **Operator queue**. The task created by the `human_queue` step in the fallback chain shows the packet:

- **Goal**: the original input (`Quote me 40 tonnes of OPC 43 to Jaipur`).
- **Completed steps**: `rate_looked_up`, `draft_written` (with output previews, 4 KB each).
- **Pending steps**: `send_to_customer`.
- **Side effects so far**: none (the tool call was read-only; `side_effect_class: none`).
- **Why**: `trigger: rule`, `failure_mode: provider_outage`, the contributing rules and the health snapshot at the time.
- **Fidelity**: `checkpoint` (path b) or `request_only` (path a).

The On-call Operator can **Claim**, **Complete** (they finish the quote themselves), or **Return to agent** once the primary is healthy. Each resolution writes `handoff.completed` / `handoff.returned` with their operator ref and becomes a label for the learning engine.

They can also **Undo** the failover from the incident view, which creates the inverse transition and places a 30-minute **hold** that blocks every rule and policy actor (D21). Humans and the kill switch bypass the hold.

### 1.8 Compliance Auditor: read the audit chain

Sign in as the **Compliance Auditor**. Console → **Audit**. Filter by `incident_id`. Every step is there, hash-chained per tenant: `alert.fired`, `incident.opened`, `routing.transition` ×2, `handoff.requested`, `handoff.claimed`, `hold.placed`, and the hourly Ed25519 anchor that covers them.

Verify without trusting the database:

```bash
curl -s "http://localhost:8000/api/v1/audit/export?from=2026-10-10T09:00:00Z&to=2026-10-10T10:00:00Z" \
  -H "Authorization: Bearer $AUDITOR_SESSION" -o audit-2026-10-10T09.jsonl
curl -s http://localhost:8000/api/v1/audit/anchors/latest -H "Authorization: Bearer $AUDITOR_SESSION" -o anchor.json
sibyl audit verify audit-2026-10-10T09.jsonl --anchor anchor.json --public-key sibyl-audit.pub
# chain ok: 212 events, 1 anchor, signature valid, no gaps
```

<!-- TBC: `sibyl audit verify` ships in the SDK CLI vs a separate `sibyl-audit-verify` tool; export format JSONL. -->

Done. Next steps for the Platform Admin: [Continuity plans in depth], [Fail-open vs fail-closed], [Checkpoint design for your framework], [Running Sibyl as a sidecar (Phase 2)].

---

## 2. API reference conventions

> **Who this is for.** Anyone writing against the control plane. The gateway data plane follows OpenAI's conventions, not these, except for the `X-Sibyl-*` headers listed in §2.7.

### 2.1 Base URLs and versioning

| Surface | Base | Version signal |
|---|---|---|
| Gateway | `https://<gateway>/v1` | OpenAI dialect; Sibyl behaviour via headers only |
| Control plane | `https://<api>/api/v1` | Path version. Breaking change ⇒ `/api/v2`; additive changes do not bump |
| Ingest | `https://<ingest>/v1/otlp/{traces,logs}` and `/v1/events` | Payload declares `sibyl.schema.version` (OTLP scope attr) or `{"schema":"sibyl-event/1"}` |

Additive-only policy (mirrors `sibyl-event/1`): new optional fields, new enum values on fields documented as *open*, new routes. Clients must ignore unknown fields. Fields documented as *closed* enums are not extended without a major.

### 2.2 Authentication

Two principal kinds. Every route in the reference states which it accepts and the required scope or permission.

| Principal | Credential | Carries | Used by |
|---|---|---|---|
| Human (console, CLI) | OIDC session, `Authorization: Bearer <session>` | role (`owner`, `admin`, `security_admin`, `auditor`, `operator`, `engineer`, `viewer` <!-- TBC: last three names -->) and optional `agent_group` scope | people |
| Agent / machine | API key, `Authorization: Bearer sbl_…` | scopes ⊆ `gateway:proxy ingest:write handoff:write routing:read agents:read agents:write killswitch:pull`, optional bound `agent_id` | SDK, gateway clients, CI |

Rules worth stating on the page:

- Keys are hashed with a lookup prefix; the secret is shown once at creation. Rotation gives a grace window (`grace_until`) during which both secrets verify.
- A key bound to an agent may only act for that agent; `X-Sibyl-Agent` may *narrow* the target, never widen it.
- Some human actions require **step-up** (recent re-authentication): kill switch, erasure approval, legal hold release, capture policy changes. The response is `403` with `type: …/step-up-required`; re-authenticate and retry with the same `Idempotency-Key`.
- `killswitch:pull` keys are accepted on exactly one route (`POST /api/v1/kill-switch`) and nowhere else; their use is audited as `access.break_glass` (D20).

### 2.3 Errors: RFC 9457 problem details

Every non-2xx response from the control plane and ingest is `application/problem+json`:

```json
{
  "type": "https://docs.sibyl.dev/errors/illegal-transition",
  "title": "Illegal incident transition",
  "status": 409,
  "detail": "Incident is 'killed'; action 'failover.alternate_model' is not allowed from this state.",
  "instance": "/api/v1/incidents/0192a0f9-…/actions",
  "code": "illegal_transition",
  "current_state": "killed",
  "allowed_actions": ["release"],
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
}
```

`type`, `title`, `status`, `detail`, `instance` are RFC 9457. `code` is a stable machine string; `trace_id` is always present. Extension members are documented per `code`. The errors catalogue (one page per `type` URL) is generated from the OpenAPI document.

Status codes and when they appear:

| Status | `code` examples | Meaning |
|---|---|---|
| 400 | `validation_failed`, `unsupported_schema_version` | Body or query invalid; `errors[]` lists field paths |
| 401 | `unauthenticated` | Missing or invalid credential |
| 403 | `forbidden`, `step_up_required`, `capture_policy_missing`, `scope_missing` | Authenticated but not allowed; `required_scope` or `required_permission` included |
| 404 | `not_found` | Also returned for resources in another tenant (never 403; no existence leak) |
| 409 | `illegal_transition`, `idempotency_conflict`, `etag_mismatch`, `hold_active` | State conflict; body says what would be legal |
| 412 | `precondition_failed` | `If-Match` did not match |
| 422 | `plan_invalid` | Semantically invalid (e.g. fallback chain references an unvaulted credential) |
| 428 | `idempotency_key_required` | POST that creates or transitions state without `Idempotency-Key` |
| 429 | `rate_limited`, `ingest_backpressure` | `Retry-After` always present |
| 503 | `snapshot_unavailable`, `fail_closed` | Gateway only; structured body even on the data plane <!-- TBC: gateway error shape is OpenAI-style `error` object or problem+json -->

The gateway, being OpenAI-compatible, returns OpenAI's `{"error": {...}}` shape for provider-originated errors and passes upstream status codes through unchanged. Sibyl-originated gateway rejections (fail-closed, killed, no snapshot) add `X-Sibyl-Reason` and, because the body must stay OpenAI-shaped, put the problem `code` in `error.code`.

### 2.4 Pagination

Cursor-based everywhere; no offset pagination.

```
GET /api/v1/audit/events?limit=100&cursor=eyJ0cyI6…
```

```json
{ "data": [ … ], "next_cursor": "eyJ0cyI6…", "has_more": true }
```

- `limit` default 50, max 500 (audit export routes: streaming, no limit).
- Cursors are opaque, URL-safe, and valid for 24 h; a stale cursor returns `400 cursor_expired`.
- Ordering is stable and documented per collection (events and audit: `(ts, id)` ascending by default, `order=desc` supported).
- Filters are query parameters with a fixed vocabulary per collection (`agent_id`, `incident_id`, `from`, `to`, `type`); unknown filters are `400`, not ignored.

### 2.5 Idempotency

Every `POST` that creates or transitions state requires `Idempotency-Key` (a client-generated UUID). The key is scoped to tenant + route + principal and retained 24 h.

| Case | Response |
|---|---|
| First call | normal 2xx; stored with request hash |
| Replay, same body | the stored 2xx, with `Idempotency-Replayed: true` |
| Replay, different body | `409 idempotency_conflict` |
| Missing key | `428 idempotency_key_required` |

Policy objects (continuity plans, routing policy, capture policy, rules) carry an `ETag`; `PUT`/`PATCH` require `If-Match`, mismatch is `412`. Reads support `If-None-Match` → `304`. The gateway uses the same mechanism for the policy snapshot.

### 2.6 Server-Sent Events

Streams are `GET` with `Accept: text/event-stream`. Each message has `id:` (a cursor), `event:` (the event type), `data:` (JSON). Reconnect with `Last-Event-ID` to resume without loss within the 24-h cursor window; a heartbeat comment `: ping` arrives every 15 s.

| Stream | Events | Scope |
|---|---|---|
| `/api/v1/incidents/stream` | `incident.opened`, `incident.transition`, `incident.closed`, `approval.requested`, `approval.resolved` | `incidents:read` |
| `/api/v1/queue/stream` | `handoff.requested`, `handoff.claimed`, `handoff.resolved` | `queue:read` |
| `/api/v1/agents/{id}/health/stream` | `health.transition` | `agents:read` |
| `/v1/policy/snapshot/stream` | `routing_changed` (invalidation only, no payload) | gateway, `routing:read` |

<!-- TBC: permission names `incidents:read`, `queue:read` follow the Step 3 role matrix naming; final stream list from backend-architect. -->

Filters are query parameters identical to the matching list route. Streams never replay history on first connect; use the list route with `from=` for backfill.

### 2.7 Gateway headers (the only Sibyl surface on the data plane)

Request headers:

| Header | Required | Meaning |
|---|---|---|
| `Authorization: Bearer sbl_…` | yes | Sibyl API key with `gateway:proxy` |
| `X-Sibyl-Agent` | recommended | Registered slug or id; unknown ⇒ auto-register with tenant default |
| `X-Sibyl-Upstream-Authorization` | yes unless vaulted | Your provider credential, passed through (D11) <!-- TBC name --> |
| `X-Sibyl-Task-Id`, `X-Sibyl-Trace-Id` | optional | Correlate with SDK task/trace; the SDK sets them for you |
| `X-Sibyl-Prompt-Version` | optional | Stamped on the event as `attrs.prompt_version` |

Response headers: `X-Sibyl-Call-Id`, `X-Sibyl-Agent-Id`, `X-Sibyl-Route`, `X-Sibyl-Policy-State`, `X-Sibyl-Retry-Attempt`, and the six `x-ratelimit-*` headers mirrored from upstream.

Streaming responses are relayed byte-for-byte; retries happen only before the first response byte. Nothing Sibyl does on the data plane waits for the control plane.

### 2.8 Rate limits and backpressure

Control plane: per key, token bucket, `X-RateLimit-Limit/Remaining/Reset` headers, `429` with `Retry-After`. Ingest: `429 ingest_backpressure` when the write path lags; the SDK honours it with exponential backoff and bounded buffering. Gateway: per-agent and per-provider limits come from the continuity plan, not from a global setting.

---

## 3. SDK reference

### 3.1 Python (`sibyl-sdk`) — page skeleton

Package `sibyl-sdk`, import `sibyl`, Python ≥ 3.10, Apache-2. Depends only on `sibyl-schemas` (shared contracts) and the OpenTelemetry SDK + GenAI instrumentation; no control-plane client code in the hot path.

```
sibyl.init(agent: str | None = None, *, api_key=..., endpoint=..., capture_mode: "inherit"|"full"|"redacted"|"metadata" = "inherit",
           instrument: Iterable[str] = ("openai", "anthropic"), buffer_max_spans=10_000, flush_interval_ms=500) -> None
sibyl.shutdown(timeout_s: float = 5.0) -> None            # flushes; never raises
sibyl.gateway_key() -> str                                 # the API key, for building an OpenAI client against the gateway

@sibyl.task(name: str, *, outcome_on_return: bool = False)  # decorator or context manager; emits agent.invoke start/end
sibyl.agent(name: str) -> ContextManager                    # switch the active agent for a block (multi-agent processes)
sibyl.checkpoint(step: str, state: Mapping, *, pending: list[str] = (), side_effects: list[SideEffect] = ()) -> CheckpointId
sibyl.handoff(reason: str, *, failure_mode: FailureMode | None = None, packet: HandoffPacket | None = None) -> PacketId
sibyl.handoff.packet(goal=..., completed=..., pending=..., side_effects=...) -> HandoffPacket   # explicit packet builder
sibyl.outcome(status: "success"|"failure"|"partial", *, reason=None, metrics=None) -> None       # task.outcome
sibyl.feedback(score: float, *, scale="1-5", target: "task"|"call" = "task", comment=None) -> None
sibyl.resolve_route(agent: str | None = None) -> Route    # read current routing (cached, refreshes ≤10 s); never blocks on miss
sibyl.tool(name: str, *, side_effect_class: "none"|"read"|"write"|"external") -> decorator          # manual tool.call when no auto-instrumentation
```

<!-- TBC: everything above the line except `init`, `agent`, `checkpoint`, `handoff.packet` (which are in CHAIR-INITIAL) is proposed naming aligned to the event types in ai-engineer.md §1; ai-engineer owns the final signatures. -->

Reference page outline (one H2 per function):

1. **Installation and configuration** — env vars (`SIBYL_API_KEY`, `SIBYL_ENDPOINT`, `SIBYL_AGENT`, `SIBYL_CAPTURE_MODE`, `SIBYL_DISABLED=1`), precedence (argument > env > default), proxies and TLS.
2. **`init()`** — what gets instrumented, what is sent, what is scrubbed, buffering guarantees, the "never blocks, never raises" contract, idempotent re-init.
3. **Tasks** — `@sibyl.task`, nesting (`parent_task_id`), async support, exceptions ⇒ `status=error`.
4. **Checkpoints** — when to checkpoint (after each side effect; before each long step), size limit, `state_schema`, `prev_checkpoint_id` chaining, what the operator sees.
5. **Handoff** — explicit vs automatic; building a packet; `fidelity`; what happens when the control plane is down (buffered, flagged `assembled_by: sdk`).
6. **Routing** — `resolve_route()`, reading `Route.target`, `Route.policy_state`, honouring a kill (`Route.killed=True` ⇒ do not call the model).
7. **Outcomes and feedback** — labels for the learning engine.
8. **Multi-agent processes** — `sibyl.agent()` context manager; A2A state mapping.
9. **Framework notes** — LangChain/LangGraph, CrewAI, OpenAI Agents SDK: what auto-instrumentation covers and where you still call `checkpoint()` yourself.
10. **Troubleshooting** — `sibyl doctor` CLI <!-- TBC -->, `dropped_spans` counter, `403 capture_policy_missing`, clock skew.

Every function page carries: signature, parameters table, what event it emits (link to `sibyl-event/1`), a 10-line example, failure behaviour.

### 3.2 TypeScript (`@sibyl/sdk`) — "coming" stub

> **Status: interface sketched, not shipped.** Phase 1 ships Python. The TypeScript package will mirror the Python surface one-for-one so the docs can share examples via tabs.

```ts
import { sibyl } from "@sibyl/sdk";

sibyl.init({ agent: "quote-worker" });                     // wraps openai / @anthropic-ai/sdk via OTel GenAI

await sibyl.task("prepare_quote", async () => {
  const rate = await lookupRate(req.destination);
  sibyl.checkpoint("rate_looked_up", { req, rate });
  // ...
});
```

Until it ships, Node agents use path (a): the OpenAI client with `baseURL` and `defaultHeaders: { "X-Sibyl-Agent": "..." }`. That gives full monitoring and failover; handoff is `request_only`.

---

## 4. Operator runbook (stub)

> **Who this is for.** The On-call Operator. Every action here is a state-machine transition on an incident or agent, audited, and visible to the Compliance Auditor. Nothing here can lose work silently.

Actions are `POST /api/v1/incidents/{id}/actions` with `{"action": "...", "reason": "..."}` (and `POST /api/v1/agents/{id}/actions` for agent-level actions). Illegal transitions return `409 illegal_transition` with `allowed_actions`. `reason` is required and lands in the audit event.

| Action | Enum <!-- TBC --> | From states | Permission | Effect | Reversible |
|---|---|---|---|---|---|
| Approve a proposed failover | `approve` | `awaiting_approval` | `incidents:approve` | Runs the proposed transition | via undo |
| Deny | `deny` | `awaiting_approval` | `incidents:approve` | Back to `degraded`; rule cooldown applies | — |
| Undo last transition | `undo` | `failed_over`, `failing_back` | `incidents:act` | Inverse transition + **30-min hold** (D21) | yes (undo the undo) |
| Place hold | `hold` | any open | `incidents:act` | Blocks all rule/policy actors until `expires_at`; humans and kill bypass | release |
| Release hold | `release_hold` | held | `incidents:act` | Rules resume next window | — |
| Quarantine agent | `quarantine` | `active`, `degraded`, `failed_over` | `agents:quarantine` | Gateway rejects traffic with `503 fail_closed`; SDK `resolve_route()` returns `quarantined` | `release` |
| Kill switch | `kill` | any | `killswitch:pull` or step-up `security_admin` | Immediate, beats fail-open, survives stale snapshot; agent, group or tenant scope | `release` (audited, step-up) |
| Release kill | `release` | `killed`, `quarantined` | step-up | Back to `active` | — |
| Close | `close` | `active` after failback | `incidents:act` | Requires **verdict** (D24) | — |

### 4.1 Approvals (D13, D22)

When an approval card appears, it carries the proposed action, the contributing rules, the health snapshot and a countdown. Timeout policy is on the continuity plan: `hold` (default) or `fail_safe`. For tier-1 agents flagged PII or residency-sensitive, timeout **always** forces `hold` (D22); the console shows the lock. The approver must differ from whoever last edited the plan. <!-- TBC: separation-of-duty rule -->

### 4.2 Undo and hold (D21)

Undo is the safety valve for a wrong automatic decision. It (1) writes the inverse `routing_transition`, (2) bumps the routing version so the gateway re-routes within 2 s, (3) places a 30-minute hold that blocks every rule and policy actor, detected *and* predicted. It does not stop another human and it does not stop the kill switch. The incident stays open; close it with a verdict when done. Undoing within the hold of a prior undo is allowed and extends the hold.

### 4.3 Kill switch (D20)

Three ways to pull it, in order of preference: console (step-up), API with a human session (step-up), or the **break-glass key** when the IdP is down. The break-glass key has one scope and reaches one route; store it offline, test it in each game-day drill, rotate it after any use. Killed agents stay killed on any stale or expired snapshot. Release requires a reason and step-up and emits `killswitch.released` with `killed_for_s`.

### 4.4 Handoff queue

Claim → work → Complete, Return to agent, or Abandon (with reason). Returned tasks resume from the last checkpoint on the agent if the primary route is healthy; otherwise the console offers to re-queue. Rate the packet (1–5, "was it useful?"); that rating is how packet quality improves.

### 4.5 Closing with a verdict (D24)

`true_positive`, `false_positive`, or `unsure`, plus optional `actual_failure_mode` and `lead_time_s`. Alerts cannot close without one. A false positive on a predicted trigger raises that rule's threshold on the next retrain window; this is the main lever against flapping.

---

## 5. Docs information architecture and tooling

### 5.1 Sidebar tree

```
Sibyl Docs
├── Start here
│   ├── What Sibyl is (one page, three personas, one diagram)
│   ├── Sibyl in 10 minutes            ← §1
│   ├── Concepts (glossary + the failover state machine)
│   └── Demo tenants: meridian, northstar, sandbox
├── Connect an agent
│   ├── Zero-code: OpenAI-compatible gateway
│   ├── Python SDK
│   ├── TypeScript SDK (coming)
│   ├── OpenTelemetry collector / third-party instrumentors
│   ├── Framework guides (LangGraph, CrewAI, OpenAI Agents SDK)
│   └── Checkpoints and handoff fidelity
├── Govern
│   ├── Registry and lifecycle
│   ├── Tiers and risk classification
│   ├── Continuity plans (fallback chains, RTO defaults D23)
│   ├── Capture policy, redaction, retention (D12, D27, D28)
│   ├── Credentials for fallback targets (D11)
│   └── Erasure, legal hold, residency (D17, D26)
├── Operate
│   ├── Operator queue and handoff packets
│   ├── Approvals, undo, hold, kill switch   ← §4
│   ├── Incidents and verdicts
│   ├── Chaos knobs and game days
│   └── Fail-open vs fail-closed; what happens when the control plane is down
├── Audit
│   ├── Audit viewer
│   ├── Verifying exports offline
│   ├── Audit event taxonomy
│   └── Compliance mapping (EU AI Act, NIST AI RMF, ISO 42001)
├── Reference
│   ├── Conventions                     ← §2
│   ├── Control-plane API (OpenAPI)
│   ├── Gateway API (OpenAPI; OpenAI dialect + X-Sibyl-* headers)
│   ├── Ingest API (OTLP + sibyl-event/1)
│   ├── Python SDK (generated from docstrings)
│   ├── Event schemas (sibyl-event/1, checkpoint/1, handoff-packet/1, health/1)
│   ├── Errors catalogue
│   ├── Scopes and roles matrix
│   └── Environment variables
├── Deploy
│   ├── docker compose (Phase 1)
│   ├── Kubernetes + managed Postgres (migration path)
│   ├── Backups and PITR (D18)
│   ├── SSO with your IdP (Keycloak, Okta, Entra)
│   └── Sizing and SLOs per deployment shape
└── Changelog
```

Persona entry points on the landing page: "I run agents" → Connect; "I keep the lights on" → Operate; "I audit" → Audit. Each reference page links back to the task page that uses it.

### 5.2 Tooling (D15: permissive-only)

Recommendation: **MkDocs + Material for MkDocs** (both MIT), **mkdocstrings-python** (ISC) for the SDK reference from docstrings, and **Scalar API Reference** (MIT) embedded for the three OpenAPI documents.

| Candidate | Licence | Verdict |
|---|---|---|
| MkDocs + Material | MIT / MIT | **Pick.** Python-native (matches the `uv` monorepo), Markdown source, tabs for Python/TS/curl, built-in search, versioning via `mike` (BSD-3) |
| mkdocstrings-python | ISC | **Pick.** SDK reference stays in the code |
| Scalar API Reference | MIT | **Pick.** Renders OpenAPI 3.1 with a try-it panel; single JS include |
| Redoc (CLI/community) | MIT | Fine alternative; no try-it in the free build |
| Swagger UI | Apache-2 | Acceptable fallback; weaker 3.1 support |
| Docusaurus | MIT | Good, but adds a Node build to a Python repo for no gain in Phase 1 |
| Mintlify, ReadMe, GitBook | hosted / proprietary | Excluded by D10 and D15 |

Build rules: docs live in `docs/site/` in the monorepo; OpenAPI documents are generated by FastAPI at build time and diffed in CI (a route without a `summary`, `description`, declared permission and at least one example fails the build); the quickstart's code blocks are extracted and run against the compose stack in CI nightly so §1 can never silently rot; `vigil` is a banned word in a lint step.

---

## 6. Terminology glossary

Use these words exactly; the console, API, SDK and docs share them.

| Term | Definition | Not to be confused with |
|---|---|---|
| **Agent** | A registered AI asset that makes model or tool calls under one identity: a chatbot, copilot, autonomous agent, RAG pipeline. Has a slug, owner, tier, lifecycle stage and continuity plan. | A *model* (what it calls) or a *provider* (who serves it) |
| **Model** | A specific model name the agent requests, e.g. `gpt-4o-mini`, `claude-sonnet-4-5`. Tracked with version where the provider exposes it. | The agent |
| **Provider** | The upstream serving the model: OpenAI-compatible endpoints, Anthropic, Ollama. Sibyl tracks provider status feeds and holds vaulted credentials only for configured fallback providers (D11). | The gateway, which is Sibyl's own component |
| **Gateway** | Sibyl's in-line, OpenAI-compatible proxy on the hot path. Reads a signed policy snapshot; never calls the control plane synchronously. | A tenant's API gateway |
| **Continuity plan** | Per-agent plan: tier, RTO/RPO, ordered fallback chain, degraded mode, owner and on-call humans. Automatic failover executes this plan. Defaults for a silent plan: RTO 15 min / 1 h / 4 h by tier (D23). | A runbook (which maps failure modes to remediation actions) |
| **Tier** | Criticality 1 (highest) to 3. Gates how much automation is allowed: tier 1 needs approval for predicted-only failover and for backup-agent failover (D13). | Risk classification under EU AI Act, which is a separate field |
| **Fallback chain** | The ordered list of targets in a continuity plan: alternate model → alternate provider → backup agent → degraded mode → human queue. | Inline retry (tactical, per request, gateway-local) |
| **Failover** | Strategic re-routing of an agent's traffic to the next target in its chain, recorded as a `routing_transition`. Automatic on detected failure; tier-gated on prediction. | *Inline fallback*: a single request retried against the next target by the gateway |
| **Failback** | Verified return to the primary after it has been healthy for 5 min and a probe passes; canaried 10 → 100 %. | Undo |
| **Incident** | The stateful record opened when rules fire for an agent, carrying the state machine (`active → degraded → failed_over → …`), its transitions, approvals and the closing verdict. One provider outage collapses to one incident per agent. | An *alert* (a rule firing; several feed one incident) |
| **Handoff packet** | The document given to a human (or backup agent) when work leaves the agent: goal, completed steps, pending steps, side effects, reason, trace tail. `fidelity: checkpoint` (SDK) or `request_only` (gateway-only). | A trace |
| **Checkpoint** | An SDK-recorded point in a task from which work can resume: step name, serialised state (≤ 64 KB inline), pending steps. Packets are built from the latest checkpoint. | A log line |
| **Hold** | (1) *Operator hold*: a 30-minute block on rule/policy actors after an undo or on request; humans and kill switch bypass (D21). (2) *Legal hold*: freezes retention and erasure for a scope. Docs always qualify which. | Quarantine |
| **Quarantine** | Agent state where the gateway rejects its traffic; operator- or policy-triggered; released by an operator. | Kill |
| **Kill switch** | Immediate stop for an agent, group or tenant that beats fail-open and survives stale snapshots. Operator-only; break-glass key available (D20). | Quarantine (softer, policy-driven) |
| **Approval** | A pending human decision on a proposed high-risk action with a timeout policy (`hold` or `fail_safe`; tier-1 PII/residency agents always `hold`, D22). | Verdict |
| **Verdict** | Mandatory label on an alert at close: `true_positive`, `false_positive`, `unsure` (D24). Feeds rule tuning and Phase 2 learning. | Outcome (`task.outcome`, the business result of a task) |
| **Anchor** | Hourly Ed25519-signed digest of the tenant's audit hash chain, signed with a key held outside the database. Exports verify offline against anchors. | A backup |
| **Policy snapshot** | The signed, versioned, TTL'd bundle of routing, limits and key hashes the gateway runs on. `policy_state ∈ fresh|stale|expired`. | Policy-as-code rules (Phase 2) |
| **Capture mode** | Tenant or agent choice: `full`, `redacted`, `metadata`. Secrets scrubbing applies regardless (D12). | Retention |
| **Fail mode** | Per-agent `open` (serve without policy when the snapshot is stale) or `closed` (503). Kill beats both. | Fail-safe (an approval timeout policy) |
| **Scope** | A permission string on an API key (`gateway:proxy`, `ingest:write`, …). | A *role* (human) or an *agent group* (authz boundary) |

---

## 7. Open questions for the chair

1. **Key prefix and provider passthrough header.** Step 2 used `vg_`; I wrote `sbl_live_…`. And is the tenant's provider key passed via `X-Sibyl-Upstream-Authorization`, or does the gateway reuse the `Authorization` header with the Sibyl key moved to `X-Sibyl-Key`? The quickstart's first code block hinges on this.
2. **Continuity plan as sub-resource or field.** I documented `PUT /agents/{id}/continuity-plan` with ETag. If backend-architect models it as a field on `PATCH /agents/{id}`, the ETag story and the "plan invalid" 422 change.
3. **Action enum spelling.** I used `approve|deny|undo|clear_hold|release|fail_back|cancel` (create: `failover|degrade|recover|handoff|quarantine|kill`; R25) on `/incidents/{id}/actions`, and `failover.alternate_model` style for automatic transitions. One vocabulary should serve both the API and the audit taxonomy.
4. **Where chaos knobs live.** A control-plane route (`/api/v1/simulator/chaos`, demo profile only) is friendlier to document than a separate simulator port, but it puts demo code on the product API. Which?
5. **Offline verification tooling.** `sibyl audit verify` in the SDK CLI makes the Compliance Auditor story a one-liner and ships under Apache-2; alternatively a standalone `sibyl-audit-verify`. The docs need the command name.
6. **SSE permission names.** The Step 3 matrix enumerates API-key scopes precisely but human permissions (`incidents:read`, `queue:read`, `incidents:approve`) only by role; I need the permission strings per route to populate the "Required" column on every reference page.
