# Concepts

The console, the API, the SDK and these docs use the same words. Where a term has fixed values in the API, they are listed exactly as the API spells them.

## The things Sibyl tracks

| Term | Meaning | Not to be confused with |
|---|---|---|
| **Tenant** | One customer organisation. All data is partitioned by tenant and isolated by row-level security. The demo has `meridian`, `northstar` and `sandbox`. | An agent group (an authorisation boundary inside a tenant) |
| **Agent** | A registered AI asset that calls models or tools under one identity, for example a chatbot, copilot, autonomous agent, RAG pipeline or workflow. It has a slug, owner, tier, risk class, fail mode, lifecycle stage and continuity plan. | A model or a provider |
| **Agent group** | A named set of agents. An Engineer's grant can be limited to some groups. Anything outside those groups returns 404. | A tenant |
| **Provider** | The upstream that serves models, recorded with a dialect (`openai_compatible` in Phase 1) and a `base_url` from an allowlist. | The gateway |
| **Model** | A model name at a provider, for example `gpt-5.4` or `claude-sonnet-5`. An agent version names its primary model. | The agent |
| **Lifecycle** | `proposed → approved → deployed → monitored → retired`. A tier-1 agent cannot leave `proposed` until an agent-bound API key exists (R35). | Routing state |
| **Tier** | Criticality from 1 (highest) to 3. Tier controls how much automation is allowed. When a continuity plan is silent, the default RTO is 15 min, 1 h and 4 h for tiers 1, 2 and 3 (D23). | Risk class (`minimal`, `limited`, `high`), which is a separate field |
| **Dependency graph** | Edges such as `uses_model`, `reads_data`, `calls_tool` and `delegates_to` between agents, models, tools and data sources. It drives blast-radius queries. | |

## Policy

| Term | Meaning |
|---|---|
| **Capture policy** | Per tenant, optionally narrowed per agent: `capture_mode` is `full`, `redacted` or `metadata`, plus a redaction profile and payload retention (default 30 days, up to 365). A tenant must have one before it can mint any key except a break-glass key (D12). An agent's policy can only be stricter than the tenant's. |
| **Secrets scrubbing** | Always on, whatever the capture mode. Detected secrets are replaced by `[KIND:hash8]` before anything is stored. |
| **Continuity plan** | Per agent: degraded mode (`queue_only` or `safe_no_tools`), the approval timeout and its policy (`hold` or `fail_safe`), credential mode, on-call reference, monthly budget, in-flight cap, and the pre-emptive mode for predictions. |
| **Fallback chain** | An ordered, versioned and approved list of steps. Step kinds: `retry`, `alt_model_same_provider`, `alt_provider` (needs a vaulted credential), `backup_agent`, `degraded_safe_mode`, `human_queue`. Nothing may follow `human_queue`. A chain is a draft until it is approved. Approved chains cannot be changed. |
| **Provider credential** | A vaulted key for a fallback target (D11). It is envelope-encrypted per tenant and reaches the gateway only as a sealed bundle that lives for 300 seconds. Your primary call uses your own key, passed through. |
| **Fail mode** | Per agent, `open` or `closed`. It decides what the gateway does when its policy snapshot is expired. A kill beats both. |
| **Policy snapshot** | The signed, versioned bundle of routing, limits and key hashes the gateway runs on. It is signed with Ed25519, lives 60 seconds plus 300 seconds of grace, and its freshness is `fresh`, `stale`, `expired` or `unavailable`. |

## Health, prediction and alerts

| Term | Meaning |
|---|---|
| **Health score and band** | Each agent is scored every 10 seconds from its rolled-up metrics. Detected rules (error rate, latency, consecutive failures, quality proxies and others) lower the score. The band summarises it, and `failed` is what triggers a detected failover. |
| **Leading rule** | A rule that looks ahead: error and latency trends, rate-limit proximity, fallback pressure, budget proximity, provider status and others. Each belongs to a signal family. |
| **Prediction** | Failure probability for each agent over 15-minute, 1-hour and 24-hour horizons. It is expressed as a band (`0.05`, `0.25`, `0.60`, `0.90`), a confidence (`low`, `medium`, `high`) and its contributing rules. Only the 15-minute horizon can trigger action in Phase 1. Action needs at least `medium` confidence and evidence from two signal families. Tiers 2–3 act at `0.90` until the D36 release criterion opens `0.60`. |
| **Alert** | One rule firing on one agent, provider or platform. State is `open`, `acked` or `resolved`. Alerts from one provider outage collapse into one provider incident. |
| **Verdict** | The label given when an alert is closed: `tp`, `fp` or `unsure`. It is mandatory (D24). An alert that resolves on its own may stay unverdicted (D33) and is listed under **Alerts → Unverdicted**. |
| **Provider incident** | One record per provider outage, listing the affected agents. |

## Failover

| Term | Meaning |
|---|---|
| **Routing state** | The agent's current route. Seven states: `active`, `degraded`, `awaiting_approval`, `failed_over`, `failing_back`, `quarantined`, `killed`. Every change is a numbered, audited routing transition. |
| **Incident** | A failover saga: the record of one routing intervention for one agent and the steps it took. State is `pending`, `running`, `waiting_approval`, `done`, `cancelled` or `failed`. Kinds include `failover`, `preemptive`, `degrade`, `recover`, `quarantine`, `release`, `kill`, `undo` and `failback`. One agent has at most one live incident (`409 saga_in_flight`). |
| **Failover** | Moving an agent's traffic to the next viable step of its chain. It is triggered by a detected failure, a prediction or an operator. |
| **Inline fallback** | The gateway retrying one request against the next chain step before the first response byte. It is tactical and per request. A failover is strategic and changes the route. |
| **Approval** | A pending human decision on a proposed move, with a timeout (default 10 minutes) and a timeout policy. The requester cannot approve (four-eyes). Tier-1 agents with PII exposure always fall back to `hold` at timeout (D22). |
| **Undo** | The inverse of the newest automated transition. It places an operator hold. |
| **Operator hold** | A 30-minute block on rule and policy actors for one agent, placed by an undo (D21). Humans and the kill switch are not blocked. |
| **Quarantine** | The gateway refuses the agent's traffic (`sibyl_agent_quarantined`) until an operator releases it. |
| **Kill switch** | An immediate stop for an agent, a provider or a whole tenant. It beats fail-open and survives a stale snapshot. A break-glass API key can pull it when the identity provider is down (D20). |
| **Failback** | The return to the primary after it has been healthy for 5 minutes. A canary ramp is available behind `SIBYL_FAILBACK_RAMP=1`. |

## Handoff

| Term | Meaning |
|---|---|
| **Checkpoint** | A resumable point in an SDK task: step name, scrubbed state (up to 64 KB inline), completed and pending steps, side effects. |
| **Handoff packet** | The `sibyl-handoff/1` document a person receives when work leaves an agent: goal, completed and pending steps, side effects, reason and failure mode, next action, deadline. Fidelity is `checkpoint` when built from SDK checkpoints, or `request_only` when Sibyl only saw gateway traffic. |
| **Handoff task** | A queue item for a packet. State is `queued`, `claimed`, `completed`, `returned` or `expired`. A claim holds a lock for 30 minutes. |
| **Outcome** | The business result of an SDK task: `success`, `partial`, `failure`, `abandoned` or `handed_off`. It is not a verdict. |

## Governance

| Term | Meaning |
|---|---|
| **Audit chain** | Each tenant's append-only, hash-chained log of every action: who, what, on which resource, and why. Rows hold references and reasons, never captured content. |
| **Anchor** | An Ed25519-signed checkpoint of the chain head. Kinds: `hourly`, `export`, `erasure`, `break_glass`, `rekey`, `partition_boundary`. The signing key lives outside the database. |
| **Audit export** | A `sibyl.audit_export/1` JSONL file of a sequence range, ending at an anchor. You can verify it offline with `sibyl audit verify`. |
| **Erasure request** | A crypto-shred of a tenant, an agent or a data subject. It needs two different humans, is blocked by legal holds, and ends with a signed certificate (D17). |
| **Legal hold** | A freeze on retention sweeps and erasure for a tenant, agent, provider incident or subject. |
| **Payload reveal** | Reading a stored prompt or output with an audited grant. It requires `X-Sibyl-Reveal-Reason` and writes a `data.revealed` row. |

## People and roles

The UI uses display names (ruling B17). The API, the audit log and role bindings use the identifiers.

| UI name | Identifier | In short |
|---|---|---|
| Admin | `owner` | Everything, including kill switch, erasure approval, holds and key rotation (with step-up) |
| Workspace admin | `admin` | Users, API keys, registry, policy; no kill switch or erasure approval |
| Security admin | `security_admin` | Approvals, quarantine, kill switch, credentials, holds, erasure approval |
| Engineer | `engineer` | Registry and routing changes for the agent groups they hold |
| Operator | `operator` | Alerts and the handoff queue |
| Auditor | `auditor` | Audit read, verify and export; payload and packet reads are always audited |
| Viewer | `viewer` | Read-only |

**Step-up** is a fresh sign-in at the identity provider within the last 5 minutes. It is needed for tenant settings, credential management, key rotation, holds, erasure approval, and pulling or releasing a kill switch.

The full scope-by-role matrix is in `packages/sibyl-schemas/src/sibyl_schemas/_scopes.py`.

API keys carry **scopes**, not roles. The machine scopes are:

| Scope | Allows |
|---|---|
| `gateway:proxy` | Calls through the gateway |
| `ingest:write` | Telemetry to ingest |
| `handoff:write` | SDK handoff packets |
| `routing:read` | Reading the policy snapshot |
| `agents:read` | Reading the registry |
| `agents:write` | Registry writes; agent-bound keys only |
| `killswitch:pull` | The break-glass key; this scope alone |
