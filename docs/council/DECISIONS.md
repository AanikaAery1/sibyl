# Founder decisions log

Authoritative answers from the founder. These override member assumptions and the defaults in STEP1-UNDERSTANDING.md.

## 2026-10-09 · after Step 1 review

| # | Question | Decision | Consequence |
|---|---|---|---|
| D1 | Internal vs commercial | **Commercial, full-fledged production product.** An independent product. | Multi-tenant from day one: `tenant_id` + RLS, tenant-scoped API keys, org/role model, OIDC SSO. Compliance mapping (EU AI Act, NIST AI RMF, ISO 42001) is the buyer's checklist. Build a defensible core; OSS observability tools are competitors, not glue. |
| D2 | Gateway in request path? | **Both**: in-line gateway proxy and SDK, from Phase 1. | Fail-open/fail-closed per agent, signed TTL policy snapshot in the gateway, no synchronous control-plane call on the hot path, CI latency benchmark, streaming passthrough are all week-one work. Proxy-side routing is no longer stretch; it is core. |
| D3 | Seed agents | **Synthetic.** No real customer agents. | Demo is 20 simulated agents across 3 providers with chaos knobs; real provider calls behind a flag, off by default. |
| D4 | Where Phase 1 runs | **Localhost now, must migrate to cloud later.** | docker-compose for Phase 1; 12-factor stateless services, config via env, Postgres as the only stateful component so a managed Postgres + Helm chart is the migration. No cloud account assumed. |
| D5 | First operators, incident stories | Not answered. | Synthetic personas; handoff packet schema validated with the founder in the design phase. |
| D6 | Handoff trigger | **Automatic**: on auto-detected failure, or when it looks like the agent is about to fail. | Phase 1 includes automated failover and handoff driven by the rule engine, not an operator click. "Looks like it would fail" in Phase 1 = rule-based leading indicators (rising error/latency trend, rate-limit proximity, provider status, budget proximity); learned prediction fills the same contract in Phase 2. Operator retains undo, override and kill switch. Risk-tiered: tier-1 agents may require approval for high-risk actions. |
| D7 | Data capture | **Store all data** (prompts, outputs, tool calls). | Full capture is the default; redaction becomes a per-tenant policy toggle, not the default. Encryption at rest and in transit, strict tenant isolation, payload storage sized for volume (blob store interface from day one). |
| D8 | Positioning | **Governance + agentic failure response + monitoring.** | Governance-led: audit log, asset registry completeness, risk classification and policy surfaces carry more Phase 1 weight than in the Step 1 default. The compliance persona is a Phase 1 user. Name and pitch stay governance-forward. |
| D9 | Operator queue | **Standalone.** | No ITSM integration in Phase 1; notifications (email/Teams/Slack webhooks) are Phase 2. |
| D10 | Budget | **No extra budget.** | All open-source, self-hosted. No managed services, no paid APIs in tests. SSO via an OSS identity provider or OIDC library; no PagerDuty; object storage via MinIO or filesystem adapter. |

### Step 1 assumptions superseded
A1 (internal-first) → commercial multi-tenant. A3 (Postgres only) → Postgres primary, but BlobStore and EventBus interfaces are now Phase 1 with the simplest OSS implementation; reopen in Step 2. A5 (proxy routing stretch) → proxy routing is core. A9 (click failover) → automatic, risk-tiered, with human undo. A11 (redacted default) → full capture default, redaction as policy. A13 (JKC operators) → synthetic personas. R2 mitigation (zero-code proxy) is now mandatory, not a hedge.

## 2026-10-09 · after Step 2 review ("continue" = council recommendations adopted)

| # | Question | Decision | Consequence |
|---|---|---|---|
| D11 | Credential custody | **Passthrough for the primary call; Vigil vaults provider credentials only for configured fallback targets** (per-tenant envelope encryption, memory-only in gateway with TTL, `base_url` allowlisted). | `provider_credential` entity; key custody scheme in Step 3; console shows which agents have cross-provider continuity. |
| D12 | Capture default | **`capture_mode` is an explicit onboarding choice with `full` pre-selected; secrets scrubbing unconditional; default payload retention 30 days; redaction profile recorded per stored object.** Refines D7. | Onboarding wizard step; `capture_policy` entity; retention tiers in Step 3. |
| D13 | Tier-1 predicted failover | **Propose-and-approve with timeout for leading-indicator-only triggers on tier 1; automatic on detected failure for all tiers and on predictions for tiers 2–3.** Refines D6. | `approval` entity with timeout policy (hold or fail-safe). |
| D14 | Cloud target, gateway placement | Undecided by founder; **default: AWS-shaped (RDS Postgres, S3) tested first, S3-API keeps GCS/Azure/Hetzner open; gateway Vigil-hosted in Phase 1, sidecar packaging in Phase 2.** | Adapters coded to S3 API; no provider-specific SDK calls outside the adapter. |
| D15 | Vigil licence | Undecided by founder; **default: proprietary core, SDK released Apache-2; permissive-only (MIT/BSD/Apache) dependency policy for the self-hosted bundle.** | No AGPL/SSPL/TSL components bundled (MinIO, Redis ≥7.4, Zitadel, Timescale excluded). |
| D16 | Anthropic-native surface | **OpenAI-compatible surface only in Phase 1; Anthropic is an upstream dialect.** `/v1/messages` is Phase 2. | One request dialect on the hot path. |
| D17 | Residency and erasure | **Per-tenant right-to-erasure from Phase 1 (crypto-shred). Residency is a declared field with policy warnings, not a promise, until region-pinned stacks exist.** | `erasure_request`, `legal_hold` entities; per-tenant data key. |
| D18 | Operations | **Single operator (The founder), business-hours SLO window in Phase 1; same-host PITR acceptable for Phase 1 with off-host backup as the first cloud task; roadmap acknowledges an external security assessment before the first paying tenant.** | Burn-rate alerts to inbox, not pager; backup runbook; roadmap item in Step 6. |

### D13 clarification (chair, 2026-10-10)
Automatic on detected failure applies to alternate-model and alternate-provider failover and to human handoff on every tier. Failover to a **backup agent** stays approval-gated for tier 1 even on detected failure (different blast radius). Predicted-only triggers: automatic for tiers 2–3, approval for tier 1.

## 2026-10-10 · naming
| # | Decision |
|---|---|
| D19 | **Product name is Sibyl** (replaces working codename Vigil). Schema/package identifiers (`vigil-event/1`, `vigil.*` OTel attributes, `vigil-schemas`) to be renamed to `sibyl*` in Step 4 before any code exists. |

## 2026-10-10 · after Step 3 review ("continue" = council defaults adopted)

| # | Question | Decision |
|---|---|---|
| D20 | Break-glass path | **Yes**: tenant-level API key scoped to `killswitch:pull` only, usable when the IdP is down. |
| D21 | Operator hold after undo | 30-min hold **blocks all rule/policy actors** (detected and predicted); humans and kill switch bypass. |
| D22 | `fail_safe` on tier-1 PII/residency agents | Approval timeout (10 min) **forces `hold`**; never shifts without a human. |
| D23 | Tier RTO defaults | **15 min / 1 h / 4 h** for tiers 1/2/3 when a continuity plan is silent. |
| D24 | Alert close verdict | **Mandatory** true/false-positive/unsure verdict before an alert can close. |
| D25 | OTel semconv | Pinned **v1.37.0**; bump the normaliser at code freeze if newer. |
| D26 | Erasure vs backups | Erasure certificate states pre-shred backups expire on date; `backup_retention_days = 7`. |
| D27 | Audit retention | **400 days minimum**, contractual extension up to 7 years. |
| D28 | Payload retention ceiling | **Up to 365 days** per tenant in Phase 1. |
| D29 | Demo naming | Tenants `meridian` (20 agents), `northstar` (3, isolation proof), `sandbox` (empty); dex personas Platform Admin (`admin`), On-call Operator (`operator`), Compliance Auditor (`auditor`). |

## 2026-10-10 · after Step 4 review ("continue" = council defaults adopted)

| # | Decision |
|---|---|
| D30 | Scope catalogue uses one `<resource>:<verb>` grammar (`ingest:write`, `agents:*`, `routing:read`, …); Step 3 scope names are amended, not aliased (R21). |
| D31 | No platform-level gateway credential; a Sibyl-hosted gateway holds one tenant key and one snapshot block per tenant it fronts (R26). |
| D32 | Tier-1 agents must be reachable only through agent-bound API keys; snapshot builder refuses otherwise (R35). |
| D33 | Hysteresis-resolved alerts may close with `verdict=null`; console keeps an unverdicted queue and the SLI counts them (R29, refines D24). |
| D34 | No hard kill-rate cap for OIDC owners; a second tenant-scope kill within 10 min requires a different owner. Break-glass key caps stand (R31). |
| D35 | Python `sibyl-sdk` first; TypeScript ships as an interface sketch only in Phase 1 (R21–R36 synthesis). |

## 2026-10-10 · after Step 5 review ("continue" = council defaults adopted)

| # | Decision |
|---|---|
| D36 | The `"0.60"` predicted-failover band on tiers 2–3 is a **release criterion**: enabled only once `sibyl-sim` shows ≥ 75 % precision / ≥ 60 % recall at 15 min for `rules/v1`; until then `"0.90"` only. Not a tenant tunable (R41). |
| D37 | **No cross-tenant pooling** of signals, baselines or models through Phase 2, even anonymised and opt-in. Per-tenant models; synthetic-trained shadow model never promoted without the tenant's own verdicts (R43). |
| D38 | `sibyl-sim` is **dev-only in Phase 1**; customer-run drills are a Phase 2 roadmap item behind a real feature flag (R46). |
| D39 | Tier-2 predicted failover is `degrade_then_auto` (20 s degraded pause, then shift); tier 3 `auto`; tenant-editable via `continuity_plan.preemptive_mode` (R40). |
| D40 | Phase 1 agent-minute SLO defaults: **99.5 % / 99.0 % / 98.0 %** for tiers 1/2/3 over 30 days; per-agent `slo_target` deferred to Phase 2. |

## 2026-10-10 · after Step 6 ("enough planning, start building")

The founder closed planning and directed the build to start. Council defaults from `roadmap/SYNTHESIS.md` adopted; rulings R52–R71 stand.

| # | Decision |
|---|---|
| D41 | Phase 1 planned at **27 working days P50 / 32 P80** with Tier A + B cuts (R53); a ~7-day **Phase 1.5 gate** restores the cuts before any design-partner traffic (R54). |
| D42 | Design partner #1 self-hosts single-tenant via Helm in their own cloud; Sibyl-hosted multi-tenant from partner #2. |
| D43 | External security assessment sequenced as unpaid pilot → assessment → first invoice funds it; D10 holds until revenue. |
| D44 | Wedge follows the first partner; NIST AI RMF + ISO/IEC 42001 mappings first, EU AI Act pack second. |
| D45 | Step 7 cadence: chair commits locally at each wave gate; the founder reviews at milestones M0–M5; nothing pushed without explicit approval. |
| D46 | Entity/IP ownership and package-name reservation remain open founder items; neither blocks the build (2026-10-10). |

## 2026-10-10 · overnight autonomous build

| # | Decision |
|---|---|
| D47 | The founder: "finish the application to the end, work all night, do not ask for approval, make reasonable assumptions." The chair builds Phase 1 through Phase 1.5 to completion without review pauses (supersedes D45's milestone reviews for this run), records every assumption as a build ruling in `docs/council/build/LANES.md`, commits locally per gate, and pushes nothing (no remote configured; pushing is outward-facing). Concurrency kept to ~6 lanes so the session usage limit is not exhausted. |

## 2026-10-11 · positioning review

| # | Decision |
|---|---|
| D48 | Thesis: Sibyl is **infrastructure that lets companies safely give AI agents more autonomy** — control what agents may do before they act, keep them running through failures, prove every decision. Prediction is a supporting capability claimed only where the harness measures it; no "data moat" claim until shown. The smallest differentiated product is the **Action Gate** (pre-execution allow/block/escalate), built next. Reasoning: `docs/strategy/TECHNICAL-THESIS.md`. |
| D49 | Demo personas are role-based: Platform Admin (`admin`), On-call Operator (`operator`), Compliance Auditor (`auditor`); no personal names in demo data or docs. |
| D50 | Plug-and-play agent monitoring: `sibyl.instrument()` / `sibyl-run` auto-instrument OpenAI, Anthropic and Google Gen AI clients and LangChain/LangGraph, OpenAI Agents SDK and CrewAI; multi-agent run trees; unknown agents auto-registered as `discovered`; native Anthropic and Gemini at the gateway (WAVE3.md). |
| D51 | Model drift detection is deterministic and watch-only: model identity drift (served model or fingerprint change) and behavioural drift (PSI / Jensen–Shannon against a frozen baseline per agent+model); never triggers automation alone (WAVE3.md). |
| D52 | Sibyl Sentinel is built as an opt-in advisory agent on the tenant's own Anthropic, OpenAI or Gemini key; it explains, recommends and flags semantic drift, and can never allow, block, approve, fail over or change policy (WAVE3.md). |
| D53 | External monitor agents: any outside agent registers as a monitor, observes through the REST API, the Sibyl MCP server or signed webhooks, and reports advisory findings (`POST /findings`); never enforces (WAVE4.md). |
| D54 | Release 1.0 on GitHub: Actions CI, GHCR images on `v*` tags, tag `v1.0.0` (WAVE4.md). |
| D55 | Two ways to run: Demo (dummy data; `make demo` or Codespaces demo link) and Real (full stack for real agents; `make up` or Codespaces real link), with `docs/setup/SETUP.md` (WAVE4.md). |
