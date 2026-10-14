# Sprint Prioritizer — Step 6: phased roadmap, Phase 1 re-estimate, Step 7 build plan

Lead member for Step 6. Follows `roadmap/CHAIR-INITIAL.md`. Authority order: `DECISIONS.md` (D1–D40) > SYNTHESIS rulings (R1–R51) > member reports. Every identifier is `sibyl*` (D19). Nothing here is committed.

Inputs read: `CHAIR-INITIAL.md`, `DECISIONS.md`, `discover/sprint-prioritizer.md` (Step 1: 56 dev-days P0, 64 with proxy), `architect/ARCHITECTURE.md` §3, §6, §9 (Step 2 re-estimate: ~75), `datamodel/DATAMODEL.md` §3, §7, §8, `api/API.md` §1–§8, `ml/ML.md` §3–§4, §7, §8, §10, `ml/qa-expert.md` §4.3.

---

## 0. Headline

1. **Phase 1 as specified is about 204 lane dev-days plus 26 for the wave 0 contract freeze: roughly 230 engineer-equivalent days, three times the Step 1/2 figure of ~75.** Most of the growth comes from founder decisions taken after Step 1, not from estimating error: multi-tenant RLS + OIDC (D1), gateway in the hot path (D2), automatic tier-gated failover with approvals (D6, D13), erasure (D17), roughly 110 control-plane routes instead of the ~15 Step 1 assumed, and a 28-scenario harness (Step 5).
2. **Wall-clock at P50 is 32 working days for full scope, 27 with the recommended cut line, and 24 with the deep cut line.** Six AI-agent lanes, one human supervisor (D18), and the conversion in §2.1 apply throughout.
3. **20 working days is only reachable with optimistic lane throughput and the deep cut line**, and the deep cut line reverses D17. I recommend the line in §3.3 (Tier A + Tier B): **27 working days P50 / 32 P80**, followed by a **Phase 1.5 of about 7 working days** that brings back everything cut.
4. **The failover story is demo-able at day 23 (M2).** The full Phase 1 exit (M4: erasure + CRITICAL harness gates + end-to-end demo) lands at day 27.

---

## 1. Phase scope tables

Legend: **1** = Phase 1 (Step 7 build). **1.5** = cut from Phase 1 by the §3 cut lines and rebuilt on localhost right after the Phase 1 exit, before any cloud work. **2** = "First design partner". **3** = "Sellable product". The Trace column cites the decision or ruling that puts the item where it is.

### 1.1 Phase 1: "Governed failover on localhost"

| # | Capability | Phase | Rationale | Trace |
|---|---|---|---|---|
| 1 | docker-compose stack: postgres 17, api, ingest, worker, gateway, console, dex, caddy, BlobStore `fs` | 1 | Localhost now; Postgres is the only stateful component so the cloud move is mechanical | D4, D10, ADR-3/4/5 |
| 2 | Multi-tenant shared schema with RLS FORCE, `set_tenant()` per tx, generated isolation test per table | 1 | Commercial from day one; isolation is a CRITICAL harness gate | D1, ADR-7, ML §8.3 |
| 3 | Tenant CLI `sibyl tenant create`; demo tenants meridian / northstar / sandbox; dex personas Platform Admin / On-call Operator / Compliance Auditor | 1 | No tenant lifecycle routes in Phase 1; the demo needs three tenants | D29, API §1 |
| 4 | OIDC relying party (PKCE), BFF session cookie, JWT path, step-up | 1 | SSO on day one with an OSS IdP; step-up guards kill release, erasure and credentials | D1, D10, ADR-8 |
| 5 | API keys: `<resource>:<verb>` scopes, agent-bound keys, rotate/revoke, break-glass `killswitch:pull` | 1 | Machine principals for SDK, gateway and ingest; break-glass works while the IdP is down | D20, D30, D31, D32, D34 |
| 6 | User / membership / OIDC-issuer / agent-group **management API** | **1.5** | Dex is static in the demo, so a CLI and the seed cover Phase 1 | cut A6 |
| 7 | Registry: agents, lifecycle, identity (allowed tools/models/providers), immutable versions, claim of provisional agents | 1 | Governance-led: registry completeness is a Phase 1 surface | D8, API §5.4 |
| 8 | Tools / data sources / business processes / declared dependency edges (CRUD + seed) | 1 | Feeds the D22 PII/residency predicate and the compliance view | D22, API §5.4 |
| 9 | AI-BOM (CycloneDX 1.6 job) and blast-radius computation | **1.5** | No demo step depends on them; the registry already shows edges | cut A1 |
| 10 | Providers, models, vendored price catalogue, discovered models | 1 | Cost derivation and the alt-model/provider targets | ADR-2, API §5.5 |
| 11 | Vaulted fallback provider credentials (envelope encryption, sealed bundle to gateway, SSRF-checked verify probe) | 1 | Without them cross-provider failover cannot work. Demo-mode interplay is open (§6 Q2) | D11, ADR-10 |
| 12 | Capture policy as an explicit onboarding step, redaction profiles, unconditional secrets scrub, payload retention 30 d default / ≤ 365 | 1 | Full capture is the default but is an explicit choice; the sandbox demo shows the 403 → wizard flow | D7, D12, D28 |
| 13 | Continuity plans (RTO/RPO defaults by tier), fallback chains with four-eyes approval on tier 1 | 1 | Inputs to automatic failover; RTO defaults when the plan is silent | D13, D23, R36, R38 |
| 14 | Gateway: OpenAI-compatible `/v1/chat/completions` (streaming), `/v1/embeddings`, `/v1/models`; signed TTL snapshot; fail-open/closed matrix; inline fallback + breaker; per-agent rps/inflight/budget; OTLP emitter with spill; kill acks; CI latency gate | 1 | The gateway is core, not stretch | D2, D16, ADR-1/2/9 |
| 15 | Gateway Anthropic **dialect translation** (OpenAI request → Anthropic upstream) | **1.5** | Cross-provider failover can be shown between OpenAI-compatible doubles (openai-stub → ollama-stub) | cut B2, refines D16 consequence; §6 Q1 |
| 16 | Ingest: `/v1/otlp/traces`, `/v1/otlp/logs`, `/v1/events`; 11-step normaliser; semconv 1.37; three-layer idempotency; `call_merge`; backpressure; heartbeat/gap | 1 | One wire contract; every OTel GenAI instrumentor onboards without a connector | ADR-11, D25, R27, R28 |
| 17 | BlobStore `fs` + `s3` adapters; per-tenant payload DEK | 1 | The `s3` adapter is written now so the cloud move is a config change | D14, ADR-5 |
| 18 | Python `sibyl-sdk` core: `init`, `agent`, `tool`, `checkpoint`, `handoff`, `feedback`, `outcome`, openai + anthropic auto-instrumentation incl. streaming, scrub pipeline, two-lane exporter, policy poll + `SibylKilled` | 1 | The SDK is the only route to checkpoint-fidelity handoff | D2, D35, API §8 |
| 19 | SDK `mcp` + `httpx` instrumentation, disk spool + replay, fork safety | **1.5** | In-memory retry already covers S-19's 90 s backpressure | cut A3 |
| 20 | TypeScript SDK as an interface sketch (types only) | 1 | Reserves the shape; implementation is Phase 2 | D35 |
| 21 | Health score `100 − Σ penalty`, tier caps, bands with dead-band, hysteresis, cooldown, flap suppression, cold start / provisional | 1 | Explainability completeness is a CRITICAL gate | ML §3, R37 |
| 22 | Detected rules R1–R9, `tool_loop`, `quality_proxy`, provider-incident collapse | 1 | Automatic handoff on detected failure covers all tiers | D6, D13, ML §3.3 |
| 23 | Leading rules **L1–L4 + provider-status leading facet**; 15 m and 1 h horizons; tier gating; `"0.60"` band gated on harness precision | 1 | "Looks like it is about to fail" = the D6-named indicators: error/latency trend, rate-limit proximity, provider status, budget proximity | D6, D13, D36, D39 |
| 24 | Leading rules **L5 fallback_pressure, L6 refusal_trend, L7 continuity_unverified**, `context_saturation`, `credential_expiry`, `model_deprecation` (leading), `drift_cusum`; peer baselines; `agent_risk` nightly; 24 h horizon | **1.5** | Not among the D6-named indicators; S-08 still detects via R6, and S-12 waits for 1.5 | cut B1; §6 Q1 |
| 25 | Routing state machine (`routing_apply()` as the single legality source), failover saga, operator incident actions | 1 | Automatic failover with human undo | D6, R24, R25 |
| 26 | Approvals with timeout; D22 forced hold; four-eyes; operator hold after undo (30 min) | 1 | Tier-1 gating is a CRITICAL gate | D13, D21, D22, R36 |
| 27 | Kill switch (session + break-glass), anchor within 10 s, gateway 403 on any snapshot, SDK `SibylKilled` | 1 | Kill beats everything | D20, D34, R31 |
| 28 | Failback: probe after 5 healthy minutes, then operator or automatic `fail_back` straight to `active` | 1 | Closes the incident loop | ML §9.4 |
| 29 | Failback **canary ramp** 10 → 100 % with breach revert and backoff | **1.5** | S-25 runs probe → active; ramp and revert come back in 1.5 | cut A4 |
| 30 | Operator queue: claim / extend / release / complete / return; packet view `sibyl-handoff/1` | 1 | The queue is standalone (no ITSM) | D9, API §5.8, §9 |
| 31 | Alerts: ack / silence / close with **mandatory verdict**; unverdicted resolved queue | 1 | The verdict loop feeds Phase 2 learning | D24, D33 |
| 32 | Hash-chained audit via `audit_append()`, hourly Ed25519 anchors, `POST /audit/verifications`, audit export, offline `sibyl audit verify` | 1 | The governance spine; the Compliance Auditor persona | D8, D27, R33 |
| 33 | Erasure: tenant + agent scope, crypto-shred, certificate (JCS JSON + sha256), legal holds (manual place/release) | 1 | Right-to-erasure is promised from Phase 1 | D17, D26 |
| 34 | Subject-scope erasure (`agent_window`), certificate PDF rendering, `/exports` data export, `sibyl ml export`, auto legal hold on provider incident | **1.5** | Not part of the per-tenant D17 promise; there are no Phase 1 training consumers | cuts A8, B4 |
| 35 | Read surfaces: fleet health, health + history, risk, metrics, events, traces, payload reveal (audited), SSE stream with outbox resume | 1 | The console and the harness oracle read through these | API §5.10, §7 |
| 36 | Console: fleet map, agent detail (score, factors, timeline, routing, actions), incidents + approval card with countdown, queue + packet, alerts + verdict queue, audit viewer + verify + export, onboarding wizard (capture policy + first key), kill switch with step-up | 1 | Operator, engineer and auditor personas, 8 screens | D8, D9, D29 |
| 37 | Console admin **editors** (alert rules, continuity plan, fallback chain, providers/credentials, users/OIDC/groups) and erasure/hold screens | **1.5** | API + CLI cover them; Phase 1 console is read-only for these | cuts A2, B3 |
| 38 | `sibyl-sim`: runner, 23 actors, three provider doubles, status-feed double, oracle (12 predicates), personas, **28 scenarios single-seed**, goldens, PR smoke ≤ 12 min, nightly | 1 | The Phase 1 exit criterion is CRITICAL gates green; dev-only | D3, D38, R45, R46 |
| 39 | Harness tier-swap variants (12), three seeds per scenario, S-24 60-min soak at 200 calls/s, nightly report generator | **1.5** | CRITICAL gates are still measured; worst-of-three-seeds confidence comes back in 1.5 | cut A5 |
| 40 | Ops: same-host PITR (pgBackRest), `/metrics` with `sibyl_*`, four cause-based pages to inbox, runbooks for the §9.4 transitions, quickstart | 1 | Single operator, business-hours window | D18, R47 |
| 41 | Prometheus rule files + automated weekly restore test | **1.5** | A manual restore runbook is enough on localhost | cut A7 |
| 42 | Tier SLO defaults 99.5 / 99.0 / 98.0 % agent-minutes | 1 | Constants in `scoring_config` | D40 |

### 1.2 Phase 1.5: "Close the cuts" (localhost, about 7 working days)

| 1.5 lane | Brings back (from §1.1) | E | Directories (same owners as Phase 1) |
|---|---|---|---|
| R/A | AI-BOM + blast radius (row 9); identity admin API (row 6) | 7 | `api/registry`, `api/tenancy` |
| G/K | Anthropic dialect (row 15); SDK mcp/httpx, spool, fork safety (row 19) | 8 | `services/gateway`, `packages/sibyl-sdk` |
| H/P/S/U | L5–L7 + extra leading rules, baselines, `agent_risk`, 24 h (row 24); canary ramp (row 29); subject erasure, PDF, `/exports`, auto-hold (row 34) | 17 | `worker/predict`, `worker/scoring`, `worker/failback`, `api/governance` |
| C/M/O | console admin editors + erasure/hold UI (row 37); variants, 3 seeds, soak, report (row 39); Prometheus rules + restore test (row 41) | 16 | `console`, `sibyl-sim`, `ops` |

Total 48 lane dev-days across 4 lanes at 2.0 E/lane-day: ~6 days of lane work plus 1 gate day. Exit criteria: the 12 tier-swap variants and three seeds green on the nightly; S-12 and S-25 (canary) pass; the console admin editors pass Playwright and visual regression. Phase 1.5 runs before Phase 2 because Phase 2's first task (off-host backup, D18) needs a stable schema. The cut items carry no migrations of their own: their tables already exist from wave 0 (§4.2).

### 1.3 Phase 2: "First design partner"

| # | Capability | Rationale | Trace |
|---|---|---|---|
| 1 | **Off-host backup first**, then cloud migration: managed Postgres (RDS-shaped), S3 BlobStore, Helm chart, KMS for the master key | Same-host PITR was only acceptable for localhost | D4, D14, D18 |
| 2 | **External security assessment before the first paying tenant** | Founder requirement; credential custody (D11) is the largest new obligation | D18, ADR-10 |
| 3 | Notifications: email, Slack and Teams webhooks | The queue was standalone in Phase 1 | D9 |
| 4 | Anthropic-native `/v1/messages` surface | One dialect on the hot path in Phase 1 | D16 |
| 5 | TypeScript SDK implementation | Interface frozen in Phase 1 | D35 |
| 6 | Sidecar gateway packaging; revisit gateway identity | Sibyl-hosted gateway in Phase 1 | D14, D31, R26 |
| 7 | Learned layer: per-tenant shadow model, promotion via the ML §8.5 gate | Needs tenant verdicts; no cross-tenant pooling | D36, D37, R42, R43 |
| 8 | Per-agent threshold adaptation from verdicts | ML §3.9 labels this "1.5", but it needs a verdict volume that only a real tenant produces, so I place it here (§6 Q6) | ML §3.9, D37 |
| 9 | LLM-as-judge, tenant opt-in | Paid-API cost is excluded in Phase 1 | ML §5.9, D10 |
| 10 | Customer-run drills behind a real feature flag (`sibyl-sim` stays dev-only until then) | Dev-only in Phase 1 | D38, R46 |
| 11 | Per-agent `slo_target` | Tier defaults in Phase 1 | D40 |
| 12 | EU AI Act `risk_assessment` table + `GET /agents/{id}/risk-assessment` | Table is Phase 2 per ML §7.3 | ML §6.2 |
| 13 | Shared rate-limit counters across gateway replicas (Valkey, BSD) and multi-replica api/ingest/worker | Counters are per replica in Phase 1 | ADR-4, API §2.8 |
| 14 | Real provider calls on by default for the design partner's agents | Synthetic in Phase 1 | D3 |

### 1.4 Phase 3: "Sellable product"

| # | Capability | Rationale | Trace |
|---|---|---|---|
| 1 | Region-pinned stacks; residency becomes a promise | Residency is a declared field until then | D17 |
| 2 | SOC 2 readiness | Commercial buyer checklist | D1 |
| 3 | ITSM integrations (ServiceNow, Jira Service Management) | Standalone queue first | D9 |
| 4 | Billing and metering | Commercial product | D1 |
| 5 | Compliance report packs: EU AI Act, NIST AI RMF, ISO 42001 | Buyer's checklist; Phase 1 audit + verdicts are the evidence base | D1, D8 |
| 6 | Marketplace of continuity templates | Needs a tenant base | chair |
| 7 | SAML + SCIM through the same RP layer | OIDC first | ADR-8 |
| 8 | Dedicated-database tenant tier | UUIDv7 + no cross-tenant FKs keep it possible | ADR-7 |
| 9 | `TimeSeriesStore` on ClickHouse beyond ~5–10k events/s | Postgres ceiling | ADR-3 |
| 10 | Temporal port of the saga, only if needed | Steps are already activity-shaped | ADR-6 |
| 11 | Executive and compliance dashboard views | Ops + audit views first | Step 1 §5 |

---

## 2. Honest Phase 1 re-estimate

### 2.1 Unit and conversion assumption

- **E (engineer-equivalent dev-day)** = the work a senior engineer completes in one focused day, **including tests** (~40 % of each figure is test code: the 80 % coverage gate, 85 % for the SDK, contract tests and generated isolation tests). This is the Step 1 unit, so the numbers compare directly.
- **Lane throughput.** One AI-agent lane working against frozen contracts with TDD produces **2.0 E per working day at P50** (1.6 at P80, 3.0 optimistic). Generation is fast; the time goes into test-fix loops, integration against other lanes' merged code, and waiting on answers.
- **Supervision cap.** the founder is the single operator (D18). He can absorb the questions, assumption reviews and gate decisions of **at most six concurrent lanes**, which is also the council's wave limit. That caps the portfolio at ~12 E/day P50. Gates are serial in his attention: **1 day per gate**.
- **Integration overhead.** Merge conflicts in steward-owned files, cross-lane bugs and flaky tests add **~12 %** to lane effort. The schedule absorbs this in slot slack and a reserve slot (§4.3), not as a separate line.
- **Effective utilisation.** The recommended schedule supplies ~266 E of lane capacity against 182 E of demand (68 %). That figure is realistic for dependency-bound parallel lanes and it doubles as the buffer.

### 2.2 The real surface (what is being estimated)

| Surface | Size | Source |
|---|---|---|
| Control-plane routes | ≈ 110 (my tally of §5 method + path pairs lands at 110–125) + 4 gateway-control routes + SSE | API §5, §7 |
| Gateway data plane | 3 routes + healthz/readyz; streaming; routing decision table; fail-mode matrix; 8 error classes | API §3 |
| Ingest | 3 routes; 11-step normaliser; 3 idempotency layers | API §4 |
| Tables | 76 total; **73 in Phase 1** (`ml_model`, `ml_prediction_shadow`, `risk_assessment` are Phase 2); 11 allowlisted, **62 under the generated isolation test** | DATAMODEL §3, ML §7.3 |
| DB functions | `set_tenant`, `audit_append`, `routing_apply`, `tenant_create`, `tenant_key_shred`, `is_allowlisted_base_url`, RLS helper, chain/edge/hold triggers | DATAMODEL §5, §7 |
| Rules | R1–R9, `tool_loop`, `quality_proxy`, L1–L7 + 5 extra leading rules; per-tier caps, thresholds, hysteresis, cooldown | ML §3.3, §4.3 |
| State machines | routing (10 states, 25 edges), failover saga, approval, handoff task, erasure, kill switch | API §6, DATAMODEL §6.5 |
| SDK | the full §8.2 public API, auto-instrumentation, scrubber, exporter, policy client | API §8 |
| Console | 14 screens if every admin editor is included; 8 operational/governance screens | §1.1 rows 36–37 |
| Harness | 28 scenarios + 12 variants × 3 seeds, 12 oracle predicates, 3 personas, goldens | ML §8 |

### 2.3 Per-lane estimate (full scope vs recommended)

| Lane | Owns | Full-scope work (E incl. tests) | E full | Cuts (§3) | E rec. |
|---|---|---|---|---|---|
| **W0** contract freeze | schemas, migrations, kernel, OpenAPI, compose, CI | §4.2 | 26 | — | 26 |
| **A** auth & tenancy | `api/auth`, `api/tenancy`, `api/keys`, `cli/tenant.py`, `cli/keys.py` | OIDC RP login/callback/step-up/logout 3; session + JWT + `/auth/me` 1; tenant GET/PATCH, sessions 1; users/invitations/memberships/issuers/groups 4; api-keys create/rotate/revoke + break-glass caps 3; tenant CLI 1 | 13 | A6 −4 | 9 |
| **R** registry & policy | `api/registry`, `api/policy`, `api/credentials`, `cli/seed.py` | agents + claim + lifecycle (R35) + identity + versions 5; tools/data/processes/edges 2; BOM job + blast radius 3; providers/models/catalog 2; credentials vault + sealed bundle + verify probe 3; capture + redaction 2; continuity plan (D22 predicate) + chains (four-eyes) 2; alert-rule CRUD/reset 1; seed via service layer (DATAMODEL §8) included | 20 | A1 −3 | 17 |
| **G** gateway & snapshot | `services/gateway/**`, `api/snapshot` | proxy + streaming passthrough 4; snapshot builder + Ed25519 signing (api) + verify order + SSE refresh 4; decision table + fail-mode matrix + error map 3; inline fallback + breaker 2; limits/budget/inflight 1; credential bundle X25519 1; OTLP emitter + spill + kill acks + auto-register 1; Anthropic dialect 4 (incl. stream translation); latency bench gate (ADR-1) — inside the above | 20 | B2 −4 | 16 |
| **I** ingest & blob | `ingest/**`, `core/blob/fs.py`, `core/blob/s3.py` | OTLP proto/JSON decode + limits 2; normaliser 11 steps + legacy maps 4; identity resolution + auto-register 1; idempotency 3 layers + `call_merge` flush 2; payload DEK encrypt + blob adapters 2; backpressure + heartbeat/gap 2 | 13 | — | 13 |
| **K** SDK | `packages/sibyl-sdk/**` (W1) | init/agent/tool/outcome/feedback 2; openai + anthropic instrumentation incl. streaming 3; scrub pipeline + corpus 1; exporter two lanes 2; policy poll/verify/`SibylKilled` 1; checkpoint + handoff builder 1; mcp/httpx 2; spool + fork safety 2 (test plan API §8.7) | 13 | A3 −4 | 9 |
| **D** sim doubles | `sibyl-sim/sim/doubles/**`, `sim/status_feed/**` (W1, K's slot) | openai-compatible, anthropic-compat and ollama doubles with chaos knobs; status-feed double | 4 | — | 4 |
| **H** health engine | `worker/rollup`, `worker/scoring`, `worker/status_poller` | rollups 1m/5m/provider-5m/1h + late arrivals 5; trend state 1; evaluate loop + score + bands + caps + floors 3; R1–R9 + collapse 3; hysteresis/cooldown/flap/cold start 2; `health_snapshot` write-on-change, `health_1h`, feature snapshot to blob 2; baselines + `agent_risk` 2; rule unit + property tests generated from YAML — inside | 20 | B1 −2; 4 E moved to P | 14 |
| **V** reads & SSE | `api/reads`, `api/sse` | fleet, health/history, metrics, events/traces 3; payload reveal (audited) 1; SSE with outbox cursor resume, reset, slow-consumer 3 | 7 | — | 7 |
| **S** saga & operations | `worker/saga`, `worker/approvals`, `worker/failback`, `worker/handoff`, `api/incidents`, `api/approvals`, `api/killswitch`, `api/queue` | saga executor + steps + SKIP LOCKED 3; rule-actor failover creation (D13 matrix) 2; incidents + actions API (§6.3, §6.4) 3; approvals + timeout + D22 forced hold 2; undo/hold (D21) 1; kill + break-glass + anchor-now 2; failback probe 1 + canary ramp 3; handoff assembly (checkpoint / request_only) + queue API 2; alert actions + verdicts 2 → moved to P | 20 | A4 −3; 2 E moved to P | 15 |
| **P** prediction & alert loop | `worker/predict`, `worker/alerts`, `api/alerts` | L1–L7 + extras + statistics + bands + confidence 5; tier gating + D36 band gate + D39 `degrade_then_auto` + guard rails 2; `prediction` sparse write + outcome filler + `/risk` 2; (+ from H: flap/tool_loop/quality_proxy/feature snapshot 4; + from S: alert actions/verdict/unverdicted queue 2) | 9 | B1 −4; +4 from H; +2 from S | 11 |
| **U** audit & governance | `api/governance`, `worker/housekeeping`, `sibyl-sdk/src/sibyl/cli/audit.py` (W2) | audit read/anchors/verifications 2; exports + anchor-first + offline verifier 2; hourly anchors job + signing-key CLI 1; partitions/retention/sweepers 2; erasure state machine + crypto-shred cascade + certificate 5; legal holds incl. auto-hold 2; `/exports` + PDF 2 | 16 | A8 −4; B4 −2 | 10 |
| **C** console | `console/**` | BFF session + CSRF + nonce CSP 3; fleet map 2; agent detail 3; incidents + approval card 2; queue + packet 2; alerts + verdict queue 2; audit viewer + verify + export 1; onboarding wizard 1; kill + step-up 1; admin editors ×5 7; erasure/holds UI 2; SSE live, Playwright, visual regression at 320/768/1024/1440, axe — spread across the above | 26 | A2 −7; B3 −3 | 16 |
| **M** harness | `sibyl-sim/**` except doubles (W2) | runner + seeded clock 2; 23 actors via SDK + personas 3; oracle 12 predicates + matching metrics 3; 28 scenarios YAML 3; goldens + diff 1; tier-swap variants + 3 seeds + soak + report 4 | 16 | A5 −5 | 11 |
| **O** ops | `deploy/compose` (post-W0), `ops/**`, `docs/quickstart.md` | PITR + backup runbook 2; metrics wiring + 4 inbox pages 1; runbooks per §9.4 1; quickstart 1; Prometheus rules + automated restore test 2 | 7 | A7 −3 | 4 |
| **Total lanes** | | | **204** | −48 | **156** |
| **Grand total incl. W0** | | | **230** | | **182** |

Reconciliation with Step 1/2: Step 1's 56 E assumed a single tenant, ~15 routes, manual failover, no gateway routing and no harness. ARCHITECTURE §9 raised that to 75 for the gateway, BlobStore and partitions. Steps 3–5 then added RLS + OIDC + keys (~25 E), the policy/credentials surface (~15), the saga, approvals and kill switch (~20), audit anchors and erasure (~15), prediction (~10) and a 28-scenario oracle harness (~20). The 3× growth follows from the decisions. The original figure was not wrong for what it covered.

### 2.4 Wall-clock

| Scope | P50 (2.0 E/lane-day) | Optimistic (3.0) | P80 (1.6) |
|---|---|---|---|
| Full scope (230 E) | **32** working days | 25 | 38 |
| **Recommended: Tier A + Tier B cuts (182 E)** | **27** | 21 | 32 |
| Deep: A + B + Tier C (164 E) | 24 | 18 | 28 |

Derivation for the recommended row (P50): W0 4 days → G0 → W1 9 days (longest slot: H 14 E, G 16 E, R 17 E) → G1 → W2 8 days (longest slot: C 16 E, S 15 E) → G2 → W3 hardening 3 days → G3. Sum 4 + 9 + 1 + 8 + 1 + 3 + 1 = **27**. The full-scope row is longer because the console (26 E) becomes a 13-day lane that cannot start before W2 without a seventh slot, and W1's R and G lanes grow to 10 days.

**Conclusion:** 20 working days needs both the optimistic throughput and Tier C, and Tier C reverses D17. I do not recommend planning to 20. Plan to 27, commit externally to 32, and treat 21 as the upside.

---

## 3. Cut lines (ranked, lowest demo impact first)

Each cut moves a **named capability to Phase 1.5** (§1.2). Tier A needs no founder decision: it removes depth, not any capability the chair listed for Phase 1. Tier B touches the chair's Phase 1 list or a decision's consequence and needs a chair ruling. Tier C reverses a founder decision and needs the founder.

### 3.1 Tier A (recommended; the chair can accept without founder input)

| Rank | Cut | Moves to 1.5 | E saved | Demo impact | Cum. P50 days |
|---|---|---|---|---|---|
| A1 | AI-BOM + blast radius | CycloneDX job, `/blast-radius` routes | 3 | None in the failover story; the Compliance Auditor cannot download a BOM | 32 |
| A2 | Console admin editors | alert-rule, continuity-plan, fallback-chain, provider/credential, user/OIDC/group editors | 7 | The Platform Admin's S-04 threshold edit runs via API/CLI instead of a form; plans and chains display read-only | 31 |
| A3 | SDK breadth | mcp + httpx instrumentation, disk spool/replay, fork safety | 4 | None; S-19 passes on in-memory retry within 90 s | 30 |
| A4 | Failback canary ramp | 10 → 100 % ramp, breach revert, backoff | 3 | S-25 shows probe → active in one step; "reverted at 25 %" not shown | 30 |
| A5 | Harness breadth | tier-swap variants, 3 seeds, 60-min soak, report generator | 5 | None visible; gates are judged on one seed rather than the worst of three (confidence, not function) | 29 |
| A6 | Identity admin API | users/invitations/memberships/issuers/groups routes → CLI | 4 | None (dex personas are static) | 29 |
| A7 | Ops depth | Prometheus rule files, automated weekly restore test | 3 | None; the restore runbook is manual | 28 |
| A8 | Governance extras | subject-scope erasure, certificate PDF, `/exports`, `sibyl ml export` | 4 | Erasure demo uses agent scope; certificate is JSON + sha256 | 28 |

### 3.2 Tier B (recommended; needs a chair ruling)

| Rank | Cut | Moves to 1.5 | E saved | Demo impact | Cum. P50 days |
|---|---|---|---|---|---|
| B1 | Prediction depth | L5, L6, L7, `context_saturation`, `credential_expiry`, `model_deprecation` (leading), `drift_cusum`, peer baselines, `agent_risk`, 24 h horizon | 6 | D6's named indicators stay (L1–L4 + provider status). S-02/03/04/05/06/27 are intact. S-08 detects via R6 but loses L6's early warning. S-12 moves to 1.5. The chair's "L1–L7" wording becomes "L1–L4 + R-facet" | 27 |
| B2 | Anthropic dialect translation | `Dialect` adapter for `anthropic` upstream | 4 | Cross-provider failover is shown openai-stub → ollama-stub (both OpenAI-compatible); the anthropic double exposes an OpenAI-compatible surface in Phase 1 | 27 |
| B3 | Erasure/hold console screens | erasure request/approve UI, legal-hold UI | 3 | Erasure demo is driven by CLI/API (`POST /erasure-requests`, `…/actions`); the certificate is opened from the audit viewer | 27 |
| B4 | Auto legal hold on provider incident | incident auto-hold trigger wiring | 2 | Holds are placed manually in the demo | 27 |

### 3.3 Recommended line

**Draw the line after B4: 182 E, 27 working days P50.** Everything above it returns in Phase 1.5 (48 E, ~7 working days). With that line the Phase 1 exit criterion still holds: the demo script runs end-to-end and every CRITICAL gate (approval-gating correctness, explainability completeness, isolation leaks) is measured on the full 28-scenario catalogue.

### 3.4 Tier C (not recommended; listed so the trade is explicit)

| Rank | Cut | E saved | Demo impact | Needs |
|---|---|---|---|---|
| C1 | Harness to 18 scenarios (keep S-01–S-07, S-11, S-13, S-15, S-16, S-20, S-21, S-22, S-24, S-26, S-27, S-28); S-08–S-10, S-12, S-14, S-17–S-19, S-23, S-25 to 1.5 | 4 | Silent-degradation, observation-gap and prompt-injection stories are absent from the demo | chair |
| C2 | Erasure entirely to 1.5 (legal holds too) | 6 | M4 loses its governance closure; the "right to erasure from Phase 1" promise slips | **The founder (reverses D17)** |
| C3 | Console to 5 screens (fleet, agent detail, incident/approval, queue, audit) | 5 | No onboarding wizard (sandbox demo by CLI), no verdict queue UI (D24 via API only) | chair |
| C4 | Gateway inline fallback + breaker | 3 | Failover happens only through routing state (saga), not inside a request; the Step 2 cut order puts this after the dialect cut and never cuts the proxy itself | chair |

Total Tier C 18 E → 24 days P50. The founder decision cost (C2) buys 3 days. Not worth it.

### 3.5 Cut impact by scenario (what the harness still proves)

| Scenario | Full | Rec. (A + B) | Deep (+ C) | Note |
|---|---|---|---|---|
| S-01 hard outage | yes | yes | yes | B2: alt-provider = openai-stub → ollama-stub |
| S-02 / S-03 rate-limit ramps | yes | yes | yes | L3 kept |
| S-04 latency creep | yes | yes | yes | A2: the Platform Admin's threshold edit via API |
| S-05 / S-06 cost, budget | yes | yes | yes | L4 kept |
| S-07 flapping | yes | yes | yes | |
| S-08 refusals | yes | yes (R6 only, no L6) | 1.5 | B1 |
| S-09 / S-10 truncation, schema | yes | yes | 1.5 | C1 |
| S-11 tool loop | yes | yes | yes | |
| S-12 context saturation | yes | 1.5 | 1.5 | B1 |
| S-13 correlated failure | yes | yes | yes | |
| S-14 model deprecation | yes | yes (detected path) | 1.5 | the leading facet is B1 |
| S-15 fallback not viable | yes | yes | yes | depends on §6 Q2 |
| S-16 status lies | yes | yes | yes | |
| S-17 status late | yes | yes | 1.5 | C1 |
| S-18 / S-19 gap, backpressure | yes | yes (in-memory retry) | 1.5 | A3, C1 |
| S-20 undo + hold | yes | yes | yes | |
| S-21 / S-22 isolation | yes | yes | yes | CRITICAL gate |
| S-23 prompt injection | yes | yes | 1.5 | C1 |
| S-24 baseline / soak | 60 min | 10 min | 10 min | A5 |
| S-25 fail-back | canary | probe → active | 1.5 | A4, C1 |
| S-26 / S-27 / S-28 four-eyes, D22, kill | yes | yes | yes | CRITICAL gate (approvals) |
| Tier-swap variants × 3 seeds | yes | 1.5 | 1.5 | A5 |

---

## 4. Step 7 build plan

### 4.1 Repo tree and directory ownership

`uv` workspace monorepo (ADR-13). `sibyl-schemas` is the only package shared across process boundaries. The gateway and SDK import schemas only (import-linter enforced). api, ingest, worker and migrate are one `control` image with four entrypoints, so they share `sibyl_control.core`. The repo directory name is legacy and is renamed separately. Wave 0 initialises git (the repo is not a git repository today) and writes this table to `docs/council/build/LANES.md`.

```
<repo root>
├── pyproject.toml  uv.lock  .importlinter  Makefile  .pre-commit-config.yaml      [W0-INF → steward]
├── openapi/sibyl-api.v1.yaml                                                      [W0-KER → steward, frozen]
├── rules/v1/defaults.yaml                                                         [W0-DB → steward; H/P read]
├── packages/
│   ├── sibyl-schemas/                                                             [W0-SCH → steward, frozen]
│   │   ├── src/sibyl_schemas/{values.py, canonical.py, scrub/, models/, jsonschema/}
│   │   └── fixtures/{ingest,health,handoff,checkpoint,snapshot}/
│   └── sibyl-sdk/
│       ├── src/sibyl/{__init__.py, _client.py, _exporter.py, _policy.py, _scrub.py,
│       │              _instrument/, checkpoint.py, handoff.py}                     [K]
│       ├── src/sibyl/cli/audit.py                                                 [U, W2]
│       └── tests/                                                                 [K]
├── services/
│   ├── control/
│   │   ├── pyproject.toml                                                         [steward]
│   │   ├── migrations/                                                            [W0-DB → steward; slots 10+ by request]
│   │   ├── src/sibyl_control/
│   │   │   ├── core/{db.py, authz.py, problems.py, idempotency.py, etag.py, paging.py,
│   │   │   │         ratelimit.py, audit.py, outbox.py, crypto/, blob/base.py}      [W0-KER → steward]
│   │   │   ├── core/blob/{fs.py, s3.py}                                           [I]
│   │   │   ├── api/app.py, api/routers.py  (one pre-registered include per module) [W0-KER → steward]
│   │   │   ├── api/{auth, tenancy, keys}/                                         [A]
│   │   │   ├── api/{registry, policy, credentials}/                               [R]
│   │   │   ├── api/snapshot/                                                      [G]
│   │   │   ├── api/{reads, sse}/                                                  [V]
│   │   │   ├── api/{incidents, approvals, killswitch, queue}/                     [S]
│   │   │   ├── api/alerts/                                                        [P]
│   │   │   ├── api/governance/  (audit, exports, erasure, holds)                   [U]
│   │   │   ├── ingest/                                                            [I]
│   │   │   ├── worker/main.py, worker/loops.py  (pre-registered loop table)        [W0-KER → steward]
│   │   │   ├── worker/{rollup, scoring, status_poller}/                           [H]
│   │   │   ├── worker/{predict, alerts}/                                          [P]
│   │   │   ├── worker/{saga, approvals, failback, handoff}/                       [S]
│   │   │   ├── worker/housekeeping/ (partitions, retention, anchors, erasure_exec) [U]
│   │   │   └── cli/{tenant.py, keys.py} [A] · cli/seed.py [R]
│   │   └── tests/
│   │       ├── contract/  (authz red wall, audit completeness, RLS generator, invariants) [W0 → steward]
│   │       └── <mirror of src>/                                                   [owning lane]
│   └── gateway/{src/sibyl_gateway/, tests/, bench/}                               [G]
├── console/{app/, components/, lib/bff/, styles/, tests/e2e/, tests/visual/}      [C]
├── sibyl-sim/
│   ├── sim/{doubles/, status_feed/}                                               [D (W1) → M (W2)]
│   └── sim/{cli.py, runner.py, actors/}, oracle/, scenarios/, golden/, reports/, tests/ [M]
├── deploy/compose/{docker-compose.yml, dex/, caddy/, env/}                         [W0-INF → O (W2)]
├── ops/{prometheus/, backup/, runbooks/}                                          [O]
├── ci/                                                                            [W0-INF → O (W2)]
└── docs/  (council docs: chair; docs/quickstart.md: O)
```

Ownership rules:
1. **One directory, one owner per wave.** Ownership transfers only at a gate (D → M, K → U for `cli/audit.py`, W0-INF → O).
2. **Steward-owned files** (`pyproject.toml`, `uv.lock`, `openapi/`, `sibyl-schemas/`, `migrations/`, `core/`, `routers.py`, `loops.py`, `tests/contract/`) change only through a change request that the contract steward (chief-architect role, run by the chair session) batches and applies **at the gate**. Inside a wave a lane works against the frozen version and records the assumption it made.
3. Every API module ships in wave 0 as a stub that returns 501, already registered in `routers.py`, so no lane edits the app factory. The same goes for worker loops in `loops.py`.
4. Migrations: wave 0 writes all of 0–9 plus the Step 4/5 amendments, so every Phase 1 table exists before W1. A lane that needs a column requests a numbered slot (10, 11, …) from the steward and receives it at the next gate.

### 4.2 Wave 0: contract freeze (days 1–4, four agents, steward-led)

| Sub-lane | Deliverable | E | Done when |
|---|---|---|---|
| **W0-SCH** | `sibyl-schemas`: §4.0 value sets; JSON Schemas `sibyl-event/1` (+ wire variant), `sibyl-health/1`, `sibyl-handoff/1`, `sibyl-checkpoint/1`, `sibyl.policy_snapshot/1`, `sibyl-ingest-response/1`, `sibyl-feature-snapshot/1`; pydantic models; RFC 8785 canonicaliser; unconditional secrets-scrubber registry with the 60-secret + false-positive corpora; golden fixtures | 6 | fixtures validate; scrub corpus 60/60 and 0 false positives; versioned 1.0.0 |
| **W0-DB** | Migrations 0–9 with **every identifier renamed per D19** (schema `sibyl`, roles `sibyl_app`, `sibyl_ingest`, `sibyl_worker`, `sibyl_audit`, `sibyl_routing`, `sibyl_migrate`) + API §12 and ML §10.1 amendments (73 Phase 1 tables); functions `set_tenant`, `audit_append`, `routing_apply`, `tenant_create`, `tenant_key_shred`, RLS helper, triggers; `state_edge` and `role_permission` seeds; `rules/v1/defaults.yaml`; the three CI gates in DATAMODEL §7 | 10 | isolation generator green on 62 tables; audit chain test green; invariants green; `routing_apply` rejects every edge not in `state_edge` |
| **W0-KER** | `openapi/sibyl-api.v1.yaml` completing the §11 skeleton for every route, with `x-sibyl-scope` and `x-sibyl-audit`; `sibyl_control.core` (tx + `set_tenant`, `authorize()`, problem+json, idempotency, ETag, cursor paging, rate limit, audit receipt header, API-key verification, outbox writer, envelope crypto, BlobStore interface); 501 stubs for every module; **authz red wall** and **audit-completeness** tests generated from OpenAPI (all red); mock server for C; frozen interface types for `RiskDocument` / `prediction` so S does not wait for P | 7 | OpenAPI lints; every route has a red authz test and a red audit test; mocks serve every route |
| **W0-INF** | uv workspace + import-linter (gateway/SDK → schemas only); compose with postgres 17, dex (3 tenants × personas per D29), caddy, service images with `/healthz`; profile `sim`; CI PR pipeline (ruff, mypy, pytest + coverage gates, eslint/tsc, contract suite); lane worktree script with port offsets | 3 | `docker compose up` green; CI runs on an empty PR in < 5 min |

**G0 gate (end of day 4):** the founder freezes the contracts (H0). From G0 on, a schema change needs a founder decision (Step 1 assumption 7, retained). §6 Q2 (demo-mode credentials) must be answered before G0 because it changes seed and chain validation.

### 4.3 Waves and slots

Six slots per wave (council maximum). A slot whose lane finishes early takes the next lane listed for it. All slots run in **separate git worktrees** (§4.6).

**Wave 1: foundations (days 5–13, 9 days, 18 E per slot)**

| Slot | Lane(s) | E | Depends on | Hands off |
|---|---|---|---|---|
| 1 | **G** gateway & snapshot | 16 | W0-SCH snapshot schema, W0-DB tables; uses its own fake upstream until D lands (~day 10) | signed snapshot route; gateway passing the bench gate |
| 2 | **H** health engine | 14 | W0-DB; event fixtures from W0-SCH; I's real events only at G1 | `health_snapshot`, `alert` rows, `health.transition` outbox |
| 3 | **R** registry & policy (+ seed CLI) | 17 | W0-KER kernel; test principals from the kernel fixture | agents, plans, chains, credentials; `sibyl seed` |
| 4 | **I** ingest & blob → reserve | 13 (+5 slack) | W0-SCH, W0-DB, blob interface | events, payload refs, `call_merge`; blob adapters |
| 5 | **A** auth & tenancy → **V** reads & SSE | 9 + 7 | kernel | sessions, keys, break-glass; read routes + SSE |
| 6 | **K** SDK → **D** sim doubles | 9 + 4 | W0-SCH; I via `pytest-httpserver` fixtures until I merges | `sibyl-sdk` 0.1; provider + status-feed doubles |

**G1 gate (day 14)** → **M1**.

**Wave 2: the loop closes (days 15–22, 8 days, 16 E per slot)**

| Slot | Lane(s) | E | Depends on | Hands off |
|---|---|---|---|---|
| 1 | **S** saga & operations | 15 | H alerts (G1), R plans/chains (G1), G snapshot propagation (G1), A step-up (G1); consumes the W0-frozen `prediction`/`RiskDocument` contract without waiting for P | incidents, approvals, kill, undo/hold, failback probe, handoff tasks, queue API |
| 2 | **P** prediction & alert loop | 11 | H (G1) | L1–L4 + facet, tier gating, D36 band gate, `prediction`, `/risk`; alert actions + verdicts; remaining detected rules |
| 3 | **U** audit & governance → **O** ops | 10 + 4 | kernel audit; I blob + `tenant_key` | audit/anchors/verify/export + offline CLI; erasure + certificate; holds; housekeeping; PITR, pages, runbooks, quickstart |
| 4 | **C** console | 16 | all W1 APIs (G1); S/P/U routes against W0 mocks until G2 | 8 screens, Playwright demo flow, visual regression, axe |
| 5 | **M** harness | 11 | G, I, K, D, V (G1); scenarios needing S/P run on the integration branch at G2 | runner, actors, oracle, personas, 28 scenarios, goldens, smoke suite |
| 6 | **Reserve / fix lane** | (16 cap) | — | takes any lane's overflow or G1 HIGH findings, inside the owning lane's directory under a delegated-ownership note |

**G2 gate (day 23)** → **M2**. M3's code is merged here too.

**Wave 3: hardening (days 24–26, no new capability)**

The owning lanes only: M runs the nightly full suite and the D36 precision/recall measurement; C finishes demo-flow polish and visual baselines; O runs the restore drill and the quickstart dry run; any lane fixes findings in its own directories. **M3 accepted day 25** (two green nightlies). **G3 gate (day 27)** → **M4 = Phase 1 exit**.

### 4.4 Dependency graph (critical path in bold)

```
W0-SCH ─┬─► G ─────────────┐
        ├─► I ─┬───────────┤
        ├─► K ─┴─► D ──────┼─► M ──────────────┐
W0-DB ──┼─► **H** ─────────┼─► P ──┐            │
W0-KER ─┼─► R ─────────────┤       ├─► **S** ───┼─► W3 nightlies ─► **M4**
        ├─► A ─► V ────────┼─► C ──┘            │
W0-INF ─┴──────────────────┴─► U ─► O ──────────┘
Critical path: W0 (4) → H (W1, 9) → G1 → S (W2, 8) → G2 → W3 (3) → G3 = 27 days
```

### 4.5 Calendar (recommended line, P50, working days)

```
day    1  2  3  4 | 5  6  7  8  9 10 11 12 13 |14| 15 16 17 18 19 20 21 22 |23| 24 25 26 |27
W0     ===========|                           |  |                         |  |          |
slot1             | G G G G G G G G           |G1| S S S S S S S S         |G2| fix      |G3
slot2             | H H H H H H H . .         |  | P P P P P P . .         |  | fix      |
slot3             | R R R R R R R R R         |  | U U U U U O O .         |  | O drill  |
slot4             | I I I I I I I . .         |  | C C C C C C C C         |  | C polish |
slot5             | A A A A A V V V V         |  | M M M M M M . .         |  | M nightly|
slot6             | K K K K K D D . .         |  | reserve / fix lane      |  | fix      |
milestones     M0 |                           |M1|                         |M2| M3 (25)  |M4
```

`.` = slot slack (integration overhead and buffer). G's 16 E fits in 8 days and H's 14 E in 7. H is still on the critical path because S cannot start until H's alerts merge at G1.

### 4.6 Worktree isolation

| Lane | Worktree | Why |
|---|---|---|
| A, R, I, H, V, S, P, U | **mandatory** | They share the `services/control` package, its `pyproject.toml`/`uv.lock`, `conftest.py` and test database; in one checkout their test runs and lockfile writes would collide |
| G | **mandatory** | It owns `api/snapshot` inside the control package as well as `services/gateway` |
| K, D, M | recommended | Separate trees, but integration tests bring up compose; port offsets avoid clashes |
| C | recommended | Separate tree; Playwright runs its own compose stack |

Mechanics: `../sibyl-wt/<lane>` on branch `lane/<wave>-<lane>`; `COMPOSE_PROJECT_NAME=sibyl_<lane>`; host ports offset by 100 × slot; one disposable Postgres per worktree for the isolation generator. Council members never commit (house rule). Each lane hands back an uncommitted worktree. At the gate, after the founder approves, the chair session commits each lane as its own commit on its lane branch and merges. Nothing is pushed without the founder's explicit approval.

### 4.7 TDD expectations per lane

| Lane | RED first | Coverage gate |
|---|---|---|
| All API lanes (A, R, V, S, P, U, G's snapshot) | The W0 authz red wall (401/403/404-not-403 cross-tenant, G object rule, step-up) and audit-completeness tests for each route turn green route by route; 409/422 vocabularies get a negative test per code | ≥ 80 % per module |
| W0-DB, then every migration slot | Isolation generator + invariants before DDL | 62/62 tables |
| H, P | Rule unit tests generated from `rules/v1/defaults.yaml` (a threshold edit without a test edit fails); property tests (monotone, Σ penalty = 100 − score, no two rule transitions within cooldown) written before the evaluator | ≥ 85 % |
| S | One test per `state_edge` row and per §6.4 409 code before the saga steps; idempotent replay of every step | ≥ 85 % |
| I | Golden OTLP → `sibyl-event/1` fixtures (W0-SCH) and replay idempotency before the normaliser | ≥ 80 % |
| G | Fail-mode matrix (API §3.5) as a parametrised test before routing code; latency bench in CI from day 1 | ≥ 80 % + bench gate |
| K | API §8.7 unit list as test stubs first | ≥ 85 % |
| C | Playwright demo-flow specs from the M-acceptance tables, written against W0 mocks before the screens; visual baselines at 320/768/1024/1440 | unit ≥ 80 % for `lib/` |
| M | Predicate unit tests and double conformance before scenarios; determinism test (same seed ⇒ same `event_id`s) | ≥ 80 % for `oracle/` |

Each lane's hand-back includes the red run and the green run summaries.

### 4.8 Merge and verify gate (after every wave, 1 day)

1. **Lane self-check** in its worktree: unit + contract green, coverage met, ruff/mypy/eslint/tsc clean, import-linter clean, files < 800 lines.
2. **Steward merge** into `integration/wN` in dependency order (W1: I, K, D, A, V, R, H, G; W2: P, S, U, O, M, C). Only the steward touches steward-owned files; queued change requests are applied here.
3. **Full suite on the merged tree:** contract (authz wall, audit completeness, OpenAPI conformance), RLS generator, invariants, gateway bench, `sim suite --tier smoke` (from G1), Playwright (from G2), nightly full suite (from G2).
4. **Three reviewers in parallel on the merged diff:** `test-automator` (gaps against the milestone acceptance table, flakiness), `ecc:code-reviewer` (quality, immutability, size, error handling), `security-auditor` (the lane's rows of API §10.2 STRIDE, scrub, RLS, key/credential handling, step-up). **CRITICAL blocks the gate. HIGH is fixed by the owning lane before the next wave starts. MEDIUM is logged.**
5. **Milestone demo to the founder**; on approval, the chair commits per lane (no push).

---

## 5. Milestones (demo-able increments)

Scenario IDs are from `ml/qa-expert.md` / ML §8.2. Routes are from API.md.

### M0: Contracts frozen (day 4, G0)

| # | Acceptance test |
|---|---|
| 0.1 | `docker compose up` → every service `/healthz` 200; dex login works for admin / operator / auditor |
| 0.2 | `alembic upgrade head` on an empty Postgres; isolation generator passes 62/62; audit-chain test (`content_mismatch`, `gap`, `signature_invalid` detected); invariants pass |
| 0.3 | OpenAPI: every route declares `x-sibyl-scope` + `x-sibyl-audit`; the red wall has one failing test per route |
| 0.4 | `sibyl-schemas` fixtures validate; scrubber 60/60 with 0 false positives |

### M1: Traffic is seen, health is explained (day 14, G1)

| # | Acceptance test | Evidence |
|---|---|---|
| 1.1 | sandbox has no capture policy: `POST /v1/otlp/traces` → 403 `capture_policy_missing`; after `POST /api/v1/capture-policies` (`capture_mode` explicit) ingest accepts; `capture.policy_set` precedes `api_key.created` in the audit | D12, DATAMODEL §8 test 5 |
| 1.2 | `sibyl seed` → `GET /api/v1/agents` returns 20 meridian agents, `routing.state=active`; `asset.created` rows exist and come from the service layer | DATAMODEL §8 |
| 1.3 | `POST /v1/chat/completions` (streaming and not) through the gateway to the doubles: `X-Sibyl-Route: primary`, `X-Sibyl-Policy-State: fresh`; fail-mode matrix cases pass; **bench p95 added latency < 15 ms, p99 < 50 ms at 200 streams** | API §3.4–3.5, ADR-1 |
| 1.4 | SDK + gateway on the same call → one `gen_ai.request` event (no duplicate `call_id`); SDK-only and gateway-only agents both produce events | API §8.6 |
| 1.5 | `GET /api/v1/agents/{id}/health` returns `sibyl-health/1`; property Σ penalty = 100 − score ± 1 holds on every snapshot | ML §8.3 explainability |
| 1.6 | S-01 detection half: R3 within 3 calls, R1 critical; `GET /api/v1/alerts` lists them; `GET /api/v1/events/stream` emits `alert.fired`, `health.transition` | S-01 |
| 1.7 | S-21: northstar zero alerts, scores ≥ 90, silent SSE; a 10-minute steady run shows zero alerts above `info` | S-21, S-24 (short) |
| 1.8 | Break-glass key: `POST /api/v1/kill-switches` with a `killswitch:pull` key → 201, `kill_switch` row + `access.break_glass` audit (the saga effect lands in M2) | D20 |

### M2: Detected failover, handed off, audited (day 23, G2)

| # | Acceptance test | Evidence |
|---|---|---|
| 2.1 | S-01 end to end: auto alt-provider/alt-model failover on all tiers; one `provider_incident` collapsing ≥ 2 agents; `X-Sibyl-Route: failover`; saga `done` within 30 s p95 | S-01, `GET /api/v1/incidents/{id}` |
| 2.2 | S-11: tool loop → automatic handoff, packet `fidelity=checkpoint`; the On-call Operator `claim` → `complete` via `POST /api/v1/handoff-tasks/{id}/actions`; packet readable at `GET …/packet` | S-11, D9 |
| 2.3 | S-13 (one incident, seven suppressed, no `saga_in_flight` leaks), S-14, S-15 (`target_not_viable`), S-16 (no failover), S-17 (traffic-only failover) | scenarios |
| 2.4 | S-07: exactly one automated failover across the flap | S-07 |
| 2.5 | S-20: `undo` → `operator_hold_until` set; rule actors blocked 30 min; `hold_suppressed_count` rises; `clear_hold` resumes | S-20, D21 |
| 2.6 | S-26: tier-1 backup-agent step waits for approval on detected failure; self-approval → 409 `self_approval` | S-26, D13 clarification, R36 |
| 2.7 | S-28: kill during S-01 → no saga progresses; gateway 403 `sibyl_agent_killed`; SDK `SibylKilled` ≤ 20 s; release only after step-up; break-glass anchor ≤ 10 s | S-28, D20 |
| 2.8 | S-25 (reduced, cut A4): primary healthy 5 min → probe → `fail_back` → `active` | S-25 |
| 2.9 | Audit: `POST /api/v1/audit/verifications` ok over the whole run; the Compliance Auditor reads `GET /api/v1/audit/events`, writes refused 403; `POST /api/v1/audit/exports` → `sibyl audit verify <export> --anchor --public-key` ok offline | D8, R33 |
| 2.10 | Console: fleet → agent detail → incident → queue → audit flows pass Playwright | §1.1 row 36 |

### M3: Sees it coming, asks before it acts (code at G2; accepted day 25)

| # | Acceptance test | Evidence |
|---|---|---|
| 3.1 | S-02: L3 fires ≥ 6 min before the first 429; tier 2 `degrade_then_auto` (20 s) then shift; tier 3 auto | S-02, D39 |
| 3.2 | S-03: tier 1 → `awaiting_approval`, `requested_by_kind=rule`; timeout 600 s → `hold` → `degraded`; console shows the countdown card | S-03, D13 |
| 3.3 | S-04 (L2 ≥ 2 windows early, `safe_no_tools`), S-05 (L4 ≥ 30 min early, tier-3 quarantine), S-06 (budget, quarantine approval) | scenarios |
| 3.4 | S-27: tier-1 PII agent with plan `fail_safe` → worker forces `hold`, audit `hold_forced_d22`; `PUT …/continuity-plan` with `fail_safe` → 422 `fail_safe_forbidden` | S-27, D22 |
| 3.5 | **D36 measurement** on two nightlies: `rules/v1` precision/recall at 15 m on the ramp scenarios reported. ≥ 75 % / ≥ 60 % enables `"0.60"` on tiers 2–3; otherwise Phase 1 ships `"0.90"` only. Either outcome passes M3; the report is the deliverable | D36, R41 |
| 3.6 | Verdicts: closing without a verdict → 422 `verdict_required`; hysteresis-resolved alerts land in the unverdicted queue; the On-call Operator persona drains it; verdicted share ≥ 90 % | D24, D33, ML §8.6 |
| 3.7 | `GET /api/v1/agents/{id}/risk` returns 15m/1h/24h with `rules_source=rules/v1`, `probability` absent (the 24 h horizon reads `low`/abstained until Phase 1.5, B1) | ML §8.4 contract |

### M4: Governance closure, Phase 1 exit (day 27, G3)

| # | Acceptance test | Evidence |
|---|---|---|
| 4.1 | Erasure, agent scope: `POST /api/v1/erasure-requests` → approve by a different owner after step-up (`…/actions`) → `GET …/certificate` lists shredded keys, the `erasure` anchor and `backups_expire_at = completed_at + 7 d`; payload reads → 410 `payload_shredded`; audit chain still verifies. Tenant scope on sandbox: ingest 429 `tenant_erasing` during execution | D17, D26 |
| 4.2 | A legal hold blocks erasure (`hold_blocked`); release re-evaluates | API §5.12 |
| 4.3 | **CRITICAL gates green** on the nightly full suite (28 scenarios, one seed): approval-gating correctness 100 %, explainability completeness 100 %, isolation leaks 0 (S-21, S-22, RLS fuzz) | ML §8.3 |
| 4.4 | HIGH gates reported against targets (false/missed failover, RTO attainment by tier); a miss becomes a Phase 1.5 ticket, not an exit blocker, unless it is on tier 1 | ML §8.3 |
| 4.5 | Demo script end to end (below) on a fresh `docker compose up` from the quickstart, in ≤ 20 minutes | §1.1 |
| 4.6 | Same-host PITR restore exercised once by runbook; the four cause-based alerts fire to the inbox in a forced test | D18, R47 |

**Demo script at M4 (project-shipper owns the final version):** (1) sandbox onboarding: 403 → capture-policy wizard → first key. (2) Fleet map, meridian 20 agents green, northstar separate. (3) S-02 rate-limit ramp: prediction badge, tier-2 degrade then shift, tier-1 approval card; the On-call Operator approves. (4) S-01 hard outage: provider incident, automatic failover, tasks handed to the queue; the On-call Operator claims and completes one. (5) The Platform Admin undoes one failover; "automation paused until hh:mm". (6) The On-call Operator pulls the kill switch on a misbehaving agent; the gateway refuses; release needs step-up. (7) Alerts closed with verdicts; one close without a verdict is refused. (8) Compliance Auditor: audit viewer, verify ok, export, offline `sibyl audit verify`. (9) Agent-scope erasure with certificate. (10) Northstar untouched throughout.

---

## 6. Open questions for the chair (max 6)

1. **Cut line.** Accept the recommended line (Tier A + Tier B: 27 days P50, Phase 1.5 ≈ 7 days)? B1 narrows the chair's "L1–L7" to "L1–L4 + provider-status facet". B2 means Anthropic is not yet a translated upstream dialect (the D16 consequence becomes Phase 1.5). Tier C is listed but not recommended, because C2 reverses D17 to save about 3 days.
2. **Demo mode vs cross-provider failover (blocks the W0 freeze).** `SIBYL_DEMO=1` refuses vaulted credentials (`409 demo_mode`, and the seed must not write active `provider_credential` rows), yet alt-provider chain steps require `credential_id` (422 `alt_provider_requires_credential`) and S-01 expects automatic alt-provider failover. Proposal: demo mode allows credentials only when `base_url` resolves to an allowlisted sim double (`*.sim.internal`), and the seed writes those through the service layer. The alternative is running the harness with `SIBYL_DEMO=0` and dummy secrets.
3. **CI compute under D10.** The nightly suite (≤ 3 h, 8 parallel compose stacks) exceeds free hosted-runner minutes for a private repo. Proposal: PR suite on hosted free minutes; nightly on a self-hosted runner on the founder's own machine, not on employer infrastructure, consistent with D1's separation.
4. **Commit mechanics.** Council members never commit. Proposal (§4.6): lanes hand back uncommitted worktrees; the chair session commits per lane at each gate after the founder approves; nothing is pushed without his explicit approval. Confirm, and confirm that wave 0 runs `git init`.
5. **Re-plan trigger.** Pre-approve this rule: if W0 takes more than 5 working days (measured throughput < 1.6 E/lane-day), the chair applies Tier C cuts C1, C3 and C4 to W1/W2 automatically (C2 still goes to the founder) and re-baselines the milestones.
6. **Threshold adaptation from verdicts** (ML §3.9 says "Phase 1.5"). I placed it in Phase 2 because it needs a verdict volume only a real tenant produces. Confirm, or keep it in 1.5 as harness-only tuning.

---

## 7. Schedule risks carried into Step 7

| Risk | Owner | Trigger | Mitigation |
|---|---|---|---|
| Lane throughput below plan | sprint-prioritizer | W0 > 5 days or G1 slips > 2 days | Q5 re-plan rule; cut order C1 → C3 → C4 |
| Contract churn after G0 | chief-architect (steward) | > 3 change requests in one wave | Batch at gates only; lanes proceed on recorded assumptions |
| Gateway misses the latency gate (Step 2 R2) | G lane | bench p95 > 15 ms at G1 | uvloop/httptools tuning; then cut C4 (inline fallback), never the proxy |
| Worker scoring on the critical path | H lane | H not merged by day 13 | Slot 4's slack takes H's alert-upsert work; P absorbs the remaining detected rules |
| Founder attention (D18) | chair | > 2 h/day of lane questions | Two batched Q&A windows per day; lanes proceed on a documented default |
| Harness wall-time (R45: latency scenarios run at 1×) | M lane | smoke suite > 12 min | Keep the 6-scenario smoke set; everything else nightly |
| Console scope creep under the design-quality rules | C lane | > 8 screens or new components outside the 8 | Admin editors are Phase 1.5 by rule; anti-template polish applies only to the 8 screens |
| Demo-mode credential contradiction | chair | unresolved at G0 | Q2; blocks S-01/S-15 acceptance otherwise |
| Verdict loop never exercised by real humans before Phase 2 | product-manager | Phase 1 exit with only persona verdicts | Design-partner onboarding plan in Phase 2 starts the D37 per-tenant verdict count from day one |
