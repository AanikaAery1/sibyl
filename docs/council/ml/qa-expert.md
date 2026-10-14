# Step 5 — ML approach: qa-expert position (2026-10-10)

Inputs: `ml/CHAIR-INITIAL.md` (harness is a Phase 1 deliverable; Phase 1 = rules + statistics), `DECISIONS.md` D3/D6/D13/D21/D22/D23/D24/D29/D33, `api/API.md` §4 ingest (three routes, idempotency layers, heartbeat R28), §6 state machines (routing, saga, approval gating, verdicts), `api/SYNTHESIS.md` R32 (`sibyl-sim` is a separate service), `datamodel/ai-engineer.md` §6 (health/prediction/feature-snapshot contract), backend-architect's seed rule table R1–R5 / L1–L5, DATAMODEL seed rules (simulator never writes derived tables).

Position in one sentence: **the harness is the only place the hysteresis, cooldowns, weights and Phase 2 models are ever tuned, and it must be deterministic enough that a failed run points at a diff, not at luck.**

---

## 1. Evaluation harness architecture

### 1.1 Shape

```
 sibyl-sim (own port :8300, own compose service, never in the prod bundle)
 ├── scenario runner      reads scenarios/*.yaml, seeds PRNG, drives the clock
 ├── 20 agent actors      meridian tenant; 3 northstar; sandbox stays empty
 ├── provider doubles     openai-compatible / anthropic / ollama stubs behind the real gateway
 ├── status-feed double   serves provider.status events the worker polls
 ├── ground-truth writer  writes labels/<run_id>.jsonl (NOT into Postgres)
 └── oracle               reads control-plane API + SSE, compares to labels, emits report
                                  │
          real path ───────────────┼───────────────────────────────────────
          SDK/gateway → POST /v1/otlp/traces | /v1/otlp/logs | /v1/events → normaliser
                       → events / call_merge → worker (windows, rules, health, saga)
                       → routing_state / alert / approval / handoff_task → SSE
```

Rules that make it a harness and not a demo:

1. **Real ingest, real gateway, real worker.** Scenarios are exercised only through `POST /v1/otlp/traces`, `/v1/otlp/logs` and `/v1/events` with ordinary agent-bound API keys, and through the gateway's OpenAI-compatible surface. `sibyl-sim` holds no database connection to any derived table (DATAMODEL seed rule: it must never write `events`, `health_snapshot`, `alert`, `failover`, `routing_state`, …). If a scenario needs a fact the product cannot observe, the scenario is wrong, not the harness.
2. **Provider doubles sit behind the gateway**, not inside it. The gateway's `base_url` allowlist for the three demo providers points at `sibyl-sim` ports. Chaos is applied at the double (status codes, latency, `RateLimit-*` headers, truncated bodies, malformed tool-call JSON), so the gateway's own breaker, inline fallback and `X-Sibyl-*` headers are under test too.
3. **Status-feed double.** `provider.status` events (R4) come from a stub status page `sibyl-sim` serves; scenarios script its transitions so "status page says major" and "traffic actually failing" can be decoupled (see S-07, S-18).
4. **Clock.** Phase 1 runs in wall time with a compressible tick: the simulator issues calls at `speed × real` and stamps span `start/end` in **simulated** time; ingest's `is_late` threshold (120 s) is respected by keeping sim-time within 60 s of wall time, so acceleration is capped at 1× for scenarios that assert on latency windows and up to 6× for budget/trend scenarios whose signals are count-based. The worker's evaluator cadence is driven by a `SIBYL_EVAL_TICK_S` env override (test-only, documented as such) rather than by a fake clock inside the worker.
5. **Determinism.** Every scenario has `seed`; all randomness (inter-arrival jitter, token counts, which agent gets the 500) derives from `numpy.random.default_rng(seed ‖ scenario_id ‖ agent_slug)`. Two runs with the same seed and the same product build must produce identical ground-truth files and identical normalised `event_id`s (the §4.3 deterministic id makes this checkable). Oracle outputs are compared **after** canonicalising timestamps to tick offsets.
6. **Ground truth lives beside the run, never in the product.** `labels/<run_id>.jsonl` rows: `{t_sim, tenant, agent, kind: onset|peak|recovery, failure_mode, injected_by, expected: {detect_by, predict_by, action, tier_gate}}`. The oracle joins these to `health_snapshot`, `alert`, `routing_transition`, `approval`, `handoff_task` read back through the control-plane API as On-call Operator/Platform Admin principals, and to the SSE stream.
7. **Isolation by construction.** `meridian` (20 agents, tier mix 3/7/10) is the chaos tenant; `northstar` (3 agents) runs a steady-state script in every scenario and the oracle asserts it stays untouched (S-21, S-22). `sandbox` stays empty and the oracle asserts zero rows for it in every table it can list.

### 1.2 Run modes

| Mode | Where | Duration | Purpose |
|---|---|---|---|
| `sim run --scenario S-xx --seed N` | dev laptop, compose | 2–20 min sim | one scenario, full report |
| `sim suite --tier smoke` | CI on every PR | ≤ 12 min wall | 6 scenarios at 1× (S-01, S-03, S-05, S-11, S-21, S-25) |
| `sim suite --tier full` | nightly | ≤ 90 min wall | all scenarios, 3 seeds each |
| `sim soak` | nightly, after full | 60 min | S-24 at 200 calls/s with random chaos draw |
| `sim shadow` | Phase 2 | continuous | replays recorded production-shaped traffic to candidate model (§5) |

### 1.3 What the oracle reads

- `GET /agents/{id}/health` (score, `status`, `factors[]`, `horizons`, `predicted_failure_mode`, `recommended_action`, `feature_snapshot_ref`).
- `GET /alerts?…` and `alert.verdict`; `GET /incidents`, `GET /approvals`, `GET /handoff-tasks`.
- `GET /api/v1/events/stream` for first-seen timestamps (time-to-detect uses the SSE arrival, not a polling interval).
- `GET /audit-log` to prove every automated transition has an audit row in the same transaction.

The oracle never reads `events` directly; "did we store it" is covered by ingest contract tests, not the ML harness.

### 1.4 Scenario file format

One YAML per scenario under `sibyl-sim/scenarios/`. Everything the oracle needs is in the file; nothing is implied by code.

```yaml
# sibyl-sim/scenarios/S-02-ratelimit-ramp.yaml
id: S-02
title: Rate-limit ramp, tiers 2-3
seed: 20261010
speed: 1.0                      # sim-time multiplier; 1.0 for latency-sensitive scenarios
duration_s: 1500
tenants:
  meridian:
    agents:
      - slug: billing-reconciler      # tier 2, primary openai-compatible
      - slug: faq-summariser          # tier 3, primary openai-compatible
      - slug: "*"                     # all other meridian agents: steady-state profile
  northstar:
    profile: steady                   # always present, always asserted untouched
traffic:
  arrivals: poisson
  rps_per_agent: 0.8
  token_mix: { in: [400, 1800], out: [80, 600] }
  tool_call_share: 0.3
timeline:
  - at: 0
    provider: openai-double
    knob: ratelimit_remaining_ratio
    value: 0.60
  - at: 0
    provider: openai-double
    knob: ratelimit_remaining_ratio
    ramp_to: 0.02
    over_s: 720
    targets: [billing-reconciler, faq-summariser]
  - at: 720
    provider: openai-double
    knob: http_429_share
    value: 0.35
    targets: [billing-reconciler, faq-summariser]
  - at: 1200
    provider: openai-double
    knob: reset
labels:
  - agent: billing-reconciler
    kind: precursor
    t: 300                           # headroom crosses 0.10 here given the ramp
    failure_mode: provider_outage
  - agent: billing-reconciler
    kind: onset
    t: 720
    failure_mode: provider_outage
  - agent: billing-reconciler
    kind: recovery
    t: 1200
  # faq-summariser labels identical
expect:
  billing-reconciler:
    predict:   { rule: L3, by_t: 420, horizon: 15m, band_min: "0.60" }
    detect:    { rule: R1, by_t: 810 }
    action:    { to_state: failed_over, actor: rule, kind: preemptive_failover, by_t: 480 }
    tier_gate: automatic
    recommended_action: reroute_to_fallback
    rto_s: 3600
  faq-summariser:
    predict:   { rule: L3, by_t: 420, horizon: 15m, band_min: "0.60" }
    detect:    { rule: R1, by_t: 810 }
    action:    { to_state: failed_over, actor: rule, kind: preemptive_failover, by_t: 480 }
    tier_gate: automatic
    rto_s: 14400
  northstar/*:
    alerts_max_severity: info
    transitions: 0
  sandbox:
    rows: 0
personas:
  operator:
    - { at: 900,  do: close_alert, match: { agent: billing-reconciler, rule: L3 }, verdict: tp }
    - { at: 1260, do: close_alert, match: { agent: faq-summariser, rule: R1 }, verdict: tp }
  admin:
    - { at: 1500, do: fail_back, agent: billing-reconciler }
  auditor:
    - { at: end, do: audit_check, expect_verbs: [failover.completed, alert.labelled, failback.started] }
```

Knob vocabulary at the provider double (the full `sibyl-sim` chaos surface, R32): `http_status_share{code}`, `http_429_share`, `ratelimit_remaining_ratio`, `latency_ms{p50,p95}`, `latency_multiplier`, `refusal_share`, `truncate_share`, `finish_reason_override`, `malformed_tool_json_share`, `output_chars_multiplier`, `token_multiplier`, `model_not_found{model}`, `per_key_behaviour{key_prefix}`, `stream_stall_ms`, `reset`. At the status-feed double: `status{provider}` ∈ `operational|degraded|partial|major`. At the agent actor: `loop_tool{name, repeats}`, `context_utilisation_ramp`, `inject_marker`, `heartbeat_pause_s`, `checkpoint_every_n_steps`, `task_outcome{success|failure|abandoned}`. At the ingest side (only through the real API): `ingest_pause_s` toggles a compose network rule, never an ingest flag.

### 1.5 Oracle predicates

The oracle is a small library of predicates over the read-back API; every `expect` key maps to exactly one predicate so a failing scenario reports the predicate name and the first offending object.

| Predicate | Reads | Passes when |
|---|---|---|
| `predict(agent, rule, by_t, horizon, band_min)` | health series via SSE `health.updated` | a snapshot with `t ≤ by_t` has `horizons[horizon].probability_band ≥ band_min` and `rule ∈ contributing_rules` |
| `detect(agent, rule, by_t)` | `alert.opened` SSE | an alert with `rule.code = rule`, `kind=detected`, arrival `≤ by_t` |
| `action(agent, to_state, actor, kind, by_t)` | `routing_transition` via `/incidents` | a transition with `to_state`, `actor_kind`, saga `kind`, `applied_at ≤ by_t` |
| `tier_gate(agent, automatic\|approval)` | `/approvals` | `approval` → a pending approval exists before any `failed_over`; `automatic` → no approval row at all |
| `no_action(agent, kinds)` | transitions | none of `kinds` by any `rule|policy` actor during the run |
| `rto(agent, rto_s)` | transitions, `/handoff-tasks` | continuing state or claimed task within `onset + rto_s` |
| `explainable(agent)` | health series | every non-healthy snapshot satisfies the §3.1 completeness rule |
| `quiet(tenant, max_severity)` | `/alerts` as that tenant's principal | no alert above `max_severity` |
| `isolated(tenant)` | every listable resource as that principal | zero rows attributable to another tenant's agents; SSE silent |
| `audit_has(verbs)` | `/audit-log` as the Compliance Auditor | each verb present with a matching `resource_id` |
| `idempotent()` | `/metrics` counters + `/events?…` | duplicate `call_id` = 0; `events_rejected` reasons only those the scenario expects |
| `single_failover(agent)` | transitions | exactly one `rule`-actor transition to `failed_over` in the run (S-07) |

Predicates take their time bounds in sim ticks and the report prints both sim and wall time.

---

## 2. Scenario catalogue

Conventions: tiers refer to `agent.tier`; "detect" = first `alert` with `kind=detected`; "predict" = `horizons.15m.probability_band ≥ 0.60` or a `kind=leading` alert; "failover" = `routing_transition` with `actor_kind ∈ {rule, policy}`. RTO defaults D23: 15 min / 1 h / 4 h. Approval rules per §6.5 and D13 clarification. Lead-time targets are measured from the **labelled onset** to the first qualifying prediction.

| # | Scenario | Injection (at provider double / status feed / agent script) | Tiers under test | Expected detection | Expected prediction | Expected action |
|---|---|---|---|---|---|---|
| S-01 | Hard provider outage | openai double → 100 % 503 from t0 | 1, 2, 3 (one each) | R3 consecutive_failures within 3 calls; R1 critical band by first 300 s window; R4 once status double flips at t0+90 s | none required (step change) | tiers 2–3: automatic `alt_provider_failover`; tier 1: automatic too (detected failure, not backup agent). Provider-incident collapse groups ≥ 2 agents; per-agent alerts `suppressed_by_incident` |
| S-02 | Rate-limit ramp | `RateLimit-Remaining` ratio decays 0.6→0.02 over 12 min, then 429s | 2, 3 | R1 only after 429 share > 5 % | L3 `ratelimit_proximity` fires when remaining < 0.10 (expected ≥ 6 min before first 429) | tiers 2–3: `preemptive_failover` auto; `recommended_action=reroute_to_fallback` |
| S-03 | Rate-limit ramp, tier 1 | same as S-02 on a tier-1 agent | 1 | as S-02 | as S-02 | `awaiting_approval` with `approval.requested_by_kind=rule`; no routing change until the On-call Operator approves; timeout 600 s → `hold` → `degraded` |
| S-04 | Latency creep | p95 drifts +12 %/window across 6 windows to 1.4× threshold | 2 | R2 at threshold crossing | L2 `latency_trend` ≥ 2 windows earlier | `degraded` first (band degraded), `degraded_mode=safe_no_tools` applied by gateway; failover only if R2 persists `hysteresis_in` |
| S-05 | Cost spike | token counts ×6 for one agent, price table unchanged | 3 | R5 when spend_ratio ≥ 1.0 (scenario sets budget so this lands at t0+9 min) | L4 `budget_proximity` ≥ 30 min before projected breach at 1-h burn | `throttle` recommended; on R5 `quarantine` policy-driven → tier 3 automatic, tier 1–2 approval |
| S-06 | Budget exhaustion mid-month | spend already at 0.97 at seed; normal traffic | 1 | R5 at crossing | L4 immediately at first evaluation | tier 1: approval for quarantine; gateway continues until decision (fail mode respected) |
| S-07 | Flapping provider | double alternates 2 min failing / 2 min healthy ×6 | 2 | R1 fires on first bad window | n/a | **exactly one** failover; `hysteresis_out=6` prevents fail-back inside the flap; `cooldown_s` prevents re-fire; `failback_probe` only after 5 healthy min |
| S-08 | Silent degradation: refusals | double returns 200 with refusal text on 40 % of calls, `finish_reason=stop` | 2 | refusal-rate feature (quality proxy) crosses 0.25; `failure_mode=quality_collapse` | leading on refusal trend if ai-engineer ships L6; otherwise detect only (see Q2) | `degraded`; `recommended_action=reroute_to_fallback`; **no** error-rate alert (R1 must stay quiet, this is the point) |
| S-09 | Silent degradation: truncation | `finish_reason=length` on 50 %, output_chars at 30 % of baseline | 3 | output-length baseline deviation > 3σ | same caveat as S-08 | `trim_context` recommended; no failover |
| S-10 | Silent degradation: schema failures | tool-call arguments malformed JSON on 35 % | 2 | schema-validation-failure share > 0.20; `failure_mode=tool_failure` | n/a | `safe_no_tools` degraded mode, handoff for in-flight tasks with checkpoint |
| S-11 | Tool-call loop | agent script calls same tool with identical args 40× in one task | 1 | `infinite_loop` via repeated-call heuristic within 10 calls; consecutive tool errors R3 if the tool double errors | n/a | tier 1: `handoff` automatic (human handoff is automatic on every tier); packet `fidelity=checkpoint`; `pending_steps` present |
| S-12 | Context saturation | `context.utilisation` climbs 0.6→0.98 across a long task | 2 | utilisation > 0.95 | leading on utilisation slope (if shipped) | `trim_context`; no routing change |
| S-13 | Correlated multi-agent failure | anthropic double degrades; 7 meridian agents share it | mixed | R4 + R1 on each; provider collapse creates one `provider_incident` | n/a | one provider-scope alert, seven suppressed; seven sagas or one per agent (assert no `saga_in_flight` 409s leak to the user) |
| S-14 | Model deprecation | double returns 404 `model_not_found` for one model only | 2 | R1 critical + `error_class=model_deprecation` | n/a | `alt_model_same_provider` automatic on every tier; `model.is_allowed` check honoured |
| S-15 | Fallback target not viable | S-01 but the fallback chain's credential is revoked at t0 | 2 | as S-01 | — | saga `failed` with `target_not_viable`; `handoff` created as terminal step; audit row present |
| S-16 | Status page lies (false outage) | status double says `major`; traffic healthy | 2 | R4 fires (status-only) | n/a | **no failover** on R4 alone; penalty applied, `status=watch`; counts toward false-failover denominator |
| S-17 | Status page late (true outage, no status) | traffic 100 % 5xx; status double stays `operational` | 3 | R1/R3 detect | n/a | failover on traffic evidence alone; R4 absence must not block |
| S-18 | Observation gap | SDK stops sending (no heartbeat) for 4 min | 1 | `observation.gap` synthesised at 30 s; `provisional.observation_coverage` < 1 | n/a | no failover on gap alone; `watch`; alert `kind=detected` with `failure_mode=null` |
| S-19 | Ingest backpressure | sibyl-ingest returns 429 `ingest_saturated` for 90 s | all | `observation.gap(cause=ingest_backpressure)` from SDK; replay closes gap | n/a | zero duplicate `call_id`; health score unaffected after replay (compare to S-24 baseline) |
| S-20 | Undo and operator hold | S-01 then the On-call Operator `undo`s within 2 min; outage continues | 2 | re-detect every tick | — | `operator_hold` 409 raised internally; `alert.hold_suppressed_count` increments; no transition for 30 min; `clear_hold` by owner resumes |
| S-21 | Tenant isolation, steady | all chaos in meridian; northstar steady | n/a | northstar: zero alerts, scores ≥ 90 | — | zero northstar `routing_transition` rows; `GET /alerts` as northstar principal returns none; SSE stream for northstar silent |
| S-22 | Tenant isolation, shared provider | openai double fails **only** for meridian keys (per-key behaviour) | n/a | meridian detects; northstar healthy | — | `provider_incident` scoped per tenant; northstar sees no provider alert |
| S-23 | Prompt injection pattern | agent script emits `policy.decision(action=blocked)` + injection marker | 1 | `prompt_injection` failure mode from policy events | n/a | tier 1: `quarantine` approval requested; kill not auto |
| S-24 | Baseline / soak | no chaos; Poisson arrivals, realistic token mix, 60 min | all | **zero** alerts above `info`; score ≥ 90 | bands `0.05` on all horizons | zero transitions; this is the precision denominator |
| S-25 | Fail-back canary | S-01 recovers at t0+10 min | 2 | R1 clears | — | `failback_probe` after 5 healthy min → `failing_back` canary 10 % → 100 %; if S-07 flap re-injected during canary → `failed_over` again |
| S-26 | Approval four-eyes | S-01 variant where fallback step is `backup_agent`, tier 1 | 1 | as S-01 | — | `awaiting_approval` even on detected failure (D13 clarification); `self_approval` 409 when the Platform Admin requests and approves |
| S-27 | D22 forced hold | tier-1 agent tagged PII; approval expires; plan says `fail_safe` | 1 | — | — | worker forces `hold`; audit `timeout_policy_applied: hold_forced_d22` |
| S-28 | Kill beats everything | S-01 running; the On-call Operator pulls kill | 2 | — | — | no saga progresses; gateway 403 on stale and fresh snapshot; SDK `SibylKilled` within 20 s; release only by step-up |

Each scenario file carries: `seed`, `agents` (slugs, tiers), `timeline` (chaos knob transitions), `labels` (onset/peak/recovery per agent), `expect` (the three right-hand columns as machine-checkable predicates), `tier_gate` (D13 expectation), `rto_s` override if the continuity plan is non-default.

### 2.1 Coverage matrix

Which seed rules and state-machine edges each scenario exercises, so a rule or edge with no row is a gap, not an oversight.

| Rule / edge | Scenarios |
|---|---|
| R1 error_rate | S-01, S-02, S-07, S-13, S-14, S-17, S-20, S-25 |
| R2 p95_latency | S-04 |
| R3 consecutive_failures | S-01, S-11, S-17 |
| R4 provider_status | S-01, S-13, S-16, S-17 (absence) |
| R5 budget_breach | S-05, S-06 |
| L1 error_trend | S-07 (should **not** promote a flap to a trend), S-13 |
| L2 latency_trend | S-04 |
| L3 ratelimit_proximity | S-02, S-03 |
| L4 budget_proximity | S-05, S-06 |
| L5 fallback_pressure | S-01 (inline fallback on tier 2-3), S-15 |
| quality proxies (no code yet, Q1) | S-08, S-09, S-10, S-12 |
| `active → degraded → failed_over` | S-02, S-04 |
| `active → failed_over` (hard) | S-01, S-14 |
| `awaiting_approval → failed_over / degraded` | S-03, S-26, S-27 |
| `failed_over → failing_back → active / failed_over` | S-25 |
| `undo` + operator hold | S-20 |
| `quarantined` | S-05, S-23 |
| `killed` | S-28 |
| provider collapse / `provider_incident` | S-01, S-13, S-22 |
| saga `failed` (`target_not_viable`) | S-15 |
| `observation.gap` | S-18, S-19 |
| handoff packet `checkpoint` vs `request_only` | S-11 (checkpoint), S-10 (request_only variant) |
| verdict `tp/fp/unsure`, 422 `verdict_required`, D33 queue | every scenario via personas (§6) |

### 2.2 Variant axis

Each catalogue row is run in three seeds; S-01, S-02, S-04 and S-08 additionally run in a **tier-swap** variant (same injection on an agent of each tier) so D13 behaviour is seen on all three tiers for the four most common failure shapes. That brings the nightly to 28 base + 12 tier variants = 40 scenario runs × 3 seeds = 120 runs, which is the 90-minute budget at 1× with 8 parallel compose stacks (one Postgres each; database-architect to confirm memory).

---

## 3. Metrics and acceptance thresholds

All metrics are computed per run, aggregated across 3 seeds in nightly, and gated at the **worst** seed, not the mean.

### 3.1 Definitions

| Metric | Definition | Source |
|---|---|---|
| Time-to-detect (TTD) | first `detected` alert SSE arrival − labelled onset | SSE + labels |
| Lead time | labelled onset of the *failure* (not the precursor) − first qualifying prediction | health horizons + labels |
| Precision / recall (detection) | per tier, per failure_mode; a TP is an alert whose `agent_id`, `failure_mode` and window overlap a label; everything else FP; labelled onsets with no overlapping alert are FN | alerts + labels |
| Precision / recall (prediction) | same, using leading alerts / band ≥ 0.60 and a 15-min lookahead window | horizons + labels |
| False-failover rate | automated `routing_transition` to `failed_over`/`quarantined` with no overlapping label ÷ all automated transitions | transitions + labels |
| Missed-failover rate | labelled failures where the plan says failover and none occurred within RTO | transitions + labels |
| RTO attainment | share of labelled failures where `routing_state` reached a continuing state (`failed_over`, or `degraded` with safe mode) or a `handoff_task` was `claimed` within `continuity_plan.rto_s` | transitions, tasks |
| Approval gating correctness | tier-1 predicted-only or backup-agent cases that produced `awaiting_approval` ÷ such cases; any automatic transition here is a **critical** failure | approvals |
| Explainability completeness | share of `health_snapshot` rows with `status ≠ healthy` where `factors[]` is non-empty, every factor has `explanation`, `value`, `threshold`, and the sum of `penalty` reproduces `100 − score` within ±1 | health |
| Isolation leaks | any northstar/sandbox row or SSE event attributable to meridian chaos | all |
| Idempotency | duplicate `call_id` count, `X-Sibyl-Replayed` behaviour on spool replay | ingest |

### 3.2 Phase 1 acceptance thresholds (gate for `ML.md` sign-off)

| Metric | Tier 1 | Tier 2 | Tier 3 | Notes |
|---|---|---|---|---|
| TTD, hard failures (S-01, S-13, S-14, S-17) | ≤ 60 s | ≤ 90 s | ≤ 120 s | bounded by 3 consecutive failures + eval tick |
| TTD, silent degradation (S-08–S-10) | ≤ 10 min | ≤ 10 min | ≤ 15 min | two 5-min windows |
| Lead time, ramps (S-02–S-06) | ≥ 5 min | ≥ 5 min | ≥ 5 min | L3/L4 are deterministic given headroom; below this the prediction is cosmetic |
| Detection recall | ≥ 0.95 | ≥ 0.95 | ≥ 0.90 | per failure_mode where a rule exists |
| Detection precision | ≥ 0.90 | ≥ 0.85 | ≥ 0.80 | S-16, S-18, S-24 populate the FP side |
| Prediction recall (ramps only) | ≥ 0.80 | ≥ 0.80 | ≥ 0.70 | |
| Prediction precision | ≥ 0.70 | ≥ 0.70 | ≥ 0.60 | leading rules are allowed to be noisy because tier 1 is approval-gated; tiers 2–3 pay for FPs with a false failover, hence the next row |
| False-failover rate | 0 automatic | ≤ 2 % | ≤ 5 % | tier 1 has no automatic predicted failover, so any is a bug |
| Missed-failover rate | 0 | ≤ 2 % | ≤ 5 % | |
| RTO attainment | 100 % within 15 min | ≥ 98 % within 1 h | ≥ 95 % within 4 h | D23 |
| Approval gating correctness | 100 % | n/a | n/a | critical |
| Explainability completeness | 100 % | 100 % | 100 % | the chair's "no black box" promise is a test, not a slogan |
| Isolation leaks | 0 | | | critical |
| S-07 flap: automated failovers per run | exactly 1 | | | hysteresis/cooldown tuning target |
| S-24 soak: alerts above `info` | 0 | | | precision denominator |
| Unverdicted-resolved backlog created by harness | reported, not gated | | | D33 SLI exists; scenario personas verdict them (§6) |

Severity mapping for a failing gate: isolation leak, approval-gating miss, automatic tier-1 predicted failover, explainability < 100 % → **CRITICAL (block)**; false-failover or RTO miss → **HIGH**; precision/recall or lead time → **MEDIUM** on first miss, HIGH if it regresses two nightlies running.

### 3.3 How the oracle computes the headline numbers

```python
# sibyl-sim/oracle/metrics.py (shape, not final code)
def match(alerts, labels, lookback_s=0, lookahead_s=0):
    """One label may match at most one alert; one alert at most one label.
    Greedy by earliest alert; window = [onset - lookback, recovery + lookahead]."""


def detection_prf(run):
    tp, fp, fn = match(run.alerts(kind="detected"), run.labels(kind="onset"))
    return per_tier(precision(tp, fp), recall(tp, fn))


def prediction_prf(run):
    # a prediction is a leading alert OR a snapshot with band >= 0.60 on 15m
    preds = run.leading_alerts() | run.snapshots(band_min="0.60", horizon="15m")
    tp, fp, fn = match(preds, run.labels(kind="onset"), lookback_s=900)
    return per_tier(precision(tp, fp), recall(tp, fn))


def lead_time(run):
    return median(label.t - first_pred(label).t for label in matched_onsets(run))


def false_failover_rate(run):
    auto = run.transitions(
        actor_kind in {"rule", "policy"}, to_state in {"failed_over", "quarantined"}
    )
    unlabelled = [t for t in auto if not overlaps_any(t, run.labels())]
    return per_tier(len(unlabelled) / max(len(auto), 1))


def rto_attainment(run):
    return per_tier(
        share(
            label
            for label in run.labels(kind="onset")
            if continuing_state_by(label.agent, label.t + plan(label.agent).rto_s)
            or task_claimed_by(label.agent, label.t + plan(label.agent).rto_s)
        )
    )


def explainability(run):
    bad = [
        s
        for s in run.snapshots(status != "healthy")
        if not s.factors
        or any(f.explanation is None for f in s.factors)
        or abs(sum(f.penalty for f in s.factors) - (100 - s.score)) > 1
    ]
    return 1 - len(bad) / max(len(run.snapshots(status != "healthy")), 1)
```

Edge rules the oracle applies so numbers are comparable across runs:

- An alert that fires **before** the labelled precursor (S-02 `t < 300`) is an FP even if the ramp later becomes real; early is not free.
- Suppressed per-agent alerts under a `provider_incident` (S-13) count once at provider scope for precision, but each agent's label still needs a matching per-agent alert for recall.
- Alerts that re-fire after `cooldown_s` on the same unresolved label count as one TP; they are reported separately as "re-fires" so cooldown tuning is visible.
- `unsure` verdicts from the On-call Operator are excluded from the persona-agreement number and from the Phase 2 sample (§5).
- A northstar alert of any severity in any scenario is an isolation failure first and an FP second; the run is marked CRITICAL regardless of the aggregate.

---

## 4. Regression suite shape and CI budget

### 4.1 Layers

| Layer | What is asserted | Runs on | Budget |
|---|---|---|---|
| Golden outputs | for each scenario and seed, canonicalised `health_snapshot` series (score, status, factor rules and penalties), alert set, transition set stored under `sibyl-sim/golden/<scenario>/<seed>.json`. Diff tolerances: score ±2, factor `value` ±5 %, timestamps as tick offsets ±1 tick. Any new factor key or rule code is a **deliberate** golden update with a one-line reason in the PR | PR (smoke set), nightly (all) | 12 min / 90 min |
| Contract tests | `sibyl-health/1`, `sibyl-feature-snapshot/1`, `sibyl-event/1`, `sibyl-handoff/1` schema conformance on every object the oracle reads; `prediction.source` matches `rules/v\d+` in Phase 1; `probability` absent unless `source` is a model; `horizons` always has 15m/1h/24h; `recommended_action` ∈ enum | PR | 2 min, unit-level, no compose |
| Rule unit tests | each R/L rule as a pure function over an `agent_window_stats` fixture: threshold edges, `min_samples` behaviour, `hysteresis_in/out`, `cooldown_s`, `escalate_after_fires`, `tier_applicability`, `collapses_to_provider`. Boundary-value fixtures generated from the seed YAML so a threshold edit without a test edit fails | PR | 1 min |
| Property tests | hypothesis: score monotone non-increasing in each penalty; sum of penalties = 100 − score; weights sum ≤ 1; same inputs → same `feature_snapshot_ref` content; hysteresis never produces two `rule` transitions on the same agent within `cooldown_s` | PR | 2 min |
| Isolation tests | S-21/S-22 as a dedicated job that also runs the RLS fuzz from Step 3 against harness-produced data | PR | 4 min |
| Nightly soak | S-24 60 min at 200 calls/s plus a random chaos draw from the catalogue (seeded by date); asserts no `events_rejected`, no duplicate `call_id`, worker lag < 2 ticks, Postgres aggregate table growth within database-architect's budget | nightly | 60 min |
| Drill replay | re-run S-01, S-11, S-26 as the `continuity_plan.drill_schedule` consumer so the drill feature itself is exercised | weekly | 15 min |

### 4.2 CI budget and gates

- PR total ≤ 20 min wall on a 4-vCPU runner (compose up ≈ 2 min, smoke 12, units 5). Anything slower moves to nightly; the PR must never skip S-21 and S-25.
- Nightly ≤ 3 h including soak; publishes `sibyl-sim/reports/<date>.md` with the §3.2 table, golden diffs, and a "tuning drift" section comparing hysteresis/cooldown effective values to the seeded YAML.
- Flake policy: a scenario failing on one seed and passing on the other two is quarantined with a ticket, not retried silently; three quarantines in a week blocks the release until the nondeterminism is found (usually sim-time vs wall-time drift).
- Golden updates require the PR to include the `sim diff` output; the chair or ai-engineer approves changes to penalties or thresholds, qa-expert approves changes to the oracle.

### 4.3 Repository layout

```
sibyl-sim/
├── pyproject.toml              # own package; depends on sibyl-sdk and sibyl-schemas only
├── sim/
│   ├── cli.py                  # sim run | suite | soak | shadow | diff | report
│   ├── runner.py               # timeline executor, seeded RNG, sim clock
│   ├── actors/agent.py         # 23 scripted agents (20 meridian + 3 northstar) using sibyl-sdk
│   ├── actors/personas.py      # Platform Admin / On-call Operator / Compliance Auditor OIDC sessions against dex
│   ├── doubles/openai.py       # OpenAI-compatible double with knobs
│   ├── doubles/anthropic.py
│   ├── doubles/ollama.py
│   ├── doubles/status_feed.py
│   └── labels.py               # ground-truth writer
├── oracle/
│   ├── reader.py               # control-plane + SSE client, per-principal
│   ├── predicates.py           # §1.5 table
│   ├── metrics.py              # §3.3
│   └── report.py               # markdown + json
├── scenarios/                  # S-01 … S-28 YAML (+ tier-swap variants generated at load)
├── golden/<scenario>/<seed>.json
├── reports/                    # nightly outputs, gitignored except the latest
└── tests/                      # the harness tests itself: predicate unit tests, double conformance
```

`sibyl-sim` is its own compose profile (`--profile sim`) and is excluded from the production bundle image list; the control plane has no knowledge of it (R32). The only product-side hooks it relies on are `SIBYL_EVAL_TICK_S` and `SIBYL_DEMO=1`, both already present for other reasons.

### 4.4 Nightly report format

```
# sibyl-sim nightly 2026-10-11 · build 3f9c2a1 · rules/v1 · 120 runs · 88 min

## Gate
CRITICAL 0 · HIGH 0 · MEDIUM 1 (S-09 tier-3 detection recall 0.87 < 0.90, seed 3)

## Headline (worst seed)
| metric | t1 | t2 | t3 | gate |
| TTD hard (s) | 41 | 58 | 77 | pass |
| TTD silent (min) | 7.0 | 8.5 | 12.0 | pass |
| lead time ramps (min) | 6.5 | 6.0 | 5.5 | pass |
| detection P/R | .96/.97 | .91/.96 | .84/.87 | R t3 MEDIUM |
| prediction P/R | .78/.86 | .74/.83 | .66/.72 | pass |
| false failover | 0 | 1.1 % | 3.8 % | pass |
| RTO attainment | 100 | 99.2 | 97.0 | pass |
| approval gating | 100 | – | – | pass |
| explainability | 100 | 100 | 100 | pass |
| isolation leaks | 0 | pass |

## Golden diffs
S-04/seed1: factor latency_trend.value 1.21 → 1.27 (+5.0 %, at tolerance edge) — investigate

## Tuning drift
hysteresis_out effective 6 (yaml 6) · cooldown_s 600 (600) · L3 remaining threshold 0.10 (0.10)

## Persona loop
verdicted share 0.93 · unverdicted backlog drained · Compliance Auditor writes refused 100 % · label agreement 0.96

## Soak
200 calls/s · 60 min · events_rejected 0 · dup call_id 0 · worker lag p99 1.3 ticks · agent_metrics_5m +41 MB
```

---

## 5. Phase 2 model promotion gate

A learned model (`prediction.source = model/<name>:<ver>`) may replace `rules/v1` on a horizon only after:

1. **Shadow mode for ≥ 14 days or ≥ 3 nightly suites, whichever is longer.** The candidate writes its band, probability and `abstained` flag into the `feature_snapshot`/`health_snapshot` beside the rule prediction; the API keeps serving `rules/v1`. The oracle scores both against labels from (a) the catalogue and (b) verdicted real alerts.
2. **Minimum verdict-labelled sample.** From `alert` rows with `verdict ∈ {tp, fp}` (D24; `unsure` and `null` excluded per R29/D33): at least **300 verdicted alerts** overall, **≥ 50 per tier**, **≥ 30 per `failure_mode` the model claims to predict**, and **≥ 100 `fp` verdicts** so the model has negatives from real operators, not just S-24. Below these counts the gate is simply closed; the model may ship as `abstained=true` only.
3. **Non-inferiority on every §3.2 row** at the worst seed, plus **superiority** on at least one of: lead time (+ ≥ 3 min median on ramps), prediction precision (+ ≥ 0.10), or coverage of a failure_mode the rules cannot see (S-08–S-10 silent degradation is the obvious target).
4. **Calibration.** Reliability diagram over the shadow period: expected-calibration-error ≤ 0.08 on the four bands; the `0.90` band must have realised rate ≥ 0.80, or the model does not get to emit `0.90`.
5. **Abstention behaviour.** When features are provisional (`observation_coverage < 0.8`) or out of training support, the model abstains and the rule fills the horizon; abstention rate ≤ 30 % in shadow, else it is not useful.
6. **Explainability parity.** Per-feature contributions (SHAP or tree path) populate `factors[]` with `kind=leading` and a human `explanation`; completeness metric stays 100 %.
7. **Rollback switch.** `SIBYL_PREDICTION_SOURCE=rules/v1` env flips back without redeploying; tested in the promotion run.
8. **Tier staging.** Promote on tier 3 first, then tier 2 after two more nightlies, then tier 1 (where it only ever creates approvals, D13).

Golden files for a promoted model are versioned per `model/<name>:<ver>`; the `rules/v1` goldens are kept as the permanent fallback baseline.

---

## 6. How the Platform Admin, On-call Operator and Compliance Auditor exercise the verdict loop

The three dex personas (D29) are scripted actors inside `sibyl-sim` with OIDC sessions, so the verdict loop is tested end-to-end and the Phase 2 training set has realistic labels from day one.

- **On-call Operator (operator, `alerts:act`, `incidents:act`, `approvals:decide`).** In every scenario the On-call Operator claims the handoff queue, approves or denies tier-1 approvals per the scenario's `tier_gate` (S-03 approve at +4 min; S-26 deny once to prove `denied → degraded`), and closes alerts with a verdict: `tp` where the oracle's label overlaps, `fp` for S-16 and S-24 noise, `unsure` for S-18 observation gaps. Their closes must hit 422 `verdict_required` exactly once per run (a deliberate missing-verdict call) to prove D24.
- **Platform Admin (engineer, `routing:override`, `agents:*`).** The Platform Admin performs the `undo` in S-20, the `fail_back` in S-25, the self-approval attempt in S-26 (expects 409 `self_approval`), edits an `alert_rule` threshold mid-run in a dedicated variant of S-04 (expects `overridden=true` and a golden diff), and claims the unverdicted-resolved queue (D33) to add one-time verdicts to hysteresis-resolved alerts.
- **Compliance Auditor (auditor, read-only + `audit:read`).** After each run the Compliance Auditor lists the audit log and verifies: every automated transition, approval, verdict and undo has a row; the `hold_forced_d22` annotation exists in S-27; they can read `label(kind=alert_verdict)` but not change it (403). Their run doubles as the explainability check from the buyer's side: every `factor.explanation` is ≤ 300 chars and names a threshold.

Outputs the harness asserts: verdicted share of closed alerts ≥ 90 % (On-call Operator), unverdicted backlog drained to 0 by the Platform Admin, zero write successes by the Compliance Auditor, and the resulting `label` rows match the oracle's own labels with ≥ 95 % agreement (the 5 % is the On-call Operator's scripted `unsure`). That agreement number is also the sanity check on §5 item 2: if synthetic personas disagree with ground truth more than that, the verdict UI or the alert payload is confusing and should be fixed before real operators see it.

### 6.1 Persona scripts

The persona blocks in every scenario YAML are compiled from three reusable scripts so the behaviour is consistent across runs; a scenario may override a step but not add a new verb.

```yaml
# sim/actors/personas/operator.yaml  (operator)
default_policy:
  approvals:
    tier_gate=approval: approve_at: onset+240   # S-03; S-26 overrides to deny once then approve
  handoff_queue:
    claim: on_arrival
    complete_with: { outcome: resolved, note: "handled from checkpoint" }
  alert_close:
    when: recovery+60
    verdict_from_label: true                   # tp if overlaps label, fp otherwise
    unsure_for: [observation_gap]
  deliberate_errors:
    - close_without_verdict: once             # expects 422 verdict_required

# sim/actors/personas/admin.yaml  (engineer)
default_policy:
  undo:        only_if_scenario_sets
  fail_back:   at: recovery+360                # after failback_probe would have fired
  rule_edit:   only_if_scenario_sets
  self_approve_attempt: in: [S-26]            # expects 409 self_approval
  drain_unverdicted_queue: at: end, verdict_from_label: true

# sim/actors/personas/auditor.yaml  (auditor)
default_policy:
  at: end
  checks:
    - audit_verbs_present_for_every_automated_transition
    - audit_verbs_present_for_every_verdict
    - label_rows_readable
    - label_write_refused                     # expects 403
    - factor_explanations_within_300_chars
    - hold_forced_d22_present: in: [S-27]
```

### 6.2 What the loop proves beyond labels

- **The alert payload is sufficient to verdict.** The On-call Operator decides from `alert` + `health_snapshot` only (no label access in their session). Agreement with ground truth is measured; if a rule's `what_to_do_template` leaves them guessing, agreement drops and the template gets fixed before a real operator sees it.
- **Verdicts are atomic with labels.** The Compliance Auditor checks that every `alert.labelled` audit row has a `label(kind=alert_verdict)` and vice versa; a mismatch is a transaction-boundary bug, not a QA note.
- **The D33 backlog is drainable.** Hysteresis-resolved alerts land in the unverdicted queue; the Platform Admin drains it with one-time closes; a second close attempt returns 409 `already_resolved`.
- **Training-set hygiene starts now.** The Phase 2 loader is run against the harness database at the end of every nightly with a dry-run flag and reports how many rows it would include; a sudden jump or drop is a schema or verdict-flow regression caught months before a model is trained.

---

## 7. Open questions for the chair

1. **Quality-proxy rules (S-08–S-10) need a rule code.** The seed table stops at R5/L5; refusal rate, truncation share and schema-failure share are named as "first-class features" but have no `alert_rule` row. Ask ai-engineer to add R6–R8 (detected) and L6 (refusal trend) so the harness has something to gate, or accept that silent degradation is detect-only in Phase 1.
2. **Sim-time acceleration vs `is_late`.** Capping at 1× for latency scenarios keeps nightly at ~90 min. If the chair wants faster CI, the worker needs a test-only clock injection (`SIBYL_NOW_OVERRIDE`), which is a product change I would rather not make. Which?
3. **Precision thresholds for tier 3 (0.80 / 0.60).** I set them low because tier 3 failovers are cheap to undo. If the pitch is "zero false failovers", tiers 2–3 need stricter gates and the leading rules need `hysteresis_in ≥ 3`. Decide before tuning starts.
4. **Verdict sample minimums (300 / 50 per tier / 100 fp).** These are my floor for a tree model to beat rules; ai-engineer may want more. Confirm, and confirm that `unsure` is excluded from training rather than treated as a soft negative.
5. **Who owns golden updates to penalties and thresholds?** I proposed ai-engineer/chair for rule changes and qa-expert for oracle changes. Needs a line in `ML.md` so tuning does not become "edit the golden until green".
6. **Should `sibyl-sim` ship in the self-hosted bundle** (so buyers can run drills against their own stack) or stay a dev-only tool per R32? If it ships, the provider doubles need the same permissive-licence review as everything else (D15) and the `SIBYL_DEMO=1` guard moves from "forbids vaulted credentials" to a real feature flag.
