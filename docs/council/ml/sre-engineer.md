# SRE Engineer: ML approach (Step 5) — Health as SLI/SLO, hysteresis, false-failover budget, RTO proof, self-observability

Date 2026-10-10. Inputs: `docs/council/ml/CHAIR-INITIAL.md` (followed), `DECISIONS.md` D1–D35 (D6/D13 tiers and gating, D18 business-hours window, D21 hold, D22 forced hold, D23 RTO defaults, D24/D33 verdicts), my Step 2 report (`architect/sre-engineer.md`), `datamodel/ai-engineer.md` §6–§7 (frozen `sibyl-health/1`, FeatureSnapshot, labels), `DATAMODEL.md` §2.5/§4.5 (`alert_rule`, `alert`, `health_snapshot`), `API.md` §5.7/§5.9/§5.10 and §6.

Governing sentence: **the health score is an SLI, not a verdict.** A number from 0 to 100 is useful only when we say what "good" means per tier, over which window, how fast the budget may burn before a machine acts, and how we prove afterwards that acting was right. Everything below makes the chair's rules-plus-statistics position operable; nothing requires a learned model.

Two framing rules I apply throughout:
1. **Two clocks.** Customer-agent reliability runs on the agent's own clock (24×7, their users are hitting it). Sibyl's operational response runs on D18's business-hours clock (one operator, inbox not pager). Agent-tier SLOs are therefore 24×7 SLIs with *automation* as the 24×7 responder and the *human* escalation path collapsing to business hours. Sibyl's own SLOs are business-hours windows in Phase 1.
2. **One rule set, tier-parameterised.** `alert_rule.thresholds` is "by tier" already (DATAMODEL). I do not propose separate rules per tier, only separate parameters. Fewer things to tune against the harness.

---

## 1. Health score as SLI/SLO per agent tier

### 1.1 The SLIs behind the score

The score is a weighted composite of six SLIs computed from `agent_metrics_1m` per the `health_snapshot` read contract (detected rules may read the two partial minutes when `request_count ≥ min_samples`; leading rules read closed buckets only). Each SLI is a ratio in [0,1] where 1 is good, so the score is `100 × Σ wᵢ·SLIᵢ` minus leading-indicator penalties, and `factors[]` carries each term's `value`, `threshold`, `penalty`.

| SLI | Definition (good / valid) | Feature keys (`features/v1`) | Weight tier 1 / 2 / 3 | Kind |
|---|---|---|---|---|
| Availability | calls with `status ∈ {ok}` or a non-provider client error / all calls excl. `killed`/`quarantined` 403s | `error_rate`, `error_rate_5xx`, `error_rate_timeout`, `error_rate_429` | 0.30 / 0.30 / 0.35 | detected |
| Latency | calls with `latency_ms ≤ max(baseline_p95 × 1.5, model floor)` / all | `latency_p95_ms`, `latency_p95_vs_baseline`, `ttfb_p95_ms` | 0.15 / 0.15 / 0.15 | detected |
| Task completion | `task_outcome ∈ {success, partial}` / tasks closed | `task_success_rate`, `task_steps_p95` | 0.20 / 0.15 / 0.10 | detected (lagging) |
| Output quality proxy | calls not refused, not truncated (`finish_length_ratio`), tool calls schema-valid (`1 − tool_error_rate`), feedback ≥ 0 | `finish_length_ratio`, `tool_error_rate`, `tool_seq_repeat_ratio`, `feedback_mean` | 0.15 / 0.15 / 0.10 | detected |
| Rate-limit headroom | 1 − proximity; `ratelimit_headroom_min` and `ratio_429` | `ratelimit_headroom_min`, `ratio_429`, `inline_fallback_ratio` | 0.10 / 0.15 / 0.15 | leading |
| Budget / dependency headroom | 1 − month-to-date burn vs linear pace; provider status; credential and deprecation runway | `static.budget_headroom`, `static.provider_status`, `days_to_credential_expiry`, `days_to_model_deprecation`, `cost_slope` | 0.10 / 0.10 / 0.15 | leading |

Weights sum to 1.0 per tier. Tier 1 leans on task completion (the thing the business notices); tier 3 leans on availability and headroom (cheap, high-volume agents where a 429 wave is the usual failure). Weights live in `alert_rule.thresholds` under a `score_weights` key per tier so the harness can tune them without a migration; the response's `factors[].weight` echoes the value actually used.

A score is **provisional** (`provisional.flag=true`) until `events_needed` (50 in the example; I recommend 50 calls *or* 30 closed minutes, whichever first) and `observation_coverage ≥ 0.8`. Provisional scores never drive automation; they drive `watch` band at most (ai-engineer's rule: provisional forces `rules/vN`; I add: provisional caps the band).

### 1.2 Bands are the SLO buckets

`status ∈ {healthy, watch, degraded, failed}` is fixed by the contract. Band edges per tier, on the 5 m grain (the grain the example uses and the one leading rules read):

| Band | Tier 1 | Tier 2 | Tier 3 | Routing consequence (API §6.1) |
|---|---|---|---|---|
| `healthy` | ≥ 85 | ≥ 80 | ≥ 75 | `active` |
| `watch` | 70–84 | 65–79 | 55–74 | `active`; alert `info`; leading rules armed |
| `degraded` | 45–69 | 40–64 | 30–54 | `active → degraded` after hysteresis-in; `degraded_mode` applies |
| `failed` | < 45 | < 40 | < 30 | detected-failure path: automatic alt-model/alt-provider failover and handoff on every tier; backup-agent on tier 1 → `awaiting_approval` (D13 clarification) |

Tier 1 edges are higher because the cost of being wrong is asymmetric: a tier-1 agent in `degraded` with `safe_no_tools` is cheap; a tier-1 agent silently failing is not. Tier 3 edges are lower to avoid paying failover cost for noise.

### 1.3 Agent-minute SLO per tier

The SLO is stated on **agent-minutes**, not on calls, so a quiet agent and a busy agent are comparable and the number is the same one the console's 3-day `health/history` shows.

- **Good minute**: the 1 m `health_snapshot` band is `healthy` or `watch` and the minute was observable (`observation_coverage ≥ 0.8` or `request_count ≥ min_samples`).
- **Valid minute**: not `killed`, not `quarantined`, not in a tenant-declared maintenance window, not `provisional`. Minutes with zero traffic and no scheduled traffic are excluded (we do not reward silence), *unless* the agent declares `rps_limit`/expected cadence in its continuity plan, in which case a silent minute is bad (missing heartbeat).
- **Window**: rolling 30 d, 24×7 for the agent SLI (reason 1 above).

| Tier | Agent-minute SLO | 30 d error budget | Equivalent | Promise? |
|---|---|---|---|---|
| 1 | 99.5% | 216 min | ~3.6 h of degraded/failed per month | Shown per agent in console and to the tenant; not a contractual promise of the agent (we do not run their model), a promise that Sibyl measures and responds within the response SLOs below |
| 2 | 99.0% | 432 min | ~7.2 h | Same |
| 3 | 98.0% | 864 min | ~14.4 h | Same |

A tenant may tighten per agent via the continuity plan (`slo_target` field, see open question Q1); loosening below the tier default requires the same four-eyes as a tier-1 chain, because loosening is how a team hides a sick agent.

### 1.4 Burn rate drives severity and the failover trigger

Burn rate = (bad minutes in window) ÷ (budget × window/30 d). I keep the Step 2 pairs (fast 14.4× over 1 h+5 m; slow 6× over 6 h+30 m; 1× over 3 d) and add a very-fast pair for failover, because 1 h is far too slow for a 15-minute RTO (D23). Each row requires **both** windows to exceed the rate (the short one proves it is still happening; the long one proves it is not a blip).

| Pair | Long / short window | Burn ≥ | Budget consumed if sustained | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|---|---|---|
| very-fast | 15 m / 2 m | 48× (t1) · 36× (t2) · 24× (t3) | 2–4% in 15 m | `critical`; detected-failure path → auto alt-model/alt-provider; backup-agent → approval | `critical`; auto failover incl. backup agent | `critical`; auto failover |
| fast | 1 h / 5 m | 14.4× | 2% in 1 h | `critical`; leading-only → `awaiting_approval` (D13); detected → auto | `warning` → `critical` on second window; predicted → auto | `warning`; predicted → auto `degrade_then_auto` |
| slow | 6 h / 30 m | 6× | 5% in 6 h | `warning`; `degraded` routing; packet pre-assembled | `warning`; `degraded` | `info` |
| ticket | 3 d / 6 h | 1× | budget exhausted on schedule | `info` + weekly review item | `info` | `info` |

Two bindings to the state machine:
- `band = failed` on the 5 m grain **is** the very-fast condition for detected rules (a failed band for ≥ 2 consecutive 10 s ticks after hysteresis-in). I do not want two mechanisms competing; `alert_rule.severity` is set from the row above, and the saga's `check_viability` reads `alert.severity` plus `kind` to decide auto vs approval.
- Leading rules (`kind=leading`) never produce `critical` on their own on tier 1; the strongest they can do is `warning` plus `recommended_action=await_approval`. On tiers 2–3 a leading `probability_band ≥ "0.60"` with `confidence ≥ medium` at the 15 m horizon is equivalent to the fast pair and triggers the predicted path (`preemptive_mode auto` / `degrade_then_auto`).

The per-tenant **error-budget policy** (D18 scale, no pager): budget > 50% consumed on a tier-1 agent → console banner on the agent, weekly digest line, `recommended_action=watch`; 100% → the agent's continuity plan is flagged `review_required`, drills are forced on (§4.3), and the alert rule copies for that agent cannot be loosened until the budget recovers. Nothing pages; the automation is the pager.

### 1.5 Seed parameters per rule, by tier

What `tenant_create()` copies into `alert_rule` (R18). Detected rules (`R*`) feed the band; leading rules (`L*`) feed `horizons` and penalties. Thresholds are the *bad* side; `min_samples` guards the two partial minutes.

| `short_code` / `code` | kind | metric, comparator | threshold t1 / t2 / t3 | `window_s` | `min_samples` | `hysteresis_in` / `out` (ticks) | `cooldown_s` | severity | penalty |
|---|---|---|---|---|---|---|---|---|---|
| R1 `error_rate_high` | detected | `error_rate` > | 0.03 / 0.05 / 0.08 | 300 | 20 | 2/18 · 3/12 · 3/6 | 300 / 600 / 900 | warning → critical at 2× threshold | 30 |
| R2 `timeout_rate_high` | detected | `error_rate_timeout` > | 0.02 / 0.03 / 0.05 | 300 | 20 | as R1 | as R1 | warning | 20 |
| R3 `latency_regression` | detected | `latency_p95_vs_baseline` > | 1.5 / 1.75 / 2.0 | 300 | 30 | as R1 | as R1 | warning | 15 |
| R4 `task_failure_high` | detected | `1 − task_success_rate` > | 0.05 / 0.10 / 0.15 | 900 | 10 tasks | 6/18 · 6/12 · 6/6 | 900 | warning | 20 |
| R5 `output_quality_drop` | detected | `finish_length_ratio` > or `tool_error_rate` > | 0.10 / 0.15 / 0.20 | 300 | 20 | as R1 | as R1 | warning | 15 |
| R6 `heartbeat_missing` | detected | `request_count` = 0 while plan declares cadence | — | 2 × declared period | — | 1/3 | 600 | warning (t1 critical) | 25 |
| L1 `ratelimit_proximity` | leading | `ratelimit_headroom_min` < | 0.15 / 0.10 / 0.10 | 300 closed | 20 | 6/18 · 6/12 · 12/6 | 600 | warning | 10, `horizon_s=900` |
| L2 `fallback_pressure` | leading | `inline_fallback_ratio` > | 0.10 / 0.20 / 0.25 | 300 closed | 20 | as L1 | 600 | warning | 18, `horizon_s=900` |
| L3 `error_trend_rising` | leading | EWMA `error_rate_slope` > and CUSUM change-point | slope > 0.5 pp/min for 3 closed minutes | 900 closed | 30 | 6/18 | 600 | info → warning | 10, `horizon_s=900` |
| L4 `provider_status_degraded` | leading, `scope=provider`, `collapses_to_provider=true` | `static.provider_status` ∉ {operational} | — | event-driven | — | 1/6 | 300 | warning (critical if `major_outage`) | 15, `horizon_s=3600` |
| L5 `budget_pace` | leading | `static.budget_headroom` < linear pace − | 0.10 / 0.15 / 0.20 | 3600 closed | — | 1/1 (hourly) | 21600 | info | 10, `horizon_s=86400` |
| L6 `runway_short` | leading | `days_to_credential_expiry` or `days_to_model_deprecation` < | 14 / 7 / 3 days | daily | — | 1/1 | 86400 | info | 5, `horizon_s=86400` |
| L7 `continuity_unverified` | leading | drill overdue vs `drill_schedule` or readiness score < threshold | t1 > 30 d · t2 > 90 d · t3 n/a | daily | — | 1/1 | 86400 | info | 5, `horizon_s=86400` |

The seed is a YAML file hashed into `alert_rule.yaml_sha256`; re-seeding touches only unmodified seed rows. Every number above is a harness knob and a dashboard series (`sibyl_rule_fire_rate{rule_code}`).


---

## 2. Hysteresis, cooldowns, flap suppression, auto-resolve (D33)

The evaluator ticks every 10 s per tenant (DATAMODEL: "ticks every 10 s"), so counts below are in ticks; the seconds in brackets are what the operator reads.

### 2.1 Hysteresis in/out, per tier

DATAMODEL seeds `hysteresis_in=2`, `hysteresis_out=6`, `cooldown_s=600`. I keep the columns and tier the values via `thresholds`:

| Transition | Tier 1 | Tier 2 | Tier 3 | Why |
|---|---|---|---|---|
| band worsens (`in`) — detected | 2 ticks (20 s) | 3 (30 s) | 3 (30 s) | Matches Step 2 MTTD p95 < 90 s with margin; tier 1 fastest |
| band worsens (`in`) — leading | 6 ticks (60 s) on closed buckets | 6 | 12 (120 s) | Leading rules are predictions; one closed minute agreeing is the floor |
| band improves (`out`) | 18 ticks (3 min) | 12 (2 min) | 6 (1 min) | Recovery must be proven longer where failover cost was higher; §6.1 "hysteresis 6-out" stays the tier-3 value |
| `failed_over → failing_back` probe | primary `healthy` for 5 min (API §6.1) | 5 min | 3 min | Then canary 10→100% on green windows |

Counters `consecutive_in/out` are stored in `health_snapshot.factors` (DATAMODEL) so a worker restart resumes mid-hysteresis instead of resetting it. A `late=true` event older than two windows never advances a counter (Step 2 R5 mitigation).

### 2.2 Cooldown and re-fire

- `cooldown_s` default **600** per `dedupe_key` (rule × agent, or rule × provider). During cooldown the rule re-evaluates and updates `last_evaluated_at`, `fired_count`, `evidence`, but does not create a new `alert` row and does not re-open an incident. Tier 1 cooldown 300 s (we would rather see a second row than miss a relapse on a tier-1 agent), tier 3 900 s.
- `escalate_after_fires=3` within `escalate_window_s=3600` → `escalation_level += 1`, severity bumps one step (`info → warning → critical`), and the `what_to_do` template switches to its escalated variant ("third fire in an hour; this is not transient — consider failover/handoff").
- A **routing transition resets nothing**: cooldowns persist across `active → degraded → active` so a bouncing agent cannot generate a row every bounce.

### 2.3 Flap suppression

A flap is the thing the Step 2 provider-outage drill fails on (> 2 transitions in 10 min). Rules:

1. **Flap detector**: ≥ 3 band transitions (any direction) for one agent within 10 min, or ≥ 2 routing transitions by `actor_kind ∈ {rule, policy}` within 10 min.
2. **On detection**: the agent is pinned at its *worse* current band (never the better one) for a **flap hold of 15 min** (tier 1: 20 min); rule actors may still move it *down* (to `failed`/`failed_over`) but not *up*; a single `alert` with `rule_code=flapping` (`warning`) carries the transition list as evidence; `recommended_action=watch` unless already `failed_over`.
3. **Failback is the flap-prone edge**, so `failing_back` has its own gate: canary ramps 10 → 25 → 50 → 100% with each step requiring the full `out` hysteresis on the canary slice; one breach reverts to `failed_over` and doubles the probe wait (5 → 10 → 20 min, cap 60) for that incident. Two reverts in one incident → `recommended_action=handoff` and the incident stops attempting automated failback until a human runs `fail_back`.
4. **Provider-level collapse** (`alert_rule.collapses_to_provider`): when ≥ 3 agents (or ≥ 30% of agents on the provider, whichever smaller) on the same provider breach the same detected rule within 2 min, one `provider_incident` is opened, member alerts get `suppressed_by_incident=true`, and failover is **batched** per provider by the worker (ordered tier 1 first, then by priority) rather than 20 independent sagas racing. Resolution of the provider incident needs `out` hysteresis on ≥ 80% of members.

### 2.4 Auto-resolve rules (D33)

An alert closes without a human when the signal that raised it is gone, and that close is legitimate and must not create verdict debt beyond what the SLI counts.

| Condition | Action | `verdict` | `outcome_observed` |
|---|---|---|---|
| Band recovered through `out` hysteresis and **no** routing transition happened while open | `state=resolved`, `resolved_at=now` | `null` (D33) → unverdicted queue | `recovered` |
| Band recovered **after** an automated failover or degrade ran (the alert "did something") | `resolved`; incident stays `done` | `null`; **flagged `verdict_wanted=true`** so the queue sorts it first — these are the labels Phase 2 needs most | `recovered` |
| Agent went to `failed_over`/handoff and the primary never recovered within 2 × RTO | stays open until the incident closes, then auto-`resolved` | `null`, `verdict_wanted=true` | `failed` |
| Provider incident resolved | member alerts auto-resolve | `null`, member of incident; one verdict on the provider incident **propagates** to members (`labeller.kind=worker`, `reason=propagated_from_provider_incident`) | from incident |
| Silenced (`until`) and expired while still breaching | re-opens (`fired_count+1`), no new row | — | — |
| Agent `killed` or `quarantined` by a human | auto-`resolved` | `null`; verdict propagates from the human's `reason` only if they chose one on the kill/quarantine form | `unknown` |

Guard rails on verdict debt: the **unverdicted backlog SLI** = unverdicted resolved alerts older than 7 d ÷ all resolved alerts in 30 d, target **< 20%** per tenant; above that the console's queue becomes a banner, and Phase 2 training (verdicted alerts only, D33) is simply starved, which is the right incentive. Auto-resolve never writes `tp`/`fp`; the only machine-written verdicts are provider-incident propagation and `failover_outcome` labels (worker-written per ai-engineer §7), which are a different `kind` and do not count as alert verdicts.

### 2.5 Worked timeline: tier-1 agent, provider 429 wave

`billing-agent` (tier 1, provider A, chain: alt-model-same-provider → alt-provider B (vaulted) → backup agent → human queue; `preemptive_mode=approval`, `approval_timeout_s=600`, `rto_s=900`, `rpo_s=60`). Ticks every 10 s; times are wall clock.

| t | Signal | Rule / gate | Band · routing | What the operator sees |
|---|---|---|---|---|
| 09:10:00 | `ratelimit_headroom_min` 0.12 (closed minute) | L1 armed, 1/6 | healthy · active | nothing |
| 09:11:00 | headroom 0.09; `inline_fallback_ratio` 0.14 | L1 2/6, L2 2/6 | watch (score 78) after 2 closed minutes of leading pressure | amber card; factors L1, L2 |
| 09:15:00 | headroom 0.045; fallback 0.34; 2 agents on provider A also L1 | L1, L2 at 6/6 → fire; `horizons.15m = "0.60", confidence low → medium` (two families) | watch · active | `warning` alert; prediction badge "provider_outage ~15 m" |
| 09:15:10 | tier 1 + leading-only | D13 → `approval` requested for `alt_provider_failover`; `expires_at` 09:25:10; D22 check: no PII tag → policy `hold` as stored | watch · **awaiting_approval** | approval card; packet pre-assembly starts; RTO clock **not** started (no failure yet) |
| 09:17:30 | `error_rate_429` 0.06 on partial minute (`request_count` 41 ≥ 20) | R1 1/2 | — | — |
| 09:17:40 | `error_rate` 0.07 | R1 2/2 → fire; score 61 → **degraded**; detected `critical`? no: 0.07 < 2 × 0.03 → `warning` | degraded · awaiting_approval (approval still pending; degrade is automatic) | alert row escalates; `degraded_mode=safe_no_tools` applied by gateway; **RTO clock starts 09:17:30** (first breaching `observed_at`) |
| 09:18:00 | 4 agents on provider A breach R1 within 2 min | §2.3 collapse → `provider_incident` opened; member alerts `suppressed_by_incident`; batched failover: t2/t3 members auto; `billing-agent` keeps its pending approval | — | fleet card "provider A: 4 agents, 1 awaiting approval" |
| 09:19:00 | `error_rate` 0.13 | R1 at 2× threshold → `critical`; score 42 → **failed** (very-fast pair holds: 2 m and 15 m windows) | failed · detected-failure path | D13: **alt-model-same-provider is automatic on every tier** → saga: `validate → check_viability` (alt model also 429ing: not viable) → next step alt-provider B: detected failure makes it automatic, the pending leading-only approval is superseded (`approval.cancelled`, reason `superseded_by_detected`) → `write_routing(failed_over)` 09:19:14; propagation ack 09:19:17 |
| 09:19:17 | — | in-flight tasks: 12 continue on B; 3 without a fresh checkpoint (age > 60 s) → `handoff_task` queued, `deadline_at` 09:34:30 | **failed_over** | incident banner; RTO attained **1 m 47 s** of 15 m; RPO breach on 3 tasks shown in red (`checkpoint_age_p95_s` 95 > 60) |
| 09:19:17 | chain has `backup_agent` after B | tier 1 → approval-gated even on detected failure (D13 clarification); **not requested** because B is viable; would only be requested if B fails | — | — |
| 09:41 | operator closes the handed-off tasks; writes `handoff_outcome` | — | — | queue empties |
| 10:05 | provider A `error_rate` 0.01 for 5 min on the canary slice | failback probe passes → `failing_back` 10%; `out` hysteresis 18 ticks per step | failing_back | ramp bar |
| 10:27 | 100% green | → **active**; `failover_outcome` label written by worker (`fallback_succeeded=true, time_to_recover_s=107, failback_verified=true, undone_by_operator=false`) | active | alert auto-resolves, `verdict_wanted=true` (it did something) |
| next business morning | operator gives verdict `tp`, `actual_failure_mode=provider_outage`, `lead_time_s=150` (prediction 09:15:00 vs failure 09:17:30) | label joins `FeatureSnapshot` at 09:15:00 | — | queue item cleared; precision/recall series update |

What the timeline shows: the predicted path bought 2.5 min of lead time and a pre-assembled packet without taking an automated action on a tier-1 agent; the detected path then acted in under 2 minutes; the 600 s approval timeout never mattered because detection superseded it. Had provider A recovered at 09:17 instead, the approval would have expired to `hold` at 09:25 with zero routing change, the alert would auto-resolve `recovered`, and the operator's `fp`/`tp` verdict would decide whether L1+L2 at `"0.60"` was right to ask.


Harness binding (chair point 4): every value in §2 is a knob in the scenario YAML; the acceptance test for hysteresis is "provider-outage scenario yields exactly one provider incident, ≤ 1 transition per agent, zero flap alerts" and "noisy-neighbour scenario (one agent oscillating ±10 around the band edge) yields ≤ 1 alert row per hour".

---

## 3. False-failover budget

A false failover is a `rule`/`policy` routing transition to `failed_over` (or an approval request for one) where the `failover_outcome` label or the alert verdict says the primary would have been fine: `undone_by_operator=true`, or `alert.verdict=fp`, or the incident closed `recovered` with `time_to_recover_s < hysteresis-out` and no corroborating provider or error signal. It is measured per tier per 30 d, from labels, so it is a lagging SLI with a 7-day settling period.

### 3.1 The budget

| Tier | Acceptable false failovers / agent / 30 d | Fleet ceiling (meridian demo: 3/7/10 agents) | False-approval-request ceiling | Rationale |
|---|---|---|---|---|
| 1 | **0 automated**; ≤ 1 unnecessary *approval request* per agent | 0 auto / ≤ 3 approval requests | ≤ 1 per agent, ≤ 25% of requests fleet-wide | Automated tier-1 failover happens only on detected failure (D13), and detected failure is by definition not false unless the detector is broken. Any automated false failover on tier 1 is an incident with a postmortem. |
| 2 | ≤ 1 | ≤ 4 | n/a (auto) | One wrong shift per agent per month is cheaper than one missed outage; alt-model/alt-provider cost is bounded |
| 3 | ≤ 2 | ≤ 10, and ≤ 10% of all tier-3 incidents | n/a | High volume, low blast radius; precision target 90% |

Precision targets (from the same labels): tier 1 detected ≥ 98%, tier 2 ≥ 92%, tier 3 ≥ 90%; leading-only predictions at the 15 m horizon: tier 2–3 ≥ 75% with recall ≥ 60% before we let `probability_band="0.60"` trigger automation, else the band required rises to `"0.90"`. These are the harness acceptance thresholds I hand qa-expert.

### 3.2 Guard rails

1. **Confidence gates on predicted paths** (ai-engineer's `prediction.confidence`): automation on tiers 2–3 needs `probability_band ≥ "0.60"` **and** `confidence ≥ medium` **and** ≥ 2 `contributing_rules` of different families (e.g. `ratelimit_proximity` + `fallback_pressure`, not two latency rules). `confidence=low` → `degrade` only, never `failed_over`. On tier 1 predicted paths always create an `approval` (D13) and the approval's `evidence` must include the contributing rules and the FeatureSnapshot ref so the approver can judge in < 1 min.
2. **Corroboration for detected `failed` on a single agent**: if no other agent on the same provider/model shows degradation and `provider.status` is green, the very-fast pair must hold for one extra `in` cycle (doubling the hysteresis) before failover; a lone agent failing is more often an agent bug than a provider fault, and a provider failover will not fix an agent bug. Factor `explanation` says so.
3. **Viability before action**: `check_viability` refuses (`409 target_not_viable`) when the fallback step's provider is itself `degraded` or breakered in the last 5 min; the saga then takes the next step or `human_queue`. A failover into a worse provider counts as false.
4. **Approval gating (D13, D21, D22)**: tier-1 backup-agent always approval-gated; D21 30-min hold after `undo` blocks all rule/policy actors; D22 forces `hold` on PII/residency tier-1 agents. The hold is also a budget signal: an `undo` automatically writes `failover_outcome.undone_by_operator=true`, debiting the budget without waiting for a verdict.
5. **Per-agent circuit breaker on automation**: 2 undone or `fp`-verdicted automated transitions on one agent within 7 d → that agent's `preemptive_mode` is forced to `approval` (any tier) until a human clears it (`clear_hold`-like action, audited `config.changed`). The system earns back autonomy; it is not granted by default after a mistake.
6. **Fleet-level breaker**: if a tier's 30 d false-failover count exceeds the ceiling, all *predicted* paths for that tier degrade to `degrade_then_auto` (tier 3) or `approval` (tier 2) tenant-wide, with a console banner naming the rule(s) responsible (grouped by `contributing_rules`). Detected paths are never disabled by the breaker — a true outage must still fail over.
7. **Rule-change gate**: a tenant editing `alert_rule.thresholds` on a tier-1 rule gets a dry-run replay against the last 7 d of `health_snapshot` rows showing how many extra/fewer fires it would have produced, before the change saves (`overridden=true`). The dry run is the harness's replayer pointed at production rows.

### 3.3 Monthly false-failover report

Produced by the worker on the 1st, kept as a `label`-derived view (no new table), shown on the Product-promise dashboard and in the tenant's compliance export:

| Column | Source |
|---|---|
| tier, agent | `agent.tier` |
| automated transitions to `failed_over` / `degraded` | `routing_transition.actor_kind ∈ {rule, policy}` |
| approval requests · approved · denied · expired | `approval.state` |
| undone within 30 min · undone later | `failover_outcome.undone_by_operator`, `routing_transition.inverse_of` |
| verdict `fp` on the raising alert | `alert.verdict` |
| false-failover count, budget, remaining | §3.1 |
| precision / recall at 15 m per `contributing_rules` set | `label.kind=alert_verdict` and `provider_incident` labels joined on `FeatureSnapshot.as_of` |
| breaker state (per agent, per tier) | §3.2 items 5–6 |

The report is also the harness's regression baseline: a rule or weight change may not ship if the replay of last month's snapshots through the new parameters moves any tier's false-failover count above its ceiling.


---

## 4. RTO/RPO verification

### 4.1 Definitions the system can measure

- **RTO (per incident)**: `first_fired_at` of the triggering alert (or `health_snapshot.evaluated_at` of the first `failed`-band tick, whichever earlier) → the agent is serving on a viable route **or** every in-flight task has a `handoff_task` row in `queued`. This is Step 2's "Completion" SLI made per-agent and tier-bounded. Contributions: detection (MTTD) + saga (`pending → done`) + propagation (`snapshot_version` ack) + for handoff, time to `queued`.
- **RTO (handoff tail)**: `handoff_task.deadline_at = created + rto_s`; a task `expired` before `claimed` counts against the RTO SLI (DATAMODEL). Under D18 a tier-1 15-min RTO outside business hours cannot be met by a human; so the plan's `degraded_mode` must be `safe_no_tools` or `queue_only` and that *is* the restored state. The RTO SLI therefore ends at `queued` + degraded route, not at human claim; **time-to-claim** is a separate business-hours SLI.
- **RPO**: `checkpoint_age_p95_s` at the moment of transition (feature already exists) and, for the packet, `fidelity` ≥ `checkpoint`. RPO breach = any task whose last checkpoint is older than `rpo_s` when the handoff is cut.

**Discrepancy to settle**: D23 says tier RTO defaults are **15 min / 1 h / 4 h** (900 / 3600 / 14400 s). DATAMODEL `continuity_plan` says defaults by tier are **300/60, 900/300, 3600/900** (`rto_s/rpo_s`). D23 is the founder decision; the DATAMODEL defaults must become `rto_s = 900 / 3600 / 14400`, and I propose `rpo_s = 60 / 300 / 900` (unchanged intent: tier 1 checkpoints every minute). Flagged to the chair (Q2) and for database-architect's Step 7 amendment list.

### 4.2 SLO on RTO/RPO attainment

| Tier | RTO default (D23) | Attainment SLO (30 d, 24×7, automated path) | Time-to-claim (business hours) | RPO default | RPO attainment |
|---|---|---|---|---|---|
| 1 | 15 min | ≥ 99% of incidents restored within RTO; **100%** within 2 × RTO or it is a Sev1 for Sibyl | p90 < 30 min | 60 s | ≥ 99% |
| 2 | 1 h | ≥ 97% | p90 < 2 h | 300 s | ≥ 97% |
| 3 | 4 h | ≥ 95% | p90 < next business day | 900 s | ≥ 95% |

The internal budget is in the detection and saga components: with MTTD p95 < 90 s, saga p95 < 30 s, propagation p95 < 5 s, Sibyl spends ≈ 2 min of a 15 min tier-1 RTO; the rest is the fallback provider's own warm-up and the approval timeout (600 s default). Note the arithmetic: **tier-1 approval timeout (600 s) + detection + saga ≈ 12.5 min of a 15 min RTO**. A tier-1 predicted failover that waits the full timeout and then `hold`s has spent 83% of RTO on waiting. That is acceptable only because the predicted path starts *before* failure; on a detected failure the alt-provider path is automatic and never waits. I recommend the console warns when `approval_timeout_s > 0.5 × rto_s`.

### 4.3 How the system proves it: continuity drills

Drills are Step 2's game days pointed at a single agent's continuity plan, run by the worker, scored into a `drill_result` document (no new entity; a `failover(kind=drill)` saga plus a label `kind=failover_outcome` with `labeller.kind=worker`, `reason=drill`). `continuity_plan.drill_schedule / last_drill_at / next_drill_at` already exist.

| Drill | What the worker does | Pass | Default cadence by tier |
|---|---|---|---|
| **Shadow RTO** (no traffic impact) | Runs `validate → check_viability` against the plan's chain, resolves credentials (vaulted fallback, D11), issues a 1-call probe to each fallback step with a canary prompt, measures propagation of a *no-op* snapshot bump | every step viable; probe p95 < 2 × primary baseline; propagation < 5 s | t1 daily · t2 weekly · t3 monthly |
| **Live canary failover** (demo and tenant opt-in) | Executes the saga with `canary_pct=10` for 5 min, then fails back; in-flight synthetic tasks produce packets | restored within RTO; ≥ 90% synthetic tasks completed; packet `fidelity ≥ checkpoint`; zero flap | t1 monthly (announced, business hours) · t2 quarterly · t3 opt-in |
| **Handoff drill** | Cuts a packet from the latest checkpoint for one synthetic task into the queue, with `deadline_at` per plan, assigned to the on-call user | packet assembled < 30 s; claimed < time-to-claim SLO; `handoff_outcome.packet_useful=true` | t1 monthly · t2 quarterly |
| **Restore + replay** (Sibyl-side) | Step 2 weekly restore test extended: replays the last 24 h of `health_snapshot` through the current rules and diffs transitions | zero divergence from recorded transitions (rules are deterministic on snapshots) | weekly, platform |

Outputs feed the Phase 2 **failover-readiness score** (Step 2 §6): plan present and approved, drilled within 30 d, last shadow RTO within target, RPO measured within target, precision on this agent's alerts ≥ tier target. A tier-1 agent whose readiness score is below threshold shows `recommended_action=watch` with a factor `rule=continuity_unverified` (`kind=leading`, `horizon_s=86400`) — unverified continuity is a leading indicator of a long outage, and this is how it enters the health score honestly rather than as a hidden flag.

### 4.4 Drill scorecard shape

Written as the `value` of the `failover_outcome` label (`labeller.kind=worker`, `reason="drill:<name>"`) so it needs no new entity and is retained with labels:

```json
{
  "fallback_succeeded": true,
  "time_to_recover_s": 71,
  "failback_verified": true,
  "undone_by_operator": false,
  "drill": {
    "name": "shadow_rto",
    "rto_s": 900, "rpo_s": 60,
    "detect_s": 0, "saga_s": 12, "propagation_s": 3, "handoff_queue_s": 0,
    "steps": [
      {"step_id": "…", "kind": "alt_model", "viable": true, "probe_p95_ms": 820},
      {"step_id": "…", "kind": "alt_provider", "viable": true, "probe_p95_ms": 1340, "credential": "vaulted_ok"},
      {"step_id": "…", "kind": "backup_agent", "viable": true, "approval_required": true},
      {"step_id": "…", "kind": "human_queue", "on_call_resolved": true}
    ],
    "checkpoint_age_p95_s": 48,
    "rpo_met": true, "rto_met": true,
    "readiness_score": 0.92
  }
}
```

A drill that cannot run (no approved chain, plan missing, D11 credential unresolvable) writes `fallback_succeeded=false` with `drill.blocked_reason`, which is what `continuity_unverified` (L7) reads.


Evidence for the compliance persona (D8): `GET /agents/{id}/routing/transitions` already expands drills (they are transitions with `trigger=system`), and the audit log carries `failover.completed` with `kind=drill`. Nothing new to export.

---

## 5. Observability of the rules/ML layer itself, and Sibyl's own SLOs

The scoring worker is now in the response path of a customer's RTO, so it gets its own SLIs on the Pipeline and Product-promise dashboards (Step 2 §2). Metric names are `sibyl_*`; `agent_id` is never a label; `tenant_id` is a label while tenants ≤ 100; `tier` and `rule_code` are labels.

### 5.1 SLIs for the scoring layer

| SLI | Metric | Phase 1 SLO (business-hours window, D18) | Why it matters |
|---|---|---|---|
| **Tick cadence** | `sibyl_health_tick_duration_seconds{tenant}` histogram; `sibyl_health_tick_skipped_total` | p95 < 2 s per tenant tick; 0 skipped ticks per hour for tenants ≤ 200 agents | 10 s tick with a 2 s evaluation leaves headroom; a skipped tick stretches every hysteresis window silently |
| **Scoring staleness** | `sibyl_health_snapshot_age_seconds{tenant,tier}` = now − newest `evaluated_at` per agent, exported as max per tier | 99.9% of agent-minutes with age < 60 s (Step 2 "freshness" kept); tier 1 max < 30 s | Stale scores mean stale routing decisions; the gateway's snapshot age already has a 5 min page — this is its upstream |
| **Worker lag** | `sibyl_rules_cursor_lag_seconds` (Postgres cursor vs newest committed event `received_at`); `sibyl_rules_stream_lag_events` | p95 < 15 s; p99 < 60 s | Lag eats MTTD directly. Alert (ticket, business hours) at slow burn; a stuck cursor > 5 min is one of the three permitted cause-based pages from Step 2, reclassified: it replaces nothing, it is the fourth and I ask the chair to allow it (Q4) |
| **Detection latency** | `sibyl_detection_latency_seconds{tier,kind}` = `observed_at` of first breaching event → `health_snapshot` band change | p95 < 90 s, p99 < 120 s (Step 2 promise) | The product's number |
| **Aggregate freshness** | `sibyl_metrics_1m_close_delay_seconds` = bucket close → materialised | p95 < 20 s | Leading rules read closed buckets only; a late close delays every leading rule by a full minute |
| **Late/dropped evidence** | `sibyl_events_late_total{tenant}`, `sibyl_rules_events_ignored_total{reason}` | late share < 1% outside replay | Late events must be stored but never advance hysteresis; a rising late share means SDK buffers are backed up and predictions run on partial data |
| **Observation coverage** | `sibyl_health_low_coverage_agents{tenant,tier}` (coverage < 0.8) | 0 tier-1 agents below 0.8 for > 10 min outside onboarding | A tier-1 agent we cannot see is a tier-1 agent we cannot protect; shows in `provisional` and as a factor |
| **Rule-set drift** (Phase 1 "drift" = behaviour, not model) | per rule: `sibyl_rule_fire_rate{rule_code,tier}` vs its 14 d median; `sibyl_rule_precision{rule_code}` from verdicts (7 d settled) | fire rate within 3× of median; precision ≥ tier target | A rule that suddenly fires 5× more across tenants is either a provider incident or a bug in a seed update; the weekly alert-quality review reads this |
| **Feature drift** (Phase 2 inputs) | `sibyl_feature_psi{feature,tier}` population stability index of each `features/v1` key vs the 30 d reference | PSI < 0.2 on the ten weighted features | Watches the baseline the composite relies on; when PSI > 0.25 the `*_vs_baseline` factors are shown `confidence=low` |
| **Prediction calibration** | `sibyl_prediction_band_outcomes_total{band,horizon,tier,outcome}` — count of predictions per band vs realised failures (from `provider_incident` and `failed` labels) | realised rate within the band's nominal ± 0.15 at 15 m | This is how `rules/v1` earns the right to trigger automation on `"0.60"`; also the acceptance gate for any `model/*` source |
| **Verdict debt** | `sibyl_alerts_unverdicted_ratio{tenant}` (§2.4) | < 20% | Labels are the Phase 2 fuel |
| **Saga health** | `sibyl_failover_saga_duration_seconds{kind,tier}`; `sibyl_failover_stuck_total` (non-terminal > 5 min) | p95 < 30 s; 0 stuck unalerted | Step 2 "Stuck" SLI, now per tier |

### 5.2 Sibyl's own SLOs in Phase 1 (consolidated with Step 2)

| Component | SLO | Window | Alert path |
|---|---|---|---|
| Gateway added latency / availability / fail-open correctness | unchanged from Step 2 (p95 < 15 ms; 99.9% one container; 100% conformance) | 30 d, 24×7 (data plane never sleeps) | Grafana → inbox; fail-open miss is Sev1 next business morning with the drill scorecard attached |
| Rule engine detection + freshness | p95 < 90 s; 99.9% agent-minutes < 60 s | 30 d, **business hours** | multi-window burn (§1.4 pairs) → inbox |
| Failover propagation / completion / stuck | < 5 s p95; ≥ 95% terminal in 60 s; 0 stuck | 30 d, 24×7 measured, business-hours responded | inbox; stuck > 5 min also opens a `handoff_task` for the operator (Sibyl dogfoods its own queue for its own incidents) |
| Scoring staleness / cursor lag | §5.1 | 30 d, business hours | inbox; cursor stuck > 5 min = cause-based page (Q4) |
| Console/API | 99.5%; p75 load < 2 s | 30 d, business hours | ticket |
| Backups | RPO 1 min (WAL archive); weekly restore test passes | — | restore-test age > 8 d is a ticket; WAL archive failing is a page (Step 2) |

Business-hours windows mean the SLO clock stops 18:00–09:00 IST and weekends for *response*; the SLI is still measured 24×7 and shown on `/status.json` as "measured 24×7, responded business hours" so the number is honest.

### 5.3 Self-observability rules carried forward

Self-telemetry never on the hot path; Sibyl does not dogfood its own ingest for its own metrics; `agent_id` is never a label; the four golden dashboards stay four — the SLIs above are rows on **Pipeline** (lag, freshness, tick) and **Product promise** (detection, calibration, precision, verdict debt, RTO attainment per tier). Alert rules in `ops/prometheus/rules/rules-engine.yml` follow the Step 2 no-noise rule: on an SLI, runbook linked, actionable within the hour, fired-and-acted in 90 days or deleted.

```yaml
# ops/prometheus/rules/rules-engine.yml (excerpt)
- alert: SibylRulesCursorStuck
  expr: max(sibyl_rules_cursor_lag_seconds) > 300
  for: 2m
  labels: {severity: page, runbook: rules-engine-stalled}
  annotations: {summary: "Rule engine cursor {{ $value }}s behind; MTTD and every hysteresis window are stretched"}
- alert: SibylTier1HealthStale
  expr: max by (tenant) (sibyl_health_snapshot_age_seconds{tier="1"}) > 60
  for: 5m
  labels: {severity: warning, runbook: rules-engine-stalled}
- alert: SibylDetectionLatencyFastBurn
  expr: |
    (1 - sum(rate(sibyl_detection_latency_seconds_bucket{le="90"}[5m])) / sum(rate(sibyl_detection_latency_seconds_count[5m]))) > 14.4 * 0.05
    and
    (1 - sum(rate(sibyl_detection_latency_seconds_bucket{le="90"}[1h])) / sum(rate(sibyl_detection_latency_seconds_count[1h]))) > 14.4 * 0.05
  for: 2m
  labels: {severity: warning, runbook: detection-latency-regression}
```

### 5.4 Weekly alert-quality review (the human loop, business hours)

Thirty minutes, one operator, one checklist, every Monday. It is the only recurring toil in this design and the harness exists to keep it at thirty minutes.

1. **Verdict debt**: clear the `verdict_wanted` queue first (alerts that caused an action), then the rest; target debt < 20%.
2. **Rule fire-rate drift**: any `rule_code` outside 3× its 14 d median → was there a provider incident? If not, open a bug against the seed version.
3. **Precision per rule and tier** against §3.1 targets; a rule below target for two consecutive weeks is demoted (`severity` down one step, or `enabled=false` with a note) and the demotion is itself audited (`config.changed`).
4. **False-failover budget**: read the monthly report-to-date; if any tier is on pace to exceed its ceiling, review the breaker state and the contributing rules.
5. **Calibration**: the `"0.60"` band's realised failure rate at 15 m; if outside ± 0.15 for 2 weeks, the automation gate (§3.1) moves to `"0.90"` until it recovers.
6. **Drill coverage**: tier-1 agents with `next_drill_at` in the past; tier-1 agents with readiness < threshold.
7. **Sibyl's own SLOs**: detection latency, cursor lag, stale-score minutes, stuck sagas; anything that fired twice without action gets deleted or demoted (Step 2 no-noise rule).
8. **Toil log**: count operator actions that were pure repetition (same `undo` on the same agent, same `silence`); three repeats → automation or rule change ticket.

Output is a short note in `docs/ops/alert-quality/<week>.md` plus the audited config changes. No slide, no meeting.


---

## 6. Runbook hooks: what the operator sees per transition

Every health or prediction transition produces a console event (SSE `GET /events/stream`, API §7), an `alert.what_to_do` from the rule's template, and, where a routing change happened, an `Incident` with `available_actions[]`. The table is the contract for ux: one line of *what*, one of *why* (top factor), one of *what Sibyl did*, one of *what you can do*. Runbooks are `docs/runbooks/agent-*.md`, linked by `rule_code`.

| Transition | Operator sees (console + SSE) | Automated action already taken | Human actions offered (`available_actions`) | Runbook |
|---|---|---|---|---|
| `healthy → watch` | Agent card turns amber; sidebar badge `info`; factor list with top 3 contributions; "leading rules armed" | none; packet pre-assembly starts for tier 1 if `inline_fallback=false` | `ack`, `silence (until)`, open metrics at the factor's `evidence` link | `agent-watch` |
| `watch → degraded` (detected) | `warning` alert row; agent routing shows `degraded` + `degraded_mode` (e.g. `safe_no_tools`); countdown "fails over automatically if band reaches failed"; RTO clock starts | `routing_apply(to='degraded')`; gateway applies degraded mode | `recover` (override), `failover` now (override), `handoff`, `ack` | `agent-degraded` |
| leading prediction ≥ "0.60" @15 m, tier 2–3 | Alert `warning`, badge "predicted: provider_outage in ~15 m (rules/v1, confidence medium)"; contributing rules listed | tier 3 `degrade_then_auto`: degraded now, failover on next confirming window; tier 2 `auto`: saga opens | `undo` (if moved), `cancel` saga before `write_routing`, `silence` | `agent-predicted-failover` |
| leading prediction ≥ "0.60" @15 m, tier 1 | **Approval card** at top of queue: action, target step, evidence (factors, FeatureSnapshot link, provider status), timeout countdown (600 s), timeout policy (`hold` / `fail_safe` / `hold (forced, D22)`) | saga `waiting_approval`; routing `awaiting_approval`; packet pre-assembled | `approve` / `deny` (decider ≠ requester), `cancel` | `agent-approval` |
| approval timeout | Card closes with "timed out → hold" or "→ fail-safe executed"; audit `approval.expired` shown inline | per policy (§6.5); D22 forces `hold` | `failover` manually; `recover` | `agent-approval` |
| `degraded → failed_over` (detected, auto) | `critical` alert; incident banner: "Rerouted to <provider/model> at hh:mm; 12 tasks continued, 3 handed off"; RTO attainment shown live (elapsed / RTO) | saga `done`; `handoff_task`s queued with `deadline_at`; `alert.failover_id` set | `undo` (30-min hold follows, D21), `fail_back`, `handoff`, `quarantine`, `kill` | `agent-failed-over` |
| tier-1 `failed` band + backup-agent step | As above **plus** approval card for the backup-agent hop; alt-provider hop (if in chain) already executed | alt-model/alt-provider automatic; backup-agent waits | `approve` / `deny` | `agent-approval` |
| `failed_over → failing_back` (probe passed) | "Primary healthy 5 min; canary 10% → …" ramp bar; canary metrics beside primary | canary saga | `cancel` (stay failed over), `fail_back` force 100% (override) | `agent-failback` |
| canary breach → `failed_over` | "Failback reverted at 25% (error_rate 9% vs 2%); next probe in 10 min"; after second revert: "automated failback suspended; run fail_back manually" | revert; probe backoff | `fail_back`, `handoff` | `agent-failback` |
| flap detected | `warning` `flapping` alert with the transition list; banner "pinned at degraded for 15 min" | flap hold | `recover` (bypasses hold, human), `clear_hold`-style release of the flap pin | `agent-flapping` |
| provider incident opened | Fleet view groups N agents under one provider card; member alerts collapsed; "failover batched: 3 tier-1 pending approval, 7 tier-2 done, 10 tier-3 done" | batched sagas | per-agent actions unchanged; `provider-incidents/{id}` single verdict later | `provider-incident` |
| `undo` by operator | Incident shows "undone by <user>: <reason>; automation paused until hh:mm" (D21); the alert row shows `hold_suppressed_count` climbing if the rule keeps firing | `failover(kind=undo)`; hold set; packets `returned` | `clear_hold` (owner/security_admin) | `agent-undo` |
| auto-resolve (hysteresis out) | Alert moves to "resolved — verdict needed" queue (sorted `verdict_wanted` first); agent card back to green; `outcome_observed` shown | resolve | one-time `close` with `tp/fp/unsure` + note | `alert-verdict` |
| `provisional` / low coverage on tier 1 | Grey card "not enough signal (34/50 calls, coverage 0.6)"; factor `continuity_unverified` if drill overdue | none (automation disabled while provisional) | open onboarding checklist; run shadow drill | `agent-onboarding` |
| Sibyl-side: cursor lag / stale scores | Header strip "detection delayed ~N s; failover automation still active on last known state"; `/status` component `rules-engine: degraded` | none on agents; gateway continues on snapshot | operator runbook | `rules-engine-stalled` |

Two cross-cutting hooks:
- **Every incident view shows the RTO clock** (`elapsed / rto_s`, red past 100%) and the **RPO at cut** (`checkpoint_age_p95_s` vs `rpo_s`). These two numbers are what the compliance persona exports.
- **Every factor has `evidence`** (deep link to `/traces?agent=&error=true` or a metrics query). No factor without a link ships; the harness fails a rule whose `explanation` is empty or whose `evidence` 404s.

---

## 7. Open questions for the chair (max 6)

1. **Per-agent SLO target field.** Should `continuity_plan` gain `slo_target numeric(5,3)` (default by tier: 0.995 / 0.99 / 0.98) so tenants can tighten per agent, with loosening below the tier default four-eyes-gated? Or do tier defaults suffice for Phase 1?
2. **D23 vs DATAMODEL defaults.** `continuity_plan.rto_s/rpo_s` defaults (300/60, 900/300, 3600/900) contradict D23 (900 / 3600 / 14400 s). I propose `rto_s = 900/3600/14400`, `rpo_s = 60/300/900`. Confirm so database-architect amends at Step 7.
3. **Approval timeout vs RTO.** Default `approval_timeout_s=600` consumes ~83% of a tier-1 15-min RTO on the predicted path. Keep 600 and warn in the console when `approval_timeout_s > 0.5 × rto_s`, or lower the tier-1 default to 300 s?
4. **Fourth cause-based page.** Step 2 permitted exactly three (snapshot stale, WAL archiving failing, disk > 85%). I want `SibylRulesCursorStuck` (> 5 min) as a fourth, since a stalled evaluator stretches every hysteresis and RTO silently. Allow, or fold into the snapshot-stale page?
5. **Flap hold semantics.** The 15-min flap pin lets rule actors move an agent *down* but not *up*. Is that acceptable for tier 3 where the cost of staying degraded (no tools) may exceed the cost of one more bounce — or should tier 3 flap handling be "pin at better band, alert only"?
6. **Automation precision gate for `"0.60"`.** I propose the predicted path on tiers 2–3 may only fire on `probability_band ≥ "0.60"` once the harness shows ≥ 75% precision / ≥ 60% recall at 15 m for `rules/v1`; until then `"0.90"` only. Does qa-expert's harness ship with that gate as a release criterion, or is it a tunable the tenant sets?
