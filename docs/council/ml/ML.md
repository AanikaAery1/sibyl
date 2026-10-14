# Sibyl — Step 5: ML approach (consolidated, 2026-10-10)

Chair's consolidated contract for health scoring, prediction, the Phase 2 learned layer, storage, evaluation and observability. Merges `ai-engineer.md` (lead), `database-architect.md`, `sre-engineer.md`, `qa-expert.md` under the rulings in `SYNTHESIS.md` (R37–R50). Where members differed, the ruling wins and is tagged inline `(R4x)`. Where this document reconciles a difference the synthesis did not name, it says `(editor)` and lists it in §10.4 for the chair.

Inputs: `docs/BRIEF.md`; `DECISIONS.md` D1–D35; `datamodel/ai-engineer.md` §6 (frozen `sibyl-health/1`, `sibyl-feature-snapshot/1`, `HealthPredictor`, `sibyl-label/1`); `DATAMODEL.md`; `api/API.md` §4–§6; `api/SYNTHESIS.md` R21–R36.

---

## 1. Overview and principles

1. **Phase 1 is rules plus statistics, not learned models.** The health score is an explainable composite of windowed SLIs; prediction is leading-indicator rules (EWMA, CUSUM, proximity, provider status). Nothing in Phase 1 is trained.
2. **Phase 2 adds a learned layer behind the same contract.** A calibrated model replaces one thing per horizon, the `probability_band` (and adds the numeric `probability`), with `source='model/sibyl-gbt:<ver>'`. Score, factors, hysteresis, floors and the API shape do not change.
3. **Explainable always.** `score = 100 − Σ factor.penalty` (plus a recorded clamp), every factor carries `value`, `threshold`, `explanation`, `evidence`; every decision is re-executable offline from its frozen `FeatureSnapshot`. The evaluation harness fails any snapshot where this does not hold (qa §3.2, 100 % gate).
4. **Everything is replayable.** Predictors are pure functions of the snapshot; EWMA/CUSUM state lives inside the snapshot; replay equals production byte for byte.
5. **The health score is an SLI, not a verdict** (sre). Bands are SLO buckets per tier; burn rates drive severity and the detected-failure trigger; false failovers have a budget.
6. **Verdicts are the labelling mechanism** (D24, D33). Human `tp/fp/unsure` on alert close is what makes Phase 2 training honest; `unsure` and null verdicts are excluded from training and counted as an SLI (R42).
7. **Postgres only; CPU only; permissive licences only** (D10, D15, R44). No feature store, no scheduler product, no GPU, no LGPL in the bundle.
8. **Tier gating is unchanged by learning** (D13, R40, R41). Rules and models emit the same `confidence` and band; routing code reads those, never the source.
9. **The harness is the only place anything is tuned** (qa). Hysteresis, cooldowns, weights, thresholds and Phase 2 promotion are decided against `sibyl-sim` scenarios with ground truth, never in production.
10. **No cross-tenant signal, Phase 1–2** (R43). Peer groups, baselines and models are per tenant; a synthetic-trained model is the day-one shadow, never promoted without the tenant's own verdicts.

### 1.1 What this step adds (all additive to frozen contracts)

- `features/v1` keys (§2.6), `ewma_*`, `cusum_*`, `*_fleet`, `anomaly_score`, `model_feature:<key>` factor rule ids.
- Rule ids: `quality_proxy`, `tool_loop`, `drift_cusum`, `anomaly_score`, `heartbeat_missing`, `continuity_unverified`; seed rows for `context_saturation`, `credential_expiry`, `model_deprecation`; alert rules R6–R8 / L6 (R37).
- Tables (§7): `agent_metrics_5m`, `provider_metrics_5m`, `agent_trend_state`, `agent_baseline`, `scoring_config`, `prediction`, `health_1h`, `agent_risk`, `rollup_job`, `ml_model`, `ml_prediction_shadow`, `risk_assessment`; plus Step 4's `idempotency_record`, `ingest_batch_seen`.
- Routes: `GET /agents/{id}/health?verbose=1`; `GET /agents/{id}/risk-assessment`; `GET /audit/export?include=health_decisions`.
- Nothing removed or renamed. `sibyl-health/1`, `sibyl-feature-snapshot/1`, `sibyl-label/1`, `HealthPredictor` unchanged.

---

## 2. Feature catalogue

Features are computed by the worker from Postgres aggregates only: `agent_metrics_1m` for 1m/5m/15m windows, `agent_metrics_5m` (materialised, R49) for leading-rule inputs and 90-day recompute, `agent_metrics_1h` for baselines, narrow bounded reads of `events` for non-counter event types, registry tables for statics. **No feature reads payload content** (R19); output-quality proxies are metadata-only by construction.

Notation: `W ∈ {1m, 5m, 15m, 1h}`; `Σ_W` sums 1m rows in the window ending at the last closed minute (leading rules) or including the open minute (detected rules). `baseline(k)` per §2.5. `_vs_baseline` = value / baseline, `null` when no baseline. Every feature is `number | null`; `null` means not computable, never zero.

### 2.1 The six SLI families (sre) and the rules that feed them

Each rule in §3 belongs to exactly one family; the family view is what the console groups by and what the SLO buckets (§3.3) are stated on. `(editor: sre's six-SLI framing and ai-engineer's rule-penalty arithmetic are the same composite viewed two ways; family weight per tier = Σ caps of its rules / Σ all caps.)`

| SLI family | Good when | Feature keys | Rules | Kind |
|---|---|---|---|---|
| Availability | calls succeed, excluding `killed`/`quarantined` 403s | `error_rate`, `error_rate_5xx`, `error_rate_timeout`, `error_rate_429`, `error_rate_blocked`, `consecutive_errors` | R1, R3, R4 (provider), L1 | detected (+ L1 leading) |
| Latency | p95 ≤ max(baseline × 1.5, model-class floor) | `latency_p50/p95/p99_ms`, `ttfb_p95_ms`, `latency_p95_vs_baseline` | R2, L2 | detected + leading |
| Task completion | tasks close `success`/`partial` | `task_success_rate`, `task_failure_rate`, `task_steps_p95`, `handoff_rate` | `tool_loop`, task-failure facet of `quality_proxy` | detected (lagging) |
| Output-quality proxy | not refused, not truncated, tool args schema-valid, feedback ≥ 0 | `finish_length_ratio`, `finish_content_filter_ratio`, `empty_output_ratio`, `schema_validation_fail_ratio`, `tool_error_rate`, `tool_seq_repeat_ratio`, `tool_seq_entropy`, `feedback_mean`, `output_chars_vs_baseline`, `tokens_out_vs_baseline` | R6, R7, R8, `quality_proxy`, L6, `context_saturation`, `drift_cusum` | detected + leading |
| Rate-limit headroom | far from 429 | `ratelimit_headroom_min`, `ratio_429`, `inline_fallback_ratio`, `breaker_open_ratio` | L3, L5 | leading |
| Budget / dependency headroom | spend on pace; provider green; credentials and models have runway | `budget_headroom`, `budget_burn_1h`, `cost_slope`, `provider_status_code`, `days_to_credential_expiry`, `days_to_model_deprecation`, `continuity_unverified` | R5, L4, `credential_expiry`, `model_deprecation`, `continuity_unverified`, provider-status leading facet | detected + leading |

### 2.2 Per agent, per window

| Feature key (`grains.W.*`) | Formula | Source columns | Consumers |
|---|---|---|---|
| `request_count` | `Σ request_count` | `agent_metrics_1m.request_count` | min_samples gate, provisional |
| `error_rate` | `Σ error_count / Σ request_count` | `error_count` | R1, L1, score |
| `error_rate_429` / `ratio_429` | `Σ rate_limit_count / Σ request_count` | `rate_limit_count` | L3 |
| `error_rate_5xx` | `Σ server_error_count / Σ request_count` | `server_error_count` | provider_outage attribution |
| `error_rate_timeout` | `Σ timeout_count / Σ request_count` | `timeout_count` | latency_degradation attribution |
| `error_rate_blocked` | `Σ blocked_count / Σ request_count` | `blocked_count` | policy_violation / permission_error attribution |
| `consecutive_errors` | trailing run of `status='error'` | `events` last 10 rows, indexed, only when `error_rate(1m) > 0` | R3 |
| `latency_p50/p95/p99_ms` | `hist_quantile(hist_sum(latency_hist), q)` | `latency_hist` | R2, L2, score |
| `ttfb_p95_ms` | same over `ttfb_hist` | `ttfb_hist` | streaming stall |
| `latency_p95_vs_baseline` | `latency_p95_ms / baseline` | + `agent_baseline` | L2 relative, Phase 2 |
| `tokens_in_mean` / `tokens_out_mean` | `Σ tokens / Σ request_count` | `tokens_in`, `tokens_out` | proxies, cost |
| `tokens_out_cv` | CV of per-minute `tokens_out` means | `tokens_out`, `tokens_out_sumsq` | quality_collapse proxy |
| `cost_usd` | `Σ cost_usd` | `cost_usd` | R5, L4 |
| `cost_slope` | EWMA slope of per-minute `cost_usd` (§4.1) | `cost_usd` | cost_runaway |
| `retry_mean` | `Σ retry_count / Σ request_count` | `retry_count` (new) | retry-storm signal |
| `inline_fallback_ratio` | `Σ inline_fallback_count / Σ request_count` | `inline_fallback_count` | L5 |
| `breaker_open_ratio` | `Σ breaker_open_count / Σ request_count` | `breaker_open_count` | L5 |
| `ratelimit_headroom_min` | `min(ratelimit_remaining_min) / limit` | `ratelimit_remaining_min`; limit from last event attrs | L3 |
| `policy_stale_ratio` | `Σ policy_stale_count / Σ request_count` | `policy_stale_count` | observation quality |
| `late_ratio` | `Σ late_count / Σ request_count` | `late_count` | observation coverage |
| `route_changes` | `routing_transition` rows in W | `routing_transition` | flap detection |

### 2.3 Per model and per provider (fleet context, per tenant)

Same SLIs grouped by `(provider, model)` and by `provider` across the tenant's agents, joined into the agent snapshot as `_fleet` keys so a single-agent blip is distinguishable from a provider-wide incident. Read from `provider_metrics_5m` (R49, db §1).

| Feature key | Formula | Consumer |
|---|---|---|
| `provider_error_rate_fleet` | tenant-wide `error_rate(5m)` on the agent's primary provider | R4 corroboration, collapse |
| `provider_latency_p95_fleet_ms` | tenant-wide p95(5m) on the provider | attribution |
| `provider_429_fleet` | tenant-wide 429 share | shared pool detection |
| `model_error_rate_fleet` | by `(provider, model)` | model-specific degradation |
| `provider_agents_degraded_fleet` | agents on the provider in `degraded`/`failed` this tick | collapse threshold |
| `provider_status_code` | ordinal of `provider_status.status`: operational 0, maintenance 1, degraded_performance 2, partial_outage 3, major_outage 4, unknown null | R4, leading facet |
| `provider_status_age_s` | `now − observed_at` | confidence |
| `provider_probe_latency_ms` | last probe latency | R4 corroboration |

No cross-tenant provider aggregate exists (R43).

### 2.4 Per tenant, output-quality proxies, feedback and outcomes

**Tenant context**: `budget_headroom` (`1 − MTD cost / continuity_plan.budget_usd_month`), `budget_burn_1h` (projected), `tenant_open_alerts`, `tenant_provider_concentration` (governance finding, not health).

**Output-quality proxies (metadata only)**:

| Feature key | Formula | Source | Failure mode |
|---|---|---|---|
| `finish_length_ratio` | share with finish reason `length`/`max_tokens` | `finish_length_count` (new) | quality_collapse (truncation), context_saturation |
| `finish_content_filter_ratio` | share with `content_filter`/`refusal`/`safety`, or normaliser `attrs.quality.refusal` | `refusal_count` (new) | policy_violation, quality_collapse (R6) |
| `finish_tool_calls_ratio` | share ending in `tool_calls` | `finish_tool_calls_count` (new) | tool-loop corroboration |
| `empty_output_ratio` | `tokens_out = 0` on `status='ok'` | `empty_output_count` (new) | quality_collapse, silent_drift |
| `output_chars_mean` / `_vs_baseline` | mean `attrs.output_chars` | `output_chars_sum` (new) | silent_drift |
| `context_utilisation_p95` | p95 of `tokens_in / model_context_limit` | `context_util_hist` (new) | context_saturation |
| `tool_call_count` | `Σ tool_call_count` | exists | infinite_loop, tool_failure |
| `tool_error_rate` | `tool.call` errors / tool calls | `tool_error_count` (new) | tool_failure, data_source_failure |
| `tool_seq_repeat_ratio` | consecutive identical tool-name pairs within a task (last 50 calls per open task) | `events.attrs.tool_name`; 5m proxy `tool_seq_hash_distinct` | infinite_loop |
| `tool_seq_entropy` | normalised bigram entropy over W | same | infinite_loop (low), silent_drift (shift) |
| `schema_validation_fail_ratio` | tool calls with `error_type ∈ {schema_validation, invalid_arguments, ValidationError}` / tool calls | `tool_schema_invalid_count` (new) | quality_collapse (R8); strongest metadata-only quality signal |
| `task_steps_p95` | p95 `agent.invoke(end).attrs.steps` | `events` | infinite_loop |
| `checkpoint_age_p95_s` | p95 age of last checkpoint over open tasks | `checkpoint` | packet fidelity, RPO |
| `undeclared_tool_ratio` | tool calls not in `agent_identity.allowed_tools` | `policy.decision(tool_blocked)` | permission_error, prompt_injection |
| `undeclared_data_source_ratio` | data sources not declared | same shape | governance, silent_drift |

**Feedback and outcome events** (slow, sparse; baselines and Phase 2 labels): `task_count`, `task_success_rate`, `task_failure_rate`, `cost_per_task_usd`, `feedback_mean`, `feedback_count`, `feedback_negative_ratio`, `handoff_count`, `handoff_rate`, `handoff_returned_ratio`, `alert_fp_rate_30d`, `failover_success_rate_90d`. LLM-as-judge scores are Phase 2, tenant opt-in, arriving as `feedback(rater='judge')` through the same path (§5.9).

### 2.5 Baselines and statics

**Baseline** per `(tenant, agent, feature, hour_of_week)`: median of the same hour-of-week over the trailing 4 weeks from `agent_metrics_1h`, falling back to trailing-7-day median, then peer group, then seed constants. `baseline_ref ∈ {own/how4w, own/7d, peer/<group>, seed/v1}` is recorded in every snapshot. Robust scale `σ̂ = 1.4826 × MAD`, floored at 5 % of the median. Persisted nightly in `agent_baseline` (db §3.1); windows inside an `observation.gap` are excluded.

**Peer group** = `tier:<t>|kind:<agent.kind>|pk:<provider_kind>|mc:<model class>`, per tenant only (R43). Model class: `small` (< 32k ctx or name matches mini|haiku|flash|8b), `reasoning` (o[1-9]|reasoning|thinking|r1), else `large`.

**Statics** (`static.*`): `tier`, `provider`, `model`, `fail_mode`, `routing_state`, `breaker_state`, `provider_status`, `budget_headroom`, `model_context_limit`, `days_to_model_deprecation`, `days_to_credential_expiry`, `hour_of_day_utc`, `day_of_week_utc`, `agent_age_days`, `peer_group`.

### 2.6 Counter additions to `agent_metrics_1m/5m/1h` (database-architect §1.2)

`retry_count`, `finish_length_count`, `finish_tool_calls_count`, `refusal_count`, `empty_output_count`, `tool_error_count`, `tool_schema_invalid_count`, `task_count`, `task_success_count`, `task_failure_count`, `handoff_count`, `feedback_count`, `feedback_sum`, `output_chars_sum`, `tokens_out_sumsq`, `context_util_hist integer[40]`, `tool_seq_hash_distinct`. All plain sums (parent grain = `sum()` of children; histograms `hist_sum()`; `ratelimit_remaining_min` by `least()`), so the 5m and 1h tiers roll up without a second pass. `(editor: database-architect's column names supersede ai-engineer's §1.8 spellings; `tool_schema_invalid_count` = `tool_schema_fail_count`, `retry_count` replaces `retry_attempt_sum`, `context_util_hist` replaces `context_util_max`.)`

New `features/v1` keys registered: `error_rate_blocked`, `breaker_open_ratio`, `late_ratio`, `finish_content_filter_ratio`, `empty_output_ratio`, `output_chars_vs_baseline`, `tokens_out_vs_baseline`, `schema_validation_fail_ratio`, `task_failure_rate`, `feedback_negative_ratio`, `undeclared_tool_ratio`, `undeclared_data_source_ratio`, all `*_fleet`, `ewma_*`, `cusum_*`. `feature_set` stays `features/v1`.

---

## 3. Phase 1 health score

### 3.1 Shape

`score = clamp(100 − Σ_i penalty_i, 0, 100)`, `penalty_i = cap_i(tier) × severity_i`, `severity_i ∈ [0, 1]`. `factor.weight = cap_i / 100`, `factor.penalty = penalty_i`. The clamp is recorded as a bookkeeping factor `{rule:"_clamp", penalty:<excess>}` so `score = 100 − Σ penalty + _clamp.penalty` holds exactly; the harness asserts it on every non-healthy snapshot (qa §3.2, ±1). No multiplicative interactions.

The 10 s tick scores detected rules on the 5m grain (open minute allowed when `request_count ≥ min_samples`) and leading rules on closed minutes only; 1m is used for `consecutive_errors`; 15m and 1h appear in the snapshot for trends and Phase 2 but do not enter the Phase 1 score.

### 3.2 Severity curves

- **above** rules (rates, shares): `severity = clamp((x − t) / (s − t), 0, 1)`, `s = 3t` for rates/shares, `s = 2t` for latency.
- **below** rules (headroom): `severity = clamp((t − x) / t, 0, 1)`.
- **ordinal** (provider status): `maintenance 0.15`, `degraded_performance 0.33`, `partial_outage 0.58`, `major_outage 1.0`, `unknown 0`.
- **count** (consecutive failures): `severity = clamp((n − t + 1) / t, 0, 1)`; R3 at `n ≥ 2t − 1` is full and forces the band floor.
- **boolean**: 0 or 1.
- **Baseline-relative variant** for R2/L2: `severity = max(sev_abs, sev_rel)`, `t_rel = 2.0`, `s_rel = 4.0`, once an `own/*` baseline exists; `factor.explanation` names which dominated.

Thresholds live in `alert_rule.thresholds` by tier (per-tenant copies, R18); weights, band cut-offs, dead-bands, hysteresis and trend parameters live in the versioned `scoring_config` row referenced by every snapshot (db §3.2), so operators tune without a release and every historical score is reproducible.

### 3.3 Caps per tier and the seed rule table

Caps are seed penalties scaled per tier; tier 1 is punished harder for the same evidence because D13 gates its predicted failovers behind approval, so a low tier-1 score mostly costs an approval request. Caps sum far above 100 on purpose: several things wrong reads as `failed`.

| rule_id (Step 3 code) | SLI family | kind | cap t1/t2/t3 | seed threshold t1/t2/t3 | hysteresis in/out (ticks, t1 · t2 · t3) | cooldown_s t1/t2/t3 |
|---|---|---|---|---|---|---|
| `error_rate` (R1) | availability | detected | 50/40/30 | 0.05 / 0.10 / 0.20 | 2/18 · 3/12 · 3/6 | 300/600/900 |
| `p95_latency` (R2) | latency | detected | 30/25/20 | model class: small 5000, large 20000, reasoning 60000 ms; relative 2.0 | as R1 | as R1 |
| `consecutive_failures` (R3) | availability | detected | 60/50/40 | 3 / 3 / 5 | 1/18 · 1/12 · 1/6 | as R1 |
| `provider_status` (R4) | budget/dependency | detected (major) + leading facet | 60/60/60 | ordinal table | 1/6 | 300 |
| `budget_breach` (R5) | budget/dependency | detected | 70/70/70 | spend ratio ≥ 1.0 | 1/1 (hourly) | 21600 |
| `refusal_share` (R6, R37) | output quality | detected | 25/20/15 | `finish_content_filter_ratio` > 0.10 / 0.15 / 0.25 | 6/18 · 6/12 · 6/6 | 600 |
| `truncation_share` (R7, R37) | output quality | detected | 20/15/12 | `finish_length_ratio` > 0.25 and `_vs_baseline` > 2 | as R6 | 600 |
| `schema_fail_share` (R8, R37) | output quality | detected | 25/20/15 | `schema_validation_fail_ratio` > 0.10 / 0.15 / 0.20 | as R6 | 600 |
| `heartbeat_missing` (R9, sre) | availability | detected | 25/20/15 | `request_count = 0` for 2 × declared cadence (plans with cadence only) | 1/3 | 600 |
| `tool_loop` | task completion | detected | 30/25/20 | `tool_seq_repeat_ratio > 0.5 ∧ tool_call_count(5m) > 20`, or `task_steps_p95 > 3 × baseline` | 2/18 · 3/12 · 3/6 | 600 |
| `quality_proxy` | output quality | detected (score factor only) | 25/20/15 | `max(sev R6, R7, R8, empty_output_ratio > 0.05)` | inherits | — |
| `error_trend` (L1) | availability | leading, H 900 | 20/15/10 | §4.3 | 6/18 · 6/12 · 12/6 | 600 |
| `latency_trend` (L2) | latency | leading, H 900 | 15/10/8 | §4.3 | as L1 | 600 |
| `ratelimit_proximity` (L3) | rate-limit headroom | leading, H 900 | 25/20/15 | headroom < 0.15 / 0.10 / 0.10 or 429 share > 0.05 or TTE < 15 min | as L1 | 600 |
| `budget_proximity` (L4) | budget/dependency | leading, H 3600 / 86400 | 15/15/15 | projected ≥ 0.9 within 1 h; month ≥ 1.0 at 24 h | 1/1 (hourly) | 21600 |
| `fallback_pressure` (L5) | rate-limit headroom | leading, H 900 | 30/25/20 | inline + breaker share > 0.10 / 0.20 / 0.25 | as L1 | 600 |
| `refusal_trend` (L6, R37) | output quality | leading, H 900 | 12/10/8 | EWMA slope of `finish_content_filter_ratio` > 0 for 3 windows and level ≥ 0.5 × R6 threshold, or CUSUM alarm | as L1 | 600 |
| `continuity_unverified` (L7, sre) | budget/dependency | leading, H 86400 | 5/5/0 | drill overdue (t1 > 30 d, t2 > 90 d) or readiness < threshold | 1/1 daily | 86400 |
| `context_saturation` | output quality | leading, H 900 | 15/12/10 | `context_utilisation_p95 > 0.85` or `finish_length_ratio > 0.25` | as L1 | 600 |
| `credential_expiry` | budget/dependency | leading, H 86400 | 20/15/10 | `days_to_credential_expiry ≤ 7` (full at ≤ 1) | 1/1 daily | 86400 |
| `model_deprecation` | budget/dependency | leading, H 86400 | 15/10/5 | `days_to_model_deprecation ≤ 30` (full at ≤ 7) | 1/1 daily | 86400 |
| `drift_cusum` | output quality | leading, info-only, H 3600 | 0 (watch) | CUSUM beyond `h` on `tokens_out_mean`, `output_chars_mean`, `tool_seq_entropy` with nothing else firing | 6/18 | 3600 |

`(editor: Step 3 numbering R1–R5/L1–L5 is canonical, as R37 presumes; sre's renumbered table is mapped onto it. ai-engineer's seed thresholds are the starting point; sre's tighter alternatives (R1 0.03/0.05/0.08, timeouts 0.02/0.03/0.05) are the second tuning candidate in the harness. `quality_proxy` is one score penalty taking the max of R6–R8 so quality never double-counts; R6–R8 are the alert rows the harness gates.)` All rule rows ship `enabled=true`, `severity=warning`, `collapses_to_provider=false` except R4; tenants may disable. The seed YAML is hashed into `alert_rule.yaml_sha256`; re-seeding touches unmodified rows only.

### 3.4 Bands, floors, SLO buckets

Band edges are tier-specific on the 5m grain (sre, accepted in SYNTHESIS) with an upward dead-band of +4 (ai-engineer) so a score hovering at an edge does not oscillate:

| Band | Tier 1 enter / leave | Tier 2 | Tier 3 | Routing consequence |
|---|---|---|---|---|
| `healthy` | ≥ 85 / leave below 85 | ≥ 80 | ≥ 75 | `active` |
| `watch` | 70–84 / up at 89 | 65–79 / up at 84 | 55–74 / up at 79 | `active`; `info` alert; leading rules armed |
| `degraded` | 45–69 / up at 74 | 40–64 / up at 69 | 30–54 / up at 59 | `active → degraded` after hysteresis-in; `degraded_mode` applies |
| `failed` | < 45 / up at 49 | < 40 / up at 44 | < 30 / up at 34 | detected-failure path |

Two floors override arithmetic and are recorded as factors (`direction='equals'`):
- any `severity='critical'` detected rule firing after hysteresis ⇒ band ≤ `degraded`;
- R3 at full severity, or R4 `major_outage` corroborated by `provider_error_rate_fleet > t_R1`, or `error_rate(5m) ≥ 0.5` with `request_count ≥ min_samples` ⇒ band = `failed`. This **is** "detected failure" for D13 and the very-fast burn condition (§3.5).

**Agent-minute SLOs** (sre §1.3): good minute = band `healthy`/`watch` and observable; valid minute = not `killed`/`quarantined`/maintenance/provisional, and not silent unless the plan declares cadence. Rolling 30 d, 24×7.

| Tier | SLO | 30 d budget | Promise |
|---|---|---|---|
| 1 | 99.5 % | 216 min | Sibyl measures and responds; not a promise about the tenant's model |
| 2 | 99.0 % | 432 min | same |
| 3 | 98.0 % | 864 min | same |

Per-agent `slo_target` is Phase 2 (sre Q1, accepted); loosening below tier default will be four-eyes gated when it exists. Error-budget policy (D18, no pager): > 50 % consumed on tier 1 → console banner + weekly digest; 100 % → plan `review_required`, drills forced on, rules for that agent cannot be loosened until budget recovers.

### 3.5 Burn rates → severity → trigger

Burn = bad minutes ÷ (budget × window / 30 d); each pair requires both windows.

| Pair | Long / short | Burn ≥ | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|---|---|
| very-fast | 15 m / 2 m | 48× / 36× / 24× | `critical`; detected path: auto alt-model/alt-provider/handoff; backup-agent → approval (D13 clar.) | `critical`; auto incl. backup agent | `critical`; auto |
| fast | 1 h / 5 m | 14.4× | `critical`; leading-only → `awaiting_approval` | `warning` → `critical` on 2nd window; predicted → `degrade_then_auto` (R40) | `warning`; predicted → auto |
| slow | 6 h / 30 m | 6× | `warning`; `degraded`; packet pre-assembled | `warning`; `degraded` | `info` |
| ticket | 3 d / 6 h | 1× | `info` + weekly review | `info` | `info` |

`band = failed` for ≥ 2 consecutive ticks after hysteresis-in **is** the very-fast condition; there is one mechanism, not two. Leading rules never produce `critical` on tier 1 alone (strongest: `warning` + `recommended_action=await_approval`).

### 3.6 Factor output, ordering, `recommended_action`

```json
{ "rule": "error_rate", "weight": 0.40, "penalty": 28, "value": 0.17, "threshold": 0.10,
  "direction": "above", "kind": "detected",
  "explanation": "Error rate 17% over the last 5 minutes (threshold 10%, saturates at 30%); 5xx share 0.14 points to the provider",
  "evidence": "/events?agent_id=…&status=error&from=…&to=…" }
```

Factors sorted by `penalty` desc; zero-penalty evaluated rules included only with `?verbose=1` (compliance export on). Bookkeeping entries `_clamp` and `_hysteresis` (per-rule `consecutive_in/out` for restart resume) ride in `health_snapshot.factors`, stripped from the API. No factor ships without `evidence`; the harness fails a rule whose `explanation` is empty or whose `evidence` 404s (sre §6).

`recommended_action` by dominant factor and tier: `provider_status`/5xx → `reroute_to_fallback`; `ratelimit_proximity` → `throttle`; `context_saturation` → `trim_context`; `tool_loop` → `quarantine` (tier 1 `await_approval`); `budget_*` → `throttle`; `quality_proxy` → `handoff` on tier 1 else `watch`; nothing → `none`/`watch` by band. Advisory for humans; default action for rule actors, subject to the saga's viability check.

### 3.7 Hysteresis, cooldown, flap suppression, auto-resolve

Tick = 10 s. Counters persist in `health_snapshot.factors._hysteresis`; a worker restart resumes mid-count. A `late=true` event older than two windows never advances a counter.

| Transition | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| band worsens, detected | 2 ticks | 3 | 3 |
| band worsens, leading (closed buckets) | 6 | 6 | 12 |
| band improves | 18 | 12 | 6 |
| `failed_over → failing_back` probe | primary healthy 5 min | 5 min | 3 min |

- **Cooldown** per `dedupe_key`: 300/600/900 s; during cooldown the rule re-evaluates and updates `fired_count`/`evidence` but creates no row. `escalate_after_fires=3` in 3600 s bumps severity one step and switches `what_to_do` to the escalated template. Routing transitions reset nothing.
- **Alert budget**: `tenant_open_alerts > 3 × active agents` ⇒ new `info` alerts hidden by default filter and counted in the fatigue SLI.
- **Flap detector**: ≥ 3 band transitions or ≥ 2 rule/policy routing transitions for one agent in 10 min. Tiers 1–2: pin at the **worse** band for 15 min (tier 1: 20 min), rule actors may still move down; tier 3: pin at the **better** band, alert only (R48). One `flapping` alert carries the transition list.
- **Failback canary**: 10 → 25 → 50 → 100 %, each step needing full `out` hysteresis on the canary slice; a breach reverts to `failed_over` and doubles the probe wait (5 → 10 → 20, cap 60 min); two reverts in one incident → `recommended_action=handoff`, automated failback suspended until a human `fail_back`.
- **Provider collapse**: ≥ 3 agents (or ≥ 30 % of agents on the provider, whichever smaller) breach the same detected rule within 2 min ⇒ one `provider_incident`, member alerts `suppressed_by_incident`, failover batched per provider (tier 1 first). Resolution needs `out` hysteresis on ≥ 80 % of members.
- **Auto-resolve (D33, R29)**:

| Condition | `state` | `verdict` | `outcome_observed` |
|---|---|---|---|
| Band recovered via `out`, no routing transition while open | `resolved` | `null` → unverdicted queue | `recovered` |
| Band recovered after an automated failover/degrade | `resolved` | `null`, `verdict_wanted=true` (sorted first) | `recovered` |
| `failed_over`/handoff and primary never recovered in 2 × RTO | open until incident closes, then `resolved` | `null`, `verdict_wanted=true` | `failed` |
| Provider incident resolved | members `resolved` | one verdict on the provider incident propagates (`labeller.kind=worker`) | from incident |
| Silenced and expired while breaching | re-opens, `fired_count+1` | — | — |
| `killed`/`quarantined` by human | `resolved` | from the human's reason if given | `unknown` |

Auto-resolve never writes `tp`/`fp`. Unverdicted-backlog SLI = unverdicted resolved alerts older than 7 d ÷ resolved in 30 d, target < 20 %; above it the queue becomes a banner (nudge only, no auto-verdicts, R42).

### 3.8 Cold start and provisional

`provisional.flag=true` while `request_count(1h) < 50` **or** `observation_coverage < 0.8` **or** no `continuity_plan` **or** `agent_age_days < 1` (or 30 closed minutes, whichever first, sre). Provisional: score shown greyed, band capped at `watch`, detected alerts capped at `warning`, leading rules do not fire, no rule actor may create a `failover`. Baseline falls back to peer group then `seed/v1` constants (p95 small 1200 / large 4000 / reasoning 15000 ms; error rate 0.01). The engine also refuses leading rules for a tenant whose rollup lag exceeds 120 s and marks snapshots provisional (db §2.4).

### 3.9 Per-agent threshold adaptation from verdicts (Phase 1.5)

With ≥ 10 verdicted alerts on a rule in 30 d and `fp` share > 0.6, the worker **proposes** a 25 % threshold raise as a `threshold_suggestion` note; an operator accepts by editing the per-tenant `alert_rule` (`overridden=true`). No automatic parameter drift in Phase 1.

---

## 4. Phase 1 prediction rules

### 4.1 Statistics, defined once

All on the closed-minute series `x_t` per `(agent, feature)`; state is held in `agent_trend_state` (db §3.1), advanced exactly once per closed 5m bucket, and copied into the snapshot as `ewma_*`/`cusum_*` keys so replay equals production.

- **EWMA** level `λ = 0.3` (~3 min memory); slope = least-squares over 3 × 300 s of 1m points, expressed per 5 min (`error_rate_slope`, `latency_p95_slope`, `cost_slope`).
- **CUSUM** on `z_t = (x_t − baseline) / σ̂`: `S⁺ = max(0, S⁺ + z − k)`, `S⁻ = max(0, S⁻ − z − k)`, `k = 0.5`, `h = 5` (ARL₀ ≈ 930 ⇒ about one false alarm per 15 h per feature). Applied to `error_rate`, `latency_p95_ms`, `tokens_out_mean`, `output_chars_mean`, `cost_usd`, `tool_call_count`, `tool_seq_entropy`, `finish_content_filter_ratio` (L6, R37).
- **Proximity** `TTE = headroom / max(burn, ε)` for rate-limit and budget; context uses `context_utilisation_p95` directly.
- **Provider status**: `major_outage` is detected (R4); `maintenance`/`degraded_performance`/`partial_outage` are leading for every agent on the provider not yet erroring.

### 4.2 Risk points per horizon and the probability band

Each leading rule contributes `r_i = severity_i × cap_i / 100` (same severity as the score, so health and risk pages cannot disagree). Horizon `H` collects rules with `H_i ≤ H` plus detected carry-over: `failed` band ⇒ `r = 1.0` into 15m and 1h; `degraded` ⇒ `r = 0.4` into 15m. Combined `R_H = 1 − Π (1 − r_i)` (noisy-OR), quantised to the frozen band: `< 0.15 → "0.05"`, `< 0.45 → "0.25"`, `< 0.80 → "0.60"`, else `"0.90"`. `rules/v1` never emits the numeric `probability`. `contributing_rules` lists rules with `r_i > 0`, sorted desc.

The 24 h horizon collects only slow rules (`budget_proximity` at 24 h, `credential_expiry`, `model_deprecation`, `continuity_unverified`, a sustained 1 h CUSUM on cost or errors); the UI says "no 24 h leading indicators; model source not yet enabled" when it is `"0.05"`.

### 4.3 Leading rule definitions

| rule_id | fires when (after hysteresis) | severity | H (s) | `predicted_failure_mode` |
|---|---|---|---|---|
| `error_trend` (L1) | `error_rate_slope > 0` for 3 windows ∧ `ewma_error_rate ≥ 0.5 × t_R1`, or `cusum_error_rate_pos > h` | `clamp((ewma / t_R1 − 0.5) / 0.5)` | 900 | by dominant error class: provider_outage / latency_degradation / permission_error / tool_failure |
| `latency_trend` (L2) | slope > 0 for 3 windows ∧ `ewma_p95 ≥ 0.8 × t_R2`, or CUSUM alarm, or `vs_baseline ≥ 1.5` rising | `clamp((ewma / t_R2 − 0.8) / 0.2)` | 900 | latency_degradation |
| `ratelimit_proximity` (L3) | headroom < tier threshold, or `error_rate_429 > 0.05`, or `TTE_rl < 15 min` | `max((t − headroom)/t, 429share/0.15, (900 − TTE)/900)` | 900 | provider_outage (rate-limit sub-mode) |
| `budget_proximity` (L4) | `budget_burn_1h ≥ 0.9`; month projected ≥ 1.0 at 24 h | `clamp((projected − 0.9) / 0.1)` | 3600 / 86400 | cost_runaway |
| `fallback_pressure` (L5) | `inline_fallback_ratio + breaker_open_ratio` > tier threshold | `clamp((share − t) / 0.4)` | 900 | provider_outage |
| `refusal_trend` (L6, R37) | EWMA slope of refusal share > 0 for 3 windows ∧ level ≥ 0.5 × t_R6, or CUSUM alarm | `clamp((ewma / t_R6 − 0.5) / 0.5)` | 900 | quality_collapse |
| `context_saturation` | `context_utilisation_p95 > 0.85` or `finish_length_ratio > 0.25` | `clamp((util − 0.85) / 0.15)` | 900 | quality_collapse |
| `credential_expiry` | `days ≤ 7` | `clamp((7 − d) / 6)` | 86400 | permission_error |
| `model_deprecation` | `days ≤ 30` | `clamp((30 − d) / 23)` | 86400 | model_deprecation |
| `continuity_unverified` (L7) | drill overdue or readiness below threshold | boolean × 0.5 | 86400 | (none; informs `recommended_action=watch`) |
| `provider_status` leading facet | `provider_status_code ∈ {1,2,3}` and agent not yet erroring | ordinal table | 900 | provider_outage |
| `drift_cusum` | CUSUM beyond `h` on tokens/output/entropy with nothing else firing | `clamp((S − h) / h) × 0.5` | 3600 | silent_drift (watch only) |

Document-level `predicted_failure_mode` = mode of the highest-`r_i` rule in the nearest horizon with `R_H ≥ 0.15`, else `null`.

### 4.4 Confidence semantics (`rules/v1`)

Confidence describes the **evidence**, not the probability:
- `high`: a detected floor is in force; or `provider_status ∈ {partial, major}` with age < 600 s corroborated by `provider_error_rate_fleet > t_R1`; or ≥ 2 independent leading rules with `r_i ≥ 0.5` and coverage ≥ 0.95.
- `medium`: one leading rule with `r_i ≥ 0.5`, `request_count(5m) ≥ 2 × min_samples`, coverage ≥ 0.8, not provisional.
- `low`: everything else, including every 24 h horizon from rules.

### 4.5 Tier gating (D13, D22, R40, R41)

| Trigger | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| Detected failure → alt-model / alt-provider / human handoff | automatic | automatic | automatic |
| Detected failure → `backup_agent` step | approval (always; four-eyes for human-initiated, R36) | automatic | automatic |
| Predicted: `15m.band ≥ "0.60"` ∧ `confidence ≥ medium` ∧ ≥ 2 contributing rules of different families | **approval**, `requested_by_kind='rule'`, timeout `approval_timeout_s` (600 s default, R39; console warns when > 0.5 × `rto_s`); D22 forces `hold` on PII/residency agents | **`degrade_then_auto`** (R40): `degraded` now, failover if band persists 2 more ticks (20 s) | **`auto`** |
| Predicted `"0.60"`, `confidence='low'`, or only one rule family | `watch` alert, no saga | `degraded` only | `degraded` only |
| Predicted `"0.25"` | `watch`/`info` | `watch` | score only |
| Any rule/policy actor during `operator_hold_until` (D21, 30 min) | blocked, `hold_suppressed_count += 1` | same | same |

**Automation gate (R41, release criterion):** the predicted path on tiers 2–3 may fire at `"0.60"` only once `sibyl-sim` shows `rules/v1` precision ≥ 75 % and recall ≥ 60 % at 15 m on the ramp scenarios; until then `"0.90"` only. Leading rules carry `hysteresis_in ≥ 3` on tiers 2–3. The weekly review (§9.3) moves the gate back to `"0.90"` if the realised failure rate at `"0.60"` leaves nominal ± 0.15 for two weeks. 1 h and 24 h horizons never trigger a saga in Phase 1.

`preemptive_mode ∈ {approval, degrade_then_auto, auto}` is a `continuity_plan` column (amendment §10.1), seeded by tier, tenant-editable.

### 4.6 False-failover budget and guard rails (sre §3)

A false failover = a rule/policy transition to `failed_over` (or an approval request for one) where `failover_outcome.undone_by_operator=true`, or `alert.verdict=fp`, or the incident closed `recovered` within hysteresis-out with no corroborating signal. Measured per tier per 30 d from labels (7-day settling).

| Tier | Automated false failovers / agent / 30 d | Fleet ceiling (meridian 3/7/10) | Detection precision target | Predicted-path precision/recall at 15 m |
|---|---|---|---|---|
| 1 | **0**; ≤ 1 unnecessary approval request per agent, ≤ 25 % of requests fleet-wide | 0 auto / ≤ 3 requests | ≥ 98 % | n/a (approval only) |
| 2 | ≤ 1 | ≤ 4 | ≥ 92 % | ≥ 75 % / ≥ 60 % before `"0.60"` automates (R41) |
| 3 | ≤ 2 | ≤ 10 and ≤ 10 % of tier-3 incidents | ≥ 90 % | same |

Guard rails:
1. Confidence gate: `"0.60"` ∧ `confidence ≥ medium` ∧ two rule families; `low` ⇒ `degrade` only. Tier-1 approvals carry factors, FeatureSnapshot ref and provider status so the approver decides in < 1 min.
2. Lone-agent corroboration: a single agent `failed` with a green provider and no fleet degradation needs one extra `in` cycle before failover (an agent bug is not fixed by a provider failover).
3. Viability before action: `check_viability` returns `409 target_not_viable` when the fallback provider is itself degraded or breakered in the last 5 min; saga takes the next step or `human_queue`.
4. D13 / D21 / D22 gating as above; an `undo` writes `undone_by_operator=true` immediately, debiting the budget.
5. Per-agent breaker: 2 undone or `fp`-verdicted automated transitions in 7 d ⇒ `preemptive_mode` forced to `approval` until a human clears it (audited `config.changed`).
6. Fleet breaker: a tier over its 30 d ceiling degrades all **predicted** paths tenant-wide (`degrade_then_auto` for tier 3, `approval` for tier 2) with a banner naming the rules. Detected paths are never disabled.
7. Rule-change gate: editing a tier-1 threshold runs a dry-run replay over the last 7 d of snapshots and shows the delta in fires before saving (R50).

A monthly false-failover report (per tier and agent: automated transitions, approvals, undos, `fp` verdicts, precision/recall per `contributing_rules` set, breaker state) is a `label`-derived view on the Product-promise dashboard and in the compliance export; it is also the regression baseline: a rule or weight change may not ship if replaying last month moves any tier above its ceiling.

### 4.7 Predictor interface conformance

`rules/v1` implements `HealthPredictor`: `name='rules'`, `version='v1'`, `required_feature_set='features/v1'`, `predict(snapshot, [900, 3600, 86400])` pure over the snapshot, `explain()` returns the factor list, `abstained` never set. Stored or synthetic snapshots yield byte-identical predictions.

---

## 5. Phase 2 learned layer

### 5.1 Scope

The model replaces the quantised `probability_band` per horizon and adds `probability`, `source='model/sibyl-gbt:<ver>'`, and its own `kind='leading'` factors. It does not replace the score, rule factors, hysteresis or floors. On abstention rules fill the horizon and `abstained=true` is set.

### 5.2 Training set (db §4, ai-eng §4.2, R42)

Unit = one `feature_snapshot` (`reason ∈ {transition, alert, approval, sample}`) joined to an outcome at `as_of + H`. Snapshots are immutable and contain nothing after `as_of`, so point-in-time correctness is structural.

Two RLS-governed views (`security_invoker`): `training_alert_examples` (verdicted alerts; LATERAL picks the newest frozen snapshot ≤ 15 min before `first_fired_at`, else `features_from_5m()` recompute flagged `features_recomputed=true`) and `training_horizon_examples` (every snapshot × {900, 3600, 86400} labelled from `health_1h.band_counts[4]`, later `tp` alerts and `failover_outcome`, with `horizon_closed`). Split by ISO week, never random rows. Outcome-only columns live in an `outcome_*` namespace and never enter features. `rules/v1` outputs and `contributing_rules` are not features.

| Source | Positive | Negative | Excluded |
|---|---|---|---|
| `alert_verdict` on a leading alert | `tp` with `actual_failure_mode`: the alert's snapshot and sampled snapshots in `[judged − H, judged]` | `fp`: hard negatives | `unsure`; `NULL` (D33) → unverdicted SLI |
| `alert_verdict` on a detected alert | `tp`: snapshots in `[judged − H, judged)` (lead-time learning) | `fp`: hard negatives | same |
| `provider_incident` (worker-synthesised, independent of rule firing) | every agent on the provider, window `[started − 1 h, started]` | — | agents already failed over |
| `failover_outcome.undone_by_operator=true` | — | the triggering snapshot | `fallback_succeeded=false` (ambiguous) |
| `failed` band with floor reason | positives only when corroborated by `tp` or `provider_incident` within 24 h | — | uncorroborated |
| `reason='sample'` with no failure in `[as_of, as_of + H + 1 h]` | — | ordinary negatives | inside `observation.gap` |

**Label strength (R42):** `label_strength ∈ {verdict, outcome, provider_feed}` is a column on labels and a fold stratifier; weak labels (`prediction.outcome`, `provider_incident`) are admitted to training, **operator verdicts are the sole evaluation set**. Volume at 20 agents ≈ 5.7k sampled + 200 event snapshots/day; 90 d ≈ 530k rows, 1–3 % positives at 15 m.

### 5.3 Features for the model

All `grains.{1m,5m,15m,1h}`, `static.*` encoded (one-hot/ordinal, cyclic hour/day), `*_fleet`, `ewma_*`, `cusum_*`, `*_vs_baseline`, `observation_coverage`, `baseline_ref` tier as ordinal. `null` passed as missing, never imputed. CI refuses any feature key not in `features/v1`.

### 5.4 Model and calibration (R44 stack)

- **Learner**: LightGBM (MIT) binary, `num_leaves ≤ 31`, `max_depth ≤ 6`, `min_child_samples ≥ 200`, `feature_fraction 0.8`, `lambda_l2 10`, early stopping on the forward fold. **Monotone constraints** where physics is known: `error_rate`, `latency_p95_vs_baseline`, `inline_fallback_ratio`, `provider_status_code` non-decreasing; `ratelimit_headroom_min`, `budget_headroom` non-increasing (an explainability guarantee a compliance reader can be told in one sentence). Fallback scikit-learn `HistGradientBoostingClassifier` (BSD-3).
- **Imbalance**: `scale_pos_weight = neg/pos` capped at 50; no synthetic oversampling.
- **Validation**: forward-chaining by time with an `H + 1 h` gap, grouped by agent, three folds.
- **Calibration**: isotonic on out-of-fold predictions; `probability` is a frequency; ECE (10 bins) and Brier reported; band = nearest lower band of the calibrated probability.
- **Abstention**: `provisional`, coverage < 0.8, < 7 d own baseline, or isolation-forest OOD (`> 0.85`) ⇒ `abstained=true`. Abstention > 20 % blocks promotion (ai-eng); qa's shadow gate tolerates ≤ 30 % (§8.5) `(editor: ai-engineer's 20 % is the promotion bar; qa's 30 % is the shadow-usefulness floor).`
- **Per horizon**: three models; 24 h may legitimately never earn promotion.
- Why GBT: tabular, mixed-scale, heavily missing, few hundred positives; inspectable (`pred_contrib`, monotone). Discrete-time hazard is the natural next reformulation on the same rows; autoencoders deferred.

### 5.5 Anomaly detection (unknown unknowns)

Both unsupervised, both emit `rule='anomaly_score'`, `kind='leading'`, never a saga trigger alone:
- **Isolation forest** (sklearn) per tenant over 5m/1h grains + statics, 200 trees, refit weekly; `> 0.7` → drift watch factor, `> 0.85` → OOD flag (abstain).
- **Seasonal-ESD** (statsmodels STL + generalised ESD, `α = 0.01`, max 5 %) on hourly `tokens_out_mean`, `output_chars_mean`, `cost_usd`, `tool_call_count`, `task_success_rate`, weekly seasonality; catches slow level shifts CUSUM misses.

Anomaly factors earn a score penalty only after the harness shows precision ≥ `drift_cusum`; until then labelled "experimental", excluded from `recommended_action`.

### 5.6 Stack and licences (D10, D15, R44)

| Component | Package | Licence |
|---|---|---|
| Arrays/frames | numpy, pandas (or polars) | BSD-3 / BSD-3 (MIT) |
| DB access | **asyncpg** (R44), sqlalchemy core | Apache-2 / MIT |
| GBT | lightgbm | MIT |
| Fallback GBT, calibration, isolation forest, metrics | scikit-learn | BSD-3 |
| Seasonal decomposition | statsmodels | BSD-3 |
| Explanations | LightGBM `pred_contrib=True` (TreeSHAP built in) | MIT |
| Artefacts | joblib → `payload_refs(kind='model_artifact')` in BlobStore, sha256, crypto-shred applies | BSD-3 |
| Scheduling | worker asyncio + `pg_advisory_lock` | — |

Excluded: psycopg (LGPL-3), MLflow server (another stateful service; `ml_model` is the registry), anything AGPL/SSPL, any GPU. Training three GBTs on 530k × ~120 features on one core < 10 min, memory < 2 GB.

### 5.7 Registry, cadence, drift, shadow, promotion

- **Registry**: `ml_model(tenant_id, id, name, version, horizon_s, feature_set, trained_at, train_from, train_to, n_rows, n_pos, metrics jsonb, calibration jsonb, artifact_ref_id, artifact_sha256, state ∈ {trained, shadow, promoted, demoted, retired}, promoted_at, demoted_at, promoted_by_user_id)`; `ml_prediction_shadow(tenant_id, health_snapshot_id, model_id, horizon_s, probability, band, abstained, evaluated_at)` daily-partitioned, 30 d. Version = `<trained_at date>.<n>`. Promotion/demotion audited (`ml_model.promoted/demoted`); human actor for promotion, `system` for drift auto-demotion.
- **Cadence**: nightly per tenant at a quiet hour; retrain only if ≥ 50 new verdicts or ≥ 1 new `provider_incident` label, else `ml.train.skipped`. Weekly IF and S-ESD refit. Every trained model enters `shadow`; promotion is never automatic in Phase 2.
- **Per-tenant models (R43)**: `model/sibyl-gbt:0.x` trained on synthetic `meridian` traffic is the day-one shadow for every tenant; never promoted without the tenant's own verdicts (≥ 200 positives per horizon take over).
- **Drift**: PSI > 0.25 on a top-10 feature → `ml.drift.feature`; positive rate > 2× change; ECE on trailing 14 d > 0.10 flags, > 0.15 auto-demotes to `shadow` (rules take over, audited); model worse than rules on precision by > 5 points over 14 d → demoted; abstention/OOD > 20 % sustained flags. Flags become `info` alerts with `alert_rule.scope='platform'` (amendment §10.1).
- **Shadow mode**: runs every tick, writes `ml_prediction_shadow`, invisible in `horizons`. Rollback switch `SIBYL_PREDICTION_SOURCE=rules/v1` flips back without redeploy (qa §5).
- **Promotion gate (per horizon; qa §5 floors adopted, R42)**: see §8.5.
- **Confidence for `model/*`**: `high` = calibrated probability ≥ 0.1 from both band edges, not OOD, coverage ≥ 0.95; `medium` = near an edge or coverage 0.8–0.95; `low` = abstained-then-filled or promoted < 7 d. D13 gating reads the same field.

### 5.8 Threshold and golden ownership (R50)

Rule, penalty and weight changes: ai-engineer with chair sign-off, always preceded by the dry-run replay (§4.6 rail 7). Oracle, scenario and ground-truth changes: qa-expert. A golden update must include the `sim diff` output and a one-line reason in the PR. Tuned configs are written as `scoring_config(origin='tuned')` rows; promotion to the seed is a CLI step `sibyl rules promote` that re-copies to tenants with `overridden=false` only (db Q6, accepted).

### 5.9 LLM-as-judge (Phase 2, tenant opt-in)

Phase 2 ships the `feedback(rater='judge')` path and a sampling job (`sibyl.eval.sample`, 1 % of calls) wired to any OpenAI-compatible endpoint the tenant configures (Ollama included). No judge is bundled or run by default; scores flow through §2.4 unchanged.

---

## 6. Explainability and EU AI Act risk assessment

### 6.1 What the compliance persona gets (D8; Compliance Auditor, D29)

1. **Decision record** per rule/policy `routing_transition`: `rule_codes`, `alert_ids`, `health_snapshot_id` → `score`, `band`, `factors[]` with arithmetic shown (`100 − (28 + 10 + 4) = 58 → degraded`), `horizons`, `rules_source`, `scoring_config_id`, `feature_snapshot_id`. Audit `route.changed` references `transition_id`.
2. **Reproducibility statement**: `sibyl replay --snapshot fs_… --predictor rules/v1` recomputes identical factors and horizons; for models it names `ml_model.version`, `artifact_sha256`, `feature_set` and reproduces `probability` to 4 decimals. Every decision is re-executable offline.
3. **Model card** per `ml_model` version, immutable, `payload_refs(kind='model_card')`: intended use, training window and counts, positives by failure mode, label sources and exclusions, feature list with monotone constraints, top-20 importances, calibration curve, per-tier precision/recall/lead time vs rules, known limitations incl. unverdicted-backlog share as a known bias (R42), who promoted and when.
4. **Per-prediction contributions** for model sources: top-8 `pred_contrib` as factors `rule='model_feature:<key>'`, templated explanations; rule factors and model factors shown in two labelled groups, never merged.
5. **Verdict ledger** per rule and model version: `tp/fp/unsure/null` counts, precision, recall, median lead time, backlog, over 30/90/400 d (D27).
6. **Threshold provenance**: `alert_rule.origin`, `seed_version`, `yaml_sha256`, `overridden`, history from audit; `scoring_config` versions with activation audit.
7. **Human-oversight evidence** (Art. 14): tier-1 share of automated actions that went through `approval`, approval latency, denials, `undo`s with reasons, D21 holds, D22 forced holds.
8. **Plain-language glossary** embedded in the export (what a score of 58 means; `"0.60"` is rule-derived in Phase 1, a calibrated frequency for model sources).
9. **Export**: `GET /audit/export?include=health_decisions` → ZIP of decision records, snapshots, model cards, verdict ledger, hashed into the audit anchor. Readable without `payloads:read`.

Every incident view shows the RTO clock (`elapsed / rto_s`) and RPO at cut (`checkpoint_age_p95_s` vs `rpo_s`); these two numbers are what the compliance persona exports (sre §6).

### 6.2 Risk assessment (EU AI Act tiers)

`agent.risk_class ∈ {unclassified, minimal, limited, high, unacceptable}` is set by a human; the ML layer never writes it. The worker computes a `risk_assessment` suggestion with evidence and **findings** that contradict declarations, daily and on `graph.changed`. Learned risk scoring is out of scope: the tiers are legal categories with explicit criteria.

**Static features**: `annex_iii_use_case` (tag `eu_ai_act:<use_case>`, normalised into the table), `prohibited_practice_flag`, `interacts_with_natural_persons`, `generates_synthetic_content`, `data_classification_max`, `residency_regions`, `business_process_criticality`, `tool_side_effect_max` (read < write < external_comm < financial < irreversible), `autonomy_level`, `human_oversight_configured`, `tier`, `lifecycle`, `model_provider_known`/`model_allowed`, `bom_present`.

**Dynamic features (30 d)**: `observed_pii_access_ratio`, `undeclared_tool_ratio`, `undeclared_data_source_ratio`, `policy_violation_count`, `permission_error_rate`, `handoff_rate`, `handoff_returned_ratio`, `approval_denial_ratio`, `finish_content_filter_ratio`, `quality_proxy` firings, `feedback_negative_ratio`, `prompt_version_churn`, `agent_version_churn_gateway_observed`, `cross_agent_delegation_depth`, `external_comm_side_effects_30d`.

**Rubric**: `unacceptable` if any prohibited flag; else `high` if Annex III use case, or (`data_classification_max ∈ {pii, restricted}` ∧ `tool_side_effect_max ≥ external_comm` ∧ `autonomy_level ≥ 2`); else `limited` if natural-person interaction or synthetic content; else `minimal`. **Findings** (never auto-applied): declared below suggested; tier 1 without oversight; `deployed` and `unclassified`; observed PII access with none declared; `undeclared_tool_ratio > 0.01`; `bom_present=false` for `high`.

**Surface**: `GET /agents/{id}/risk-assessment` → `{suggested_class, declared_class, findings[], static{}, dynamic{}, computed_at}` (accepted, ai-eng Q5). Governance composite `agent_risk` (db §3.5: inherent, control coverage, 28-day health, contributions) is a daily row per agent; `GET /agents/{id}/risk` stays failure risk (API §5.10). The D22 predicate (PII/residency) = data-source edges `classification ∈ {pii, restricted}` or `residency_region` set, or tag `pii`.

---

## 7. Storage and worker

### 7.1 Grains and retention (database-architect §1; R49)

| Grain | Table | Partition | Retention | Reader |
|---|---|---|---|---|
| 1m | `agent_metrics_1m` (exists, + §2.6 counters) | daily | 14 d | health tick (detected rules, last 10 min), 5m rollup |
| 5m | `agent_metrics_5m` (new, **materialised**, R49) | daily | 90 d | leading-rule inputs, FeatureSnapshot 5m/15m, training recompute, charts > 6 h |
| 5m provider | `provider_metrics_5m` (new) | daily | 90 d | provider rules, collapse, peer baseline |
| 1h | `agent_metrics_1h` (exists) | monthly | 13 months | 24 h horizon, baselines, cost |
| 1h score | `health_1h` (new) | monthly | 13 months | score history (closes U12); 24 h horizon label |
| state | `agent_trend_state`, `agent_baseline`, `agent_risk`, `scoring_config`, `rollup_job` | none | current / durable | tick, nightly, governance |
| predictions | `prediction` (new, sparse) | monthly by `predicted_at` | 400 d | harness scoring, Phase 2 calibration, console timeline |

15m is the only query-time grain (sum of three 5m rows). Rollups hold no content, so they are outside crypto-shred and hard-deleted in the erasure cascade. **Feature snapshots (R49):** `feature_snapshot.doc` moves to BlobStore (`payload_refs.kind='feature_snapshot'`) with a ≤ 2 KB in-row summary (`grains.5m` only); 1-in-30 sampling kept; `reason='sample'` rows older than 90 d are swept unless referenced by a label or a `prediction` with `outcome='failed'`. Training reads Parquet exports (`sibyl ml export`, audited `data.export`).

**`health_snapshot` write cadence** `(editor: db Q1, default adopted, not in SYNTHESIS, chair to confirm §10.4)`: write on change (score moved ≥ 3 points, band change, factor-set change, horizon band change) plus a 60 s heartbeat row per agent, instead of every 10 s tick. Cuts 2,000-agent volume ~8× (17 M rows and 26 GB WAL/day → ~2 M); the read contract already tolerates gaps; `health_1h` keeps hourly history; time-to-detect is measured from `prediction`/`alert` timestamps.

### 7.2 Materialisation pipeline (db §2)

```
events ──(cursor on received_at)──► dirty 1m buckets ──recompute from scratch──► agent_metrics_1m
agent_metrics_1m ──(dirty parents)──► agent_metrics_5m ──► agent_metrics_1h
agent_metrics_5m ──(GROUP BY provider)──► provider_metrics_5m
agent_metrics_5m (closed) ──► agent_trend_state (EWMA/CUSUM) ──► health tick
```

One transaction per tenant per 10 s tick under `pg_advisory_xact_lock('rollup:'||tenant)`: `set_tenant`; dirty set from `events` by `received_at` (watermark `now() − 2 s`, `LIMIT 5000` buckets with `rollup_job.carryover`); recompute each dirty 1m bucket **from scratch** and upsert replace-not-add; dirty 5m, provider-5m and 1h parents recomputed from children (`children_1m` records partial buckets); for each 5m bucket that just closed, advance `agent_trend_state` exactly once (`last_bucket` never goes backwards, so a reopened bucket updates the rollup but never re-advances CUSUM); commit offset in the same transaction. Crash replay rewrites identical rows.

**Late arrivals**: dirty set keys on `received_at`, so a late event (`is_late`, > 120 s) dirties its true `ts` bucket and parents; beyond the 14 d 1m window the 5m bucket is recomputed from `events` directly (`children_1m = 0`); beyond raw retention ingest rejects. A late event into a bucket a `health_snapshot` already read does not rewrite the snapshot (append-only); recomputed features are flagged `features_recomputed`.

**Backfill/repair**: `rollup_job(kind ∈ {backfill, repair, purge}, grains, range, progress_to, state)` walks hour slices under the same lock; `repair` resets trend state for the range and replays forward; every job writes `audit_append('rollup.backfill')`.

**Freshness**: `rollup_lag_s` per tenant; leading rules are refused above 120 s lag and snapshots marked provisional.

### 7.3 Scoring tables (db §3; DDL in `database-architect.md`)

- `agent_trend_state(tenant, agent, metric, last_bucket, ewma, ewma_var, cusum_pos, cusum_neg, cusum_alarm_at, samples, scoring_config_id)`.
- `agent_baseline(tenant, agent | peer pseudo-id, metric, hour_of_week, mean, stddev, p95, samples, computed_at, baseline_ref, peer_group)`, rebuilt nightly from 28 d of `agent_metrics_1h`.
- `scoring_config(tenant, id, rules_source, feature_set, version_no, config jsonb ≤ 32 KB, config_sha256, origin ∈ {seed, custom, tuned}, activated_at, superseded_at, created_by)`, immutable rows, one active per tenant; `health_snapshot.scoring_config_id` added. Activation is audited.
- `prediction(tenant, predicted_at, id, agent, health_snapshot_id, feature_snapshot_id, scoring_config_id, horizon_s, source, probability_band, probability, confidence, predicted_failure_mode, contributions ≤ 8 KB, abstained, outcome ∈ {failed, recovered, no_event, unknown}, outcome_failure_mode, outcome_at, outcome_label_id, lead_time_s)`. **Sparse write rule (R49)**: on band change, when band ≥ `"0.25"`, on every snapshot-freezing tick, and hourly heartbeat. Hourly outcome filler reads nothing with `ts > predicted_at + horizon_s`, so outcomes are point-in-time. Lead time is measured from the first band rise, which the sparse rule captures exactly.
- `health_1h(tenant, agent, bucket_start, ticks, score_min/max/avg, band_counts[4], provisional_ticks, coverage_avg, transitions, top_factors ≤ 2 KB, scoring_config_ids[])`, written before the 3-day snapshot partition drops.
- `agent_risk(tenant, agent, as_of date, risk_score, risk_band, inherent, control_coverage, health_28d, contributions, scoring_config_id, graph_version)`.
- Phase 2: `ml_model`, `ml_prediction_shadow` (§5.7); `risk_assessment` (§6.2).

Net inventory: 62 + 2 (Step 4) + 9 (Step 5 core) + 3 (`ml_model`, `ml_prediction_shadow`, `risk_assessment`) = **76 tables**. `partition_registry` gains `agent_metrics_5m`, `provider_metrics_5m`, `prediction`, `health_1h`, `idempotency_record`, `ingest_batch_seen`, `ml_prediction_shadow`.

### 7.4 Worker architecture (ai-eng §7)

`sibyl-worker`: one Python process per deployment, horizontally shardable by tenant via `pg_try_advisory_lock('worker:'||tenant)`. asyncio loops, no external scheduler or queue (D10, Postgres is the only stateful component). Driver: asyncpg (R44).

| Loop | Cadence | Work |
|---|---|---|
| rollup | 10 s / tenant | §7.2 |
| evaluate | 10 s / tenant, after rollup commits | one read of `agent_metrics_1m` (10 min) + trend state + latest 5m + fleet rows + 60 s registry cache + bounded tail reads (only agents in the dirty set) → in-memory `FeatureSnapshot` per active agent → score, floors, rules, hysteresis → `predict()` → write `health_snapshot` (per §7.1 cadence) and `feature_snapshot` (transition/alert/approval or 1-in-30) → alert upserts, provider collapse → `failover` creation for rule actors (D13/D21/D22) → `health.transition` events → outbox |
| baseline | hourly / tenant | §2.5 medians/MAD; peer groups; `provider_status` poll on change |
| ml (Phase 2) | nightly train, weekly IF/S-ESD, shadow predict every tick | §5.7 |

Plus the existing saga executor, partition job, sweeper, erasure steps. Everything idempotent and resumable; the evaluate loop skips a tick rather than queueing (alarm at 2 s), writing `observation.gap(cause=worker_lag)` so coverage, not confidence, drops.

### 7.5 Cost model: 20 → 2,000 agents (db §5)

Assumptions: 0.6 req/s/agent at 20 agents (chaos demo), 0.1 at 2,000; tool calls 1.8× requests; 1.2 `(provider, model)` pairs per agent; 60 % active minutes.

| Table | Rows/day @ 20 | Rows/day @ 2,000 | Resident @ 2,000 | Size |
|---|---|---|---|---|
| `events` (reference) | 3.0 M | 50 M | 1.5 B (30 d) | 35 GB/day |
| `agent_metrics_1m` | 21 k | 2.1 M | 29 M (14 d) | 17 GB |
| `agent_metrics_5m` | 4.1 k | 415 k | 37 M (90 d) | 22 GB |
| `provider_metrics_5m` | 3.5 k | 20 k | 1.8 M | small |
| `agent_metrics_1h` | 350 | 35 k | 14 M (13 mo) | 8 GB |
| `health_snapshot` (write-on-change + 60 s heartbeat) | ~25 k | ~2.5 M | ~7 M (3 d) | ~10 GB |
| `health_1h` | 480 | 48 k | 19 M | 8 GB |
| `prediction` (sparse) | 20 k | 1.5 M | 600 M (400 d) | ~400 GB at the ceiling; partition drops and the 90-day sample sweep keep it bounded |
| `feature_snapshot` summary (doc in BlobStore) | 5.7 k | 576 k | 230 M × ≤ 2 KB | ≤ 460 GB row + blob; sweep per R49 |
| `agent_trend_state` | — | 24 k total | 24 k | tiny |
| `agent_baseline` | — | 4 M total | 4 M | 400 MB |

Per-tick work at 2,000 agents: dirty scan ≤ 50 ms (BRIN), 1m recompute ≤ 300 ms, upserts ≤ 100 ms, health read ~60 ms, snapshot inserts bounded by write-on-change. Everything stays under one second per tick on one box; the two things that did not scale (every-tick snapshots, in-row feature docs) are fixed by §7.1. New indexes all lead with `tenant_id`; no GIN on `factors`/`contributions`; worker `work_mem` 64 MB; `autovacuum_vacuum_scale_factor 0.02` and `fillfactor 70` on the 1m/5m tables.

---

## 8. Evaluation harness (`sibyl-sim`)

### 8.1 Architecture (qa §1; R32, R45, R46)

```
 sibyl-sim (own port :8300, own compose profile `sim`, never in the prod bundle — R46)
 ├── scenario runner      reads scenarios/*.yaml, seeds PRNG, drives the clock
 ├── 23 agent actors      20 meridian (tiers 3/7/10), 3 northstar; sandbox stays empty (D29)
 ├── provider doubles     openai-compatible / anthropic / ollama stubs behind the REAL gateway
 ├── status-feed double   serves provider.status the worker polls
 ├── ground-truth writer  labels/<run_id>.jsonl — never into Postgres
 └── oracle               reads control-plane API + SSE as Platform Admin/On-call Operator/Compliance Auditor, compares to labels
                                  │
          real path ───────────────┼──────────────────────────────────────────────
          SDK/gateway → POST /v1/otlp/traces | /v1/otlp/logs | /v1/events → normaliser
                       → events → worker (rollup, rules, health, saga) → routing_state / alert / approval / handoff_task → SSE
```

Rules: real ingest, gateway and worker only (the simulator never writes a derived table); chaos is applied at the provider double so the gateway's breaker, inline fallback and `X-Sibyl-*` headers are under test; status feed and traffic can be decoupled (S-16, S-17); **no product clock override (R45)** — latency-sensitive scenarios run at 1×, count-based scenarios up to 6× while keeping sim-time within 60 s of wall time so `is_late` is respected; the only product hooks are `SIBYL_EVAL_TICK_S` and `SIBYL_DEMO=1`; every scenario has a `seed` and identical seed + build ⇒ identical ground truth and `event_id`s; isolation by construction (northstar steady in every run, sandbox zero rows). Customer-facing drills are a Phase 2 roadmap item behind a real feature flag (R46).

Run modes: `sim run` (one scenario), `sim suite --tier smoke` (6 scenarios, ≤ 12 min, every PR), `sim suite --tier full` (all, 3 seeds, ≤ 90 min nightly), `sim soak` (S-24 60 min at 200 calls/s), `sim shadow` (Phase 2). Oracle predicates: `predict`, `detect`, `action`, `tier_gate`, `no_action`, `rto`, `explainable`, `quiet`, `isolated`, `audit_has`, `idempotent`, `single_failover`; every `expect` key maps to one predicate so a failure names the predicate and the first offending object.

### 8.2 Scenario catalogue (28 + 12 tier-swap variants × 3 seeds = 120 nightly runs)

| # | Scenario | Injection | Tiers | Expected |
|---|---|---|---|---|
| S-01 | Hard provider outage | 100 % 503 | 1,2,3 | R3 in 3 calls; R1 critical; R4 at +90 s; auto alt-provider on all tiers; collapse groups ≥ 2 agents |
| S-02 | Rate-limit ramp | headroom 0.6→0.02 over 12 min, then 429 | 2,3 | L3 ≥ 6 min before first 429; preemptive failover auto (R40 tier 2 degrades first) |
| S-03 | Rate-limit ramp, tier 1 | as S-02 | 1 | `awaiting_approval`, `requested_by_kind=rule`; timeout 600 s → `hold` → `degraded` |
| S-04 | Latency creep | p95 +12 %/window to 1.4× | 2 | L2 ≥ 2 windows early; `degraded` + `safe_no_tools`; failover only if R2 persists |
| S-05 | Cost spike | tokens ×6 | 3 | L4 ≥ 30 min early; R5 at breach; `throttle`; quarantine auto on tier 3 |
| S-06 | Budget exhaustion mid-month | spend 0.97 at seed | 1 | L4 immediately; R5; approval for quarantine; fail mode respected |
| S-07 | Flapping provider | 2 min bad / 2 min good ×6 | 2 | **exactly one** failover; no fail-back inside the flap |
| S-08 | Silent degradation: refusals | 40 % refusals, `finish_reason=stop` | 2 | R6/L6 (R37); `quality_collapse`; R1 stays quiet |
| S-09 | Silent degradation: truncation | 50 % `length`, chars 30 % of baseline | 3 | R7; `trim_context`; no failover |
| S-10 | Silent degradation: schema failures | 35 % malformed tool JSON | 2 | R8 > 0.20; `safe_no_tools`; handoff with checkpoint |
| S-11 | Tool-call loop | same tool ×40 in one task | 1 | `tool_loop` within 10 calls; handoff automatic; packet `fidelity=checkpoint` |
| S-12 | Context saturation | utilisation 0.6→0.98 | 2 | `context_saturation`; `trim_context`; no routing change |
| S-13 | Correlated multi-agent failure | anthropic double degrades, 7 agents | mixed | one `provider_incident`, seven suppressed; no `saga_in_flight` 409 leaks |
| S-14 | Model deprecation | 404 `model_not_found` one model | 2 | R1 critical + `model_deprecation` class; alt-model same provider auto |
| S-15 | Fallback not viable | S-01 + revoked fallback credential | 2 | saga `failed target_not_viable`; handoff terminal; audit row |
| S-16 | Status page lies | status `major`, traffic healthy | 2 | R4 fires; **no failover**; `watch`; counts toward FP denominator |
| S-17 | Status page late | 100 % 5xx, status `operational` | 3 | R1/R3 detect; failover on traffic alone |
| S-18 | Observation gap | SDK silent 4 min | 1 | `observation.gap` at 30 s; no failover on gap alone; `watch` |
| S-19 | Ingest backpressure | 429 `ingest_saturated` 90 s | all | gap with cause; replay closes it; zero duplicate `call_id` |
| S-20 | Undo and operator hold | S-01 then `undo` at 2 min | 2 | `operator_hold` blocks rules 30 min; `hold_suppressed_count` climbs; `clear_hold` resumes |
| S-21 | Tenant isolation, steady | all chaos in meridian | — | northstar zero alerts, scores ≥ 90, zero transitions, silent SSE |
| S-22 | Tenant isolation, shared provider | double fails only for meridian keys | — | `provider_incident` scoped per tenant |
| S-23 | Prompt injection pattern | `policy.decision(blocked)` + marker | 1 | `prompt_injection`; quarantine approval; no auto kill |
| S-24 | Baseline / soak | no chaos, 60 min | all | **zero** alerts above `info`; bands `"0.05"`; precision denominator |
| S-25 | Fail-back canary | S-01 recovers at +10 min | 2 | probe after 5 healthy min; canary 10 → 100 %; flap re-injection reverts |
| S-26 | Approval four-eyes | tier-1 backup-agent step | 1 | `awaiting_approval` even on detected failure; `self_approval` 409 |
| S-27 | D22 forced hold | tier-1 PII agent, plan says `fail_safe`, approval expires | 1 | worker forces `hold`; audit `hold_forced_d22` |
| S-28 | Kill beats everything | S-01 running; the On-call Operator pulls kill | 2 | no saga progresses; gateway 403; SDK `SibylKilled` ≤ 20 s; release by step-up only |

Coverage matrix (qa §2.1) maps every seed rule and state-machine edge to scenarios; a rule or edge with no row is a gap. S-01, S-02, S-04, S-08 run tier-swap variants.

### 8.3 Acceptance gates (Phase 1 sign-off; worst seed, not mean)

| Metric | Tier 1 | Tier 2 | Tier 3 | Severity on miss |
|---|---|---|---|---|
| TTD, hard failures | ≤ 60 s | ≤ 90 s | ≤ 120 s | MEDIUM → HIGH on 2nd nightly |
| TTD, silent degradation | ≤ 10 min | ≤ 10 min | ≤ 15 min | MEDIUM |
| Lead time, ramps | ≥ 5 min | ≥ 5 min | ≥ 5 min | MEDIUM |
| Detection recall | ≥ 0.95 | ≥ 0.95 | ≥ 0.90 | MEDIUM |
| Detection precision | ≥ 0.90 | ≥ 0.85 | ≥ 0.80 | MEDIUM |
| Prediction recall (ramps) | ≥ 0.80 | ≥ 0.80 | ≥ 0.70 | MEDIUM |
| Prediction precision | ≥ 0.70 | ≥ 0.70 | ≥ 0.60 | MEDIUM; **R41 automation gate** separately requires ≥ 0.75 / recall ≥ 0.60 at 15 m before `"0.60"` automates on tiers 2–3 |
| False-failover rate | 0 automatic | ≤ 2 % | ≤ 5 % | HIGH |
| Missed-failover rate | 0 | ≤ 2 % | ≤ 5 % | HIGH |
| RTO attainment (D23, R38) | 100 % in 15 min | ≥ 98 % in 1 h | ≥ 95 % in 4 h | HIGH |
| Approval-gating correctness | 100 % | — | — | **CRITICAL** |
| Explainability completeness (Σ penalty = 100 − score ± 1, every factor explained) | 100 % | 100 % | 100 % | **CRITICAL** |
| Isolation leaks | 0 | | | **CRITICAL** |
| S-07 automated failovers per run | exactly 1 | | | tuning target |
| S-24 alerts above `info` | 0 | | | precision denominator |
| Unverdicted backlog created | reported, not gated | | | personas drain it |

Edge rules: an alert before the labelled precursor is an FP; suppressed member alerts count once at provider scope for precision but each agent's label needs its own match for recall; cooldown re-fires count as one TP, reported as "re-fires"; `unsure` excluded from agreement and training; any northstar alert is an isolation failure first.

### 8.4 Regression suite and CI budget

| Layer | Asserts | Runs | Budget |
|---|---|---|---|
| Golden outputs | canonicalised `health_snapshot` series, alert set, transition set per scenario/seed; tolerances score ±2, factor value ±5 %, ±1 tick; new rule/factor key = deliberate golden update with reason (R50) | PR smoke / nightly all | 12 / 90 min |
| Contract tests | `sibyl-health/1`, `sibyl-feature-snapshot/1`, `sibyl-event/1`, `sibyl-handoff/1` conformance; `source` matches `rules/v\d+` in Phase 1; `probability` absent unless model; `horizons` has 15m/1h/24h | PR | 2 min |
| Rule unit tests | each rule as a pure function over `agent_window_stats`: edges, `min_samples`, hysteresis, cooldown, escalation; fixtures generated from the seed YAML so a threshold edit without a test edit fails | PR | 1 min |
| Property tests | score monotone in each penalty; Σ penalty = 100 − score; weights ≤ 1; deterministic snapshot; no two rule transitions within `cooldown_s` | PR | 2 min |
| Isolation | S-21/S-22 + RLS fuzz over harness data | PR | 4 min |
| Nightly soak | S-24 60 min @ 200 calls/s + seeded chaos draw; no `events_rejected`, no duplicate `call_id`, worker lag < 2 ticks, aggregate growth within budget | nightly | 60 min |
| Drill replay | S-01, S-11, S-26 through `continuity_plan.drill_schedule` | weekly | 15 min |

PR total ≤ 20 min on 4 vCPU; nightly ≤ 3 h; 8 parallel compose stacks for the full suite (one Postgres each). Flake policy: a one-seed failure is quarantined with a ticket, never silently retried; three quarantines in a week block release. Nightly publishes `sibyl-sim/reports/<date>.md` with the gate table, golden diffs, tuning drift and persona-loop stats. Repository layout per qa §4.3 (`sim/`, `oracle/`, `scenarios/`, `golden/`, `reports/`, `tests/`); `sibyl-sim` depends on `sibyl-sdk` and `sibyl-schemas` only.

### 8.5 Phase 2 promotion gate (per horizon; R42)

1. Shadow ≥ 14 days or ≥ 3 nightly suites, whichever longer; API keeps serving `rules/v1`.
2. Verdict sample: ≥ 300 verdicted alerts, ≥ 50 per tier, ≥ 30 per claimed `failure_mode`, ≥ 100 `fp`; `unsure` and null excluded. Below these the gate is closed and the model ships `abstained=true` only.
3. Non-inferiority on every §8.3 row at the worst seed, plus superiority on one of: lead time (+ ≥ 3 min median on ramps), prediction precision (+ ≥ 0.10), or coverage of a failure mode rules cannot see (S-08–S-10).
4. ai-engineer's deltas also hold: precision at `"0.60"` ≥ rules + 5 points with recall ≥ rules − 2, or recall + 10 at equal precision; median lead time ≥ rules; Brier ≤ rules' pseudo-Brier.
5. Calibration: ECE ≤ 0.08; the `"0.90"` band's realised rate ≥ 0.80 or the model may not emit `"0.90"`.
6. Abstention ≤ 30 % in shadow (usefulness floor), ≤ 20 % for promotion.
7. Explainability parity: model factors populate `factors[]` with `kind='leading'` and explanations; completeness stays 100 %.
8. Rollback switch `SIBYL_PREDICTION_SOURCE=rules/v1` tested in the promotion run.
9. Tier staging: tier 3 first, tier 2 after two more nightlies, tier 1 last (approvals only).
10. A human promotes (audited) after the model card is generated.

`rules/v1` goldens are the permanent fallback baseline; model goldens are versioned per `model/<name>:<ver>`.

### 8.6 Personas and the verdict loop (D29)

- **On-call Operator** (operator): claims the queue, approves/denies per `tier_gate` (S-03 approve at +4 min; S-26 deny once), closes alerts with `tp` where a label overlaps, `fp` for S-16/S-24 noise, `unsure` for S-18; one deliberate close without a verdict per run must hit 422 `verdict_required` (D24).
- **Platform Admin** (engineer): `undo` in S-20, `fail_back` in S-25, self-approval 409 in S-26, a mid-run `alert_rule` edit variant of S-04 (`overridden=true`, golden diff), drains the D33 unverdicted queue.
- **Compliance Auditor** (auditor): every automated transition, approval, verdict and undo has an audit row; `hold_forced_d22` present in S-27; label rows readable, writes refused (403); every `factor.explanation` ≤ 300 chars and names a threshold.

Asserted: verdicted share ≥ 90 %, backlog drained to 0, zero Compliance Auditor writes, label agreement with ground truth ≥ 95 %. The On-call Operator decides from `alert` + `health_snapshot` only, so low agreement means the alert payload or `what_to_do` template is confusing and gets fixed before a real operator sees it. The Phase 2 loader runs dry against the harness database every nightly and reports row counts, so verdict-flow regressions are caught months before training.

---

## 9. Observability of the scoring layer and runbook hooks

### 9.1 Scoring-layer SLIs (sre §5; `sibyl_*` metrics, `agent_id` never a label)

| SLI | Metric | Phase 1 SLO (business hours, D18) |
|---|---|---|
| Tick cadence | `sibyl_health_tick_duration_seconds`, `_skipped_total` | p95 < 2 s; 0 skipped/hour for tenants ≤ 200 agents |
| Scoring staleness | `sibyl_health_snapshot_age_seconds{tier}` | 99.9 % of agent-minutes < 60 s; tier-1 max < 30 s |
| Worker lag | `sibyl_rules_cursor_lag_seconds`, `_stream_lag_events` | p95 < 15 s, p99 < 60 s; **stuck > 5 min = page (R47)** |
| Detection latency | `sibyl_detection_latency_seconds{tier,kind}` | p95 < 90 s, p99 < 120 s |
| Aggregate freshness | `sibyl_metrics_1m_close_delay_seconds` | p95 < 20 s |
| Late/dropped evidence | `sibyl_events_late_total`, `sibyl_rules_events_ignored_total{reason}` | late share < 1 % |
| Observation coverage | `sibyl_health_low_coverage_agents{tier}` | 0 tier-1 agents < 0.8 for > 10 min outside onboarding |
| Rule-set drift | `sibyl_rule_fire_rate{rule_code,tier}` vs 14 d median; `sibyl_rule_precision{rule_code}` | within 3× median; precision ≥ tier target |
| Feature drift | `sibyl_feature_psi{feature,tier}` | PSI < 0.2 on weighted features; > 0.25 ⇒ `*_vs_baseline` factors `confidence=low` |
| Prediction calibration | `sibyl_prediction_band_outcomes_total{band,horizon,tier,outcome}` | realised rate within band nominal ± 0.15 at 15 m (the R41 gate) |
| Verdict debt | `sibyl_alerts_unverdicted_ratio` | < 20 % |
| Saga health | `sibyl_failover_saga_duration_seconds{kind,tier}`, `_stuck_total` | p95 < 30 s; 0 stuck unalerted |

Sibyl's own SLOs (consolidated with Step 2): gateway p95 added latency < 15 ms, 99.9 %, 100 % fail-open conformance (24×7); rule engine detection p95 < 90 s and 99.9 % agent-minutes < 60 s (business hours); failover propagation < 5 s p95, ≥ 95 % terminal in 60 s, 0 stuck; console 99.5 %, p75 < 2 s; backups RPO 1 min, weekly restore test. SLIs are measured 24×7 and shown as "measured 24×7, responded business hours". **Cause-based pages are four (R47):** snapshot stale, WAL archiving failing, disk > 85 %, `SibylRulesCursorStuck` (> 5 min). Everything else goes to the inbox.

```yaml
# ops/prometheus/rules/rules-engine.yml (excerpt)
- alert: SibylRulesCursorStuck
  expr: max(sibyl_rules_cursor_lag_seconds) > 300
  for: 2m
  labels: {severity: page, runbook: rules-engine-stalled}
- alert: SibylTier1HealthStale
  expr: max by (tenant) (sibyl_health_snapshot_age_seconds{tier="1"}) > 60
  for: 5m
  labels: {severity: warning, runbook: rules-engine-stalled}
```

### 9.2 RTO/RPO verification and drills (sre §4; D23, R38)

RTO per incident = first breaching `observed_at` (or first `failed` tick) → agent on a viable route **or** every in-flight task `queued` for handoff; time-to-claim is a separate business-hours SLI. RPO = `checkpoint_age_p95_s` at cut vs `rpo_s`; packet `fidelity ≥ checkpoint`.

| Tier | RTO default (D23/R38) | RPO default (R38) | RTO attainment SLO | Time-to-claim (business hours) |
|---|---|---|---|---|
| 1 | 900 s | 60 s | ≥ 99 %; 100 % within 2 × RTO or Sev1 | p90 < 30 min |
| 2 | 3600 s | 300 s | ≥ 97 % | p90 < 2 h |
| 3 | 14400 s | 900 s | ≥ 95 % | p90 < next business day |

Internal budget: MTTD p95 < 90 s + saga p95 < 30 s + propagation p95 < 5 s ≈ 2 min of a 15-min tier-1 RTO; the approval timeout (600 s, R39) is acceptable only because the predicted path starts before failure, and the console warns when `approval_timeout_s > 0.5 × rto_s`.

Drills run by the worker as `failover(kind=drill)` + `label(kind=failover_outcome, labeller=worker, reason="drill:<name>")`: **shadow RTO** (validate → viability → vaulted credential resolution → 1-call probe per step → no-op snapshot bump; t1 daily, t2 weekly, t3 monthly), **live canary failover** (10 % for 5 min then fail back; t1 monthly announced, t2 quarterly, t3 opt-in), **handoff drill** (packet from latest checkpoint into the queue; t1 monthly, t2 quarterly), **restore + replay** (last 24 h of snapshots through current rules, zero divergence; weekly). The scorecard (`rto_met`, `rpo_met`, per-step viability, `readiness_score`) feeds `continuity_unverified` (L7) so unverified continuity enters the health score honestly.

### 9.3 Weekly alert-quality review (30 min, one operator, Monday)

1. Clear `verdict_wanted` queue first, then the rest; debt < 20 %.
2. Rule fire-rate drift outside 3× median → provider incident or seed bug.
3. Precision per rule/tier vs targets; two weeks below → demote (audited `config.changed`).
4. False-failover budget pace; breaker state and contributing rules.
5. `"0.60"` realised rate at 15 m; outside ± 0.15 for 2 weeks → gate back to `"0.90"` (R41).
6. Tier-1 drill coverage and readiness.
7. Sibyl's own SLOs; anything that fired twice without action is deleted or demoted.
8. Toil log: three repeats of the same operator action → automation or rule-change ticket.

Output: `docs/ops/alert-quality/<week>.md` plus audited config changes.

### 9.4 Runbook hooks (sre §6): what the operator sees per transition

| Transition | Operator sees | Automated action | Human actions | Runbook |
|---|---|---|---|---|
| `healthy → watch` | amber card, top-3 factors, "leading rules armed" | packet pre-assembly (tier 1) | `ack`, `silence`, evidence link | `agent-watch` |
| `watch → degraded` (detected) | `warning` row, `degraded_mode`, failover countdown, RTO clock starts | `routing_apply(degraded)` | `recover`, `failover`, `handoff`, `ack` | `agent-degraded` |
| prediction ≥ `"0.60"` @15 m, tiers 2–3 | badge "predicted: <mode> in ~15 m (rules/v1, medium)", contributing rules | tier 2 `degrade_then_auto` (R40), tier 3 saga opens | `undo`, `cancel`, `silence` | `agent-predicted-failover` |
| prediction ≥ `"0.60"` @15 m, tier 1 | approval card: target step, evidence, 600 s countdown, timeout policy incl. `hold (forced, D22)` | saga `waiting_approval`, packet pre-assembled | `approve`/`deny` (decider ≠ requester), `cancel` | `agent-approval` |
| approval timeout | "timed out → hold" / "→ fail-safe executed" | per policy; D22 forces `hold` | `failover`, `recover` | `agent-approval` |
| `degraded → failed_over` (detected, auto) | `critical`, incident banner with tasks continued/handed off, live RTO attainment | saga done; `handoff_task`s queued | `undo` (30-min hold follows), `fail_back`, `handoff`, `quarantine`, `kill` | `agent-failed-over` |
| tier-1 `failed` + backup-agent step | above plus approval card for the backup hop | alt-model/provider automatic; backup waits | `approve`/`deny` | `agent-approval` |
| `failed_over → failing_back` | ramp bar 10 → 100 %, canary metrics beside primary | canary saga | `cancel`, `fail_back` force | `agent-failback` |
| canary breach | "reverted at 25 %; next probe in 10 min"; after 2nd: "automated failback suspended" | revert, backoff | `fail_back`, `handoff` | `agent-failback` |
| flap detected | `flapping` alert with transition list; "pinned at <band> for 15 min" | flap hold (R48 direction by tier) | `recover` (human bypass), release pin | `agent-flapping` |
| provider incident | fleet card "provider A: N agents, k pending approval"; members collapsed | batched sagas | per-agent actions; single verdict later | `provider-incident` |
| `undo` | "undone by <user>: <reason>; automation paused until hh:mm"; `hold_suppressed_count` | hold set; packets returned | `clear_hold` | `agent-undo` |
| auto-resolve | alert in "resolved — verdict needed" (sorted `verdict_wanted` first); `outcome_observed` | resolve | one-time `close` with `tp/fp/unsure` | `alert-verdict` |
| provisional / low coverage, tier 1 | grey card "not enough signal (34/50, coverage 0.6)", `continuity_unverified` if overdue | none | onboarding checklist; run shadow drill | `agent-onboarding` |
| cursor lag / stale scores | header strip "detection delayed ~N s; automation on last known state"; `/status` `rules-engine: degraded` | gateway continues on snapshot | operator runbook | `rules-engine-stalled` |

---

## 10. Amendments and open items

### 10.1 DATAMODEL amendments requested by Step 5 (database-architect applies at Step 7 start; consolidated DDL in `database-architect.md` §1.3, §3, §6)

1. New tables: `agent_metrics_5m`, `provider_metrics_5m`, `agent_trend_state`, `agent_baseline`, `scoring_config`, `prediction`, `health_1h`, `agent_risk`, `rollup_job`; Phase 2 `ml_model`, `ml_prediction_shadow`; `risk_assessment`.
2. `agent_metrics_1m/1h` += the §2.6 counters (17 columns incl. `context_util_hist`).
3. `health_snapshot.scoring_config_id`; write cadence changed to on-change + 60 s heartbeat (db Q1, §10.4).
4. `feature_snapshot.doc` → BlobStore with ≤ 2 KB in-row summary; 90-day sample sweep (R49).
5. `payload_refs.kind` += `model_artifact`, `model_card`, `feature_snapshot` (export class `source_kind='export'`).
6. `alert_rule.scope` += `platform`; seed rows for R6–R8, L6 (R37), `heartbeat_missing`, `continuity_unverified`, `quality_proxy`, `tool_loop`, `drift_cusum`, `context_saturation`, `credential_expiry`, `model_deprecation`.
7. `continuity_plan`: RTO/RPO defaults `rto_s = 900/3600/14400`, `rpo_s = 60/300/900` (R38); `preemptive_mode ∈ {approval, degrade_then_auto, auto}` seeded by tier (R40).
8. `label.label_strength ∈ {verdict, outcome, provider_feed}` (R42); `alert.verdict_wanted boolean`; partial index `ix_alert_unverdicted` for the D33 queue.
9. `alert_rule.thresholds` carries per-tier `hysteresis_in/out`, `cooldown_s`; dead-band widths and band edges live in `scoring_config.config`.
10. Step 4 amendments carried (db §6): `idempotency_record`, `ingest_batch_seen`, `tenant.ingest_rate_limit`, `events_rejected.reason` += `env_mismatch|agent_not_permitted`, `audit_anchors.kind` += `break_glass`, `api_key.scopes` CHECK re-enumerated to the R21 catalogue with `killswitch:pull` exclusive and tenant-level, `tenant.backup_retention_days` default 7 (R30).

### 10.2 API amendments

- `GET /agents/{id}/health?verbose=1` (zero-penalty factors included).
- `GET /agents/{id}/risk-assessment` (additive; §6.2).
- `GET /audit/export?include=health_decisions`.
- Console warning when `approval_timeout_s > 0.5 × rto_s` (R39); `threshold_suggestion` note on alert-rule page (§3.9); dry-run replay on tier-1 threshold edit (R50).
- SDK CLI: `sibyl replay`, `sibyl ml export`, `sibyl rules promote`, `sibyl audit verify` (R33).

### 10.3 Rulings applied (SYNTHESIS R37–R50)

R37 quality rules R6–R8/L6 · R38 RTO/RPO defaults · R39 approval timeout 600 s + warning · R40 tier 2 `degrade_then_auto` · R41 `"0.60"` automation gate is a release criterion · R42 verdict floors, weak labels with `label_strength`, no auto-verdicts · R43 no cross-tenant signal or pooling · R44 asyncpg · R45 no product clock override · R46 `sibyl-sim` dev-only · R47 fourth page `SibylRulesCursorStuck` · R48 tier-3 flap pin at better band · R49 feature snapshot to BlobStore, 5m materialised, sparse predictions · R50 golden/threshold ownership.

### 10.4 Editor reconciliations for the chair to confirm (not in SYNTHESIS)

1. **Score shape**: ai-engineer's penalty arithmetic (`100 − Σ penalty`, caps per tier) is canonical because qa's explainability gate and the frozen `factor` contract require it; sre's six SLI families are the grouping and SLO layer over it. Band edges are sre's tier-specific values with a +4 upward dead-band.
2. **Rule numbering**: Step 3 codes R1–R5/L1–L5 stay canonical (as R37 presumes); sre's renumbered table is mapped; sre's extra rules become `heartbeat_missing` (R9) and `continuity_unverified` (L7). `quality_proxy` is one score penalty taking the max of R6–R8 so quality is never double-counted.
3. **Seed thresholds**: ai-engineer's values are the seed; sre's tighter alternatives are the second tuning candidate in the harness.
4. **`health_snapshot` write-on-change + 60 s heartbeat** (database-architect Q1 default) adopted; it changes R17 from "every tick" to "on change", which the read contract already tolerates.
5. **Abstention**: ≤ 30 % shadow usefulness floor (qa), ≤ 20 % promotion bar (ai-engineer).
6. **Counter names**: database-architect's spellings win (`tool_schema_invalid_count`, `retry_count`, `context_util_hist`).

## Next
Step 6, phased roadmap: sprint-prioritizer leads, project-shipper on launch readiness, chief-architect on sequencing risk, product-manager on scope cut lines. Waits for the founder's review of Step 5.
