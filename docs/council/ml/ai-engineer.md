# AI Engineer: ML approach (Step 5) — features, health score, prediction rules, Phase 2 learned layer

Product: Sibyl. Date: 2026-10-10. Role: lead for Step 5. Inputs: `docs/council/ml/CHAIR-INITIAL.md` (followed as written), `DECISIONS.md` D1–D35, my Step 3 §6 (frozen contract: `sibyl-health/1`, `sibyl-feature-snapshot/1`, `HealthPredictor`), `DATAMODEL.md` §2.3/§2.5/§4.3/§4.5/§6.2, `API.md` §4–§6, backend-architect's Step 3 seed table (R1–R5, L1–L5; bands healthy ≥ 80, watch ≥ 60, degraded ≥ 30, failed < 30; provisional under 50 calls/h).

Governing rule for this step: **nothing in Phase 1 is learned, everything in Phase 1 is replayable, and Phase 2 must fit the contract without an API change.** The `prediction` object, the `factor` object and `FeatureSnapshot` are already frozen; this document says what fills them, from which columns, with which arithmetic, and how a model later takes over one horizon at a time behind the same shape.

Where I reuse a name from an earlier step it is unchanged (rule ids, grain keys, band names, `failure_mode` enum). Where I add a feature key it is additive under `features/v1` (§1.8 lists the additions). Schema ids are `https://sibyl.dev/schemas/...` per D19; `vigil*` identifiers from Step 3 are to be read as `sibyl*`.

---

## 1. Feature catalogue

Features are computed by the worker from Postgres aggregates only (chair §5): `agent_metrics_1m` for windows 1m/5m/15m/1h, `agent_metrics_1h` for baselines, plus narrow reads of `events` for event types that are not counters (`tool.call`, `agent.invoke`, `task.outcome`, `feedback`, `checkpoint`, `policy.decision`, `observation.gap`) and registry tables for static facts. No feature reads `payload_refs` or any content (R19); output-quality proxies are metadata-only by construction.

Notation. `W` ∈ {1m, 5m, 15m, 1h} is the grain; `Σ_W` sums 1 m rows in the window ending at the last closed minute (leading rules) or including the open minute (detected rules, R6 read contract). `baseline(k)` is §1.6. A key with `_vs_baseline` suffix is `value / baseline`, `null` when no baseline. Every feature is `number | null`; `null` means not computable in that grain (contract), never zero.

### 1.1 Per agent, per window (the core SLIs)

| Feature key (`grains.W.*`) | Formula | Source columns | Rules/consumers |
|---|---|---|---|
| `request_count` | `Σ request_count` | `agent_metrics_1m.request_count` | min_samples gate, provisional |
| `error_rate` | `Σ error_count / Σ request_count` | `error_count`, `request_count` | R1, L1, score |
| `error_rate_429` | `Σ rate_limit_count / Σ request_count` | `rate_limit_count` | L3 (`share_429`) |
| `error_rate_5xx` | `Σ server_error_count / Σ request_count` | `server_error_count` | provider_outage attribution |
| `error_rate_timeout` | `Σ timeout_count / Σ request_count` | `timeout_count` | latency_degradation attribution |
| `error_rate_blocked` | `Σ blocked_count / Σ request_count` | `blocked_count` | policy_violation / permission_error attribution |
| `consecutive_errors` | run length of trailing `status='error'` calls | `events` last 10 rows `(tenant_id, agent_id, ts DESC)`, `status` | R3 |
| `latency_p50_ms` / `latency_p95_ms` / `latency_p99_ms` | `hist_quantile(hist_sum(latency_hist), q)` | `latency_hist` | R2, L2, score |
| `ttfb_p95_ms` | same over `ttfb_hist` | `ttfb_hist` | streaming stall signal |
| `latency_p95_vs_baseline` | `latency_p95_ms / baseline(latency_p95_ms)` | + `agent_metrics_1h` | L2 normalisation, Phase 2 |
| `tokens_in_mean` / `tokens_out_mean` | `Σ tokens_in / Σ request_count`, same for out | `tokens_in`, `tokens_out` | output-quality proxies, cost |
| `tokens_out_cv` | coefficient of variation of `tokens_out` across the window's 1 m means | `tokens_out`, `request_count` per row | quality_collapse proxy (§1.4) |
| `cost_usd` | `Σ cost_usd` | `cost_usd` | R5, L4 |
| `cost_slope` | §3.1 EWMA slope of per-minute `cost_usd` | `cost_usd` | cost_runaway |
| `ratio_429` | alias of `error_rate_429` kept for `features/v1` compatibility | — | L3 |
| `retry_mean` | `Σ attrs.retry.attempt / Σ request_count` | needs new counter `retry_attempt_sum` (§1.8) | retry-storm signal |
| `inline_fallback_ratio` | `Σ inline_fallback_count / Σ request_count` | `inline_fallback_count` | L5 |
| `breaker_open_ratio` | `Σ breaker_open_count / Σ request_count` | `breaker_open_count` | L5 |
| `ratelimit_headroom_min` | `min(ratelimit_remaining_min) / limit` | `ratelimit_remaining_min`; `limit` from last event `attrs.ratelimit.limit_*` | L3 |
| `policy_stale_ratio` | `Σ policy_stale_count / Σ request_count` | `policy_stale_count` | observation quality, ADR-9 audit |
| `late_ratio` | `Σ late_count / Σ request_count` | `late_count` | observation coverage |
| `route_changes` | count of `routing_transition` rows in W | `routing_transition(tenant_id, agent_id, created_at)` | flap detection |

`consecutive_errors` is the only per-agent SLI that reads `events` on the hot tick; it is bounded (`LIMIT 10`, indexed) and only consulted when `error_rate(1m) > 0`.

### 1.2 Per model and per provider (shared context, computed once per tenant tick)

These are the same SLIs as §1.1 grouped by `(provider, model)` and by `provider` across all agents of the tenant. They are not stored in the agent's `grains` map (which stays per agent); they are joined into the agent snapshot as `_fleet` suffixed keys so a single agent's blip is distinguishable from a provider-wide incident.

| Feature key | Formula | Source | Consumer |
|---|---|---|---|
| `provider_error_rate_fleet` | tenant-wide `error_rate(5m)` over agents on the same primary provider | `agent_metrics_1m` grouped by `provider` | R4 corroboration, provider collapse |
| `provider_latency_p95_fleet_ms` | tenant-wide p95(5m) on the provider | same | provider_outage vs single-agent attribution |
| `provider_429_fleet` | tenant-wide 429 share on the provider | `rate_limit_count` | shared rate-limit pool detection |
| `model_error_rate_fleet` | same by `(provider, model)` | same, grouped by model | model-specific degradation |
| `provider_agents_degraded_fleet` | count of agents on the provider with band ∈ {degraded, failed} this tick | in-memory tick state | collapse threshold (≥ 2) |
| `provider_status_code` | ordinal of `provider_status.status`: operational 0, maintenance 1, degraded_performance 2, partial_outage 3, major_outage 4, unknown null | `provider_status` latest row per `(tenant_id, provider_id)` | R4 |
| `provider_status_age_s` | `now − observed_at` | `provider_status.observed_at` | confidence |
| `provider_probe_latency_ms` | last probe latency when `source='probe'` | `provider_status.raw.probe_latency_ms` | R4 corroboration |

Fleet features are per tenant by construction (RLS); there is no cross-tenant provider aggregate in Phase 1 (open question Q1).

### 1.3 Per tenant (budget and estate context)

| Feature key (`static.*` or tenant map) | Formula | Source | Consumer |
|---|---|---|---|
| `budget_headroom` | `1 − month_to_date_cost / continuity_plan.budget_usd_month` (agent) | `agent_metrics_1h.cost_usd` since month start; `continuity_plan.budget_usd_month` | R5, L4 |
| `budget_burn_1h` | `Σ cost_usd(1h) × 24 × days_remaining / budget` | same | L4 projection |
| `tenant_budget_headroom` | tenant-level analogue when `tenant.budget_usd_month` exists | tenant row (if added; else null) | fleet view |
| `tenant_open_alerts` | count of `alert.state <> 'resolved'` | `alert` | alert-budget fatigue control (§2.6) |
| `tenant_provider_concentration` | share of tier-1 agents whose primary provider is the dominant one | `agent`, `agent_version.primary_model_id → model → provider` | concentration-risk finding (governance, not health) |

### 1.4 Output-quality proxies (metadata only, chair §6)

No content is read. Each proxy is a ratio over `gen_ai.request` or `tool.call` events in W and compares against baseline.

| Feature key | Formula | Source | Failure mode it informs |
|---|---|---|---|
| `finish_length_ratio` | share of calls whose `finish_reasons` contains `length`/`max_tokens` | `events.attrs.finish_reasons` (new counter `finish_length_count`, §1.8) | quality_collapse (truncation), context_saturation |
| `finish_content_filter_ratio` | share with finish reason `content_filter`/`refusal`/`safety` | same attr (new counter `finish_filtered_count`) | policy_violation, prompt_injection |
| `finish_tool_calls_ratio` | share with finish reason `tool_calls`/`tool_use` | same | tool-loop detection with `tool_seq_repeat_ratio` |
| `empty_output_ratio` | share with `tokens_out = 0` or `output_chars = 0` on `status='ok'` | `events.tokens_out`, `attrs.output_chars` (new counter `empty_output_count`) | quality_collapse, silent_drift |
| `output_chars_mean` / `output_chars_vs_baseline` | mean `attrs.output_chars` | `attrs.output_chars` (new column `output_chars_sum`) | silent_drift (length collapse or explosion) |
| `tokens_out_vs_baseline` | `tokens_out_mean / baseline` | §1.1 | silent_drift |
| `context_utilisation_p95` | p95 of `attrs.context.utilisation` | new hist `context_util_hist` (10 buckets) or `max` column | context_saturation (registered rule id) |
| `tool_call_count` | `Σ tool_call_count` | `agent_metrics_1m.tool_call_count` | infinite_loop, tool_failure |
| `tool_error_rate` | `tool.call` rows with `status='error'` / all `tool.call` rows in W | `events WHERE event_type='tool.call'` (new counters `tool_error_count`) | tool_failure, data_source_failure (by `tool.kind`) |
| `tool_seq_repeat_ratio` | share of consecutive identical `(tool_name)` pairs within a task | `events.attrs.tool_name` per `task_id`, last 50 tool calls per open task | infinite_loop |
| `tool_seq_entropy` | Shannon entropy of the tool-name bigram distribution over W, normalised by log(#bigrams) | same | infinite_loop (low), silent_drift (shift vs baseline) |
| `schema_validation_fail_ratio` | tool calls whose `error_type` ∈ {`schema_validation`, `invalid_arguments`, `ValidationError`} / tool calls | `events.error_type` for `tool.call` (new counter `tool_schema_fail_count`) | quality_collapse (malformed tool arguments is the strongest metadata-only quality signal we have) |
| `task_steps_p95` | p95 of `agent.invoke(phase=end).attrs.steps` | `events` type `agent.invoke` | infinite_loop |
| `checkpoint_age_p95_s` | p95 of `now − last checkpoint.created_at` over open tasks | `checkpoint(tenant_id, agent_id, created_at DESC)` | packet fidelity, stuck tasks |
| `undeclared_tool_ratio` | tool calls naming a tool not in `agent_identity.allowed_tools` | `events.attrs.tool_name` × `agent_identity.allowed_tools`, or `policy.decision(action='tool_blocked')` | permission_error, prompt_injection (behaviour change) |
| `undeclared_data_source_ratio` | calls with `attrs.data_source_ids` not in `agent_version.declared_data_source_ids` | same shape | data governance (risk §6), silent_drift |

LLM-as-judge quality scores are **Phase 2, tenant opt-in** (chair §6). When enabled they arrive as `feedback` events with `rater='judge'` and flow through §1.5 unchanged; no separate feature path.

### 1.5 Feedback and outcome events (labels and slow features)

| Feature key | Formula | Source | Role |
|---|---|---|---|
| `task_count` | `agent.invoke(phase=end)` rows in W | `events` | denominator |
| `task_success_rate` | `task.outcome.outcome='success'` / `task.outcome` rows in W | `events.attrs.outcome`, or `label(kind='task_outcome')` | quality baseline, Phase 2 label |
| `task_failure_rate` | `outcome ∈ {failure, abandoned}` share | same | quality_collapse |
| `cost_per_task_usd` | `cost_usd(W) / successful tasks` | §1.1 + above | cost_runaway, exec view |
| `feedback_mean` / `feedback_count` | mean `score` normalised to [−1, 1] | `events.attrs.feedback.score, scale` / `label(kind='feedback')` | quality baseline |
| `feedback_negative_ratio` | `score < 0` share | same | quality_collapse |
| `handoff_count` / `handoff_rate` | `handoff.requested` rows / tasks | `events`, `handoff_task` | escalation rate (brief §3) |
| `handoff_returned_ratio` | `handoff.returned` / `handoff.completed + returned` | `handoff_task.outcome` | packet usefulness, operator load |
| `alert_fp_rate_30d` | fp verdicts / verdicted alerts, per agent, 30 d | `alert.verdict`, `label(kind='alert_verdict')` | per-agent threshold adaptation (§2.7), fatigue SLI |
| `failover_success_rate_90d` | `fallback_succeeded=true` share | `label(kind='failover_outcome')` | continuity readiness, recommended_action |

These are slow (minutes to days) and sparse; they feed baselines and Phase 2 labels more than the 10 s tick. They are computed on the 1 m tick only when the relevant event types appeared in the dirty set.

### 1.6 Baselines (what "normal" means)

Baseline is per `(tenant, agent, feature, hour_of_week)`: the **median of the same hour-of-week over the trailing 4 weeks** from `agent_metrics_1h`, falling back to the trailing-7-day median when fewer than 2 same-hour samples exist, falling back to the peer group (§2.5) when the agent is younger than 7 days, falling back to seed constants. `baseline_ref` in the snapshot records which tier was used: `own/how4w`, `own/7d`, `peer/<group>`, `seed/v1`. Robust scale is the MAD of the same samples (`σ̂ = 1.4826 × MAD`), floored at 5 % of the median so a perfectly flat history cannot produce infinite z-scores.

Baselines are recomputed hourly per tenant (one query over `agent_metrics_1h`, 13 months retained) into a worker-held cache keyed by `(agent_id, feature)`; they are not persisted as a table in Phase 1 because they are a pure function of `agent_metrics_1h` and can be rebuilt in seconds. Windows inside an `observation.gap` are excluded from baseline samples (Step 3 §1).

### 1.7 Static features (`static.*`, registry facts at `as_of`)

Already in the frozen schema: `tier`, `provider`, `model`, `fail_mode`, `routing_state`, `breaker_state`, `provider_status`, `budget_headroom`, `model_context_limit`, `days_to_model_deprecation`, `days_to_credential_expiry`, `hour_of_day_utc`, `day_of_week_utc`, `agent_age_days`, `peer_group`. Sources: `agent.tier/fail_mode`, `routing_state.state`, last `attrs.retry.breaker_state`, `provider_status.status`, `model.retires_on`/`model_catalog.retires_on`, `provider_credential.expires_at` (fallback-target credentials, D11), `agent.created_at`, `model_catalog.context_window`.

### 1.8 Additions needed from database-architect (additive, `features/v1`)

To compute §1.4 without scanning `events` every tick, `agent_metrics_1m` needs seven more counters and one sum, all recomputed by the existing §6.2 replace-not-add rollup: `finish_length_count`, `finish_filtered_count`, `finish_tool_calls_count`, `empty_output_count`, `tool_error_count`, `tool_schema_fail_count`, `retry_attempt_sum`, `output_chars_sum`, plus `context_util_max numeric(4,3)`. `tool_call_count` already exists. `tool_seq_*`, `task_steps_p95`, `checkpoint_age_p95_s`, `consecutive_errors` stay as bounded `events`/`checkpoint` reads (indexed, `LIMIT`-ed). New feature keys registered under `features/v1`: `error_rate_blocked`, `breaker_open_ratio`, `late_ratio`, `finish_content_filter_ratio`, `empty_output_ratio`, `output_chars_vs_baseline`, `tokens_out_vs_baseline`, `schema_validation_fail_ratio`, `task_failure_rate`, `feedback_negative_ratio`, `undeclared_tool_ratio`, `undeclared_data_source_ratio`, `*_fleet` keys, `ewma_*`, `cusum_*` (§3). Additive under the contract's "new feature is a new key" rule; `feature_set` stays `features/v1`.

---

## 2. Phase 1 health score

### 2.1 Shape

`score = clamp(100 − Σ_i penalty_i, 0, 100)` where `penalty_i = cap_i(tier) × severity_i`, `severity_i ∈ [0, 1]`. Each rule contributes at most its cap; `weight_i = cap_i / 100` is what the frozen `factor.weight` carries, `factor.penalty` carries `penalty_i`. The sum is capped at 100, and the capping is recorded (§2.4) so an auditor can see when more than one rule was saturated. No multiplication of rules, no hidden interactions: a reader can add the `penalty` column of the factors list and recover the score exactly.

The 10 s tick computes the score on the 5 m grain for every detected rule and the closed-minute grains for leading rules (R6 read contract); 1 m is used for `consecutive_errors` only; 15 m and 1 h appear in the snapshot for trends and Phase 2 but do not enter the Phase 1 score.

### 2.2 Normalisation: severity curves

Severity is a piecewise-linear function of the measured value `x` against the rule's threshold `t` and a saturation point `s`:

- `above` rules (error rate, latency, shares): `severity = clamp((x − t) / (s − t), 0, 1)`; default `s = 3t` for rates and shares, `s = 2t` for latency. Below threshold the rule contributes zero; at 3× the threshold it contributes its full cap.
- `below` rules (headroom): `severity = clamp((t − x) / t, 0, 1)` so headroom 0 is full severity.
- ordinal rules (provider status): table lookup, `degraded_performance 0.33`, `partial_outage 0.58`, `major_outage 1.0`, `maintenance 0.15`, `unknown 0` (penalties 20/35/60 against the seed cap of 60 reproduce backend-architect's per-status penalties exactly).
- count rules (consecutive failures): `severity = clamp((n − t + 1) / t, 0, 1)` (at `t` failures the rule is already at 1/t severity... no: at `n = t` severity is 1/t; at `n = 2t − 1` it is 1). Corrected: `severity = clamp((n − t + 1) / t, 0, 1)` gives severity 1/t at the first firing and full at `2t − 1`; R3 keeps severity 1.0 at `n ≥ 2t − 1`. Because R3 carries `severity=critical`, band is forced to at least `degraded` while R3 fires regardless of score (§2.4 band floor).
- boolean rules: 0 or 1.

Thresholds come from `alert_rule.thresholds` by tier or model class; everything is per-tenant data, so operators tune `t` and `s` without a release. Latency thresholds use model class (`small 5000, large 20000, reasoning 60000`) from the seed; a tenant whose agents stream can switch R2 to `ttfb_p95_ms` by editing `alert_rule.metric`.

Baseline-relative variant: for R2 and L2 the normaliser also computes `x_rel = latency_p95_vs_baseline` and takes `severity = max(sev_abs, sev_rel)` with `t_rel = 2.0`, `s_rel = 4.0` once the agent has an `own/*` baseline. Absolute thresholds catch "slow for everyone"; relative thresholds catch "slow for this agent". Which one dominated is written in `factor.explanation`.

### 2.3 Default caps per tier (`cap_i(tier)`)

Caps are the seed `penalty` values, scaled per tier. Tier 1 is punished harder for the same evidence because the cost of missing is higher and D13 already gates its predicted failovers behind approval, so a lower score there mostly costs an approval request, not a traffic shift.

| rule_id | kind | cap tier 1 | cap tier 2 | cap tier 3 | threshold by tier (seed) |
|---|---|---|---|---|---|
| `error_rate` (R1) | detected | 50 | 40 | 30 | 0.05 / 0.10 / 0.20 |
| `p95_latency` (R2) | detected | 30 | 25 | 20 | by model class |
| `consecutive_failures` (R3) | detected | 60 | 50 | 40 | 3 / 3 / 5 |
| `provider_status` (R4) | detected | 60 | 60 | 60 | ordinal table |
| `budget_breach` (R5) | detected | 70 | 70 | 70 | spend ratio ≥ 1.0 |
| `error_trend` (L1) | leading | 20 | 15 | 10 | §3.3 |
| `latency_trend` (L2) | leading | 15 | 10 | 8 | §3.3 |
| `ratelimit_proximity` (L3) | leading | 25 | 20 | 15 | headroom < 0.10 or 429 share > 0.05 |
| `budget_proximity` (L4) | leading | 15 | 15 | 15 | projected ≥ 0.9 within 1 h |
| `fallback_pressure` (L5) | leading | 30 | 25 | 20 | inline + breaker share > 0.20 |
| `context_saturation` (new, registered id) | leading | 15 | 12 | 10 | `context_utilisation_p95 > 0.85` |
| `quality_proxy` (new) | detected | 25 | 20 | 15 | `max(schema_validation_fail_ratio > 0.10, empty_output_ratio > 0.05, finish_length_ratio > 0.25 and vs baseline > 2)` |
| `tool_loop` (new) | detected | 30 | 25 | 20 | `tool_seq_repeat_ratio > 0.5 and tool_call_count(5m) > 20` or `task_steps_p95 > 3 × baseline` |
| `credential_expiry` (registered) | leading | 20 | 15 | 10 | `days_to_credential_expiry ≤ 7` (severity 1 at ≤ 1 day) |
| `model_deprecation` (registered) | leading | 15 | 10 | 5 | `days_to_model_deprecation ≤ 30` (severity 1 at ≤ 7 days) |

The three new rule ids (`context_saturation` was already registered; `quality_proxy` and `tool_loop` are additive registrations) ship as `alert_rule` seed rows `enabled=true, severity=warning`, `collapses_to_provider=false`, so a tenant can disable them. Caps sum far above 100 on purpose: the clamp means "several things wrong" reads as failed, which is the right reading.

### 2.4 Band, floors and the per-feature contribution output

Band from score: `healthy ≥ 80`, `watch ≥ 60`, `degraded ≥ 30`, `failed < 30` (unchanged). Two floors override the arithmetic and are recorded as factors with `kind='detected'`, `direction='equals'`:

- any `severity='critical'` detected rule firing after hysteresis ⇒ band ≤ `degraded`;
- R3 at full severity, or R4 `major_outage` corroborated by `provider_error_rate_fleet > R1 threshold`, or `error_rate(5m) ≥ 0.5` with `request_count ≥ min_samples` ⇒ band = `failed` (this is "detected failure" for D13 purposes).

Output shape is the frozen `factor`; the Phase 1 writer fills every field like this:

```json
{ "rule": "error_rate", "weight": 0.40, "penalty": 28, "value": 0.17, "threshold": 0.10,
  "direction": "above", "kind": "detected",
  "explanation": "Error rate 17% over the last 5 minutes (threshold 10%, saturates at 30%); 5xx share 0.14 points to the provider",
  "evidence": "/events?agent_id=…&status=error&from=…&to=…" }
```

Ordering: factors sorted by `penalty` desc; zero-penalty rules that were evaluated are included with `penalty: 0` only when `?verbose=1` on `GET /agents/{id}/health` (console default off, compliance export on). Two bookkeeping entries ride in `health_snapshot.factors` but are stripped from the API response: `{rule:"_clamp", penalty:<excess>}` when `Σ penalty > 100`, and `{rule:"_hysteresis", consecutive_in, consecutive_out}` per rule for restart resume (backend-architect §5). The response `score`, `factors[].penalty` and the clamp entry satisfy `score = 100 − Σ penalty + _clamp.penalty`, which the conformance test asserts on every example.

`recommended_action` is a lookup on the dominant factor and tier: `provider_status`/`error_rate_5xx`-dominant → `reroute_to_fallback`; `ratelimit_proximity` → `throttle`; `context_saturation` → `trim_context`; `tool_loop` → `quarantine` (tier 1: `await_approval`); `budget_*` → `throttle`; `quality_proxy` → `handoff` when tier 1 else `watch`; nothing firing → `none`/`watch` by band. The worker's saga then checks viability against the approved chain; the recommendation is advisory text for humans and the default action for rules.

### 2.5 Cold start and provisional

An agent is `provisional.flag=true` while `request_count(1h) < 50` **or** `observation_coverage < 0.8` **or** it has no `continuity_plan` (DATAMODEL §4.4) **or** `agent_age_days < 1`. `events_needed = 50`, `events_seen = request_count(1h)`. Provisional agents: score computed and shown greyed; detected rules fire alerts with `severity` capped at `warning`; leading rules do not fire; no rule actor may create a `failover` (the snapshot builder already refuses plan-less agents). D13 is unaffected because detected failure on a provisional tier-3 agent still routes to `human_queue` via the tenant default chain if one exists.

Peer group id = `tier:<t>|kind:<agent.kind>|pk:<provider_kind>|mc:<model class>`; model class from `model_catalog.context_window` and name heuristics (`small < 32k ctx or name matches mini|haiku|flash|8b`, `reasoning` matches `o[1-9]|reasoning|thinking|r1`, else `large`). Peer baseline = median over the tenant's agents in the same group that have an `own/*` baseline; when the group is empty the seed constants from the synthetic demo (`seed/v1`: p95 small 1200 ms, large 4000 ms, reasoning 15000 ms; error rate 0.01; tokens_out by class) apply. Cross-tenant peer groups are not computed (Q1).

### 2.6 Hysteresis, cooldown and alert budget (fatigue controls)

Per rule, per agent: `hysteresis_in=2` consecutive ticks over threshold to fire, `hysteresis_out=6` consecutive ticks under `0.8 × threshold` (a dead band, so the exit threshold is lower than the entry threshold) to clear; `cooldown_s=600` with `× 2^escalation_level` on re-fire; three resolves inside `escalate_window_s=3600` escalate severity (backend-architect §5, unchanged). Band hysteresis is separate from rule hysteresis: the **band** moves down immediately when a rule fires after its own hysteresis, and moves up only when the score has been in the higher band for 6 consecutive ticks (60 s) **and** no detected rule is firing. Band and rule states are persisted in `health_snapshot.factors._hysteresis`, so a worker restart resumes mid-count.

Dead-band on the score itself: `watch/healthy` boundary is 80 entering, 84 leaving; `degraded/watch` 60 / 64; `failed/degraded` 30 / 34. This removes oscillation when the score hovers at a boundary without changing any rule state.

Alert budget per tenant: if `tenant_open_alerts > 3 × active agents`, new `info`-severity alerts are written with `suppressed_by_incident=false, state='open'` but `severity='info'` alerts are hidden by the console's default filter and counted in the fatigue SLI (sre-engineer owns the SLI). Provider collapse (≥ 2 agents on the same provider firing a `collapses_to_provider` rule ⇒ one `provider_incident`, member alerts suppressed) is the single largest fatigue reducer and is unchanged.

### 2.7 Per-agent threshold adaptation from verdicts (rules-only "learning", Phase 1.5)

When an agent has ≥ 10 verdicted alerts on a rule in 30 d and `fp` share > 0.6, the worker proposes (never applies) a threshold raise of 25 % for that `(agent, rule)` in a `threshold_suggestion` note on the alert rule page; an operator accepts it by editing the per-tenant `alert_rule` (which sets `overridden=true`). This keeps Phase 1 free of automatic parameter drift while making the verdict loop visibly useful before Phase 2 ships.

---

## 3. Phase 1 prediction rules (filling `horizons.{15m,1h,24h}`)

### 3.1 Statistics, defined once

All on the closed-minute series of a feature `x_t` (1 m buckets), per `(agent, feature)`, state held in worker memory and persisted in `_hysteresis` alongside the rule counters.

- **EWMA level and slope.** `level_t = λ x_t + (1 − λ) level_{t−1}`, `λ = 0.3` (≈ 3 min memory). Slope = least-squares slope over the last `trend_windows × window_s` (seed: 3 × 300 s = 15 min of 1 m points), expressed per 5 min. Written as `ewma_<feature>` and `<feature>_slope` (already keyed `error_rate_slope`, `latency_p95_slope`, `cost_slope`).
- **CUSUM change-point.** On the standardised residual `z_t = (x_t − baseline) / σ̂` (§1.6): `S⁺_t = max(0, S⁺_{t−1} + z_t − k)`, `S⁻_t = max(0, S⁻_{t−1} − z_t − k)`, `k = 0.5`, decision `h = 5` (standard ARL₀ ≈ 930 samples ⇒ about one false alarm per 15 h per feature at 1 m resolution). Written as `cusum_<feature>_pos`/`_neg`; the time since the last reset gives the change-point estimate. Applied to `error_rate`, `latency_p95_ms`, `tokens_out_mean`, `output_chars_mean`, `cost_usd`, `tool_call_count`, `tool_seq_entropy`.
- **Proximity.** Time-to-exhaust `TTE = headroom / max(burn, ε)`: rate-limit `TTE_rl = ratelimit_headroom_min × limit / (requests per minute)`, budget `TTE_budget = budget_headroom × budget / cost_per_hour`, context `TTE_ctx` not time-based: use `context_utilisation_p95` directly.
- **Provider status.** Ordinal from §1.2 plus age; `major_outage` is a detected fact (R4), `degraded_performance` and `partial_outage` are leading for every agent on the provider that is not yet erroring.

### 3.2 Risk points per horizon and the probability band

Each leading rule `i` with `horizon_s = H_i` contributes risk points `r_i = severity_i × cap_i / 100` (the same severity as the score, so the health page and the risk page cannot disagree). A horizon `H` collects rules with `H_i ≤ H` **plus** detected-state carry-over: a `failed` band contributes `r = 1.0` to 15m and 1h, a `degraded` band `r = 0.4` to 15m. Combined risk `R_H = 1 − Π_i (1 − r_i)` (noisy-OR; it is the natural explainable combination: each rule is read as an independent reason the agent could fail, and the product form avoids the "two half-reasons sum to certainty" artefact of addition). `R_H` is then **quantised to the frozen band**: `< 0.15 → "0.05"`, `< 0.45 → "0.25"`, `< 0.80 → "0.60"`, else `"0.90"`. The `probability` number is **not** emitted by `rules/v1` (contract: only from a calibrated model source). `contributing_rules` lists the rules with `r_i > 0` in that horizon, sorted by `r_i` desc.

24 h horizon in Phase 1 collects only slow rules: `budget_proximity` (projected at 24 h instead of 1 h), `credential_expiry`, `model_deprecation`, plus a CUSUM positive on `cost_usd` or `error_rate` sustained over 1 h. Everything else is below the noise floor at 24 h with rules; the band will usually be `"0.05"` and the UI says so honestly ("no 24 h leading indicators; model source not yet enabled").

### 3.3 Rule definitions (leading; detected rules are backend-architect's R1–R5 unchanged)

| rule_id | fires when (after hysteresis) | severity formula | H | `predicted_failure_mode` |
|---|---|---|---|---|
| `error_trend` (L1) | `error_rate_slope > 0` for 3 windows **and** `ewma_error_rate ≥ 0.5 × t_R1` **or** `cusum_error_rate_pos > h` | `clamp((ewma / t_R1 − 0.5) / 0.5, 0, 1)` | 900 | `provider_outage` if `error_rate_5xx` dominates, `latency_degradation` if timeouts, `permission_error` if blocked/4xx, else `tool_failure` |
| `latency_trend` (L2) | `latency_p95_slope > 0` for 3 windows **and** `ewma_p95 ≥ 0.8 × t_R2`, or `cusum_latency_pos > h`, or `latency_p95_vs_baseline ≥ 1.5` rising | `clamp((ewma / t_R2 − 0.8) / 0.2, 0, 1)` | 900 | `latency_degradation` |
| `ratelimit_proximity` (L3) | `ratelimit_headroom_min < 0.10` or `error_rate_429 > 0.05` or `TTE_rl < 15 min` | `max((0.10 − headroom)/0.10, 429share/0.15, (900 − TTE_rl)/900)` | 900 | `provider_outage` (rate-limit sub-mode in explanation) |
| `budget_proximity` (L4) | `budget_burn_1h ≥ 0.9` (1 h) / projected month ≥ 1.0 at 24 h | `clamp((projected − 0.9) / 0.1, 0, 1)` | 3600 / 86400 | `cost_runaway` |
| `fallback_pressure` (L5) | `inline_fallback_ratio + breaker_open_ratio > 0.20` | `clamp((share − 0.2) / 0.4, 0, 1)` | 900 | `provider_outage` |
| `context_saturation` | `context_utilisation_p95 > 0.85` or `finish_length_ratio > 0.25` | `clamp((util − 0.85) / 0.15, 0, 1)` | 900 | `quality_collapse` |
| `credential_expiry` | `days_to_credential_expiry ≤ 7` | `clamp((7 − d) / 6, 0, 1)` | 86400 | `permission_error` |
| `model_deprecation` | `days_to_model_deprecation ≤ 30` | `clamp((30 − d) / 23, 0, 1)` | 86400 | `model_deprecation` |
| `provider_status` leading facet | `provider_status_code ∈ {1,2,3}` and agent not yet erroring | ordinal table (§2.2) | 900 | `provider_outage` |
| `drift_cusum` (new, info only) | CUSUM positive or negative beyond `h` on `tokens_out_mean`, `output_chars_mean` or `tool_seq_entropy` with no other rule firing | `clamp((S − h) / h, 0, 1) × 0.5` | 3600 | `silent_drift` |

`predicted_failure_mode` at the document level is the mode of the highest-`r_i` rule in the nearest horizon with `R_H ≥ 0.15`, else `null`. `drift_cusum` carries no penalty in the score (it is a `watch`-only informer) until Phase 2 evaluation shows it earns one; it exists so that `silent_drift` has a Phase 1 detector at all and so that the label `provider_incident.rule_fired_before` is not the only thing teaching Phase 2 about unknown-unknowns.

### 3.4 Confidence semantics for `rules/v1`

`confidence` is about the **evidence**, not the probability. Rules emit:

- `high`: a detected floor (§2.4) is in force, or `provider_status ∈ {partial_outage, major_outage}` with `provider_status_age_s < 600` corroborated by `provider_error_rate_fleet` above the R1 threshold, or ≥ 2 independent leading rules with `r_i ≥ 0.5` and `observation_coverage ≥ 0.95`.
- `medium`: one leading rule with `r_i ≥ 0.5`, `request_count(5m) ≥ 2 × min_samples`, coverage ≥ 0.8, agent not provisional.
- `low`: everything else, including every 24 h horizon from rules, any provisional agent, any horizon whose contributing rules all have `r_i < 0.5`, or coverage < 0.8.

Confidence is what D13 gating reads (§3.5); it is deliberately conservative so that rules alone rarely reach `high` for a *predicted* (non-detected) failure.

### 3.5 Tier gating (D13 and its clarification)

| Trigger | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| Detected failure (band `failed` floor, or critical detected rule after hysteresis) → alt-model / alt-provider / human handoff | automatic | automatic | automatic |
| Detected failure → `backup_agent` step | approval (always) | automatic | automatic |
| Predicted only: `horizons.15m.probability_band ≥ "0.60"` **and** `confidence ≥ medium` → `preemptive_failover` | **approval**, `approval.requested_by_kind='rule'`, timeout `continuity_plan.approval_timeout_s` (D22 forces `hold` on PII/residency agents) | automatic when `preemptive_mode ∈ {auto, degrade_then_auto}` (default tier 2 = `degrade_then_auto`: first `degraded`, then failover if the band persists 2 more ticks) | automatic (`preemptive_mode='auto'`) |
| Predicted only, `"0.60"` band but `confidence='low'` | alert only (`watch`), no saga | routing → `degraded` only | routing → `degraded` only |
| Predicted only, `"0.25"` band | `watch` alert, info | `watch` alert | nothing beyond score |
| Any rule/policy actor during `operator_hold_until` (D21) | blocked, `hold_suppressed_count += 1` | same | same |

The 1 h and 24 h horizons never trigger a saga in Phase 1; they create `info` alerts (`budget_proximity`, `credential_expiry`, `model_deprecation`) with `what_to_do`. This matches the chair's "leading indicators" reading of D6 and keeps the predicted auto-failover surface to one horizon that the evaluation harness (qa-expert) can measure for lead time and false-failover rate.

### 3.6 Predictor interface conformance

`rules/v1` implements `HealthPredictor` exactly: `name='rules', version='v1'`, `required_feature_set='features/v1'`, `predict(snapshot, [900, 3600, 86400])` is a pure function of the snapshot (the EWMA/CUSUM state is **inside** the snapshot as `ewma_*`/`cusum_*` keys so replay equals production), `explain()` returns the factors list. `abstained` is never set by rules. This is what makes the evaluation harness honest: the harness feeds stored or synthetic snapshots and gets byte-identical predictions.

---

## 4. Phase 2 learned layer

### 4.1 What the model does and does not do

The model replaces **one thing**: the quantised `probability_band` (and adds the numeric `probability`) per horizon, with `source='model/sibyl-gbt:<version>'`. It does not replace the score, the factors, the hysteresis or the detected floors. Rules keep producing the explanation list; the model adds its own contributions as factors with `kind='leading'` when `explain()` is implemented. If the model abstains, rules fill the horizon and `abstained=true` is set (contract).

### 4.2 Training set from verdict-labelled alerts (D24/D33) and other labels

Unit of training: one `feature_snapshot` row (`reason ∈ {transition, alert, approval, sample}`) joined to an outcome at `as_of + H`. Snapshots are already immutable, frozen at `as_of`, and contain nothing after `as_of` (Step 3 §6), so point-in-time correctness is structural, not a discipline.

Label construction per horizon `H ∈ {900, 3600, 86400}` s, per `(tenant, agent, as_of)`:

| Source | Positive if | Negative if | Excluded |
|---|---|---|---|
| `label(kind='alert_verdict')` on a **leading** alert (D24 mandatory on human close) | `verdict='tp'` and `actual_failure_mode` set: the snapshot at the alert's `health_snapshot_id` **and every sampled snapshot of the agent in `[judged_as_of − H, judged_as_of]`** are positive for horizon `H` ≥ `lead_time_s` | `verdict='fp'`: the alert's snapshot and the window before it are **hard negatives** (the agent looked bad and nothing happened) | `verdict='unsure'`; `verdict IS NULL` (hysteresis-resolved, D33) — excluded from training, counted in the "unverdicted backlog" SLI |
| `label(kind='alert_verdict')` on a **detected** alert | `tp`: the moment of failure is `judged_as_of`; snapshots in `[judged_as_of − H, judged_as_of)` are positives for `H` (this is where lead-time learning comes from) | `fp`: hard negatives | same |
| `label(kind='provider_incident')` (worker-synthesised, judges window `[started_at − 1 h, started_at]`, exists whether or not a rule fired) | every agent on the provider: snapshots in the window are positive for `H ≥ (started_at − as_of)`, `failure_mode='provider_outage'` | — | agents already `failed_over` before the window |
| `label(kind='failover_outcome')` with `undone_by_operator=true` | — | the snapshot that triggered the automated transition is a hard negative (operator said "that was wrong") | `fallback_succeeded=false` (ambiguous: may have been a real failure with a bad chain) |
| `health_snapshot.band='failed'` with floor reason (machine) | positives in `[t − H, t)` **only when** a `tp` verdict or `provider_incident` label corroborates within 24 h | — | uncorroborated `failed` bands (the rules may have been wrong) |
| Sampled snapshots (`reason='sample'`, 1-in-30) with no failure, no `tp` alert and no provider incident in `[as_of, as_of + H + 1 h]` | — | ordinary negatives (the bulk of the set) | windows inside an `observation.gap` |

Rules that stop the model imitating the rules: (i) the `provider_incident` label is independent of rule firing; (ii) `fp` verdicts are hard negatives precisely where rules fired; (iii) `rules/v1` outputs (`horizons`, `score`) are **not** features, only the raw grains and statics are; (iv) `contributing_rules` are not features. The model may rediscover the rules, which is fine, but it is scored against outcomes, not against rules.

Volume estimate per tenant (20 agents, synthetic demo cadence): ~5.7k sampled snapshots/day + ~200 transition/alert snapshots/day; with 90 days of history ≈ 530k rows, positives perhaps 1–3 % at 15 m. Training is per tenant by default (Q2); synthetic-tenant pooling is used to ship a `model/sibyl-gbt:0.x` that works on day one of a new tenant, with the tenant's own data taking over at ≥ 200 positives per horizon.

### 4.3 Features for the model

Everything in `grains.{1m,5m,15m,1h}` plus `static.*` one-hot/ordinal encoded (`tier`, `provider_kind`, `model class`, `fail_mode`, `routing_state`, `breaker_state`, `provider_status_code`, hour/day cyclic encodings `sin/cos`), the fleet features (§1.2), `ewma_*`, `cusum_*`, `*_vs_baseline`, `observation_coverage`, `baseline_ref` tier as ordinal. Missing (`null`) is passed as missing (GBTs handle it natively), never imputed to zero. Target leakage check in CI: every feature name must be in `features/v1`; the training job refuses unknown keys.

### 4.4 Model: gradient-boosted trees + calibration, one model per horizon

- **Learner**: LightGBM (MIT) `LGBMClassifier`, `objective='binary'`, `num_leaves ≤ 31`, `max_depth ≤ 6`, `min_child_samples ≥ 200`, `feature_fraction 0.8`, `lambda_l2 10`, early stopping on the forward-validation fold. Monotone constraints where the physics is known: `error_rate`, `latency_p95_vs_baseline`, `inline_fallback_ratio`, `provider_status_code` non-decreasing in P(fail); `ratelimit_headroom_min`, `budget_headroom` non-increasing. Monotonicity is itself an explainability guarantee a compliance reader can be told in one sentence. Fallback learner when LightGBM is not installable: scikit-learn `HistGradientBoostingClassifier` (BSD-3), same constraints API.
- **Class imbalance**: `scale_pos_weight` = neg/pos capped at 50; no synthetic oversampling (it breaks calibration).
- **Validation**: forward-chaining by time (train on `[T0, T1)`, validate on `[T1 + H + 1 h, T2)` with the gap removing label leakage across the boundary), grouped by agent so one chatty agent cannot sit in both folds in the same week. Three folds; report per fold.
- **Calibration**: isotonic regression (sklearn) fitted on the out-of-fold predictions of the last fold, so the emitted `probability` is a frequency: among snapshots given 0.60, about 60 % fail within `H`. Calibration quality = expected calibration error (ECE, 10 bins) and Brier score; `probability_band` = nearest lower band of the calibrated probability (`0.05 / 0.25 / 0.60 / 0.90`).
- **Abstention**: the model returns `abstained=true` when `provisional.flag`, `observation_coverage < 0.8` (contract-forced anyway), the agent has fewer than 7 days of own baseline, or the isolation-forest OOD score (§4.5) marks the snapshot as outside the training support. Abstention rate is a tracked metric; above 20 % the model is not promoted.
- **Per-horizon**: three models, same code path, different label windows; 24 h is expected to remain rules-dominated (budget/credential/deprecation) and may legitimately never earn promotion.

Why GBT and not the brief's survival/hazard or autoencoder candidates: tabular, mixed-scale, heavily missing features with a few hundred positives are the regime where boosted trees are hard to beat and remain inspectable (per-tree contributions, monotone constraints). A discrete-time hazard model is the natural next step once the three horizon models agree well; it is a reformulation of the same rows (one row per snapshot per horizon with a survival label) and can run on the same learner, so nothing in the data path changes. Autoencoders need more positives than we will have and give weaker explanations; deferred.

### 4.5 Anomaly detection (unknown unknowns)

Two detectors, both unsupervised, both emitting a factor with `rule='anomaly_score'` (registered additively) and `kind='leading'`, never a saga trigger on their own:

- **Isolation forest** (sklearn, BSD-3) per tenant over the 5 m and 1 h grains plus statics, 200 trees, `contamination='auto'`, refit weekly. Output: anomaly score in [0, 1] (normalised path length). Dual use: `score > 0.7` → `drift`/`silent_drift` watch factor; `score > 0.85` → OOD flag that makes the GBT abstain (§4.4).
- **Seasonal-ESD** (STL from statsmodels, BSD-3, plus a 40-line generalised ESD) on hourly series of `tokens_out_mean`, `output_chars_mean`, `cost_usd`, `tool_call_count`, `task_success_rate` with weekly seasonality, `max_anomalies = 5 %`, `α = 0.01`. Catches level shifts the CUSUM misses when the baseline itself has drifted slowly over weeks (CUSUM resets its baseline hourly; S-ESD looks at 4 weeks).

Anomaly factors earn a score penalty only after the evaluation harness shows their precision ≥ the `drift_cusum` rule's; until then they are visible, labelled "experimental", and excluded from `recommended_action`.

### 4.6 CPU-only OSS stack (D10, D15 permissive-only)

| Component | Package | Licence | Why |
|---|---|---|---|
| Arrays, frames | `numpy`, `pandas` (or `polars`) | BSD-3 / BSD-3 (MIT) | feature frames from Postgres |
| DB access | `psycopg[binary]` 3, `sqlalchemy` core | LGPL-3 (psycopg; linked, not modified — flag to chair Q3) / MIT | Postgres reads; `asyncpg` (Apache-2) is the alternative if LGPL is a concern |
| GBT | `lightgbm` | MIT | learner, native `pred_contrib` |
| Fallback GBT, calibration, isolation forest, metrics | `scikit-learn` | BSD-3 | isotonic, ECE/Brier, IF |
| Seasonal decomposition | `statsmodels` | BSD-3 | STL for S-ESD |
| Explanations | LightGBM `pred_contrib=True` (SHAP-equivalent TreeSHAP values built in); optional `shap` | MIT | per-prediction contributions without an extra dependency |
| Artefact storage | `joblib` dump + sha256 → `payload_refs(kind='feature_snapshot')`-style blob (`kind='model_artifact'`, additive) | BSD-3 | ADR-5 BlobStore; crypto-shred applies |
| Scheduling | worker's own asyncio loop + `pg_advisory_lock` | — | no Airflow/Temporal in Phase 1–2 |

Excluded on licence or budget: Prophet is fine (MIT) but unnecessary; Evidently (Apache-2) is fine but a 40-line PSI is enough; no MLflow server (Apache-2 but another stateful service — the `ml_model` table is the registry); nothing AGPL/SSPL; no GPU anywhere. Training the three GBTs on 530k × ~120 features on one CPU core takes under 10 minutes; isolation forest under 2; S-ESD seconds.

### 4.7 Model registry and versioning (additive tables, for database-architect)

`ml_model(tenant_id, id*, name text, version text, horizon_s int, feature_set text, trained_at, train_from, train_to, n_rows, n_pos, metrics jsonb, calibration jsonb, artifact_ref_id uuid → payload_refs, artifact_sha256 bytea, state text CHECK IN (trained, shadow, promoted, demoted, retired), promoted_at?, demoted_at?, promoted_by_user_id?)`; `ml_prediction_shadow(tenant_id, health_snapshot_id, model_id, horizon_s, probability numeric(5,4), band text, abstained bool, evaluated_at)` daily-partitioned, 30 d. `source` string = `model/sibyl-gbt:<version>` where version is `<trained_at date>.<n>`. Promotion is an audited action (`ml_model.promoted`, `ml_model.demoted`) with a human actor in Phase 2; auto-demotion by the drift monitor is a `system` actor.

### 4.8 Retraining cadence

Nightly per tenant at a tenant-local quiet hour (or 02:00 UTC default): rebuild the label table from `label`, `health_snapshot`, `feature_snapshot`; retrain only if ≥ 50 new verdicts or ≥ 1 new `provider_incident` label since the last training, else skip (log `ml.train.skipped`). Weekly: isolation forest and S-ESD refit. Every trained model enters `shadow` automatically; promotion is never automatic in Phase 2 (§4.10).

### 4.9 Drift monitoring

- **Feature drift**: PSI per feature between the training window and the trailing 7 days; PSI > 0.25 on any top-10-importance feature flags `ml.drift.feature`.
- **Label drift / base rate**: positive rate per horizon vs training; > 2× change flags.
- **Calibration drift**: ECE on the trailing 14 days of verdicted outcomes; ECE > 0.10 flags; > 0.15 auto-demotes to `shadow` and rules take over (`abstained=true` path, audited).
- **Performance vs rules**: precision/recall at the `"0.60"` band and lead time, both for the model and for `rules/v1`, computed on the same verdicted alerts; if the model is worse than rules on precision by > 5 points over 14 days it is demoted.
- **Abstention rate** and **OOD rate** tracked; sustained > 20 % flags.

All of these are rows in `ml_model.metrics` history and one SLI each for sre-engineer's dashboard; flags create `info` alerts with `scope='provider'`-like tenant scope (new `alert_rule.scope='platform'` value, Q4) so the operator sees "model demoted, rules in force".

### 4.10 Shadow mode and promotion criteria

A `shadow` model runs on every tick, writes `ml_prediction_shadow`, and is **not** visible in `horizons` (rules stay authoritative). Promotion per horizon requires, over ≥ 14 days of shadow with ≥ 30 verdicted leading alerts in the period:

1. precision at band ≥ `"0.60"` ≥ rules' precision + 5 points **and** recall ≥ rules' recall − 2 points, or recall + 10 points at equal precision;
2. median lead time on `tp` ≥ rules' median lead time;
3. ECE ≤ 0.08, Brier ≤ rules' pseudo-Brier (band midpoints);
4. false-failover rate (predicted auto-failovers later `fp`/undone, tiers 2–3) ≤ rules';
5. abstention ≤ 20 %;
6. a human promotes it (audited), after the compliance view (§5) has been generated for the version.

After promotion the model fills `probability`, `probability_band`, `source`, `confidence` (§4.11) for that horizon; `contributing_rules` continues to list rules so the operator's mental model does not change. Demotion is instant and reversible.

### 4.11 Confidence semantics for `model/*`

`high`: calibrated probability within a band's interior (≥ 0.1 from both band edges), not OOD, coverage ≥ 0.95; `medium`: near a band edge or coverage 0.8–0.95; `low`: abstained-then-filled, or recently promoted (< 7 days). D13 gating reads the same `confidence` field, so moving from rules to model changes no routing code.

---

## 5. Explainability surface for the compliance persona (Compliance Auditor; D8, D29)

What an auditor needs is not SHAP plots; it is the ability to answer, for any automated action, "what did the system know, what rule or model produced the decision, could a human have reproduced it, and was the decision later judged correct". Everything below is already derivable from frozen tables; this section fixes what the console and the export render.

1. **Decision record** (per `routing_transition` by a `rule`/`policy` actor): `routing_transition.rule_codes`, `alert_ids`, `health_snapshot_id` → the `health_snapshot` row's `score`, `band`, `factors[]` (with `penalty`, `value`, `threshold`, `explanation`, `evidence` deep link), `horizons`, `rules_source`, `feature_snapshot_id`. Rendered as a one-page "why" with the arithmetic shown: `100 − (28 + 10 + 4) = 58 → degraded`. The audit event (`route.changed`) already references `transition_id`; the export bundles the snapshot JSON by `health_snapshot_id`.
2. **Reproducibility statement**: because predictors are pure functions of `FeatureSnapshot`, the export includes the snapshot and a `sibyl replay --snapshot fs_… --predictor rules/v1` command that recomputes the same factors and horizons; for model sources it names `ml_model.version`, `artifact_sha256`, `feature_set`, and the replay reproduces `probability` to 4 decimals. This is the single strongest answer to "is it a black box": every decision is re-executable offline.
3. **Model card per `ml_model` version** (generated at `shadow` entry, finalised at promotion, immutable): intended use (per horizon, per tenant), training window and row counts, positive counts by failure mode, label sources and exclusions (unsure, null-verdict), feature list with monotone constraints, global importances (gain) top 20, calibration curve data, per-tier precision/recall/lead-time vs rules, known limitations (abstention conditions, OOD), who promoted, when. Stored as `payload_refs(kind='model_card')` (additive), hash referenced from the `ml_model.promoted` audit event.
4. **Per-prediction contributions** for model sources: `explain()` returns the top-8 `pred_contrib` values as factors (`rule='model_feature:<key>'`, `weight` = |contrib| / Σ|contrib|, `direction` from the contribution sign, `explanation` templated: "latency p95 is 2.4× this agent's Tuesday-09:00 baseline; contributes +0.21 to the 15 m failure probability"). Rules' factors and model factors are shown in two labelled groups, never merged, so a reader always knows which came from arithmetic they can check by hand.
5. **Verdict ledger**: per rule and per model version, counts of `tp/fp/unsure/null` verdicts, precision, recall, median lead time, unverdicted backlog, over 30/90/400 days (D27 retention). This is the "we measure our own false positives and here is the trend" page; it also powers §2.7.
6. **Threshold provenance**: every `alert_rule` row carries `origin`, `seed_version`, `yaml_sha256`, `overridden`, `updated_at`, and the audit log holds who changed what; the compliance view shows the effective thresholds per tier with their history.
7. **Human oversight evidence** (EU AI Act Art. 14 framing): for tier-1 agents, the share of automated actions that went through `approval`, approval latencies, denials, `undo` events with reasons, D21 holds, and D22 forced holds. All from `approval`, `routing_transition`, `failover`.
8. **Plain-language glossary** embedded in the export: what a score of 58 means, what `"0.60"` band means ("in Phase 1 this is a rule-derived band, not a measured frequency"; for model sources "a calibrated frequency: of agents given this value, about 60 % failed within 15 minutes in the validation period").
9. **Export**: `GET /audit/export` (API §5.11) gains an `include=health_decisions` option producing a ZIP of the decision records, snapshots, model cards and verdict ledger for a time window, hashed into the audit anchor. Technical-writer owns the prose template.

Nothing in this surface reads payload content; the compliance view is safe to show to a reader without `payloads:read`.

---

## 6. Risk classification features (EU AI Act tiers), static + dynamic

`agent.risk_class ∈ {unclassified, minimal, limited, high, unacceptable}` is a **governance decision set by a human** (DATAMODEL §4.2). The ML layer never writes it. What it does is compute a `risk_assessment` suggestion with evidence, so the compliance persona classifies with the facts in front of them and is told when observed behaviour contradicts the declared class.

### 6.1 Static features (declared facts, from the registry)

| Feature | Source | Signal for |
|---|---|---|
| `annex_iii_use_case` (tenant-entered tag: employment, education, credit, essential services, law enforcement, migration, justice, biometrics, critical infrastructure, none) | new `agent.tags` convention `eu_ai_act:<use_case>` or an `agent.attrs` key (Q5) | `high` presumption (Annex III) |
| `prohibited_practice_flag` (social scoring, manipulative techniques, real-time remote biometric id) | same tag family | `unacceptable` |
| `interacts_with_natural_persons` | `agent.kind ∈ {chatbot, copilot}` or tag | `limited` transparency obligations (Art. 50) |
| `generates_synthetic_content` | `attrs.request.output_type ∈ {image, speech}` observed, or tag | Art. 50 labelling |
| `data_classification_max` | max `data_source.classification` over `reads_data`/`writes_data` edges (`pii`/`restricted` highest) | high-risk data handling, D22 predicate |
| `residency_regions` | `data_source.residency_region` set | D17 residency warnings |
| `business_process_criticality` | `business_process.criticality` | tier alignment |
| `tool_side_effect_max` | max `tool.permissions.side_effect_class` / observed `sibyl.tool.side_effect_class` over `calls_tool` edges (read < write < external_comm < financial < irreversible) | autonomy and harm potential |
| `autonomy_level` | `agent.kind` ordinal (`model_endpoint` 0 … `autonomous_agent`/`multi_agent` 3) × whether `human_queue`/approval exists in the chain | Art. 14 oversight |
| `human_oversight_configured` | `continuity_plan.preemptive_mode='approval'` or tier 1, approval rules present | Art. 14 |
| `tier` | `agent.tier` | consistency check (tier 1 with `minimal` is a finding) |
| `lifecycle` | `agent.lifecycle` | `deployed` with `unclassified` is a finding |
| `model_provider_known` / `model_allowed` | `provider.is_known_provider`, `model.is_allowed`, `model.is_discovered` | GPAI provenance |
| `bom_present` | `ai_bom` row for current version | documentation obligation |

### 6.2 Dynamic features (observed behaviour, 30 d windows)

| Feature | Source | Signal for |
|---|---|---|
| `observed_pii_access_ratio` | share of calls with `data_source_ids` ∩ `pii`-classified sources | declared vs observed data handling |
| `undeclared_tool_ratio`, `undeclared_data_source_ratio` | §1.4 | scope creep, identity drift |
| `policy_violation_count` | `policy.decision` rows with `action ∈ {tool_blocked, fail_closed_rejected, quarantine}`; audit `policy.violated` | control effectiveness |
| `permission_error_rate` | `error_rate_blocked`, `error_class='client_error'` with 401/403 | least-privilege drift |
| `handoff_rate`, `handoff_returned_ratio` | §1.5 | how often humans had to step in |
| `approval_denial_ratio` | `approval.state='denied'` / decided | oversight friction |
| `finish_content_filter_ratio` | §1.4 | content risk |
| `quality_proxy` firings, `feedback_negative_ratio` | §2.3, §1.5 | performance obligations (Art. 15) |
| `prompt_version_churn` | distinct `attrs.prompt_version` per 30 d | change management |
| `agent_version_churn_gateway_observed` | `agent_version.source='gateway_observed'` count | silent model drift vs declared |
| `cross_agent_delegation_depth` | `dependency_edge(edge_type='delegates_to')` depth | multi-agent blast radius |
| `external_comm_side_effects_30d` | `tool.call` with `side_effect_class ∈ {external_comm, financial, irreversible}` | real-world impact |

### 6.3 Rubric (transparent, not learned)

`suggested_class` = `unacceptable` if any prohibited flag; else `high` if `annex_iii_use_case ≠ none` or (`data_classification_max ∈ {pii, restricted}` and `tool_side_effect_max ≥ external_comm` and `autonomy_level ≥ 2`); else `limited` if `interacts_with_natural_persons` or `generates_synthetic_content`; else `minimal`. **Findings** (never auto-applied): declared class below suggested; tier 1 without `human_oversight_configured`; `deployed` and `unclassified`; `observed_pii_access_ratio > 0` with no `pii` source declared; `undeclared_tool_ratio > 0.01`; `bom_present=false` for `high`. Each finding carries the evidence rows. Learned risk scoring is out of scope: the EU AI Act tiers are legal categories with explicit criteria, and a model guessing them would be the opposite of what the compliance buyer wants. Dynamic features exist to **contradict** declarations, which is the valuable part.

Surface: a `RiskAssessment` block on `GET /agents/{id}/risk`? No — that route is failure risk (API §5.10). Propose `GET /agents/{id}/risk-assessment` (additive, Q5) returning `{suggested_class, declared_class, findings[], static{}, dynamic{}, computed_at}`, recomputed daily and on registry change (`graph.changed` outbox).

---

## 7. Worker architecture (Postgres aggregates, scheduling, cost)

### 7.1 One process, four loops

`sibyl-worker` is one Python process per deployment (12-factor, D4), horizontally shardable by tenant via `pg_try_advisory_lock(hashtext('worker:' || tenant_id))`. Loops:

| Loop | Cadence | Work | Owner of the step |
|---|---|---|---|
| **rollup** | 10 s per tenant | DATAMODEL §6.2 (dirty 1 m buckets → `agent_metrics_1m/1h`, replace-not-add) + the §1.8 counters | database-architect (defined) |
| **evaluate** | 10 s per tenant, after rollup commits | one query over `agent_metrics_1m` (last 10 min, grouped by agent, bucket), one over `agent_metrics_1h` for month-to-date cost, bounded `events`/`checkpoint` reads for §1.1/§1.4 tail features (only agents with activity in the dirty set), registry statics from a 60 s cache → build `FeatureSnapshot` in memory for every active agent → update EWMA/CUSUM state → score, floors, rules, hysteresis → `predict()` → write `health_snapshot` (every tick) and `feature_snapshot` (on transition/alert/approval or 1-in-30 sample) → alert upserts, provider collapse → `failover` creation for rule actors (respecting D13/D21) → `health.transition` events → `outbox` | this document |
| **baseline** | hourly per tenant | §1.6 medians/MAD from `agent_metrics_1h`; peer groups; `provider_status` feed poll (on change only, R10) | this document |
| **ml** (Phase 2) | nightly train, weekly IF/S-ESD, every tick shadow predict | §4.8–4.10 | this document |

Plus the existing saga executor, partition job, sweeper, erasure steps (DATAMODEL §6). Everything is idempotent and resumable: the evaluate loop reads its hysteresis state from the last `health_snapshot`, the ml loop from `ml_model`.

### 7.2 Query shapes and cost (20 agents, 3 providers, demo cadence ≈ 2 req/s/agent)

- `agent_metrics_1m` window read: `WHERE tenant_id = $1 AND bucket_start >= now() − 10 min` → ≤ 20 agents × ≤ 3 (provider, model) × 10 rows = 600 rows, index `(tenant_id, bucket_start)`, < 5 ms.
- Fleet aggregates: same rows, grouped in memory; zero extra queries.
- `agent_metrics_1h` MTD cost: ≤ 20 × 3 × 744 rows/month worst case, read once per hour into cache, incremented from the 1 m rows between refreshes.
- Tail reads: `consecutive_errors` (`LIMIT 10` on `ix_events_agent_ts`) only when `error_rate(1m) > 0`; tool sequence (`LIMIT 50` per open task, ≤ 5 tasks) only when `tool_call_count(5m) > 20`; checkpoint age (`LIMIT 1` per open task). Worst case ~30 small index scans per tick, typical < 5.
- Writes per tick: 20 `health_snapshot` rows (≈ 170k/day/tenant, 3 d partitions, R17), ~0.7 `feature_snapshot` rows on average, a handful of alert upserts. Write-on-change for `health_snapshot` is the first optimisation if a tenant has hundreds of agents; it needs no schema change (the read contract already tolerates gaps).
- CPU: scoring 20 agents × 15 rules × 4 grains is microseconds; EWMA/CUSUM state ≈ 20 × 10 features × 2 floats. The whole evaluate tick is dominated by the one Postgres round-trip; budget 50 ms, alarm at 2 s (then the tick is skipped, not queued, and `observation.gap(cause=worker_lag)` is written).
- Phase 2 shadow predict: three LightGBM `predict` calls on a 20-row frame, < 5 ms; model loaded once per process, reloaded on `ml_model` change via `outbox`.
- Nightly training: one CPU core, < 10 min, memory < 2 GB for 530k rows; runs under `pg_advisory_lock` so it never overlaps with itself; reads `feature_snapshot.doc` (JSONB, ≤ 32 KB) in 10k-row pages.

### 7.3 Scheduling and failure behaviour

Plain asyncio tasks with per-tenant advisory locks; no external scheduler, no queue product (D10, ARCHITECTURE: Postgres is the only stateful component). A crashed worker loses nothing: rollups are replace-not-add from `consumer_offsets`, evaluation resumes from the last snapshot, training from `ml_model`. Two workers on the same tenant are prevented by the lock, two on different tenants run in parallel. The evaluate loop is the only latency-sensitive one; it skips a tick rather than falling behind, and the gap is itself a feature (`observation_coverage`) so the health page says "worker lagged" instead of showing stale confidence.

### 7.4 Evaluation harness hooks (qa-expert leads; what I need from it)

The harness drives the same `evaluate` code with synthetic `agent_metrics_1m` rows (or stored `feature_snapshot`s) and ground-truth failure times. Metrics I need per scenario, per tier, per rule and per predictor source: lead time distribution (`first fire at ≥ "0.60"` → ground-truth failure), precision/recall at `"0.60"`, time-to-detect for detected rules, false-failover rate (tiers 2–3 automated transitions that the scenario says were unnecessary), alert count per incident (collapse effectiveness), flap count per agent-hour, and band-change count. Hysteresis (`2/6`), dead-band widths, `λ`, `k`, `h`, noisy-OR band cut-points (0.15/0.45/0.80) and the tier caps are the tunables; the harness is where they get their final values before Step 7, and the chosen values are written back to `rules/v1/defaults.yaml` with the scenario id that justified them.

---

## 8. Open questions for the chair (max 8)

| # | Question | My default if unanswered |
|---|---|---|
| Q1 | **Cross-tenant signals.** Peer baselines and provider-wide error rates would be far stronger pooled across tenants (a provider outage is visible in every tenant at once). RLS and D1 forbid it today. Allow an opt-in, anonymised platform-level aggregate (`provider`, `model class`, counts and quantiles only, no agent ids) written by the worker under the platform tenant? | No cross-tenant features in Phase 1–2; per-tenant peer groups and seed constants only. |
| Q2 | **Per-tenant vs pooled models.** Per-tenant training is clean for isolation but most tenants will not reach 200 positives per horizon for months. Pooled training on synthetic + opted-in tenants, with per-tenant calibration, is the pragmatic path. Is opt-in pooling acceptable as a contract term? | Per-tenant models; a synthetic-trained `model/sibyl-gbt:0.x` as the day-one shadow for every tenant, never promoted without the tenant's own verdicts. |
| Q3 | **LGPL in the self-hosted bundle.** `psycopg` 3 is LGPL-3 (dynamically linked, unmodified). D15 says permissive-only. Accept LGPL for an unmodified, dynamically linked driver, or standardise on `asyncpg` (Apache-2)? | `asyncpg` for the worker to stay strictly permissive; note the choice in the licence inventory. |
| Q4 | **Platform-scope alerts.** Drift/demotion notices (§4.9) and risk findings (§6.3) are not about one agent or provider. Add `alert_rule.scope='platform'` (tenant-wide) to the frozen value set, or route them as `info` alerts on a synthetic "sibyl" provider? | Add `scope='platform'` (additive CHECK value) at Step 7 start via the DATAMODEL amendment path. |
| Q5 | **Where EU AI Act declarations live.** `agent.tags` convention (`eu_ai_act:annex_iii:credit`) vs a proper `risk_assessment` table with history and a `GET /agents/{id}/risk-assessment` route. Governance-forward positioning (D8) argues for the table. | Table + route, additive; tags accepted as input in the wizard and normalised into the table. |
| Q6 | **Predicted auto-failover for tier 2.** I defaulted tier 2 to `degrade_then_auto` (degrade first, failover if the band persists 20 s). D13 says "automatic on predictions for tiers 2–3". Is a 20 s degraded pause an acceptable reading, or must tier 2 shift immediately at `"0.60"` + `medium`? | `degrade_then_auto` for tier 2, `auto` for tier 3; both tenant-editable on `continuity_plan.preemptive_mode`. |
| Q7 | **Verdict backlog policy.** D33 lets hysteresis-resolved alerts close with `verdict=null`; the training set excludes them. If the backlog grows past, say, 50 % of resolved alerts, the model is trained on a biased sample (only alerts someone bothered to judge). Should the console nudge (daily digest of unverdicted alerts) or should the worker auto-assign `unsure` after 30 days to keep the ledger honest? | Nudge only; no auto-verdicts. Track the backlog share as an SLI and show it on the model card as a known bias. |
| Q8 | **LLM-as-judge in Phase 2.** Tenant opt-in is settled (chair §6). Which model runs the judge under D10? Ollama on the tenant's own box (`provider_kind='ollama'`) is the only zero-cost path; it means a judge quality that varies by tenant hardware. Accept, or defer judge scores to Phase 3 and rely on the metadata proxies in §1.4? | Phase 2 ships the `feedback(rater='judge')` path and a sampling job (`sibyl.eval.sample`, 1 % of calls) wired to any OpenAI-compatible endpoint the tenant configures, Ollama included; no judge is bundled or run by default. |

---

### Summary of what this step adds to the frozen contracts (all additive)

- `features/v1` keys: §1.8 list, `ewma_*`, `cusum_*`, `*_fleet`, `anomaly_score` factor rule id, `model_feature:<key>` factor rule ids.
- Registered rule ids: `quality_proxy`, `tool_loop`, `drift_cusum`, `anomaly_score` (plus the already registered `context_saturation`, `credential_expiry`, `model_deprecation` now get seed rows).
- `agent_metrics_1m` counters: `finish_length_count`, `finish_filtered_count`, `finish_tool_calls_count`, `empty_output_count`, `tool_error_count`, `tool_schema_fail_count`, `retry_attempt_sum`, `output_chars_sum`, `context_util_max`.
- Tables: `ml_model`, `ml_prediction_shadow`; `payload_refs.kind` values `model_artifact`, `model_card`; proposed `risk_assessment` (Q5); proposed `alert_rule.scope='platform'` (Q4).
- Routes: `GET /agents/{id}/health?verbose=1`; `GET /audit/export?include=health_decisions`; proposed `GET /agents/{id}/risk-assessment`.
- Nothing removed, nothing renamed, `sibyl-health/1`, `sibyl-feature-snapshot/1`, `sibyl-label/1` and `HealthPredictor` unchanged.
