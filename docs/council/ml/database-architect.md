# Step 5 — ML approach: database-architect slice

database-architect · 2026-10-10 · Inputs: `ml/CHAIR-INITIAL.md` (Postgres-only feature storage, worker-materialised 1m/5m/1h, no feature-store product), `DECISIONS.md` D1–D35, `datamodel/DATAMODEL.md` (62 tables; §4.3 rollups, §4.5 health, §6.2 rollup write path, §9 U2/U12), `api/SYNTHESIS.md` §DATAMODEL amendments 1–6, `datamodel/ai-engineer.md` §6 (FeatureSnapshot v1, `HealthPredictor`), §7 (labels).

Conventions carried over from DATAMODEL unchanged unless stated: Postgres 17, schema `sibyl` (D19 rename of `vigil`), roles `sibyl_app`, `sibyl_ingest`, `sibyl_worker`, `sibyl_audit`, `sibyl_routing`, `sibyl_migrate`; `uuidv7()` ids; every tenant-scoped table goes through `sibyl.enable_tenant_rls(regclass)` (ENABLE + FORCE + one policy `rls_tenant_<table>` on `tenant_id = current_tenant()`), every index leads with `tenant_id`, no nullable `tenant_id` anywhere; partitions are created by the worker's hourly job and registered in `partition_registry`, never by Alembic. DDL below is written as the migration body the build lane copies; `-- ck:` comments name the CHECK constraint per DATAMODEL `ck_<table>_<col>`.

What this slice adds to the 62(+1) tables: `agent_metrics_5m`, `provider_metrics_5m`, `agent_trend_state`, `agent_baseline`, `scoring_config`, `prediction`, `health_1h`, `agent_risk`, `rollup_job`, plus the Step 4 amendment tables `idempotency_record` and `ingest_batch_seen`. Net: **73 tables.** Nothing in `events` changes.

## 1. Windowed aggregate tables (1m / 5m / 1h)

### 1.1 Grain roles

| Grain | Table | Partition | Retention | Reader | Why materialised |
|---|---|---|---|---|---|
| 1m | `agent_metrics_1m` (exists) | daily by `bucket_start` | 14 d (rollup class) | health tick (detected rules, last 10 min), 5m rollup | Already frozen in Step 3; adds output-quality counters below |
| 5m | `agent_metrics_5m` (new) | daily | 90 d | health tick leading rules (EWMA/CUSUM inputs), FeatureSnapshot 5m/15m grains, training-set recompute, console charts > 6 h | Step 3 said "5 m sums at query time"; at 2,000 agents a tick would sum 2,000 × 10 rows every 10 s and the training view would re-aggregate 1m rows that no longer exist after 14 d. Materialising 5m is what lets features be recomputed point-in-time for 90 d (§4) |
| 5m provider | `provider_metrics_5m` (new) | daily | 90 d | provider-scope rules (`provider_status`, incident collapse), peer-group baseline | Provider rules aggregate across all agents of a tenant on one provider; without this the tick does a GROUP BY over every agent each 10 s |
| 1h | `agent_metrics_1h` (exists) | monthly | 13 months | 24h horizon, seasonal baseline, capacity/cost reporting | Unchanged key; recomputed from 5m, not 1m |
| 1h score | `health_1h` (new, §3.4) | monthly | 13 months | score history, U12 | Closes U12 |

15m is a query-time sum of three 5m rows (the only query-time grain left). The FeatureSnapshot `grains.15m` is computed that way by the worker.

### 1.2 Counter set (shared by 1m / 5m / 1h / provider_5m)

The Step 3 counter set stays; chair point 6 (output-quality signals as first-class features) adds the second block. All counters are `integer NOT NULL DEFAULT 0` unless typed otherwise; every counter is a plain sum so a parent grain is `sum()` of its children and `hist_sum()` of the histograms, with `ratelimit_remaining_min` merged by `least()`.

```sql
-- Step 3 block (unchanged names)
request_count, error_count, timeout_count, rate_limit_count, server_error_count,
blocked_count, inline_fallback_count, breaker_open_count, tool_call_count,
late_count, policy_stale_count                          integer,
tokens_in, tokens_out                                   bigint,
cost_usd                                                numeric(18,8),
ratelimit_remaining_min                                 integer NULL,
latency_hist, ttfb_hist                                 integer[40],
-- Step 5 output-quality block (chair §6)
retry_count            integer,  -- attrs.retry.attempt > 0
finish_length_count    integer,  -- gen_ai.response.finish_reasons ∋ 'length' (truncation)
finish_tool_calls_count integer,
refusal_count          integer,  -- status=ok AND attrs.quality.refusal = true (normaliser sets it)
empty_output_count     integer,  -- tokens_out = 0 on status=ok
tool_error_count       integer,  -- tool.call rows with status=error
tool_schema_invalid_count integer, -- tool.call attrs.schema_valid = false
task_count, task_success_count, task_failure_count integer, -- task.outcome rows
handoff_count          integer,  -- handoff.requested rows
feedback_count         integer,
feedback_sum           numeric(10,4),  -- Σ score ∈ [-1,1]; mean = sum/count
output_chars_sum       bigint,
tokens_out_sumsq       numeric(24,0),  -- Σ tokens_out², for tokens_out_cv
context_util_hist      integer[40],    -- (tokens_in / model_context_limit) × 1000 bucketed as ms-equivalents
tool_seq_hash_distinct integer,        -- HLL-free approximation: count(DISTINCT attrs.tool.seq_hash) per bucket
computed_at            timestamptz NOT NULL DEFAULT clock_timestamp()
```

`tokens_out_sumsq` and `output_chars_sum` give `tokens_out_cv` and `output_chars_mean` without a second pass; `tool_seq_hash_distinct` over a 5m bucket is the Phase 1 proxy for `tool_seq_entropy`/`tool_seq_repeat_ratio` (the infinite-loop detector) and is exact within a bucket because the recompute scans the bucket anyway. The ai-engineer §6 grain keys map 1:1 onto these columns; the mapping table is appended to `features/v1` by ai-engineer, not duplicated here.

### 1.3 DDL

```sql
-- Migration 10: ml_aggregates. Adds Step 5 counters to the two Step 3 rollup tables
-- (ADD COLUMN ... DEFAULT 0 is metadata-only in PG 11+, no rewrite) and creates the new grains.

ALTER TABLE sibyl.agent_metrics_1m
  ADD COLUMN retry_count integer NOT NULL DEFAULT 0,
  ADD COLUMN finish_length_count integer NOT NULL DEFAULT 0,
  ADD COLUMN finish_tool_calls_count integer NOT NULL DEFAULT 0,
  ADD COLUMN refusal_count integer NOT NULL DEFAULT 0,
  ADD COLUMN empty_output_count integer NOT NULL DEFAULT 0,
  ADD COLUMN tool_error_count integer NOT NULL DEFAULT 0,
  ADD COLUMN tool_schema_invalid_count integer NOT NULL DEFAULT 0,
  ADD COLUMN task_count integer NOT NULL DEFAULT 0,
  ADD COLUMN task_success_count integer NOT NULL DEFAULT 0,
  ADD COLUMN task_failure_count integer NOT NULL DEFAULT 0,
  ADD COLUMN handoff_count integer NOT NULL DEFAULT 0,
  ADD COLUMN feedback_count integer NOT NULL DEFAULT 0,
  ADD COLUMN feedback_sum numeric(10,4) NOT NULL DEFAULT 0,
  ADD COLUMN output_chars_sum bigint NOT NULL DEFAULT 0,
  ADD COLUMN tokens_out_sumsq numeric(24,0) NOT NULL DEFAULT 0,
  ADD COLUMN context_util_hist integer[] NOT NULL DEFAULT array_fill(0, ARRAY[40]),
  ADD COLUMN tool_seq_hash_distinct integer NOT NULL DEFAULT 0;
-- identical ALTER for sibyl.agent_metrics_1h (omitted)

CREATE TABLE sibyl.agent_metrics_5m (
  tenant_id     uuid        NOT NULL,
  agent_id      uuid        NOT NULL,
  provider      text        NOT NULL,
  model         text        NOT NULL,
  bucket_start  timestamptz NOT NULL,
  -- full counter set of §1.2 (same names, types, defaults) ...
  request_count integer NOT NULL DEFAULT 0,
  /* ... */
  latency_hist  integer[] NOT NULL DEFAULT array_fill(0, ARRAY[40]),
  ttfb_hist     integer[] NOT NULL DEFAULT array_fill(0, ARRAY[40]),
  context_util_hist integer[] NOT NULL DEFAULT array_fill(0, ARRAY[40]),
  ratelimit_remaining_min integer,
  children_1m   smallint NOT NULL DEFAULT 0,   -- how many 1m rows fed it (0..5); < 5 = partial
  computed_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, agent_id, provider, model, bucket_start),
  CONSTRAINT ck_agent_metrics_5m_bucket CHECK (bucket_start = date_trunc('hour', bucket_start)
      + (extract(minute FROM bucket_start)::int / 5) * interval '5 min'),
  CONSTRAINT ck_agent_metrics_5m_hist CHECK (cardinality(latency_hist) = 40 AND cardinality(ttfb_hist) = 40
      AND cardinality(context_util_hist) = 40)
) PARTITION BY RANGE (bucket_start);
CREATE INDEX ix_agent_metrics_5m_tenant_bucket ON sibyl.agent_metrics_5m (tenant_id, bucket_start);
SELECT sibyl.enable_tenant_rls('sibyl.agent_metrics_5m');

CREATE TABLE sibyl.provider_metrics_5m (
  tenant_id     uuid        NOT NULL,
  provider      text        NOT NULL,
  model         text        NOT NULL,      -- '*' row = all models of the provider
  bucket_start  timestamptz NOT NULL,
  agent_count   smallint    NOT NULL DEFAULT 0,  -- distinct agents contributing
  /* same counter set as agent_metrics_5m, minus task/feedback/handoff (agent-level only) */
  computed_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, provider, model, bucket_start)
) PARTITION BY RANGE (bucket_start);
CREATE INDEX ix_provider_metrics_5m_tenant_bucket ON sibyl.provider_metrics_5m (tenant_id, bucket_start);
SELECT sibyl.enable_tenant_rls('sibyl.provider_metrics_5m');

-- partition_registry rows (worker): agent_metrics_5m daily/90 d; provider_metrics_5m daily/90 d.
GRANT SELECT, INSERT, UPDATE, DELETE ON sibyl.agent_metrics_5m, sibyl.provider_metrics_5m TO sibyl_worker;
GRANT SELECT ON sibyl.agent_metrics_5m, sibyl.provider_metrics_5m TO sibyl_app;
```

`agent_metrics_1m` keeps its 14-day daily partitions; `agent_metrics_1h` its monthly 13-month partitions. The 5m tables are the new middle tier: 90 days is the longest window the training view (§4) must be able to recompute features for when no `feature_snapshot` row exists (DATAMODEL U2 recommendation), and it is what the console charts read beyond six hours.

### 1.4 Retention tiers (rollup class, amended)

| Table | Partition grain | Drop after | Sweeper for shorter tenant settings | Erasure |
|---|---|---|---|---|
| `agent_metrics_1m` | daily | 14 d | none (not tenant-tunable) | DELETE by tenant in cascade |
| `agent_metrics_5m`, `provider_metrics_5m` | daily | 90 d | none | DELETE by tenant |
| `agent_metrics_1h`, `health_1h` | monthly | 13 months | none | DELETE by tenant |
| `agent_trend_state`, `agent_baseline`, `agent_risk` | none | current rows only | — | DELETE by tenant |
| `prediction` | monthly by `predicted_at` | 400 d, or while a `label` references the snapshot | — | DELETE by tenant |
| `scoring_config` | none | durable, immutable rows | — | DELETE by tenant |

Rollups hold no content (counts, sums, histograms), so they are outside crypto-shred and are hard-deleted in the §6.5 cascade between `derived_purged` and `verified`. They are tenant-scoped (RLS) because `request_count` per agent per minute is business data.

## 2. Materialisation strategy

### 2.1 Pipeline

```
events ──(cursor on received_at)──► dirty 1m buckets ──recompute from scratch──► agent_metrics_1m
agent_metrics_1m ──(dirty parents)──► agent_metrics_5m ──► agent_metrics_1h
agent_metrics_5m ──(dirty parents, GROUP BY provider)──► provider_metrics_5m
agent_metrics_5m (closed) ──► agent_trend_state (EWMA/CUSUM) ──► health tick
```

One worker transaction per tenant per 10 s tick (DATAMODEL §6.2 steps 1–5, extended):

1. `set_tenant($t)`; read cursor from `consumer_offsets('rollup_1m', $t, 'events')`; `watermark = now() − 2 s`.
2. Dirty 1m set = `SELECT DISTINCT agent_id, provider, model, date_trunc('minute', ts) FROM events WHERE tenant_id = $t AND received_at > $cursor AND received_at <= $watermark AND event_type IN (…rolled types…)`. Bounded: `LIMIT 5000` buckets per tick; if hit, the cursor advances only to the `received_at` of the last bucket taken and the rest carries to the next tick (`rollup_job.carryover` counter for the SLI).
3. Recompute each dirty 1m bucket **from scratch** over `ix_events_agent_ts` and upsert with `ON CONFLICT (pk) DO UPDATE SET col = EXCLUDED.col` (replace, never add). `provider.status`, `observation.gap`, `health.transition` rows are excluded (no agent or not telemetry).
4. Dirty 5m parents = distinct `date_trunc 5m` of step 3; recompute each from its 1m rows (`sum`, `hist_sum`, `least`, `children_1m = count(*)`), upsert. Dirty provider 5m rows = distinct `(provider, model, bucket)` of step 4, recomputed from `agent_metrics_5m` GROUP BY provider, model (plus the `'*'` all-models row), upsert.
5. Dirty 1h parents recomputed from their 5m rows, upsert.
6. For every 5m bucket that **just closed** (`bucket_start + 5 min <= watermark` and not previously `children_1m = 5`-complete), advance `agent_trend_state` (§3.1) for that agent.
7. Advance the offset to `(watermark, last event_id)`; `COMMIT`.

Idempotency falls out of replace semantics plus a cursor committed in the same transaction: a crash between steps replays the tick and rewrites identical rows. Two workers cannot run the same tenant concurrently because the tick takes `pg_advisory_xact_lock(hashtextextended('rollup:' || $t, 0))` first.

### 2.2 Late arrivals

`events.is_late` (received − ts > 120 s) is already stored. The dirty-set query keys on `received_at`, not `ts`, so a late event dirties its true `ts` bucket and the recompute replaces that bucket and its parents. Rules:

- Late within the 1m retention (14 d): fully absorbed; `late_count` increments; `agent_metrics_5m.computed_at` moves forward, which is how `agent_trend_state` knows a closed bucket was reopened (see §3.1 for the "do not re-advance CUSUM" guard).
- Late beyond 14 d but within 90 d: the 1m partition is gone; the worker recomputes the 5m bucket directly from `events` (`events` retention ≤ 30 d per R7, so in practice 14–30 d) and marks `children_1m = 0`.
- Late beyond `tenant.raw_retention_days`: ingest already rejects it (`outside_retention`); rollups never see it.
- Late event into a bucket a `health_snapshot` already read: the snapshot is not rewritten (append-only, R17); the FeatureSnapshot it froze is the truth of what the engine saw. The training view (§4) prefers frozen snapshots for exactly this reason, and recomputed features from rollups are flagged `features_recomputed = true`.

### 2.3 Backfill and repair

`sibyl.rollup_backfill(p_tenant uuid, p_from timestamptz, p_to timestamptz, p_grains text[])` is a worker job, not a function: it writes a `rollup_job` row, then walks `[p_from, p_to)` in one-hour slices, recomputing 1m (if partitions exist), 5m, provider 5m and 1h with the same replace upserts, committing per slice and recording `progress_to`. It takes the same advisory lock as the tick, so backfill and live rollup never interleave on one tenant; the live tick skips a tenant whose lock is held and reports `rollup_lag_s` instead. Use cases: a normaliser bug fix (recompute everything since the bad release), a rule-counter addition (new column, backfill 90 d from `events` where still present, else zero), erasure verification (`derived_purged` step runs a backfill with `p_grains = '{}'` which deletes only).

```sql
CREATE TABLE sibyl.rollup_job (
  tenant_id    uuid NOT NULL,
  id           uuid NOT NULL DEFAULT sibyl.uuidv7(),
  kind         text NOT NULL,          -- ck: backfill | repair | purge
  grains       text[] NOT NULL,        -- ⊆ {1m,5m,provider_5m,1h,health_1h}
  range_from   timestamptz NOT NULL,
  range_to     timestamptz NOT NULL,
  progress_to  timestamptz,
  state        text NOT NULL DEFAULT 'queued',  -- ck: queued | running | done | failed | cancelled
  reason       text NOT NULL,
  requested_by uuid,                  -- app_user or NULL for system
  carryover    integer NOT NULL DEFAULT 0,
  error        text,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ix_rollup_job_state ON sibyl.rollup_job (tenant_id, state, range_from);
SELECT sibyl.enable_tenant_rls('sibyl.rollup_job');
```

Every backfill writes `audit_append('rollup.backfill', actor system|human, detail {job_id, grains, range})` because it changes what operators saw on charts; it does not touch `health_snapshot` or `alert` history.

### 2.4 Freshness SLI

`rollup_lag_s = now() − consumer_offsets.last_created_at` per tenant, exported by the worker; sre-engineer owns the target (proposal: p95 ≤ 15 s, which is one and a half ticks). The health engine refuses to evaluate **leading** rules for a tenant whose lag exceeds 120 s (it would be reading stale closed buckets) and marks `health_snapshot.provisional = true` with `observation_coverage` reduced accordingly; detected rules still run on whatever is there.

## 3. Health score, prediction and risk tables

### 3.1 Trend state and baselines (inputs the leading rules need between ticks)

EWMA and CUSUM are recursive; recomputing them from 90 d of 5m rows every tick is wasteful, and the engine must not double-advance when a closed bucket is reopened by a late event. So the state is a row per `(agent, metric)`, advanced exactly once per closed 5m bucket.

```sql
CREATE TABLE sibyl.agent_trend_state (
  tenant_id       uuid NOT NULL,
  agent_id        uuid NOT NULL,
  metric          text NOT NULL,                -- features/vN key: error_rate, latency_p95_ms, cost_usd, ...
  last_bucket     timestamptz NOT NULL,         -- last closed 5m bucket consumed; never goes backwards
  ewma            double precision,
  ewma_var        double precision,             -- for z-scores
  cusum_pos       double precision NOT NULL DEFAULT 0,
  cusum_neg       double precision NOT NULL DEFAULT 0,
  cusum_alarm_at  timestamptz,                  -- when h was crossed; cleared on reset
  samples         integer NOT NULL DEFAULT 0,
  scoring_config_id uuid NOT NULL,              -- alpha, k, h came from here
  PRIMARY KEY (tenant_id, agent_id, metric)
);
SELECT sibyl.enable_tenant_rls('sibyl.agent_trend_state');

CREATE TABLE sibyl.agent_baseline (
  tenant_id     uuid NOT NULL,
  agent_id      uuid NOT NULL,                  -- or peer-group pseudo id (see peer_group)
  metric        text NOT NULL,
  hour_of_week  smallint NOT NULL,              -- 0..167 UTC
  mean          double precision,
  stddev        double precision,
  p95           double precision,
  samples       integer NOT NULL DEFAULT 0,
  computed_at   timestamptz NOT NULL,
  baseline_ref  text NOT NULL,                  -- 'baseline/v1:<yyyy-ww>' rendered into FeatureSnapshot.baseline_ref
  peer_group    text,                           -- NULL = agent's own; else the cold-start group
  PRIMARY KEY (tenant_id, agent_id, metric, hour_of_week)
);
SELECT sibyl.enable_tenant_rls('sibyl.agent_baseline');
```

`agent_baseline` is rebuilt nightly from `agent_metrics_1h` (last 28 days, hour-of-week) and, for agents younger than 7 days, from the peer group (same `provider`, `model`, `agent.kind`) so `latency_p95_vs_baseline` exists on day one. `agent_trend_state.last_bucket` is the guard: a reopened bucket ≤ `last_bucket` updates the rollup but does not re-advance the state; a backfill that must re-derive trends resets the rows for the range (`rollup_job.kind = 'repair'`) and replays forward.

### 3.2 Versioned scoring config

The composite score is only explainable if the weights that produced it are recoverable. `health_snapshot.rules_source = 'rules/v1'` names the rule set; it does not pin the tenant's overrides. Add an immutable, content-addressed config row and reference it from every snapshot and prediction.

```sql
CREATE TABLE sibyl.scoring_config (
  tenant_id       uuid NOT NULL,
  id              uuid NOT NULL DEFAULT sibyl.uuidv7(),
  rules_source    text NOT NULL,               -- rules/v1 | model/<name>:<ver> (predictor that may use it)
  feature_set     text NOT NULL,               -- features/vN this config scores
  version_no      integer NOT NULL,            -- per tenant, monotonic
  config          jsonb NOT NULL,              -- weights per rule, band cut-offs, hysteresis, ewma alpha, cusum k/h, min_samples, penalties
  config_sha256   bytea NOT NULL,              -- sha256(JCS(config)); UK per tenant
  origin          text NOT NULL,               -- ck: seed | custom | tuned   (tuned = written by the eval harness)
  activated_at    timestamptz,
  superseded_at   timestamptz,
  created_by      uuid,                        -- app_user, NULL for seed/tuned
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, config_sha256),
  UNIQUE (tenant_id, version_no),
  CONSTRAINT ck_scoring_config_size CHECK (pg_column_size(config) <= 32768)
);
CREATE UNIQUE INDEX ux_scoring_config_active ON sibyl.scoring_config (tenant_id)
  WHERE activated_at IS NOT NULL AND superseded_at IS NULL;
SELECT sibyl.enable_tenant_rls('sibyl.scoring_config');
-- trg_block_mutation attached, with the one allowed UPDATE: activated_at/superseded_at NULL → value.

ALTER TABLE sibyl.health_snapshot ADD COLUMN scoring_config_id uuid;   -- NOT NULL after backfill of the 3-day window
```

`alert_rule` rows (per-tenant copies, R18) remain the thresholds and hysteresis for alerts; `scoring_config.config` holds the **score** composition (weight × penalty per rule, band cut-offs) and the trend parameters. Changing a weight = inserting a new row and flipping `activated_at`; the eval harness (qa-expert) writes `origin = 'tuned'` rows and the operator activates one. Every activation is `audit_append('scoring_config.activated')`.

### 3.3 Per-feature contribution and the prediction table

`health_snapshot.factors` already carries the `health/1#factor[]` array (rule, weight, penalty, value, threshold, direction, explanation). Two gaps for the ML step: the snapshot lives 3 days (R17), so predictions cannot be scored against outcomes that arrive later; and `horizons` is a blob that cannot be indexed by horizon or band. Add a sparse, long-lived `prediction` table.

```sql
CREATE TABLE sibyl.prediction (
  tenant_id            uuid NOT NULL,
  predicted_at         timestamptz NOT NULL,          -- = health_snapshot.evaluated_at; partition key
  id                   uuid NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id             uuid NOT NULL,
  health_snapshot_id   uuid NOT NULL,                  -- loose ref (snapshot partition may be dropped)
  feature_snapshot_id  uuid,                           -- → feature_snapshot when frozen on this tick
  scoring_config_id    uuid NOT NULL,
  horizon_s            integer NOT NULL,               -- ck: 900 | 3600 | 86400
  source               text NOT NULL,                  -- rules/v1 | model/<name>:<ver>
  probability_band     text NOT NULL,                  -- ck: 0.05 | 0.25 | 0.60 | 0.90
  probability          real,                           -- only from a calibrated model source
  confidence           text NOT NULL,                  -- ck: low | medium | high
  predicted_failure_mode text,                         -- failure_mode set or NULL
  contributions        jsonb NOT NULL DEFAULT '[]',    -- [{rule|feature, weight, value, threshold, direction, contribution}] ≤ 8 KB
  abstained            boolean NOT NULL DEFAULT false,
  -- outcome, filled by the worker once predicted_at + horizon_s has passed (point-in-time safe)
  outcome              text,                           -- ck: failed | recovered | no_event | unknown
  outcome_failure_mode text,
  outcome_at           timestamptz,
  outcome_label_id     uuid,                           -- → label that decided it, when one exists
  lead_time_s          integer,                        -- outcome_at − predicted_at when outcome = failed
  PRIMARY KEY (tenant_id, predicted_at, id),
  CONSTRAINT ck_prediction_contrib_size CHECK (pg_column_size(contributions) <= 8192)
) PARTITION BY RANGE (predicted_at);
CREATE INDEX ix_prediction_agent ON sibyl.prediction (tenant_id, agent_id, predicted_at DESC);
CREATE INDEX ix_prediction_open ON sibyl.prediction (tenant_id, predicted_at) WHERE outcome IS NULL;
CREATE INDEX ix_prediction_eval ON sibyl.prediction (tenant_id, source, horizon_s, probability_band, predicted_at);
SELECT sibyl.enable_tenant_rls('sibyl.prediction');
```

Sparsity rule (keeps the table small, see §5): write a `prediction` row when the band for a horizon **changes** from the previous tick, when the band is ≥ `0.25`, on every tick that also freezes a `feature_snapshot` (transition, alert, approval, 1-in-30 sample), and at least once per agent per hour as a heartbeat. The outcome filler runs hourly: for rows with `outcome IS NULL AND predicted_at + horizon_s < now()` it looks for a `failed` band in `health_1h`/`health_snapshot`, an `alert` with `verdict = 'tp'` or a `failover` of kind `failover|preemptive` whose `first_fired_at`/`created_at ∈ (predicted_at, predicted_at + horizon_s]`, else writes `no_event`; `recovered` when a degraded band returned to healthy inside the horizon. It never reads anything with `ts > predicted_at + horizon_s`, so the outcome is itself point-in-time. This table is what qa-expert's harness scores (lead time, precision/recall per band, false-failover rate) and what the Phase 2 calibration reads.

### 3.4 Score history (closes U12)

```sql
CREATE TABLE sibyl.health_1h (
  tenant_id     uuid NOT NULL,
  agent_id      uuid NOT NULL,
  bucket_start  timestamptz NOT NULL,                  -- partition key, monthly, 13 months
  ticks         integer NOT NULL DEFAULT 0,
  score_min     smallint, score_max smallint, score_avg numeric(5,2),
  band_counts   integer[] NOT NULL DEFAULT '{0,0,0,0}',   -- healthy, watch, degraded, failed
  provisional_ticks integer NOT NULL DEFAULT 0,
  coverage_avg  numeric(4,3),
  transitions   smallint NOT NULL DEFAULT 0,          -- band changes inside the hour
  top_factors   jsonb NOT NULL DEFAULT '[]',          -- [{rule, penalty_sum, ticks}] top 5, ≤ 2 KB
  scoring_config_ids uuid[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id, agent_id, bucket_start)
) PARTITION BY RANGE (bucket_start);
CREATE INDEX ix_health_1h_tenant_bucket ON sibyl.health_1h (tenant_id, bucket_start);
SELECT sibyl.enable_tenant_rls('sibyl.health_1h');
```

Written by the worker from `health_snapshot` for each closed hour before the 3-day partition drop (the partition job checks `health_1h` covers the hours in a partition before `DETACH`). `band_counts[4] > 0` is the "agent reached failed in this hour" signal the training view uses as the positive label for the 24h horizon when no verdict exists.

### 3.5 Agent risk (governance surface, D8)

Risk is not the health score. It is the governance composite the compliance persona reads: tier, EU AI Act class, blast radius, data classification, control coverage, recent health. One current row per agent plus a daily history so "risk went up on Tuesday because a PII data source was attached" is answerable.

```sql
CREATE TABLE sibyl.agent_risk (
  tenant_id        uuid NOT NULL,
  agent_id         uuid NOT NULL,
  as_of            date NOT NULL,                      -- one row per agent per day; today's row is upserted each tick that changes an input
  risk_score       smallint NOT NULL,                  -- 0..100
  risk_band        text NOT NULL,                      -- ck: low | medium | high | critical
  inherent         jsonb NOT NULL,                     -- {tier, risk_class, data_classification_max, residency, blast_radius_agents, blast_radius_processes, criticality_max}
  control_coverage jsonb NOT NULL,                     -- {continuity_plan, approved_chain, agent_identity_enforce, capture_policy, bom_present, owner_assigned, on_call}
  health_28d       jsonb NOT NULL,                     -- {failed_hours, degraded_hours, tp_alerts, fp_alerts, failovers, handoffs}
  contributions    jsonb NOT NULL,                     -- [{factor, weight, value, contribution, explanation}] ≤ 8 KB
  scoring_config_id uuid NOT NULL,
  graph_version    bigint NOT NULL,                    -- tenant.graph_version read
  computed_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, agent_id, as_of)
);
CREATE INDEX ix_agent_risk_band ON sibyl.agent_risk (tenant_id, as_of, risk_band);
SELECT sibyl.enable_tenant_rls('sibyl.agent_risk');
```

Inputs are all existing tables (`agent`, `dependency_edge`/`blast_radius`, `data_source.classification`, `continuity_plan`, `fallback_chain.status`, `agent_identity.enforcement`, `capture_policy`, `ai_bom`, `health_1h`, `alert.verdict`). Recomputed on `graph.changed` outbox events and once a day. Retention: durable (small: agents × days).

## 4. Training-set extraction (point-in-time, no leakage)

### 4.1 Rules

1. The feature vector for an example is the **FeatureSnapshot frozen at or before the moment being judged**: `feature_snapshot.as_of <= judged_as_of`, the latest such row, and never more than `grain` older (15 min for alert examples). ai-engineer §6 guarantees "no event with ts > as_of contributed".
2. When no snapshot exists (older than the 1-in-30 sample cadence, or pre-snapshot history) features are recomputed from **closed** `agent_metrics_5m` buckets with `bucket_start + 5 min <= judged_as_of` and flagged `features_recomputed = true`. Recomputed rows must not be mixed with frozen rows in one evaluation fold without the flag as a feature or a stratifier.
3. Labels come only from `label` (`alert_verdict`, `task_outcome`, `failover_outcome`, `provider_incident`) and from `prediction.outcome`; `alert.verdict` is a projection and is not read. `verdict = 'unsure'` and R29/D33 `verdict IS NULL` rows are excluded from the labelled set and counted separately (`unverdicted`).
4. Columns that exist only because of the outcome never enter the feature side: `alert.resolved_at`, `fired_count`, `escalation_level`, `outcome_observed`, `failover_id`, `routing_state` **after** the alert, and anything in `label`. The view exposes them in a separate `outcome_*` namespace only.
5. Time-based split: `split_week = to_char(judged_as_of, 'IYYY-IW')`; the harness holds out whole weeks, never random rows (autocorrelation within an incident would leak).
6. Tenant isolation holds: the view is RLS-governed like any table; cross-tenant training (Phase 2, if ever) is a separate, consented export path and not a view.

### 4.2 Alert-verdict examples

```sql
CREATE VIEW sibyl.training_alert_examples AS
WITH judged AS (
  SELECT a.tenant_id, a.id AS alert_id, a.agent_id, a.rule_id, r.code AS rule_code, r.kind AS rule_kind,
         r.horizon_s, a.severity, a.first_fired_at AS judged_as_of,
         l.id AS label_id, l.value->>'verdict' AS verdict,
         l.value->>'actual_failure_mode' AS actual_failure_mode,
         (l.value->>'lead_time_s')::int AS lead_time_s, l.labelled_at
  FROM sibyl.alert a
  JOIN sibyl.alert_rule r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id
  LEFT JOIN sibyl.label l ON l.tenant_id = a.tenant_id AND l.kind = 'alert_verdict'
        AND l.judges_kind = 'alert' AND l.judges_id = a.id::text
  WHERE a.scope = 'agent'
),
frozen AS (
  SELECT j.alert_id, fs.id AS feature_snapshot_id, fs.as_of, fs.feature_set, fs.observation_coverage, fs.doc
  FROM judged j
  JOIN LATERAL (
    SELECT fs.* FROM sibyl.feature_snapshot fs
    WHERE fs.tenant_id = j.tenant_id AND fs.agent_id = j.agent_id
      AND fs.as_of <= j.judged_as_of AND fs.as_of > j.judged_as_of - interval '15 min'
    ORDER BY fs.as_of DESC LIMIT 1
  ) fs ON true
),
recomputed AS (                      -- only for alerts without a frozen snapshot
  SELECT j.alert_id,
         sibyl.features_from_5m(j.tenant_id, j.agent_id, j.judged_as_of) AS doc   -- §4.4
  FROM judged j LEFT JOIN frozen f ON f.alert_id = j.alert_id
  WHERE f.alert_id IS NULL
),
statics AS (                         -- registry facts as of judged_as_of, from the temporal tables
  SELECT j.alert_id, ag.tier, ag.kind AS agent_kind, ag.fail_mode, ag.risk_class,
         (SELECT count(*) FROM sibyl.dependency_edge e
           WHERE e.tenant_id = j.tenant_id AND e.src_kind = 'agent' AND e.src_id = j.agent_id
             AND e.valid_from <= j.judged_as_of AND (e.valid_to IS NULL OR e.valid_to > j.judged_as_of)) AS edges_at
  FROM judged j JOIN sibyl.agent ag ON ag.tenant_id = j.tenant_id AND ag.id = j.agent_id
)
SELECT j.tenant_id, j.alert_id, j.agent_id, j.rule_code, j.rule_kind, j.horizon_s, j.severity,
       j.judged_as_of, to_char(j.judged_as_of, 'IYYY-IW') AS split_week,
       coalesce(f.feature_snapshot_id, NULL) AS feature_snapshot_id,
       coalesce(f.doc, rc.doc)                AS features,
       (f.alert_id IS NULL)                   AS features_recomputed,
       coalesce(f.observation_coverage, (rc.doc->>'observation_coverage')::numeric) AS observation_coverage,
       s.tier, s.agent_kind, s.fail_mode, s.risk_class, s.edges_at,
       -- label side (never joined into features)
       CASE j.verdict WHEN 'tp' THEN 1 WHEN 'fp' THEN 0 END AS y_tp,
       j.verdict, j.actual_failure_mode, j.lead_time_s, j.label_id, j.labelled_at,
       (j.verdict IS NULL) AS unverdicted
FROM judged j
LEFT JOIN frozen f      ON f.alert_id = j.alert_id
LEFT JOIN recomputed rc ON rc.alert_id = j.alert_id
JOIN statics s          ON s.alert_id = j.alert_id;
```

Guard: `frozen` requires `fs.as_of <= judged_as_of`; the LATERAL picks the newest snapshot that is still in the past. `agent.tier`/`risk_class` are current values (the registry is not temporal for those two); if Phase 2 needs them as-of, `lifecycle_transition` and `audit_events` carry the history and the view gains a lookup. `dependency_edge` is temporal and is read as-of.

### 4.3 Horizon examples (for the Phase 2 predictor, not just verdicts)

Verdicts label *alerts*, so the set above is biased toward moments a rule already fired. The predictor also needs negatives and failures the rules missed. `training_horizon_examples` takes every `feature_snapshot` (including `reason = 'sample'`) as an anchor and labels each horizon from what happened afterwards, reading only the future relative to `as_of` and only up to `as_of + horizon`:

```sql
CREATE VIEW sibyl.training_horizon_examples AS
SELECT fs.tenant_id, fs.id AS feature_snapshot_id, fs.agent_id, fs.as_of, fs.feature_set, fs.doc AS features,
       to_char(fs.as_of, 'IYYY-IW') AS split_week, h.horizon_s,
       EXISTS (SELECT 1 FROM sibyl.health_1h hh
               WHERE hh.tenant_id = fs.tenant_id AND hh.agent_id = fs.agent_id
                 AND hh.bucket_start >= date_trunc('hour', fs.as_of)
                 AND hh.bucket_start < fs.as_of + make_interval(secs => h.horizon_s)
                 AND hh.band_counts[4] > 0)                                         AS y_failed_band,
       EXISTS (SELECT 1 FROM sibyl.alert a JOIN sibyl.label l
                 ON l.tenant_id = a.tenant_id AND l.judges_kind = 'alert' AND l.judges_id = a.id::text
                AND l.kind = 'alert_verdict' AND l.value->>'verdict' = 'tp'
               WHERE a.tenant_id = fs.tenant_id AND a.agent_id = fs.agent_id
                 AND a.first_fired_at > fs.as_of
                 AND a.first_fired_at <= fs.as_of + make_interval(secs => h.horizon_s))  AS y_tp_alert,
       (SELECT l.value->>'outcome' FROM sibyl.label l
         WHERE l.tenant_id = fs.tenant_id AND l.agent_id = fs.agent_id AND l.kind = 'failover_outcome'
           AND l.judged_as_of > fs.as_of AND l.judged_as_of <= fs.as_of + make_interval(secs => h.horizon_s)
         ORDER BY l.judged_as_of LIMIT 1)                                          AS failover_outcome,
       (fs.as_of + make_interval(secs => h.horizon_s) <= now())                    AS horizon_closed
FROM sibyl.feature_snapshot fs
CROSS JOIN (VALUES (900), (3600), (86400)) AS h(horizon_s);
```

Rows with `horizon_closed = false` are not yet labelled and must be filtered by the exporter. `prediction` rows join on `(tenant_id, feature_snapshot_id, horizon_s)` to compare what `rules/v1` said with the realised label.

### 4.4 `features_from_5m()`

`sibyl.features_from_5m(p_tenant uuid, p_agent uuid, p_as_of timestamptz) RETURNS jsonb STABLE` (owner `sibyl_migrate`, EXECUTE to `sibyl_worker`, `sibyl_app`): builds a `sibyl-feature-snapshot/1` document from `agent_metrics_5m` rows with `bucket_start + interval '5 min' <= p_as_of` for the 5m/15m/1h grains (1m grain omitted: `grains.1m = {}` and `observation_coverage` reduced), statics from the registry, baseline from `agent_baseline` for the hour-of-week of `p_as_of`. It is the same code path the worker uses to freeze snapshots (shared `features/vN` definition in `sibyl-schemas` generated SQL), so recomputed and frozen features agree bit-for-bit for closed buckets; the only difference is the open-minute partial that the live tick sees and the recompute does not, which is why `features_recomputed` is kept as a column.

### 4.5 Export

The harness pulls with `COPY (SELECT ... FROM sibyl.training_alert_examples WHERE horizon ...) TO STDOUT (FORMAT csv)` under `set_tenant()`, or `sibyl ml export --tenant --from --to` in the SDK CLI (Apache-2), which writes Parquet to BlobStore as `payload_refs.kind = 'feature_snapshot'`-class objects (`source_kind = 'export'` added to the CHECK) so an export is erasable and auditable (`audit_append('data.export')`, scope `data:export`).

## 5. Query cost model: 20 → 2,000 agents

Assumptions (one tenant unless stated; `meridian` at 20 agents is the Phase 1 demo; 2,000 agents is the first paying-tenant ceiling for one Postgres before sharding by tenant). Per-agent traffic averages 0.6 gen_ai req/s active (20 agents, chaos-driven demo) and 0.1 req/s at 2,000 (real fleets are long-tailed); tool calls ≈ 1.8 × requests; 1.2 `(provider, model)` pairs per agent; 60 % of minutes active.

| Table | Rows/day @ 20 agents | Rows/day @ 2,000 agents | Retention | Resident rows @ 2,000 | Row width | Notes |
|---|---|---|---|---|---|---|
| `events` (reference) | ≈ 3.0 M | ≈ 50 M | ≤ 30 d | 1.5 B | ~700 B + attrs | DATAMODEL 35 GB/day figure; not changed here |
| `agent_metrics_1m` | 20 × 1.2 × 864 ≈ 21 k | 2.1 M | 14 d | 29 M | ~600 B (3 × 40-int arrays) | 17 GB; daily partitions keep the drop O(1) |
| `agent_metrics_5m` | 4.1 k | 415 k | 90 d | 37 M | ~600 B | 22 GB; the biggest new table |
| `provider_metrics_5m` | 3 providers × 4 models × 288 ≈ 3.5 k | ≈ 20 k | 90 d | 1.8 M | ~550 B | small |
| `agent_metrics_1h` | 350 | 35 k | 13 months | 14 M | ~600 B | 8 GB |
| `health_snapshot` | 20 × 8,640 = 173 k | 17.3 M | 3 d | 52 M | ~1.5 KB (factors 8 KB cap) | **the hot spot**; see Q1 |
| `health_1h` | 480 | 48 k | 13 months | 19 M | ~400 B | 8 GB |
| `prediction` (sparse rule) | ≈ 3 × (transitions + alerts + samples + hourly) ≈ 20 k | ≈ 1.5 M | 400 d | 600 M | ~700 B | too big at 2,000 with 400 d; see Q2 |
| `feature_snapshot` (1-in-30 + events) | 5.7 k | 576 k | 400 d | 230 M | ~8 KB doc | 1.8 TB: untenable in-row; see Q2 |
| `agent_trend_state` | 20 × 12 metrics | 24 k rows total | current | 24 k | 120 B | upserted 12 × per 5 min per agent |
| `agent_baseline` | 20 × 12 × 168 = 40 k total | 4 M total | current | 4 M | 100 B | nightly rewrite, 400 MB |
| `agent_risk` | 20 | 2,000 | durable | 730 k/yr | ~2 KB | fine |
| `alert` / `label` | ≈ 40 / 40 | ≈ 2,000 / 1,500 | durable | ~1 M/yr | — | verdict rate is the training-set ceiling |

Per-tick work (every 10 s, per tenant):

| Step | @ 20 agents | @ 2,000 agents | Bound by |
|---|---|---|---|
| Dirty-set scan on `events` (BRIN on `received_at`) | ~350 events, ~30 buckets | ~5,800 events, ~1,500 buckets | BRIN range + one heap pass; ≤ 50 ms |
| 1m recompute (index range per bucket, ~12 events) | 30 × 12 rows | 1,500 × 4 rows | `ix_events_agent_ts (tenant_id, agent_id, ts)`; ≤ 300 ms |
| 5m/1h/provider upserts | ~40 rows | ~1,800 rows | pk upserts; ≤ 100 ms |
| Health read: 10 min of 1m rows | 240 rows | 24,000 rows | `ix_agent_metrics_1m_tenant_bucket`; ~60 ms at 2,000 |
| Health read: trend state + latest 5m | 240 + 24 rows | 24,000 + 2,400 rows | pk lookups |
| `health_snapshot` INSERT | 20 rows | 2,000 rows × 1.5 KB = 3 MB per tick, 26 GB/day | WAL; this is Q1 |
| `prediction` sparse INSERT | ~2 rows | ~170 rows | fine |

Conclusion: rollup and read paths scale linearly and stay under one second per tick at 2,000 agents on one box. The two things that do not scale are `health_snapshot` written every tick for every agent (R17) and `feature_snapshot` documents kept in-row for 400 days (U2). Both are chair questions (§7 Q1, Q2), and both have mechanical fixes: write snapshots on change plus a 60 s heartbeat (cuts 2,000-agent volume ~8×), and move `feature_snapshot.doc` to BlobStore under `payload_refs.kind = 'feature_snapshot'` (already a listed kind) with a 2 KB summary in-row.

Index plan (all lead with `tenant_id`; new ones only):

| Index | Purpose |
|---|---|
| `agent_metrics_5m (tenant_id, bucket_start)` | tick reads, charts, provider recompute |
| `agent_metrics_5m` pk `(tenant_id, agent_id, provider, model, bucket_start)` | `features_from_5m`, per-agent charts |
| `provider_metrics_5m (tenant_id, bucket_start)` | provider rules |
| `prediction (tenant_id, agent_id, predicted_at DESC)` | console timeline |
| `prediction (tenant_id, predicted_at) WHERE outcome IS NULL` | hourly outcome filler, stays tiny |
| `prediction (tenant_id, source, horizon_s, probability_band, predicted_at)` | harness metrics per band |
| `feature_snapshot (tenant_id, agent_id, as_of DESC)` (exists) | LATERAL in §4.2 |
| `label (tenant_id, judges_kind, judges_id)` (exists) | verdict join |
| `health_1h (tenant_id, bucket_start)` | horizon labels, score charts |
| `agent_risk (tenant_id, as_of, risk_band)` | compliance dashboard |
| BRIN `events (received_at)` (exists), `ix_events_agent_ts` (exists) | rollup |

No GIN on `factors`/`contributions`: they are read by primary key and rendered, never searched. `work_mem` for the worker role: 64 MB (hist_sum over 24k arrays); `autovacuum_vacuum_scale_factor = 0.02` on `agent_metrics_1m`/`5m` because replace-upserts churn tuples; `fillfactor = 70` on both so HOT updates land in-page.

## 6. Step 3 + Step 4 amendment DDL (consolidated)

Applies `api/SYNTHESIS.md` amendments 1–6 plus the Step 3 escalations D20/D26 that touch columns. All names `sibyl*`. Migration 11 `step4_amendments`, expand/contract, `lock_timeout = '5s'`.

```sql
-- 1. idempotency_record (63rd table; infrastructure-adjacent but tenant-scoped: the key is per tenant+principal)
CREATE TABLE sibyl.idempotency_record (
  tenant_id       uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),   -- partition key, daily, 2 partitions kept (24 h retention)
  principal_kind  text NOT NULL,            -- ck: user | api_key
  principal_id    uuid NOT NULL,
  route           text NOT NULL,            -- method + template, e.g. 'POST /api/v1/incidents/{id}/actions'
  idempotency_key text NOT NULL CHECK (length(idempotency_key) <= 128),
  request_sha256  bytea NOT NULL,
  state           text NOT NULL DEFAULT 'in_progress',   -- ck: in_progress | done
  status_code     smallint,
  response_body   jsonb CHECK (pg_column_size(response_body) <= 65536),
  completed_at    timestamptz,
  PRIMARY KEY (tenant_id, principal_kind, principal_id, route, idempotency_key, created_at)
) PARTITION BY RANGE (created_at);
SELECT sibyl.enable_tenant_rls('sibyl.idempotency_record');
GRANT SELECT, INSERT, UPDATE ON sibyl.idempotency_record TO sibyl_app;
-- api: INSERT ... ON CONFLICT DO NOTHING; 0 rows → read row: state in_progress → 409 idempotency_in_progress;
-- request_sha256 ≠ → 422 idempotency_key_reuse; else replay with Idempotency-Replayed: true.

-- 2. ingest_batch_seen + tenant.ingest_rate_limit + events_rejected reasons
CREATE TABLE sibyl.ingest_batch_seen (
  tenant_id       uuid NOT NULL,
  received_at     timestamptz NOT NULL DEFAULT clock_timestamp(),   -- partition key, daily, 3 d
  batch_id        text NOT NULL CHECK (length(batch_id) <= 128),    -- X-Sibyl-Batch-Id
  api_key_id      uuid NOT NULL,
  response_sha256 bytea NOT NULL,
  response_body   jsonb NOT NULL CHECK (pg_column_size(response_body) <= 16384),
  PRIMARY KEY (tenant_id, batch_id, received_at)
) PARTITION BY RANGE (received_at);
SELECT sibyl.enable_tenant_rls('sibyl.ingest_batch_seen');
GRANT SELECT, INSERT ON sibyl.ingest_batch_seen TO sibyl_ingest;

ALTER TABLE sibyl.tenant
  ADD COLUMN ingest_rate_limit jsonb NOT NULL DEFAULT '{"events_per_s": 500, "burst": 5000}'
  CONSTRAINT ck_tenant_ingest_rate_limit CHECK (
    (ingest_rate_limit->>'events_per_s')::int BETWEEN 1 AND 100000
    AND (ingest_rate_limit->>'burst')::int BETWEEN 1 AND 1000000);

ALTER TABLE sibyl.events_rejected DROP CONSTRAINT ck_events_rejected_reason;
ALTER TABLE sibyl.events_rejected ADD CONSTRAINT ck_events_rejected_reason CHECK (reason IN (
  'schema_invalid','missing_required','unknown_type','late_contribution','outside_retention',
  'no_partition','capture_policy_missing','tenant_erasing','env_mismatch','agent_not_permitted')) NOT VALID;
ALTER TABLE sibyl.events_rejected VALIDATE CONSTRAINT ck_events_rejected_reason;

-- 3. audit_anchors.kind += break_glass; outbox topic anchor_now
ALTER TABLE sibyl.audit_anchors DROP CONSTRAINT ck_audit_anchors_kind;
ALTER TABLE sibyl.audit_anchors ADD CONSTRAINT ck_audit_anchors_kind CHECK (kind IN (
  'hourly','partition_boundary','erasure','export','rekey','break_glass')) NOT VALID;
ALTER TABLE sibyl.audit_anchors VALIDATE CONSTRAINT ck_audit_anchors_kind;
-- outbox.topic is open text; 'audit.anchor_now' is registered in sibyl-schemas topic list (no DDL).
-- audit_action seed: INSERT ('access.break_glass','security','{system}','kill_switch',
--   '{api_key_id,action_taken,scope_kind,scope_id,ip_hash}', false, true, 'critical') ON CONFLICT DO NOTHING.

-- 4. api_key.scopes CHECK re-enumerated to the R21 catalogue; prefix sbl_
ALTER TABLE sibyl.api_key DROP CONSTRAINT IF EXISTS ck_api_key_scopes;
ALTER TABLE sibyl.api_key ADD CONSTRAINT ck_api_key_scopes CHECK (
  scopes <@ ARRAY['ingest:write','gateway:proxy','gateway:snapshot','routing:read','handoff:write',
                  'agents:read','agents:write','killswitch:pull']::text[]
  AND cardinality(scopes) >= 1
  AND ('killswitch:pull' <> ALL (scopes) OR scopes = ARRAY['killswitch:pull']::text[])   -- D20: exclusive
) NOT VALID;
ALTER TABLE sibyl.api_key VALIDATE CONSTRAINT ck_api_key_scopes;
-- Break-glass key (D20/D34): agent_id IS NULL AND scopes = {killswitch:pull}; enforced by the same CHECK plus
ALTER TABLE sibyl.api_key ADD CONSTRAINT ck_api_key_breakglass_tenant_level
  CHECK (scopes <> ARRAY['killswitch:pull']::text[] OR agent_id IS NULL);
-- Key format sbl_<env>_<prefix12>_<secret> (R22): prefix column unchanged (char(12)); format lives in the api, not DDL.
-- Default scopes for agent-bound keys (api constant): {ingest:write, routing:read, handoff:write}.
-- gateway:snapshot sits on tenant-level keys held by the hosted gateway (R26/D31: N keys, no platform credential).

-- 5. backup_retention_days default 7 (D26/R30); OTLP 202→200 is API text, no DDL
ALTER TABLE sibyl.tenant ALTER COLUMN backup_retention_days SET DEFAULT 7;
ALTER TABLE sibyl.tenant ADD CONSTRAINT ck_tenant_backup_retention CHECK (backup_retention_days BETWEEN 1 AND 35);
UPDATE sibyl.tenant SET backup_retention_days = 7 WHERE backup_retention_days = 35;   -- seed tenants only, < 10 rows

-- 6. agent_id nullable on provider.status / observation.gap: already the Step 3 CHECK (DATAMODEL §4.3, U1); no change.

-- Step 3 escalations with column impact (D20–D28), confirmed present:
--   D23 continuity_plan.rto_s default by tier → trigger trg_continuity_plan_defaults reads agent.tier: 900/3600/14400.
--   D21 routing_state.operator_hold_until: routing_apply() raises operator_hold for actor_kind IN (rule, policy) only (humans + kill bypass).
--   D22 approval.timeout_policy forced 'hold' when D22 predicate true: trigger trg_approval_fail_safe_guard on INSERT.
--   D27 tenant.audit_retention_days CHECK >= 400 (exists). D28 capture_policy.payload_retention_days CHECK 1..365 (exists).
--   D33 alert.verdict nullable on state = 'resolved' (exists); partial index (tenant_id, resolved_at) WHERE state='resolved' AND verdict IS NULL for the unverdicted queue — ADD.
CREATE INDEX ix_alert_unverdicted ON sibyl.alert (tenant_id, resolved_at DESC) WHERE state = 'resolved' AND verdict IS NULL;

-- Grants: re-run the grant matrix; isolation test (§7.1 CI gate) picks up the new tables automatically;
-- allowlist literal unchanged (both new Step 4 tables are tenant-scoped).
```

Updated inventory: 62 + `idempotency_record` + `ingest_batch_seen` + the nine Step 5 tables (`agent_metrics_5m`, `provider_metrics_5m`, `agent_trend_state`, `agent_baseline`, `scoring_config`, `prediction`, `health_1h`, `agent_risk`, `rollup_job`) = **73**. `partition_registry` gains six partitioned tables: `agent_metrics_5m`, `provider_metrics_5m`, `prediction`, `health_1h`, `idempotency_record`, `ingest_batch_seen`.

Writer matrix additions: `sibyl_worker` DML on all nine Step 5 tables and SELECT on `label`/`alert`; `sibyl_app` SELECT on all, plus INSERT on `scoring_config` and UPDATE of its two timestamps (activation), plus INSERT on `rollup_job` (operator-requested backfill). `sibyl_ingest` INSERT on `ingest_batch_seen` only. The training views are owned by `sibyl_migrate` with `security_invoker = true` so RLS applies to the caller, never the owner.

## 7. Open questions for the chair

| # | Question | My default |
|---|---|---|
| Q1 | R17 writes a `health_snapshot` every 10 s for every agent. At 2,000 agents that is 17 M rows and ~26 GB WAL per day for 3 days of history. Amend R17 to **write on change** (score moved ≥ 3 points, band change, factors set change, horizons band change) plus a 60 s heartbeat row per agent? The health response is assembled from the latest row either way; `health_1h` (§3.4) keeps the hourly history. | Yes; the harness measures time-to-detect from `prediction`/`alert` timestamps, not from snapshot cadence. |
| Q2 | `feature_snapshot.doc` (≤ 32 KB, median ~8 KB) kept 400 d in-row is 1.8 TB at 2,000 agents with the 1-in-30 sample. Move `doc` to BlobStore (`payload_refs.kind = 'feature_snapshot'` already exists) with a ≤ 2 KB in-row summary (`grains.5m` only) and drop the sample rate to 1-in-120 beyond 90 d? Training then reads Parquet exports, not the table. | Yes to BlobStore for `doc`; keep 1-in-30 but sweep `reason = 'sample'` rows older than 90 d unless referenced by a label or a `prediction` with `outcome = 'failed'`. |
| Q3 | Is `agent_metrics_5m` as a materialised tier accepted (Step 3 said query-time)? It costs 22 GB at 2,000 agents and buys 90-day point-in-time recompute plus a cheap tick. Alternative: keep query-time 5m and accept that features cannot be recomputed after 14 d. | Materialise. |
| Q4 | `prediction` sparsity rule (write on band change, band ≥ 0.25, snapshot ticks, hourly heartbeat): does qa-expert's harness need every tick's horizons to compute lead time, or is "first tick the band rose" sufficient? If every tick, `prediction` must be 3-day retention like `health_snapshot` and the harness must run inside that window. | Sparse + 400 d; lead time is measured from the first band rise, which the sparse rule captures exactly. |
| Q5 | The training view excludes `verdict = 'unsure'` and the D33 `NULL` verdicts. With ~40 alerts/day at 20 agents and a realistic 50 % verdict rate, Phase 2 has ~7,000 labelled examples per year per demo tenant. Should the `provider_incident` label kind and `prediction.outcome = failed|no_event` (weak labels) be admitted into the Phase 2 training set as a separate `label_strength` column, or do we hold Phase 2 to operator verdicts only? | Admit weak labels with `label_strength ∈ {verdict, outcome, provider_feed}` as a feature of the fold, operator verdicts as the evaluation set. |
| Q6 | `scoring_config` is per tenant (R18 pattern). The eval harness tunes against synthetic `meridian` traffic; should tuned configs be promotable to the seed (`origin = 'seed'`, `seed_version` bump, re-copied to tenants with `overridden = false`) by a CLI step, or is every tenant's config independent after creation? | Promotable via `sibyl rules promote`; tenants that activated a `custom` row are untouched (same rule as `alert_rule` re-seeding). |
