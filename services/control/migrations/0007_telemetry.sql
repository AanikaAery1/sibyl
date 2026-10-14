-- 0007 telemetry & rollups (DATAMODEL §4.3; ML db §1, §6 folded per R59; R60 xid8 cursors).
-- Partitioned tables get their partitions from partition_ensure() (0014 and the worker).

-- Migration-only helper: grant INSERT on every column except the listed ones, so writers
-- cannot supply commit-order (xid) or generated columns.
CREATE FUNCTION sibyl.grant_insert_except(p_table regclass, p_role text, p_except text[]) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  v_cols text;
BEGIN
  SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum) INTO v_cols
    FROM pg_attribute
   WHERE attrelid = p_table AND attnum > 0 AND NOT attisdropped AND attgenerated = ''
     AND NOT (attname = ANY (p_except));
  EXECUTE format('GRANT INSERT (%s) ON %s TO %I', v_cols, p_table, p_role);
END
$$;

CREATE TABLE sibyl.events (
  tenant_id               uuid          NOT NULL,
  event_id                uuid          NOT NULL,
  ts                      timestamptz   NOT NULL,
  observed_at             timestamptz,
  received_at             timestamptz   NOT NULL DEFAULT clock_timestamp(),
  is_late                 boolean       GENERATED ALWAYS AS (received_at - ts > interval '120 seconds') STORED,
  xid                     xid8          NOT NULL DEFAULT pg_current_xact_id(),
  event_type              text          NOT NULL,
  source                  text          NOT NULL,
  schema_version          text          NOT NULL DEFAULT 'sibyl-event/1',
  agent_id                uuid,
  agent_version_id        uuid,
  task_id                 uuid,
  call_id                 uuid,
  trace_id                uuid,
  span_id                 bytea,
  parent_span_id          bytea,
  emitter_id              text          NOT NULL,
  seq                     bigint        NOT NULL,
  provider                text,
  model                   text,
  response_model          text,
  status                  text,
  error_type              text,
  error_class             text,
  http_status             smallint,
  latency_ms              integer,
  ttfb_ms                 integer,
  tokens_in               integer,
  tokens_out              integer,
  cost_usd                numeric(18,8),
  policy_state            text          NOT NULL,
  policy_version          bigint,
  route_decision          text,
  capture_mode            text          NOT NULL,
  redaction_profile_hash  bytea         NOT NULL,
  api_key_id              uuid,
  identity_version        integer,
  tools_hash              bytea,
  payload_ref_id          uuid,
  payload_sha256          bytea,
  payload_bytes           bigint,
  raw_ref_id              uuid,
  normaliser_version      text          NOT NULL,
  semconv_version         text,
  ingest                  jsonb,
  attrs                   jsonb         NOT NULL DEFAULT '{}',
  scrub_late_hits         integer,
  scrub_rules_fired       text[],
  created_at              timestamptz   NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, event_id, ts),
  CONSTRAINT ck_events_event_type CHECK (event_type IN ('gen_ai.request', 'tool.call', 'agent.invoke', 'checkpoint',
    'handoff.requested', 'handoff.completed', 'handoff.returned', 'feedback', 'task.outcome', 'agent.discovered',
    'policy.decision', 'observation.gap', 'provider.status', 'health.transition')),
  CONSTRAINT ck_events_source CHECK (source IN ('sdk', 'gateway', 'ingest', 'worker', 'api')),
  CONSTRAINT ck_events_status CHECK (status IN ('ok', 'error', 'handed_off', 'cancelled')),
  CONSTRAINT ck_events_error_class CHECK (error_class IN ('timeout', 'rate_limit', 'server_error', 'client_error',
                                                          'blocked', 'other')),
  CONSTRAINT ck_events_policy_state CHECK (policy_state IN ('fresh', 'stale', 'expired', 'unavailable',
                                                            'not_applicable')),
  CONSTRAINT ck_events_route_decision CHECK (route_decision IN ('primary', 'failover', 'inline_fallback', 'canary',
                                                                'stale_primary')),
  CONSTRAINT ck_events_capture_mode CHECK (capture_mode IN ('full', 'redacted', 'metadata')),
  CONSTRAINT ck_events_agent_id CHECK (agent_id IS NOT NULL OR event_type IN ('provider.status', 'observation.gap')),
  CONSTRAINT ck_events_span_ids CHECK ((span_id IS NULL OR octet_length(span_id) = 8)
                                       AND (parent_span_id IS NULL OR octet_length(parent_span_id) = 8)),
  CONSTRAINT ck_events_attrs CHECK (pg_column_size(attrs) <= 4096 AND jsonb_typeof(attrs) = 'object'
    AND NOT sibyl.has_content_key(attrs)),
  CONSTRAINT ck_events_ingest CHECK (ingest IS NULL OR pg_column_size(ingest) <= 1024),
  -- INT-1: ingest's own scrub result (D12): secrets it found that the emitter missed and the
  -- detector ids that fired (emitter's and ingest's). Ids only, never matched text.
  CONSTRAINT ck_events_scrub_late_hits CHECK (scrub_late_hits IS NULL OR scrub_late_hits >= 0),
  CONSTRAINT ck_events_scrub_rules_fired CHECK (scrub_rules_fired IS NULL OR (
    cardinality(scrub_rules_fired) <= 64
    AND array_to_string(scrub_rules_fired, ',', '!') ~ '^([A-Za-z0-9_.:-]{1,64}(,|$))*$')),
  CONSTRAINT ck_events_payload_sha256 CHECK (payload_sha256 IS NULL OR octet_length(payload_sha256) = 32)
) PARTITION BY RANGE (ts);
CREATE INDEX ix_events_agent_ts ON sibyl.events (tenant_id, agent_id, ts DESC);
CREATE INDEX ix_events_task ON sibyl.events (tenant_id, task_id, ts) WHERE task_id IS NOT NULL;
CREATE INDEX ix_events_trace ON sibyl.events (tenant_id, trace_id);
CREATE UNIQUE INDEX ux_events_call ON sibyl.events (tenant_id, call_id, ts) WHERE event_type = 'gen_ai.request';
CREATE INDEX ix_events_xid ON sibyl.events (tenant_id, xid);

CREATE TABLE sibyl.events_rejected (
  tenant_id    uuid        NOT NULL,
  id           uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  received_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  reason       text        NOT NULL,
  raw_ref_id   uuid,
  head         jsonb       NOT NULL DEFAULT '{}',
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id, received_at),
  CONSTRAINT ck_events_rejected_reason CHECK (reason IN ('schema_invalid', 'missing_required', 'unknown_type',
    'late_contribution', 'outside_retention', 'no_partition', 'capture_policy_missing', 'tenant_erasing',
    'env_mismatch', 'agent_not_permitted')),
  CONSTRAINT ck_events_rejected_head CHECK (pg_column_size(head) <= 2048)
) PARTITION BY RANGE (received_at);

CREATE TABLE sibyl.call_merge (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  call_id               uuid        NOT NULL,
  first_seen_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
  sdk_contribution      jsonb,
  gateway_contribution  jsonb,
  state                 text        NOT NULL DEFAULT 'partial',
  flush_due_at          timestamptz NOT NULL DEFAULT clock_timestamp() + interval '5 seconds',
  flushed_at            timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, call_id),
  CONSTRAINT ck_call_merge_state CHECK (state IN ('partial', 'complete', 'flushed')),
  CONSTRAINT ck_call_merge_flushed CHECK ((state = 'flushed') = (flushed_at IS NOT NULL)),
  CONSTRAINT ck_call_merge_contribution CHECK (sdk_contribution IS NOT NULL OR gateway_contribution IS NOT NULL),
  CONSTRAINT ck_call_merge_size CHECK (pg_column_size(sdk_contribution) <= 16384
                                       AND pg_column_size(gateway_contribution) <= 16384)
);
CREATE INDEX ix_call_merge_flush ON sibyl.call_merge (tenant_id, state, flush_due_at);

CREATE TABLE sibyl.payload_refs (
  tenant_id               uuid        NOT NULL,
  id                      uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  created_at              timestamptz NOT NULL DEFAULT now(),
  kind                    text        NOT NULL,
  uri                     text        NOT NULL,
  content_type            text        NOT NULL DEFAULT 'application/json',
  parts                   text[]      NOT NULL DEFAULT '{}',
  sha256                  bytea       NOT NULL,
  size_bytes              bigint      NOT NULL,
  stored_bytes            bigint      NOT NULL,
  tenant_key_id           uuid        NOT NULL,
  key_version             integer     NOT NULL,
  nonce                   bytea       NOT NULL,
  capture_mode            text        NOT NULL,
  redaction_profile_hash  bytea       NOT NULL,
  api_key_id              uuid,
  agent_id                uuid,
  source_kind             text        NOT NULL,
  source_id               uuid,
  expires_at              timestamptz NOT NULL,
  state                   text        NOT NULL DEFAULT 'stored',
  swept_at                timestamptz,
  shredded_at             timestamptz,
  PRIMARY KEY (tenant_id, id, created_at),
  CONSTRAINT ck_payload_refs_kind CHECK (kind IN ('span_content', 'raw_batch', 'prompt', 'checkpoint_state',
    'handoff_packet', 'feature_snapshot', 'bom_export', 'anchor_export', 'comment', 'model_artifact', 'model_card')),
  CONSTRAINT ck_payload_refs_state CHECK (state IN ('stored', 'swept', 'shredded')),
  CONSTRAINT ck_payload_refs_capture_mode CHECK (capture_mode IN ('full', 'redacted', 'metadata')),
  CONSTRAINT ck_payload_refs_source_kind CHECK (source_kind IN ('event', 'checkpoint', 'packet', 'agent_version',
                                                                'bom', 'anchor', 'comment', 'export')),
  CONSTRAINT ck_payload_refs_sha256 CHECK (octet_length(sha256) = 32),
  CONSTRAINT ck_payload_refs_nonce CHECK (octet_length(nonce) = 12),
  CONSTRAINT ck_payload_refs_sizes CHECK (size_bytes >= 0 AND stored_bytes >= 0)
) PARTITION BY RANGE (created_at);
CREATE INDEX ix_payload_refs_expiry ON sibyl.payload_refs (tenant_id, expires_at) WHERE state = 'stored';
CREATE INDEX ix_payload_refs_agent ON sibyl.payload_refs (tenant_id, agent_id, created_at);

CREATE TABLE sibyl.checkpoint (
  tenant_id               uuid        NOT NULL,
  id                      uuid        NOT NULL,
  created_at              timestamptz NOT NULL DEFAULT now(),
  agent_id                uuid        NOT NULL,
  task_id                 uuid        NOT NULL,
  seq                     integer     NOT NULL,
  step_index              integer     NOT NULL,
  step_name               text,
  state_bytes             integer     NOT NULL,
  state                   jsonb,
  state_ref_id            uuid,
  state_sha256            bytea,
  state_schema            text        NOT NULL,
  doc                     jsonb       NOT NULL,
  capture_mode            text        NOT NULL,
  redaction_profile_hash  bytea       NOT NULL,
  api_key_id              uuid,
  PRIMARY KEY (tenant_id, id, created_at),
  CONSTRAINT uq_checkpoint_task_seq UNIQUE (tenant_id, task_id, seq, created_at),
  -- INT-1: metadata capture keeps the checkpoint row (task, seq, step) but never its state;
  -- every other mode carries exactly one of inline state or a state ref.
  CONSTRAINT ck_checkpoint_metadata CHECK (capture_mode <> 'metadata' OR (state IS NULL AND state_ref_id IS NULL)),
  CONSTRAINT ck_checkpoint_state_xor CHECK (capture_mode = 'metadata' OR (state IS NULL) <> (state_ref_id IS NULL)),
  CONSTRAINT ck_checkpoint_inline CHECK (capture_mode = 'metadata' OR (state_bytes <= 65536) = (state IS NOT NULL)),
  CONSTRAINT ck_checkpoint_sizes CHECK (pg_column_size(state) <= 65536 AND pg_column_size(doc) <= 65536),
  CONSTRAINT ck_checkpoint_capture_mode CHECK (capture_mode IN ('full', 'redacted', 'metadata'))
) PARTITION BY RANGE (created_at);
CREATE INDEX ix_checkpoint_agent ON sibyl.checkpoint (tenant_id, agent_id, created_at DESC);

-- Rollup grains. The counter set is shared (ML db §1.2); built once so the grains cannot drift.
DO $$
DECLARE
  v_step3 text := $c$
    request_count integer NOT NULL DEFAULT 0, error_count integer NOT NULL DEFAULT 0,
    timeout_count integer NOT NULL DEFAULT 0, rate_limit_count integer NOT NULL DEFAULT 0,
    server_error_count integer NOT NULL DEFAULT 0, blocked_count integer NOT NULL DEFAULT 0,
    inline_fallback_count integer NOT NULL DEFAULT 0, breaker_open_count integer NOT NULL DEFAULT 0,
    tool_call_count integer NOT NULL DEFAULT 0, late_count integer NOT NULL DEFAULT 0,
    policy_stale_count integer NOT NULL DEFAULT 0, tokens_in bigint NOT NULL DEFAULT 0,
    tokens_out bigint NOT NULL DEFAULT 0, cost_usd numeric(18,8) NOT NULL DEFAULT 0,
    ratelimit_remaining_min integer,
    latency_hist integer[] NOT NULL DEFAULT sibyl.zero_hist(),
    ttfb_hist integer[] NOT NULL DEFAULT sibyl.zero_hist(),
    retry_count integer NOT NULL DEFAULT 0, finish_length_count integer NOT NULL DEFAULT 0,
    finish_tool_calls_count integer NOT NULL DEFAULT 0, refusal_count integer NOT NULL DEFAULT 0,
    empty_output_count integer NOT NULL DEFAULT 0, tool_error_count integer NOT NULL DEFAULT 0,
    tool_schema_invalid_count integer NOT NULL DEFAULT 0, output_chars_sum bigint NOT NULL DEFAULT 0,
    tokens_out_sumsq numeric(24,0) NOT NULL DEFAULT 0,
    context_util_hist integer[] NOT NULL DEFAULT sibyl.zero_hist(),
    tool_seq_hash_distinct integer NOT NULL DEFAULT 0,$c$;
  v_agent_only text := $c$
    task_count integer NOT NULL DEFAULT 0, task_success_count integer NOT NULL DEFAULT 0,
    task_failure_count integer NOT NULL DEFAULT 0, handoff_count integer NOT NULL DEFAULT 0,
    feedback_count integer NOT NULL DEFAULT 0, feedback_sum numeric(10,4) NOT NULL DEFAULT 0,$c$;
  v_tail text := $c$
    computed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT now(),$c$;
  v_hist_check text := 'CHECK (cardinality(latency_hist) = 40 AND cardinality(ttfb_hist) = 40 '
                       'AND cardinality(context_util_hist) = 40)';
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['agent_metrics_1m', 'agent_metrics_5m', 'agent_metrics_1h'] LOOP
    EXECUTE format($f$CREATE TABLE sibyl.%I (
      tenant_id uuid NOT NULL, agent_id uuid NOT NULL, provider text NOT NULL, model text NOT NULL,
      bucket_start timestamptz NOT NULL, %s %s %s %s
      PRIMARY KEY (tenant_id, agent_id, provider, model, bucket_start),
      CONSTRAINT %I %s) PARTITION BY RANGE (bucket_start)$f$,
      t, v_step3, v_agent_only,
      CASE WHEN t = 'agent_metrics_5m' THEN 'children_1m smallint NOT NULL DEFAULT 0,' ELSE '' END,
      v_tail, 'ck_' || t || '_hist', v_hist_check);
    EXECUTE format('CREATE INDEX %I ON sibyl.%I (tenant_id, bucket_start)', 'ix_' || t || '_tenant_bucket', t);
  END LOOP;
  EXECUTE format($f$CREATE TABLE sibyl.provider_metrics_5m (
      tenant_id uuid NOT NULL, provider text NOT NULL, model text NOT NULL, bucket_start timestamptz NOT NULL,
      agent_count smallint NOT NULL DEFAULT 0, %s %s
      PRIMARY KEY (tenant_id, provider, model, bucket_start),
      CONSTRAINT ck_provider_metrics_5m_hist %s) PARTITION BY RANGE (bucket_start)$f$,
      v_step3, v_tail, v_hist_check);
  CREATE INDEX ix_provider_metrics_5m_tenant_bucket ON sibyl.provider_metrics_5m (tenant_id, bucket_start);
END
$$;
ALTER TABLE sibyl.agent_metrics_5m ADD CONSTRAINT ck_agent_metrics_5m_bucket CHECK (
  bucket_start = date_bin(interval '5 minutes', bucket_start, timestamptz '2000-01-01 00:00:00+00'));
ALTER TABLE sibyl.agent_metrics_5m ADD CONSTRAINT ck_agent_metrics_5m_children CHECK (children_1m BETWEEN 0 AND 5);
ALTER TABLE sibyl.provider_metrics_5m ADD CONSTRAINT ck_provider_metrics_5m_bucket CHECK (
  bucket_start = date_bin(interval '5 minutes', bucket_start, timestamptz '2000-01-01 00:00:00+00'));

-- R49: the snapshot document lives in BlobStore (payload_refs kind feature_snapshot); the row
-- keeps a <= 2 KB summary (grains.5m). Immutable content; retention sweeps may delete.
CREATE TABLE sibyl.feature_snapshot (
  tenant_id             uuid         NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid         NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id              uuid         NOT NULL,
  as_of                 timestamptz  NOT NULL,
  feature_set           text         NOT NULL,
  reason                text         NOT NULL,
  observation_coverage  numeric(4,3) NOT NULL,
  summary               jsonb        NOT NULL DEFAULT '{}',
  doc_ref_id            uuid,
  doc_sha256            bytea,
  created_at            timestamptz  NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_feature_snapshot_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_feature_snapshot_reason CHECK (reason IN ('transition', 'alert', 'approval', 'sample')),
  CONSTRAINT ck_feature_snapshot_feature_set CHECK (feature_set ~ '^features/v[0-9]+$'),
  CONSTRAINT ck_feature_snapshot_coverage CHECK (observation_coverage BETWEEN 0 AND 1),
  CONSTRAINT ck_feature_snapshot_summary CHECK (pg_column_size(summary) <= 2048),
  CONSTRAINT ck_feature_snapshot_doc CHECK ((doc_ref_id IS NULL) = (doc_sha256 IS NULL))
);
CREATE INDEX ix_feature_snapshot_agent ON sibyl.feature_snapshot (tenant_id, agent_id, as_of DESC);

CREATE TABLE sibyl.label (
  tenant_id            uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                   uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id             uuid        NOT NULL,
  kind                 text        NOT NULL,
  label_strength       text        NOT NULL,
  judges_kind          text        NOT NULL,
  judges_id            text        NOT NULL,
  window_start         timestamptz,
  window_end           timestamptz,
  feature_snapshot_id  uuid,
  judged_as_of         timestamptz NOT NULL,
  labelled_at          timestamptz NOT NULL DEFAULT now(),
  labeller_kind        text        NOT NULL,
  labeller_ref         text,
  value                jsonb       NOT NULL,
  reason               text,
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_label_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_label_feature_snapshot FOREIGN KEY (tenant_id, feature_snapshot_id)
    REFERENCES sibyl.feature_snapshot (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_label_kind CHECK (kind IN ('alert_verdict', 'task_outcome', 'feedback', 'failover_outcome',
                                           'handoff_outcome', 'provider_incident')),
  CONSTRAINT ck_label_label_strength CHECK (label_strength IN ('verdict', 'outcome', 'provider_feed')),
  CONSTRAINT ck_label_judges_kind CHECK (judges_kind IN ('health_snapshot', 'event', 'alert', 'packet', 'transition',
                                                         'window')),
  CONSTRAINT ck_label_labeller_kind CHECK (labeller_kind IN ('operator', 'end_user', 'sdk', 'judge', 'worker')),
  CONSTRAINT ck_label_value CHECK (pg_column_size(value) <= 8192),
  CONSTRAINT ck_label_window CHECK (window_end IS NULL OR window_start IS NULL OR window_end >= window_start)
);
CREATE INDEX ix_label_judges ON sibyl.label (tenant_id, judges_kind, judges_id);
CREATE INDEX ix_label_kind ON sibyl.label (tenant_id, kind, labelled_at);

CREATE TABLE sibyl.ingest_batch_seen (
  tenant_id        uuid        NOT NULL,
  received_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
  batch_id         text        NOT NULL,
  api_key_id       uuid        NOT NULL,
  response_sha256  bytea       NOT NULL,
  response_body    jsonb       NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, batch_id, received_at),
  CONSTRAINT ck_ingest_batch_seen_batch_id CHECK (length(batch_id) <= 128),
  CONSTRAINT ck_ingest_batch_seen_body CHECK (pg_column_size(response_body) <= 16384),
  CONSTRAINT ck_ingest_batch_seen_sha256 CHECK (octet_length(response_sha256) = 32)
) PARTITION BY RANGE (received_at);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['events', 'events_rejected', 'call_merge', 'payload_refs', 'checkpoint',
                           'agent_metrics_1m', 'agent_metrics_5m', 'agent_metrics_1h', 'provider_metrics_5m',
                           'feature_snapshot', 'label', 'ingest_batch_seen'] LOOP
    PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', t)::regclass);
  END LOOP;
END
$$;
CREATE TRIGGER trg_call_merge_updated_at BEFORE UPDATE ON sibyl.call_merge
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();
-- Append-only: no UPDATE ever; DELETE only by the per-tenant retention sweeper (R7) and erasure.
CREATE TRIGGER trg_events_immutable BEFORE UPDATE ON sibyl.events
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_checkpoint_immutable BEFORE UPDATE OR DELETE ON sibyl.checkpoint
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_label_immutable BEFORE UPDATE OR DELETE ON sibyl.label
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_label_no_truncate BEFORE TRUNCATE ON sibyl.label
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_feature_snapshot_immutable BEFORE UPDATE ON sibyl.feature_snapshot
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();

-- Grant matrix (DATAMODEL §3 writers; ML db §6 writer additions).
GRANT SELECT ON sibyl.events, sibyl.events_rejected, sibyl.payload_refs, sibyl.checkpoint, sibyl.label,
  sibyl.feature_snapshot TO sibyl_app, sibyl_worker, sibyl_ingest;
SELECT sibyl.grant_insert_except('sibyl.events', r, ARRAY['xid'])
  FROM unnest(ARRAY['sibyl_ingest', 'sibyl_worker', 'sibyl_app']) AS r;
GRANT DELETE ON sibyl.events TO sibyl_worker;
GRANT INSERT ON sibyl.events_rejected, sibyl.checkpoint TO sibyl_ingest;
GRANT SELECT, INSERT, UPDATE, DELETE ON sibyl.call_merge TO sibyl_ingest;
GRANT SELECT, DELETE ON sibyl.call_merge TO sibyl_worker;
GRANT INSERT ON sibyl.payload_refs TO sibyl_ingest, sibyl_app, sibyl_worker;
GRANT UPDATE (state, swept_at, shredded_at) ON sibyl.payload_refs TO sibyl_worker;
GRANT SELECT, UPDATE (state, shredded_at) ON sibyl.payload_refs TO sibyl_audit;
GRANT SELECT, INSERT, UPDATE, DELETE ON sibyl.agent_metrics_1m, sibyl.agent_metrics_5m, sibyl.agent_metrics_1h,
  sibyl.provider_metrics_5m TO sibyl_worker;
GRANT SELECT ON sibyl.agent_metrics_1m, sibyl.agent_metrics_5m, sibyl.agent_metrics_1h, sibyl.provider_metrics_5m
  TO sibyl_app;
GRANT INSERT, DELETE ON sibyl.feature_snapshot TO sibyl_worker;
GRANT INSERT ON sibyl.label TO sibyl_app, sibyl_worker;
GRANT SELECT, INSERT ON sibyl.ingest_batch_seen TO sibyl_ingest;
REVOKE ALL ON FUNCTION sibyl.grant_insert_except(regclass, text, text[]) FROM PUBLIC;
