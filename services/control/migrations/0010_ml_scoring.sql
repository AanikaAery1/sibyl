-- 0010 ML & scoring (ML db §1.3, §2.3, §3; ML.md §5.7, §6.2, §7; R42, R49). Folded per R59.
-- Phase 2 tables (ml_model, ml_prediction_shadow, risk_assessment) are created empty so the
-- isolation and erasure generators cover them from day one.

-- Immutable, content-addressed scoring composition. config_canonical is the JCS text from
-- sibyl-schemas (the config holds decimals, which the in-DB JCS does not format).
CREATE TABLE sibyl.scoring_config (
  tenant_id         uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  rules_source      text        NOT NULL,
  feature_set       text        NOT NULL,
  version_no        integer     NOT NULL,
  config            jsonb       NOT NULL,
  config_canonical  text        NOT NULL,
  config_sha256     bytea       NOT NULL,
  origin            text        NOT NULL,
  activated_at      timestamptz,
  superseded_at     timestamptz,
  created_by        uuid,
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_scoring_config_sha UNIQUE (tenant_id, config_sha256),
  CONSTRAINT uq_scoring_config_version UNIQUE (tenant_id, version_no),
  CONSTRAINT fk_scoring_config_created_by FOREIGN KEY (tenant_id, created_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_scoring_config_origin CHECK (origin IN ('seed', 'custom', 'tuned')),
  CONSTRAINT ck_scoring_config_size CHECK (pg_column_size(config) <= 32768),
  CONSTRAINT ck_scoring_config_canonical CHECK (config_canonical::jsonb = config),
  CONSTRAINT ck_scoring_config_sha CHECK (config_sha256 = sibyl.sha256_text(config_canonical)),
  CONSTRAINT ck_scoring_config_lifecycle CHECK (superseded_at IS NULL OR activated_at IS NOT NULL)
);
CREATE UNIQUE INDEX ux_scoring_config_active ON sibyl.scoring_config (tenant_id)
  WHERE activated_at IS NOT NULL AND superseded_at IS NULL;

CREATE TABLE sibyl.agent_trend_state (
  tenant_id          uuid             NOT NULL REFERENCES sibyl.tenant (id),
  agent_id           uuid             NOT NULL,
  metric             text             NOT NULL,
  last_bucket        timestamptz      NOT NULL,
  ewma               double precision,
  ewma_var           double precision,
  cusum_pos          double precision NOT NULL DEFAULT 0,
  cusum_neg          double precision NOT NULL DEFAULT 0,
  cusum_alarm_at     timestamptz,
  samples            integer          NOT NULL DEFAULT 0,
  scoring_config_id  uuid             NOT NULL,
  created_at         timestamptz      NOT NULL DEFAULT now(),
  updated_at         timestamptz      NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, agent_id, metric),
  CONSTRAINT fk_agent_trend_state_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_agent_trend_state_config FOREIGN KEY (tenant_id, scoring_config_id)
    REFERENCES sibyl.scoring_config (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE
);

-- last_bucket never goes backwards (a reopened bucket must not re-advance CUSUM).
CREATE FUNCTION sibyl.trg_trend_state_forward() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.last_bucket < OLD.last_bucket THEN
    RAISE EXCEPTION 'sibyl:immutable_row: agent_trend_state.last_bucket moved backwards' USING ERRCODE = 'SB030';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_agent_trend_state_forward BEFORE UPDATE ON sibyl.agent_trend_state
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_trend_state_forward();

-- agent_id may be a peer-group pseudo id (cold start), hence no FK to agent.
CREATE TABLE sibyl.agent_baseline (
  tenant_id     uuid             NOT NULL REFERENCES sibyl.tenant (id),
  agent_id      uuid             NOT NULL,
  metric        text             NOT NULL,
  hour_of_week  smallint         NOT NULL,
  mean          double precision,
  stddev        double precision,
  p95           double precision,
  samples       integer          NOT NULL DEFAULT 0,
  computed_at   timestamptz      NOT NULL,
  baseline_ref  text             NOT NULL,
  peer_group    text,
  created_at    timestamptz      NOT NULL DEFAULT now(),
  updated_at    timestamptz      NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, agent_id, metric, hour_of_week),
  CONSTRAINT ck_agent_baseline_hour CHECK (hour_of_week BETWEEN 0 AND 167)
);

CREATE TABLE sibyl.prediction (
  tenant_id               uuid        NOT NULL,
  predicted_at            timestamptz NOT NULL,
  id                      uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id                uuid        NOT NULL,
  health_snapshot_id      uuid        NOT NULL,
  feature_snapshot_id     uuid,
  scoring_config_id       uuid        NOT NULL,
  horizon_s               integer     NOT NULL,
  source                  text        NOT NULL,
  probability_band        text        NOT NULL,
  probability             real,
  confidence              text        NOT NULL,
  predicted_failure_mode  text,
  contributions           jsonb       NOT NULL DEFAULT '[]',
  abstained               boolean     NOT NULL DEFAULT false,
  outcome                 text,
  outcome_failure_mode    text,
  outcome_at              timestamptz,
  outcome_label_id        uuid,
  lead_time_s             integer,
  created_at              timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, predicted_at, id),
  CONSTRAINT ck_prediction_horizon CHECK (horizon_s IN (900, 3600, 86400)),
  CONSTRAINT ck_prediction_band CHECK (probability_band IN ('0.05', '0.25', '0.60', '0.90')),
  CONSTRAINT ck_prediction_probability CHECK (probability IS NULL OR (probability >= 0 AND probability <= 1)),
  CONSTRAINT ck_prediction_confidence CHECK (confidence IN ('low', 'medium', 'high')),
  CONSTRAINT ck_prediction_source CHECK (source ~ '^(rules/v[0-9]+|model/.+:.+)$'),
  CONSTRAINT ck_prediction_failure_mode CHECK (
    predicted_failure_mode IS NULL OR predicted_failure_mode = ANY (sibyl.failure_modes())),
  CONSTRAINT ck_prediction_outcome CHECK (outcome IN ('failed', 'recovered', 'no_event', 'unknown')),
  CONSTRAINT ck_prediction_contrib_size CHECK (pg_column_size(contributions) <= 8192)
) PARTITION BY RANGE (predicted_at);
CREATE INDEX ix_prediction_agent ON sibyl.prediction (tenant_id, agent_id, predicted_at DESC);
CREATE INDEX ix_prediction_open ON sibyl.prediction (tenant_id, predicted_at) WHERE outcome IS NULL;
CREATE INDEX ix_prediction_eval ON sibyl.prediction (tenant_id, source, horizon_s, probability_band, predicted_at);

CREATE TABLE sibyl.health_1h (
  tenant_id           uuid         NOT NULL,
  agent_id            uuid         NOT NULL,
  bucket_start        timestamptz  NOT NULL,
  ticks               integer      NOT NULL DEFAULT 0,
  score_min           smallint,
  score_max           smallint,
  score_avg           numeric(5,2),
  band_counts         integer[]    NOT NULL DEFAULT '{0,0,0,0}',
  provisional_ticks   integer      NOT NULL DEFAULT 0,
  coverage_avg        numeric(4,3),
  transitions         smallint     NOT NULL DEFAULT 0,
  top_factors         jsonb        NOT NULL DEFAULT '[]',
  scoring_config_ids  uuid[]       NOT NULL DEFAULT '{}',
  created_at          timestamptz  NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, agent_id, bucket_start),
  CONSTRAINT ck_health_1h_band_counts CHECK (cardinality(band_counts) = 4),
  CONSTRAINT ck_health_1h_top_factors CHECK (pg_column_size(top_factors) <= 2048),
  CONSTRAINT ck_health_1h_bucket CHECK (bucket_start = date_trunc('hour', bucket_start))
) PARTITION BY RANGE (bucket_start);
CREATE INDEX ix_health_1h_tenant_bucket ON sibyl.health_1h (tenant_id, bucket_start);

CREATE TABLE sibyl.agent_risk (
  tenant_id          uuid        NOT NULL REFERENCES sibyl.tenant (id),
  agent_id           uuid        NOT NULL,
  as_of              date        NOT NULL,
  risk_score         smallint    NOT NULL,
  risk_band          text        NOT NULL,
  inherent           jsonb       NOT NULL,
  control_coverage   jsonb       NOT NULL,
  health_28d         jsonb       NOT NULL,
  contributions      jsonb       NOT NULL,
  scoring_config_id  uuid        NOT NULL,
  graph_version      bigint      NOT NULL,
  computed_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, agent_id, as_of),
  CONSTRAINT fk_agent_risk_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_agent_risk_config FOREIGN KEY (tenant_id, scoring_config_id)
    REFERENCES sibyl.scoring_config (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_agent_risk_score CHECK (risk_score BETWEEN 0 AND 100),
  CONSTRAINT ck_agent_risk_band CHECK (risk_band IN ('low', 'medium', 'high', 'critical')),
  CONSTRAINT ck_agent_risk_contributions CHECK (pg_column_size(contributions) <= 8192)
);
CREATE INDEX ix_agent_risk_band ON sibyl.agent_risk (tenant_id, as_of, risk_band);

CREATE TABLE sibyl.rollup_job (
  tenant_id     uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id            uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  kind          text        NOT NULL,
  grains        text[]      NOT NULL,
  range_from    timestamptz NOT NULL,
  range_to      timestamptz NOT NULL,
  progress_to   timestamptz,
  state         text        NOT NULL DEFAULT 'queued',
  reason        text        NOT NULL,
  requested_by  uuid,
  carryover     integer     NOT NULL DEFAULT 0,
  error         text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_rollup_job_requested_by FOREIGN KEY (tenant_id, requested_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_rollup_job_kind CHECK (kind IN ('backfill', 'repair', 'purge')),
  CONSTRAINT ck_rollup_job_grains CHECK (grains <@ ARRAY['1m', '5m', 'provider_5m', '1h', 'health_1h']),
  CONSTRAINT ck_rollup_job_state CHECK (state IN ('queued', 'running', 'done', 'failed', 'cancelled')),
  CONSTRAINT ck_rollup_job_range CHECK (range_from < range_to)
);
CREATE INDEX ix_rollup_job_state ON sibyl.rollup_job (tenant_id, state, range_from);

-- Phase 2 (ML.md §5.7): per-tenant model registry and shadow predictions (R43: no pooling).
CREATE TABLE sibyl.ml_model (
  tenant_id            uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                   uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  name                 text        NOT NULL,
  version              text        NOT NULL,
  horizon_s            integer     NOT NULL,
  feature_set          text        NOT NULL,
  trained_at           timestamptz NOT NULL,
  train_from           timestamptz NOT NULL,
  train_to             timestamptz NOT NULL,
  n_rows               integer     NOT NULL,
  n_pos                integer     NOT NULL,
  metrics              jsonb       NOT NULL DEFAULT '{}',
  calibration          jsonb       NOT NULL DEFAULT '{}',
  artifact_ref_id      uuid        NOT NULL,
  artifact_sha256      bytea       NOT NULL,
  model_card_ref_id    uuid,
  state                text        NOT NULL DEFAULT 'trained',
  promoted_at          timestamptz,
  demoted_at           timestamptz,
  promoted_by_user_id  uuid,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_ml_model_version UNIQUE (tenant_id, name, version, horizon_s),
  CONSTRAINT fk_ml_model_promoted_by FOREIGN KEY (tenant_id, promoted_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_ml_model_state CHECK (state IN ('trained', 'shadow', 'promoted', 'demoted', 'retired')),
  CONSTRAINT ck_ml_model_horizon CHECK (horizon_s IN (900, 3600, 86400)),
  CONSTRAINT ck_ml_model_promoted CHECK (state <> 'promoted' OR (promoted_at IS NOT NULL AND promoted_by_user_id IS NOT NULL)),
  CONSTRAINT ck_ml_model_counts CHECK (n_rows >= 0 AND n_pos >= 0 AND n_pos <= n_rows),
  CONSTRAINT ck_ml_model_artifact CHECK (octet_length(artifact_sha256) = 32)
);
CREATE UNIQUE INDEX ux_ml_model_promoted ON sibyl.ml_model (tenant_id, horizon_s) WHERE state = 'promoted';

CREATE TABLE sibyl.ml_prediction_shadow (
  tenant_id           uuid        NOT NULL,
  evaluated_at        timestamptz NOT NULL,
  health_snapshot_id  uuid        NOT NULL,
  model_id            uuid        NOT NULL,
  horizon_s           integer     NOT NULL,
  probability         real,
  band                text        NOT NULL,
  abstained           boolean     NOT NULL DEFAULT false,
  created_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, evaluated_at, health_snapshot_id, model_id, horizon_s),
  CONSTRAINT ck_ml_prediction_shadow_horizon CHECK (horizon_s IN (900, 3600, 86400)),
  CONSTRAINT ck_ml_prediction_shadow_band CHECK (band IN ('0.05', '0.25', '0.60', '0.90')),
  CONSTRAINT ck_ml_prediction_shadow_probability CHECK (probability IS NULL OR (probability >= 0 AND probability <= 1))
) PARTITION BY RANGE (evaluated_at);
CREATE INDEX ix_ml_prediction_shadow_model ON sibyl.ml_prediction_shadow (tenant_id, model_id, evaluated_at);

-- EU AI Act suggestion with findings (ML.md §6.2); never writes agent.risk_class.
CREATE TABLE sibyl.risk_assessment (
  tenant_id        uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id               uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id         uuid        NOT NULL,
  computed_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
  suggested_class  text        NOT NULL,
  declared_class   text        NOT NULL,
  findings         jsonb       NOT NULL DEFAULT '[]',
  static           jsonb       NOT NULL DEFAULT '{}',
  dynamic          jsonb       NOT NULL DEFAULT '{}',
  rubric_version   text        NOT NULL DEFAULT 'risk/v1',
  graph_version    bigint      NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_risk_assessment_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_risk_assessment_suggested CHECK (suggested_class IN ('minimal', 'limited', 'high', 'unacceptable')),
  CONSTRAINT ck_risk_assessment_declared CHECK (declared_class IN ('unclassified', 'minimal', 'limited', 'high',
                                                                   'unacceptable')),
  CONSTRAINT ck_risk_assessment_size CHECK (pg_column_size(findings) + pg_column_size(static)
                                            + pg_column_size(dynamic) <= 16384)
);
CREATE INDEX ix_risk_assessment_agent ON sibyl.risk_assessment (tenant_id, agent_id, computed_at DESC);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['scoring_config', 'agent_trend_state', 'agent_baseline', 'prediction', 'health_1h',
                           'agent_risk', 'rollup_job', 'ml_model', 'ml_prediction_shadow', 'risk_assessment'] LOOP
    PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', t)::regclass);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['agent_trend_state', 'agent_baseline', 'rollup_job', 'ml_model'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON sibyl.%I FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at()',
                   'trg_' || t || '_updated_at', t);
  END LOOP;
END
$$;
CREATE TRIGGER trg_scoring_config_immutable BEFORE UPDATE OR DELETE ON sibyl.scoring_config
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation('allow_activation');
CREATE TRIGGER trg_scoring_config_no_truncate BEFORE TRUNCATE ON sibyl.scoring_config
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();

-- Grant matrix (ML db §6 writer additions).
GRANT SELECT ON sibyl.scoring_config, sibyl.agent_trend_state, sibyl.agent_baseline, sibyl.prediction,
  sibyl.health_1h, sibyl.agent_risk, sibyl.rollup_job, sibyl.ml_model, sibyl.ml_prediction_shadow,
  sibyl.risk_assessment TO sibyl_app, sibyl_worker;
GRANT INSERT ON sibyl.scoring_config TO sibyl_app, sibyl_worker;
GRANT UPDATE (activated_at, superseded_at) ON sibyl.scoring_config TO sibyl_app, sibyl_worker;
GRANT INSERT ON sibyl.rollup_job TO sibyl_app;
GRANT INSERT, UPDATE, DELETE ON sibyl.agent_trend_state, sibyl.agent_baseline, sibyl.prediction, sibyl.health_1h,
  sibyl.agent_risk, sibyl.rollup_job, sibyl.ml_model, sibyl.ml_prediction_shadow, sibyl.risk_assessment TO sibyl_worker;
GRANT UPDATE (state, promoted_at, demoted_at, promoted_by_user_id) ON sibyl.ml_model TO sibyl_app;
GRANT SELECT ON sibyl.scoring_config TO sibyl_ingest;
