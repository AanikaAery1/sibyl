-- 0018 lane DRIFT: model drift detection (D51, docs/council/build/WAVE3.md).
-- Single sources: sibyl_schemas DriftBaselineState / DriftVerdict (drift-tested CHECKs), the
-- drift:read / drift:write scopes and the drift.baseline_reset audit action. Deterministic and
-- watch-only: the worker (worker/drift) freezes per agent+provider+model baselines, compares a
-- recent window with PSI (binned numeric) and Jensen-Shannon (categorical) and checks the served
-- model identity; it raises `silent_drift` / `model_change` alerts (rule kind `leading`, cap 0)
-- that never start a saga.
--
-- Tables: drift_baseline (one current baseline per agent, provider and requested model; the
-- frozen distributions, the served-model and fingerprint sets, sample counts and the alert
-- hysteresis counters) and drift_report (one immutable row per evaluation with every feature's
-- statistic, its thresholds and verdict, plus the identity findings). Reports are kept 30 days
-- and superseded baselines 30 days after supersession (ruling B24); the drift loop deletes
-- older rows in bounded batches.

-- --- catalogues -------------------------------------------------------------------------------

-- D51 scopes (sibyl_schemas Scope.DRIFT_*): every role reads drift (watch-only health
-- information, like agents:read); Admin and Security admin reset a baseline.
INSERT INTO sibyl.role_permission (role_name, permission, scope_rule, step_up, self_audited) VALUES
  ('owner', 'drift:read', 'tenant', false, false),
  ('admin', 'drift:read', 'tenant', false, false),
  ('security_admin', 'drift:read', 'tenant', false, false),
  ('engineer', 'drift:read', 'tenant', false, false),
  ('operator', 'drift:read', 'tenant', false, false),
  ('auditor', 'drift:read', 'tenant', false, false),
  ('viewer', 'drift:read', 'tenant', false, false),
  ('owner', 'drift:write', 'tenant', false, false),
  ('admin', 'drift:write', 'tenant', false, false),
  ('security_admin', 'drift:write', 'tenant', false, false);

INSERT INTO sibyl.audit_action
  (name, domain, actor_types, resource_type, required_fields, reason_required, is_evidence, severity)
VALUES
  ('drift.baseline_reset', 'drift', '{human}', 'agent', '{agent_id,superseded,new_baselines,since}', true,
   true, 'notice');

-- The drift loop keeps the tenant's two drift alert rules present (silent_drift, model_change;
-- kind leading, cap 0, origin seed): new tenants get them on the loop's first tick.
GRANT INSERT ON sibyl.alert_rule TO sibyl_worker;

-- --- drift_baseline -----------------------------------------------------------------------------

-- One baseline per (agent, provider, requested model) and period. `collecting` accumulates from
-- window_start until it has enough samples over a long enough span, then the worker freezes it:
-- `features` holds the frozen distributions (numeric: decile edges + bin proportions; categorical:
-- category proportions), `served_models` / `fingerprints` what the provider served. A reset
-- (POST /agents/{agent_id}/drift/baseline) supersedes it and starts a new collecting baseline.
-- drift_streak / clear_streak / identity_clear_streak are the alert hysteresis counters.
CREATE TABLE sibyl.drift_baseline (
  tenant_id              uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                     uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id               uuid        NOT NULL,
  provider               text        NOT NULL,
  model                  text        NOT NULL,
  state                  text        NOT NULL DEFAULT 'collecting',
  window_start           timestamptz NOT NULL,
  window_end             timestamptz,
  sample_count           integer     NOT NULL DEFAULT 0,
  tool_sample_count      integer     NOT NULL DEFAULT 0,
  features               jsonb       NOT NULL DEFAULT '{}'::jsonb,
  served_models          text[]      NOT NULL DEFAULT '{}',
  fingerprints           text[]      NOT NULL DEFAULT '{}',
  frozen_at              timestamptz,
  reset_by_user_id       uuid,
  reset_reason           text,
  supersedes             uuid,
  superseded_by          uuid,
  superseded_at          timestamptz,
  drift_streak           smallint    NOT NULL DEFAULT 0,
  clear_streak           smallint    NOT NULL DEFAULT 0,
  identity_clear_streak  smallint    NOT NULL DEFAULT 0,
  last_evaluated_at      timestamptz,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_drift_baseline_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_drift_baseline_reset_by FOREIGN KEY (tenant_id, reset_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_drift_baseline_state CHECK (state IN ('collecting', 'frozen', 'superseded')),
  CONSTRAINT ck_drift_baseline_provider CHECK (char_length(provider) <= 64),
  CONSTRAINT ck_drift_baseline_model CHECK (char_length(model) BETWEEN 1 AND 256),
  CONSTRAINT ck_drift_baseline_counts CHECK (sample_count >= 0 AND tool_sample_count >= 0
    AND drift_streak >= 0 AND clear_streak >= 0 AND identity_clear_streak >= 0),
  CONSTRAINT ck_drift_baseline_features CHECK (jsonb_typeof(features) = 'object'
                                               AND octet_length(features::text) <= 65536),
  CONSTRAINT ck_drift_baseline_sets CHECK (cardinality(served_models) <= 64
                                           AND cardinality(fingerprints) <= 64),
  CONSTRAINT ck_drift_baseline_window CHECK (window_end IS NULL OR window_end >= window_start),
  CONSTRAINT ck_drift_baseline_reason CHECK (reset_reason IS NULL OR char_length(reset_reason) BETWEEN 1 AND 2000),
  CONSTRAINT ck_drift_baseline_lifecycle CHECK (
    (state <> 'frozen' OR (window_end IS NOT NULL AND frozen_at IS NOT NULL))
    AND (state <> 'superseded' OR superseded_at IS NOT NULL)
    AND (state = 'superseded' OR superseded_at IS NULL))
);
CREATE UNIQUE INDEX ux_drift_baseline_current ON sibyl.drift_baseline (tenant_id, agent_id, provider, model)
  WHERE state <> 'superseded';
CREATE INDEX ix_drift_baseline_list ON sibyl.drift_baseline (tenant_id, created_at DESC, id DESC);
CREATE INDEX ix_drift_baseline_agent ON sibyl.drift_baseline (tenant_id, agent_id, created_at DESC);
CREATE INDEX ix_drift_baseline_superseded ON sibyl.drift_baseline (tenant_id, superseded_at)
  WHERE state = 'superseded';
SELECT sibyl.enable_tenant_rls('sibyl.drift_baseline');
CREATE TRIGGER trg_drift_baseline_updated_at BEFORE UPDATE ON sibyl.drift_baseline
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- collecting -> frozen | superseded, frozen -> superseded; superseded is final. A frozen
-- baseline's distributions and window never change (only its evaluation counters do).
CREATE FUNCTION sibyl.trg_drift_baseline_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'collecting' AND NEW.state IN ('frozen', 'superseded'))
       OR (OLD.state = 'frozen' AND NEW.state = 'superseded')) THEN
    RAISE EXCEPTION 'sibyl:invalid_transition: drift_baseline % -> %', OLD.state, NEW.state
      USING ERRCODE = 'SB010';
  END IF;
  IF OLD.state <> 'collecting' AND (NEW.features IS DISTINCT FROM OLD.features
       OR NEW.window_start IS DISTINCT FROM OLD.window_start
       OR NEW.window_end IS DISTINCT FROM OLD.window_end
       OR NEW.served_models IS DISTINCT FROM OLD.served_models
       OR NEW.fingerprints IS DISTINCT FROM OLD.fingerprints
       OR NEW.sample_count IS DISTINCT FROM OLD.sample_count) THEN
    RAISE EXCEPTION 'sibyl:immutable_row: a frozen drift baseline keeps its distributions'
      USING ERRCODE = 'SB030';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_drift_baseline_guard BEFORE UPDATE ON sibyl.drift_baseline
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_drift_baseline_guard();

-- --- drift_report -------------------------------------------------------------------------------

-- One evaluation of a frozen baseline against [window_start, window_end): `features` is the
-- per-feature array (feature, statistic psi|js, value, watch and drift thresholds, verdict,
-- sample counts, top contributors), `identity` the model-identity findings. Immutable.
CREATE TABLE sibyl.drift_report (
  tenant_id            uuid             NOT NULL REFERENCES sibyl.tenant (id),
  id                   uuid             NOT NULL DEFAULT sibyl.uuidv7(),
  baseline_id          uuid             NOT NULL,
  agent_id             uuid             NOT NULL,
  provider             text             NOT NULL,
  model                text             NOT NULL,
  evaluated_at         timestamptz      NOT NULL DEFAULT now(),
  window_start         timestamptz      NOT NULL,
  window_end           timestamptz      NOT NULL,
  sample_count         integer          NOT NULL,
  tool_sample_count    integer          NOT NULL DEFAULT 0,
  verdict              text             NOT NULL,
  behaviour_evaluated  boolean          NOT NULL,
  identity_changed     boolean          NOT NULL DEFAULT false,
  max_ratio            double precision NOT NULL DEFAULT 0,
  features             jsonb            NOT NULL,
  identity             jsonb            NOT NULL DEFAULT '[]'::jsonb,
  config               jsonb            NOT NULL DEFAULT '{}'::jsonb,
  created_at           timestamptz      NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_drift_report_baseline FOREIGN KEY (tenant_id, baseline_id)
    REFERENCES sibyl.drift_baseline (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_drift_report_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_drift_report_verdict CHECK (verdict IN ('none', 'watch', 'drift')),
  CONSTRAINT ck_drift_report_window CHECK (window_end > window_start),
  CONSTRAINT ck_drift_report_counts CHECK (sample_count >= 0 AND tool_sample_count >= 0 AND max_ratio >= 0),
  CONSTRAINT ck_drift_report_features CHECK (jsonb_typeof(features) = 'array'
                                             AND octet_length(features::text) <= 65536),
  CONSTRAINT ck_drift_report_identity CHECK (jsonb_typeof(identity) = 'array'
                                             AND jsonb_array_length(identity) <= 64
                                             AND identity_changed = (jsonb_array_length(identity) > 0)),
  CONSTRAINT ck_drift_report_config CHECK (jsonb_typeof(config) = 'object'
                                           AND octet_length(config::text) <= 8192)
);
CREATE INDEX ix_drift_report_baseline ON sibyl.drift_report (tenant_id, baseline_id, evaluated_at DESC);
CREATE INDEX ix_drift_report_agent ON sibyl.drift_report (tenant_id, agent_id, evaluated_at DESC);
CREATE INDEX ix_drift_report_age ON sibyl.drift_report (tenant_id, evaluated_at);
SELECT sibyl.enable_tenant_rls('sibyl.drift_report');
CREATE TRIGGER trg_drift_report_immutable BEFORE UPDATE ON sibyl.drift_report
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();

-- --- grants ---------------------------------------------------------------------------------------

GRANT SELECT ON sibyl.drift_baseline, sibyl.drift_report TO sibyl_app, sibyl_worker;
GRANT INSERT ON sibyl.drift_baseline TO sibyl_app, sibyl_worker;
GRANT INSERT ON sibyl.drift_report TO sibyl_worker;
GRANT UPDATE (state, superseded_by, superseded_at, updated_at) ON sibyl.drift_baseline TO sibyl_app;
GRANT UPDATE (state, window_start, window_end, sample_count, tool_sample_count, features, served_models,
              fingerprints, frozen_at, drift_streak, clear_streak, identity_clear_streak, last_evaluated_at,
              updated_at) ON sibyl.drift_baseline TO sibyl_worker;
GRANT DELETE ON sibyl.drift_report, sibyl.drift_baseline TO sibyl_worker;

-- --- erasure cascade --------------------------------------------------------------------------------

-- 0017's single list plus the two drift tables (reports before baselines, both before agent).
CREATE OR REPLACE FUNCTION sibyl.erasure_cascade()
RETURNS TABLE (ord integer, table_name text, phase text, action text, agent_predicate text,
               subject_predicate text)
LANGUAGE sql IMMUTABLE AS $$
  SELECT (row_number() OVER ())::integer, t, p, a, pred,
         CASE t WHEN 'events' THEN 'agent_id = ANY ($3) AND ts >= $4 AND ($5 IS NULL OR ts < $5)'
                WHEN 'payload_refs' THEN 'agent_id = ANY ($3) AND created_at >= $4 AND ($5 IS NULL OR created_at < $5)'
                WHEN 'checkpoint' THEN 'agent_id = ANY ($3) AND created_at >= $4 AND ($5 IS NULL OR created_at < $5)'
           END
  FROM (VALUES
    ('payload_refs',         'objects_deleted', 'delete',     'agent_id = $2'),
    ('checkpoint',           'objects_deleted', 'delete',     'agent_id = $2'),
    ('events',               'objects_deleted', 'delete',     'agent_id = $2'),
    ('events_rejected',      'objects_deleted', 'delete',     NULL),
    ('call_merge',           'objects_deleted', 'delete',     NULL),
    ('ingest_batch_seen',    'objects_deleted', 'delete',     NULL),
    ('idempotency_record',   'objects_deleted', 'delete',     NULL),
    ('handoff_task',         'derived_purged',  'delete',     'agent_id = $2'),
    ('ml_prediction_shadow', 'derived_purged',  'delete',     NULL),
    ('prediction',           'derived_purged',  'delete',     'agent_id = $2'),
    ('risk_assessment',      'derived_purged',  'delete',     'agent_id = $2'),
    ('agent_risk',           'derived_purged',  'delete',     'agent_id = $2'),
    ('agent_trend_state',    'derived_purged',  'delete',     'agent_id = $2'),
    ('agent_baseline',       'derived_purged',  'delete',     'agent_id = $2'),
    ('health_1h',            'derived_purged',  'delete',     'agent_id = $2'),
    ('label',                'derived_purged',  'delete',     'agent_id = $2'),
    ('feature_snapshot',     'derived_purged',  'delete',     'agent_id = $2'),
    ('health_snapshot',      'derived_purged',  'delete',     'agent_id = $2'),
    ('alert',                'derived_purged',  'delete',     'agent_id = $2'),
    ('approval',             'derived_purged',  'delete',     'agent_id = $2'),
    ('held_action',          'derived_purged',  'delete',     'agent_id = $2'),
    ('action_decision',      'derived_purged',  'delete',     'agent_id = $2'),
    ('action_counter',       'derived_purged',  'delete',     'agent_id = $2'),
    ('action_rule',          'derived_purged',  'delete',
       'policy_id IN (SELECT p.id FROM sibyl.action_policy p WHERE p.tenant_id = $1 AND p.agent_id = $2)'),
    ('action_policy',        'derived_purged',  'delete',     'agent_id = $2'),
    ('drift_report',         'derived_purged',  'delete',     'agent_id = $2'),
    ('drift_baseline',       'derived_purged',  'delete',     'agent_id = $2'),
    ('failover',             'derived_purged',  'delete',     'agent_id = $2'),
    ('routing_transition',   'derived_purged',  'routing_fn', 'agent_id = $2'),
    ('routing_state',        'derived_purged',  'routing_fn', 'agent_id = $2'),
    ('provider_incident',    'derived_purged',  'delete',     NULL),
    ('blast_radius',         'derived_purged',  'delete',     'node_kind = ''agent'' AND node_id = $2'),
    ('agent_metrics_1m',     'derived_purged',  'delete',     'agent_id = $2'),
    ('agent_metrics_5m',     'derived_purged',  'delete',     'agent_id = $2'),
    ('agent_metrics_1h',     'derived_purged',  'delete',     'agent_id = $2'),
    ('provider_metrics_5m',  'derived_purged',  'delete',     NULL),
    ('rollup_job',           'derived_purged',  'delete',     NULL),
    ('job',                  'derived_purged',  'delete',     NULL),
    ('ml_model',             'derived_purged',  'delete',     NULL),
    ('dependency_edge',      'derived_purged',  'delete',
       '(src_kind = ''agent'' AND src_id = $2) OR (dst_kind = ''agent'' AND dst_id = $2)'),
    ('ai_bom',               'derived_purged',  'delete',
       'agent_version_id IN (SELECT v.id FROM sibyl.agent_version v WHERE v.tenant_id = $1 AND v.agent_id = $2)'),
    ('agent_version',        'derived_purged',  'delete',     'agent_id = $2'),
    ('agent_identity',       'derived_purged',  'delete',     'agent_id = $2'),
    ('continuity_plan',      'derived_purged',  'delete',     'agent_id = $2'),
    ('fallback_step',        'derived_purged',  'delete',
       'chain_id IN (SELECT c.id FROM sibyl.fallback_chain c WHERE c.tenant_id = $1 AND c.agent_id = $2)'),
    ('fallback_chain',       'derived_purged',  'delete',     'agent_id = $2'),
    ('kill_switch_ack',      'derived_purged',  'delete',
       'kill_switch_id IN (SELECT k.id FROM sibyl.kill_switch k WHERE k.tenant_id = $1 AND k.scope_kind = ''agent'' AND k.scope_id = $2)'),
    ('kill_switch',          'derived_purged',  'delete',     'scope_kind = ''agent'' AND scope_id = $2'),
    ('api_key',              'derived_purged',  'delete',     'agent_id = $2'),
    ('capture_policy',       'derived_purged',  'delete',     'agent_id = $2'),
    ('lifecycle_transition', 'derived_purged',  'delete',     'agent_id = $2'),
    ('scoring_config',       'derived_purged',  'delete',     NULL),
    ('provider_status',      'derived_purged',  'delete',     NULL),
    ('outbox',               'derived_purged',  'delete',     'aggregate_kind = ''agent'' AND aggregate_id = $2'),
    ('agent',                'derived_purged',  'delete',     'id = $2'),
    ('tool',                 'derived_purged',  'delete',     NULL),
    ('data_source',          'derived_purged',  'delete',     NULL),
    ('business_process',     'derived_purged',  'delete',     NULL),
    ('provider_credential',  'derived_purged',  'delete',     NULL),
    ('model',                'derived_purged',  'delete',     NULL),
    ('provider',             'derived_purged',  'delete',     NULL),
    ('alert_rule',           'derived_purged',  'delete',     NULL),
    ('redaction_profile',    'derived_purged',  'delete',     NULL),
    ('membership',           'derived_purged',  'delete',     NULL),
    ('session',              'derived_purged',  'delete',     NULL),
    ('agent_group',          'derived_purged',  'delete',     NULL),
    ('app_user',             'derived_purged',  'anonymise',  NULL),
    ('oidc_issuer',          'derived_purged',  'anonymise',  NULL),
    ('audit_events',         'keep',            'keep',       NULL),
    ('audit_anchors',        'keep',            'keep',       NULL),
    ('erasure_request',      'keep',            'keep',       NULL),
    ('legal_hold',           'keep',            'keep',       NULL),
    ('tenant_key',           'keep',            'keep',       NULL),
    ('audit_chain_head',     'keep',            'keep',       NULL),
    ('tenant_pseudonym_key', 'keep',            'keep',       NULL)
  ) AS v(t, p, a, pred)
$$;
