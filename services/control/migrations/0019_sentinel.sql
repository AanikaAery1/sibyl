-- 0019 lane SENTINEL: Sibyl Sentinel, the opt-in advisory monitoring agent (D52, WAVE3.md).
-- Single sources: sibyl_schemas Scope.SENTINEL_READ / SENTINEL_ADMIN, the five sentinel.* audit
-- actions and sibyl_schemas.models.sentinel (providers, tasks, kinds, feedback) (drift-tested).
--
-- Tables (all tenant-scoped, RLS):
--   sentinel_config   one row per tenant: on/off, provider, model, the tenant's own API key sealed
--                     with seal_credential (AAD bound to credential_id), daily budget, sampling,
--                     tasks. Write-only key: the worker reads it only through the definer
--                     sibyl.sentinel_sealed_key(), never by SELECT.
--   sentinel_finding  one advisory finding: kind, subject, severity, summary, structured body,
--                     recommendation, provider, model, prompt hash, tokens, cost, feedback.
--                     Immutable except the feedback columns (column grants).
--   sentinel_usage    per tenant and UTC day: spend (reservations settled to actuals), tokens,
--                     calls, findings, skips (budget, sampling) and when the budget ran out.
-- Sentinel never writes anything else except watch-only `sentinel_finding` alerts (an alert_rule
-- of kind `leading` that is not in the rules seed: the scoring engine never evaluates it and the
-- failover saga only starts from `detected` alerts).

-- --- catalogues -------------------------------------------------------------------------------

INSERT INTO sibyl.role_permission (role_name, permission, scope_rule, step_up, self_audited) VALUES
  ('owner', 'sentinel:read', 'tenant', false, false),
  ('admin', 'sentinel:read', 'tenant', false, false),
  ('security_admin', 'sentinel:read', 'tenant', false, false),
  ('operator', 'sentinel:read', 'tenant', false, false),
  ('auditor', 'sentinel:read', 'tenant', false, false),
  ('owner', 'sentinel:admin', 'tenant', false, false),
  ('admin', 'sentinel:admin', 'tenant', false, false),
  ('security_admin', 'sentinel:admin', 'tenant', false, false);

INSERT INTO sibyl.audit_action
  (name, domain, actor_types, resource_type, required_fields, reason_required, is_evidence, severity)
VALUES
  ('sentinel.config_changed', 'sentinel', '{human}', 'sentinel_config',
   '{enabled,provider,model,tasks,daily_budget_usd,sampling_rate,credential_changed}', true, true, 'notice'),
  ('sentinel.config_tested', 'sentinel', '{human}', 'sentinel_config', '{provider,model,ok,http_status}', false,
   true, 'info'),
  ('sentinel.finding_created', 'sentinel', '{human,system}', 'sentinel_finding',
   '{finding_id,kind,subject_kind,provider,model,prompt_sha256,tokens_in,tokens_out,cost_usd,trigger}', false, true,
   'info'),
  ('sentinel.feedback_recorded', 'sentinel', '{human}', 'sentinel_finding', '{finding_id,feedback}', false, true,
   'info'),
  ('sentinel.budget_exhausted', 'sentinel', '{human,system}', 'sentinel_config',
   '{day,spent_usd,daily_budget_usd}', false, true, 'warning');

-- --- sentinel_config ----------------------------------------------------------------------------

CREATE TABLE sibyl.sentinel_config (
  tenant_id               uuid          NOT NULL REFERENCES sibyl.tenant (id),
  enabled                 boolean       NOT NULL DEFAULT false,
  provider                text          NOT NULL,
  model                   text          NOT NULL,
  base_url                text,
  credential_id           uuid          NOT NULL DEFAULT sibyl.uuidv7(),
  ciphertext              bytea,
  nonce                   bytea,
  tenant_key_id           uuid,
  key_version             integer,
  key_hint             text,
  key_updated_at          timestamptz,
  daily_budget_usd        numeric(12,4) NOT NULL,
  sampling_rate           numeric(5,4)  NOT NULL,
  tasks                   text[]        NOT NULL,
  price_in_usd_per_mtok   numeric(12,4),
  price_out_usd_per_mtok  numeric(12,4),
  version                 integer       NOT NULL DEFAULT 1,
  updated_by_user_id      uuid          NOT NULL,
  created_at              timestamptz   NOT NULL DEFAULT now(),
  updated_at              timestamptz   NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id),
  CONSTRAINT fk_sentinel_config_key FOREIGN KEY (tenant_id, tenant_key_id)
    REFERENCES sibyl.tenant_key (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_sentinel_config_updated_by FOREIGN KEY (tenant_id, updated_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_sentinel_config_provider CHECK (provider IN ('anthropic', 'openai', 'gemini')),
  CONSTRAINT ck_sentinel_config_model CHECK (model ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  CONSTRAINT ck_sentinel_config_base_url CHECK (base_url IS NULL OR char_length(base_url) BETWEEN 8 AND 2048),
  CONSTRAINT ck_sentinel_config_sealed CHECK (
    (ciphertext IS NULL AND nonce IS NULL AND tenant_key_id IS NULL AND key_version IS NULL)
    OR (ciphertext IS NOT NULL AND octet_length(nonce) = 12 AND tenant_key_id IS NOT NULL
        AND key_version >= 1 AND key_updated_at IS NOT NULL)),
  CONSTRAINT ck_sentinel_config_enabled_key CHECK (NOT enabled OR ciphertext IS NOT NULL),
  CONSTRAINT ck_sentinel_config_hint CHECK (key_hint IS NULL OR char_length(key_hint) <= 8),
  CONSTRAINT ck_sentinel_config_budget CHECK (daily_budget_usd BETWEEN 0 AND 10000),
  CONSTRAINT ck_sentinel_config_sampling CHECK (sampling_rate BETWEEN 0 AND 1),
  CONSTRAINT ck_sentinel_config_tasks CHECK (
    tasks <@ ARRAY['incident_explanation', 'held_action_review', 'semantic_drift', 'fleet_summary']::text[]
    AND cardinality(tasks) <= 4),
  CONSTRAINT ck_sentinel_config_prices CHECK (
    (price_in_usd_per_mtok IS NULL) = (price_out_usd_per_mtok IS NULL)
    AND coalesce(price_in_usd_per_mtok, 0) >= 0 AND coalesce(price_out_usd_per_mtok, 0) >= 0),
  CONSTRAINT ck_sentinel_config_version CHECK (version >= 1)
);
SELECT sibyl.enable_tenant_rls('sibyl.sentinel_config');
CREATE TRIGGER trg_sentinel_config_updated_at BEFORE UPDATE ON sibyl.sentinel_config
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- The sealed key of the current (RLS) tenant, for the worker and for the api's connectivity test
-- and on-demand explain. The worker has no SELECT on the ciphertext columns.
CREATE FUNCTION sibyl.sentinel_sealed_key()
RETURNS TABLE (credential_id uuid, ciphertext bytea, nonce bytea, key_version integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT c.credential_id, c.ciphertext, c.nonce, c.key_version
    FROM sibyl.sentinel_config c
   WHERE c.tenant_id = sibyl.current_tenant() AND c.ciphertext IS NOT NULL
$$;
REVOKE EXECUTE ON FUNCTION sibyl.sentinel_sealed_key() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sibyl.sentinel_sealed_key() TO sibyl_app, sibyl_worker;

-- --- sentinel_finding ---------------------------------------------------------------------------

-- `subject_id` names the incident (failover id), held action or agent; NULL for a fleet summary.
-- `agent_id` is the agent the finding is about (erasure, visibility); `dedupe_key` makes the
-- scheduled tasks idempotent (`incident:<id>`, `held_action:<id>`, `drift:<agent>:<window>`,
-- `fleet:<day>`); on-demand explains have none. `prompt_sha256` is the SHA-256 of the exact
-- request sent (system + messages + schema), never the prompt itself.
CREATE TABLE sibyl.sentinel_finding (
  tenant_id             uuid          NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid          NOT NULL DEFAULT sibyl.uuidv7(),
  kind                  text          NOT NULL,
  subject_kind          text          NOT NULL,
  subject_id            uuid,
  agent_id              uuid,
  severity              text          NOT NULL,
  summary               text          NOT NULL,
  body                  jsonb         NOT NULL DEFAULT '{}'::jsonb,
  recommendation        text,
  provider              text          NOT NULL,
  model                 text          NOT NULL,
  prompt_sha256         bytea         NOT NULL,
  tokens_in             integer       NOT NULL DEFAULT 0,
  tokens_out            integer       NOT NULL DEFAULT 0,
  cost_usd              numeric(14,6) NOT NULL DEFAULT 0,
  cost_estimated        boolean       NOT NULL DEFAULT false,
  calls                 smallint      NOT NULL DEFAULT 1,
  trigger               text          NOT NULL,
  requested_by_user_id  uuid,
  dedupe_key            text,
  alert_id              uuid,
  feedback              text,
  feedback_by_user_id   uuid,
  feedback_at           timestamptz,
  created_at            timestamptz   NOT NULL DEFAULT now(),
  updated_at            timestamptz   NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_sentinel_finding_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_sentinel_finding_alert FOREIGN KEY (tenant_id, alert_id)
    REFERENCES sibyl.alert (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_sentinel_finding_requested_by FOREIGN KEY (tenant_id, requested_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_sentinel_finding_feedback_by FOREIGN KEY (tenant_id, feedback_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_sentinel_finding_kind CHECK (
    kind IN ('incident_explanation', 'held_action_review', 'semantic_drift', 'fleet_summary')),
  CONSTRAINT ck_sentinel_finding_subject CHECK (
    (kind = 'incident_explanation' AND subject_kind = 'incident' AND subject_id IS NOT NULL)
    OR (kind = 'held_action_review' AND subject_kind = 'held_action' AND subject_id IS NOT NULL)
    OR (kind = 'semantic_drift' AND subject_kind = 'agent' AND subject_id IS NOT NULL
        AND agent_id = subject_id)
    OR (kind = 'fleet_summary' AND subject_kind = 'fleet' AND subject_id IS NULL)),
  CONSTRAINT ck_sentinel_finding_severity CHECK (severity IN ('info', 'warning', 'critical')),
  CONSTRAINT ck_sentinel_finding_summary CHECK (char_length(summary) BETWEEN 1 AND 2000),
  CONSTRAINT ck_sentinel_finding_body CHECK (
    jsonb_typeof(body) = 'object' AND octet_length(body::text) <= 32768),
  CONSTRAINT ck_sentinel_finding_recommendation CHECK (
    recommendation IS NULL OR char_length(recommendation) <= 2000),
  CONSTRAINT ck_sentinel_finding_provider CHECK (provider IN ('anthropic', 'openai', 'gemini')),
  CONSTRAINT ck_sentinel_finding_model CHECK (char_length(model) BETWEEN 1 AND 128),
  CONSTRAINT ck_sentinel_finding_sha CHECK (octet_length(prompt_sha256) = 32),
  CONSTRAINT ck_sentinel_finding_usage CHECK (
    tokens_in >= 0 AND tokens_out >= 0 AND cost_usd >= 0 AND calls BETWEEN 1 AND 10),
  CONSTRAINT ck_sentinel_finding_trigger CHECK (
    (trigger = 'scheduled' AND requested_by_user_id IS NULL)
    OR (trigger = 'on_demand' AND requested_by_user_id IS NOT NULL AND dedupe_key IS NULL)),
  CONSTRAINT ck_sentinel_finding_dedupe CHECK (
    dedupe_key IS NULL OR char_length(dedupe_key) BETWEEN 1 AND 200),
  CONSTRAINT ck_sentinel_finding_feedback CHECK (
    (feedback IS NULL AND feedback_by_user_id IS NULL AND feedback_at IS NULL)
    OR (feedback IN ('useful', 'not_useful', 'wrong') AND feedback_by_user_id IS NOT NULL
        AND feedback_at IS NOT NULL))
);
CREATE UNIQUE INDEX ux_sentinel_finding_dedupe ON sibyl.sentinel_finding (tenant_id, dedupe_key)
  WHERE dedupe_key IS NOT NULL;
CREATE INDEX ix_sentinel_finding_list ON sibyl.sentinel_finding (tenant_id, created_at DESC, id DESC);
CREATE INDEX ix_sentinel_finding_subject ON sibyl.sentinel_finding (tenant_id, subject_kind, subject_id);
CREATE INDEX ix_sentinel_finding_agent ON sibyl.sentinel_finding (tenant_id, agent_id, created_at DESC)
  WHERE agent_id IS NOT NULL;
SELECT sibyl.enable_tenant_rls('sibyl.sentinel_finding');
CREATE TRIGGER trg_sentinel_finding_updated_at BEFORE UPDATE ON sibyl.sentinel_finding
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- --- sentinel_usage -----------------------------------------------------------------------------

-- Spend per UTC day. A call first reserves its worst-case cost with one conditional update
-- (`spent_usd + estimate <= budget`), then settles to the actual cost, so concurrent callers can
-- never overshoot the budget.
CREATE TABLE sibyl.sentinel_usage (
  tenant_id         uuid          NOT NULL REFERENCES sibyl.tenant (id),
  day               date          NOT NULL,
  spent_usd         numeric(14,6) NOT NULL DEFAULT 0,
  tokens_in         bigint        NOT NULL DEFAULT 0,
  tokens_out        bigint        NOT NULL DEFAULT 0,
  calls             integer       NOT NULL DEFAULT 0,
  findings          integer       NOT NULL DEFAULT 0,
  failures          integer       NOT NULL DEFAULT 0,
  skipped_budget    integer       NOT NULL DEFAULT 0,
  skipped_sampling  integer       NOT NULL DEFAULT 0,
  exhausted_at      timestamptz,
  created_at        timestamptz   NOT NULL DEFAULT now(),
  updated_at        timestamptz   NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, day),
  CONSTRAINT ck_sentinel_usage_nonneg CHECK (
    spent_usd >= 0 AND tokens_in >= 0 AND tokens_out >= 0 AND calls >= 0 AND findings >= 0
    AND failures >= 0 AND skipped_budget >= 0 AND skipped_sampling >= 0)
);
SELECT sibyl.enable_tenant_rls('sibyl.sentinel_usage');
CREATE TRIGGER trg_sentinel_usage_updated_at BEFORE UPDATE ON sibyl.sentinel_usage
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- --- grants ---------------------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON sibyl.sentinel_config TO sibyl_app;
GRANT SELECT (tenant_id, enabled, provider, model, base_url, credential_id, tenant_key_id, key_version,
              key_hint, key_updated_at, daily_budget_usd, sampling_rate, tasks, price_in_usd_per_mtok,
              price_out_usd_per_mtok, version, updated_by_user_id, created_at, updated_at)
  ON sibyl.sentinel_config TO sibyl_worker;
GRANT SELECT, INSERT ON sibyl.sentinel_finding TO sibyl_app, sibyl_worker;
GRANT UPDATE (feedback, feedback_by_user_id, feedback_at, updated_at) ON sibyl.sentinel_finding TO sibyl_app;
GRANT UPDATE (alert_id, updated_at) ON sibyl.sentinel_finding TO sibyl_worker;
GRANT SELECT, INSERT, UPDATE ON sibyl.sentinel_usage TO sibyl_app, sibyl_worker;

-- --- erasure cascade --------------------------------------------------------------------------------

-- 0018's single list (0017 plus the two drift tables) plus the three Sentinel tables (findings
-- before alert and agent). Any later redefinition must carry every wave-3 table (ruling B27).

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
    ('sentinel_finding',     'derived_purged',  'delete',     'agent_id = $2'),
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
    ('sentinel_usage',       'derived_purged',  'delete',     NULL),
    ('sentinel_config',      'derived_purged',  'delete',     NULL),
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
