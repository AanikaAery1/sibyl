-- 0026 lane HARDEN (wave 4, docs/council/build/WAVE4.md): tenant-tunable drift thresholds.
-- Single sources: sibyl_schemas.models.drift THRESHOLD_BOUNDS (the range CHECKs below) and the
-- drift.thresholds_updated audit action (sibyl_schemas._audit). Scopes are unchanged: every role
-- reads with drift:read; Owner, Admin and Security admin write with drift:write (0018).
--
-- drift_thresholds holds at most one row per tenant: the tenant's overrides of the drift
-- detector's deployment defaults (worker/drift/config.py DEFAULT_CONFIG). Every value is
-- nullable and NULL means "use the deployment default", so a tenant without a row, or with an
-- all-NULL row (a reset), is judged exactly like before this migration. The API also checks
-- watch < drift on the effective pair (override else default); the CHECKs here hold whenever
-- both values of a pair are overridden. Drift stays watch-only: these values only change when a
-- report reads `watch` / `drift` and when a feature has enough samples.

-- --- catalogues -------------------------------------------------------------------------------

INSERT INTO sibyl.audit_action
  (name, domain, actor_types, resource_type, required_fields, reason_required, is_evidence, severity)
VALUES
  ('drift.thresholds_updated', 'drift', '{human}', 'drift_thresholds', '{before,after}', true, true,
   'notice');

-- --- drift_thresholds ----------------------------------------------------------------------------

CREATE TABLE sibyl.drift_thresholds (
  tenant_id               uuid             NOT NULL REFERENCES sibyl.tenant (id),
  psi_watch               double precision,
  psi_drift               double precision,
  js_two_category_watch   double precision,
  js_two_category_drift   double precision,
  js_many_category_watch  double precision,
  js_many_category_drift  double precision,
  min_samples_calls       integer,
  min_samples_tools       integer,
  version                 integer          NOT NULL DEFAULT 1,
  updated_by_user_id      uuid             NOT NULL,
  created_at              timestamptz      NOT NULL DEFAULT now(),
  updated_at              timestamptz      NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id),
  CONSTRAINT fk_drift_thresholds_updated_by FOREIGN KEY (tenant_id, updated_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_drift_thresholds_psi CHECK (
    (psi_watch IS NULL OR psi_watch BETWEEN 0.01 AND 2.0)
    AND (psi_drift IS NULL OR psi_drift BETWEEN 0.01 AND 2.0)
    AND (psi_watch IS NULL OR psi_drift IS NULL OR psi_watch < psi_drift)),
  CONSTRAINT ck_drift_thresholds_js_two CHECK (
    (js_two_category_watch IS NULL OR js_two_category_watch BETWEEN 0.0005 AND 0.5)
    AND (js_two_category_drift IS NULL OR js_two_category_drift BETWEEN 0.0005 AND 0.5)
    AND (js_two_category_watch IS NULL OR js_two_category_drift IS NULL
         OR js_two_category_watch < js_two_category_drift)),
  CONSTRAINT ck_drift_thresholds_js_many CHECK (
    (js_many_category_watch IS NULL OR js_many_category_watch BETWEEN 0.005 AND 1.0)
    AND (js_many_category_drift IS NULL OR js_many_category_drift BETWEEN 0.005 AND 1.0)
    AND (js_many_category_watch IS NULL OR js_many_category_drift IS NULL
         OR js_many_category_watch < js_many_category_drift)),
  CONSTRAINT ck_drift_thresholds_samples CHECK (
    (min_samples_calls IS NULL OR min_samples_calls BETWEEN 50 AND 5000)
    AND (min_samples_tools IS NULL OR min_samples_tools BETWEEN 10 AND 20000)),
  CONSTRAINT ck_drift_thresholds_version CHECK (version >= 1)
);
SELECT sibyl.enable_tenant_rls('sibyl.drift_thresholds');
CREATE TRIGGER trg_drift_thresholds_updated_at BEFORE UPDATE ON sibyl.drift_thresholds
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- The api reads and upserts (a reset writes NULLs, never deletes); the drift loop only reads.
GRANT SELECT, INSERT, UPDATE ON sibyl.drift_thresholds TO sibyl_app;
GRANT SELECT ON sibyl.drift_thresholds TO sibyl_worker;

-- --- erasure cascade --------------------------------------------------------------------------------

-- 0025's single list (every wave-3 table and 0025's four monitor tables, ruling B27) plus drift_thresholds (tenant scoped, no
-- agent column; before app_user, which it references). Any later redefinition must carry it.

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
    ('webhook_delivery',     'derived_purged',  'delete',     'agent_id = $2'),
    ('external_finding',     'derived_purged',  'delete',     'agent_id = $2'),
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
    ('monitor_webhook',      'derived_purged',  'delete',     NULL),
    ('monitor',              'derived_purged',  'delete',     NULL),
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
    ('drift_thresholds',     'derived_purged',  'delete',     NULL),
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
