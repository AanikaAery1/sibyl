-- 0025 lane EXTMON: external monitor agents (D53, WAVE4.md).
-- Single sources: sibyl_schemas Scope.MONITOR_READ / FINDINGS_WRITE / MONITORS_ADMIN, the seven
-- monitor/finding/webhook audit actions and sibyl_schemas._enums_monitor (kinds, states, event
-- types, finding kinds and subjects) (drift-tested).
--
-- Tables (all tenant-scoped, RLS):
--   monitor           one external monitor: name, kind, owner, the agent groups it watches (or
--                     all), state (active | paused | revoked, revoked terminal), rate limit.
--   monitor_webhook   a signed-webhook endpoint of a monitor: https URL on the egress allowlist,
--                     its signing secret sealed with seal_credential (AAD bound to
--                     credential_id; read back only through sibyl.monitor_webhook_secret()),
--                     subscribed event types, delivery health.
--   webhook_delivery  one event to one webhook: attempts, status, next attempt, response code.
--                     References only (never content); purged 14 days after it settles.
--   external_finding  a finding submitted by a monitor key: the Sentinel finding shape plus
--                     monitor_id and the monitor's own provider/model. A parallel table rather
--                     than a widened sentinel_finding, so 0019's invariants (provider allowlist,
--                     prompt hash, trigger, immutability grants) stay untouched; GET /findings
--                     reads both. Immutable except feedback (api) and the alert link (worker).
-- api_key gains monitor_id: a monitor-bound key holds monitor:read and/or findings:write and
-- nothing else, is never agent-bound, and the binding is immutable like the rest of the grant.
-- Advisory only: nothing here can allow, block, approve, fail over or change policy. External
-- findings raise watch-only `external_finding` alerts through the worker (an alert_rule of kind
-- `leading` outside the rules seed, exactly like Sentinel's).

-- --- catalogues -------------------------------------------------------------------------------

-- monitor:read and findings:write are monitor-bound machine scopes (no role row).
INSERT INTO sibyl.role_permission (role_name, permission, scope_rule, step_up, self_audited) VALUES
  ('owner', 'monitors:admin', 'tenant', false, false),
  ('admin', 'monitors:admin', 'tenant', false, false),
  ('security_admin', 'monitors:admin', 'tenant', false, false);

INSERT INTO sibyl.audit_action
  (name, domain, actor_types, resource_type, required_fields, reason_required, is_evidence, severity)
VALUES
  ('monitor.registered', 'monitor', '{human}', 'monitor', '{monitor_id,name,kind,all_groups,group_ids}',
   true, true, 'notice'),
  ('monitor.updated', 'monitor', '{human}', 'monitor', '{monitor_id,change}', true, true, 'notice'),
  ('monitor.revoked', 'monitor', '{human}', 'monitor', '{monitor_id,keys_revoked,webhooks_disabled}',
   true, true, 'warning'),
  ('finding.submitted', 'monitor', '{api_key}', 'external_finding',
   '{finding_id,monitor_id,kind,subject_kind,severity}', false, true, 'info'),
  ('finding.feedback_recorded', 'monitor', '{human}', 'external_finding', '{finding_id,feedback}', false,
   true, 'info'),
  ('webhook.tested', 'monitor', '{human}', 'monitor_webhook', '{monitor_id,webhook_id,ok,http_status}',
   false, true, 'info'),
  ('webhook.delivery_failed', 'monitor', '{system}', 'monitor_webhook',
   '{monitor_id,webhook_id,event_type,attempts,http_status,error}', false, true, 'warning');

-- --- monitor ------------------------------------------------------------------------------------

CREATE TABLE sibyl.monitor (
  tenant_id           uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                  uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  name                text        NOT NULL,
  kind                text        NOT NULL,
  description         text,
  owner_user_id       uuid        NOT NULL,
  all_groups          boolean     NOT NULL DEFAULT true,
  group_ids           uuid[]      NOT NULL DEFAULT '{}'::uuid[],
  state               text        NOT NULL DEFAULT 'active',
  rate_limit_per_min  integer     NOT NULL DEFAULT 60,
  version             integer     NOT NULL DEFAULT 1,
  created_by_user_id  uuid        NOT NULL,
  revoked_at          timestamptz,
  revoked_by_user_id  uuid,
  revoke_reason       text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_monitor_owner FOREIGN KEY (tenant_id, owner_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_monitor_created_by FOREIGN KEY (tenant_id, created_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_monitor_revoked_by FOREIGN KEY (tenant_id, revoked_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_monitor_name CHECK (name ~ '^[^[:cntrl:]]{1,128}$'),
  CONSTRAINT ck_monitor_kind CHECK (kind IN ('mcp', 'webhook', 'api')),
  CONSTRAINT ck_monitor_description CHECK (description IS NULL OR char_length(description) <= 2000),
  CONSTRAINT ck_monitor_state CHECK (state IN ('active', 'paused', 'revoked')),
  CONSTRAINT ck_monitor_groups CHECK (
    (all_groups AND cardinality(group_ids) = 0)
    OR (NOT all_groups AND cardinality(group_ids) BETWEEN 1 AND 64)),
  CONSTRAINT ck_monitor_rate CHECK (rate_limit_per_min BETWEEN 1 AND 600),
  CONSTRAINT ck_monitor_version CHECK (version >= 1),
  CONSTRAINT ck_monitor_revoked CHECK (
    (state = 'revoked') = (revoked_at IS NOT NULL)
    AND (revoked_at IS NULL OR (revoke_reason IS NOT NULL AND char_length(revoke_reason) <= 2000)))
);
CREATE UNIQUE INDEX ux_monitor_name ON sibyl.monitor (tenant_id, lower(name)) WHERE state <> 'revoked';
CREATE INDEX ix_monitor_list ON sibyl.monitor (tenant_id, created_at DESC, id DESC);
SELECT sibyl.enable_tenant_rls('sibyl.monitor');
CREATE TRIGGER trg_monitor_updated_at BEFORE UPDATE ON sibyl.monitor
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- A revoked monitor is terminal; identity and creation fields never change.
CREATE FUNCTION sibyl.trg_monitor_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state = 'revoked' THEN
    RAISE EXCEPTION 'sibyl:invalid_transition: monitor % is revoked', OLD.id USING ERRCODE = 'SB010';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.id <> OLD.id OR NEW.created_at <> OLD.created_at
     OR NEW.created_by_user_id <> OLD.created_by_user_id OR NEW.kind <> OLD.kind THEN
    RAISE EXCEPTION 'sibyl:immutable_row: monitor % identity is immutable', OLD.id USING ERRCODE = 'SB030';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_monitor_guard BEFORE UPDATE ON sibyl.monitor
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_monitor_guard();

-- --- api_key: monitor binding -------------------------------------------------------------------

ALTER TABLE sibyl.api_key ADD COLUMN monitor_id uuid;
ALTER TABLE sibyl.api_key ADD CONSTRAINT fk_api_key_monitor FOREIGN KEY (tenant_id, monitor_id)
  REFERENCES sibyl.monitor (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sibyl.api_key DROP CONSTRAINT ck_api_key_scopes;
ALTER TABLE sibyl.api_key ADD CONSTRAINT ck_api_key_scopes CHECK (
  scopes <@ ARRAY['ingest:write', 'gateway:proxy', 'routing:read', 'handoff:write',
                  'agents:read', 'agents:write', 'killswitch:pull', 'actions:hold',
                  'monitor:read', 'findings:write']::text[]
  AND cardinality(scopes) >= 1
  AND ('killswitch:pull' <> ALL (scopes) OR scopes = ARRAY['killswitch:pull']::text[]));
ALTER TABLE sibyl.api_key ADD CONSTRAINT ck_api_key_monitor CHECK (
  (monitor_id IS NULL AND NOT (scopes && ARRAY['monitor:read', 'findings:write']::text[]))
  OR (monitor_id IS NOT NULL AND agent_id IS NULL
      AND scopes <@ ARRAY['monitor:read', 'findings:write']::text[]));
CREATE INDEX ix_api_key_monitor ON sibyl.api_key (tenant_id, monitor_id) WHERE monitor_id IS NOT NULL;

-- 0003's immutability trigger, plus the monitor binding.
CREATE OR REPLACE FUNCTION sibyl.trg_api_key_immutable_fields() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.id <> OLD.id OR NEW.prefix <> OLD.prefix
     OR NEW.secret_hash <> OLD.secret_hash OR NEW.env <> OLD.env
     OR NEW.agent_id IS DISTINCT FROM OLD.agent_id OR NEW.created_at <> OLD.created_at
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.rotated_from_id IS DISTINCT FROM OLD.rotated_from_id
     OR NEW.monitor_id IS DISTINCT FROM OLD.monitor_id
     OR NOT (NEW.scopes <@ OLD.scopes) OR NEW.expires_at > OLD.expires_at THEN
    RAISE EXCEPTION 'sibyl:key_field_immutable: api_key % may only narrow scopes or shorten expiry in place; rotate instead', OLD.id
      USING ERRCODE = 'SB044';
  END IF;
  RETURN NEW;
END
$$;

-- The pre-tenant key lookup now names the monitor a key is bound to (owned by sibyl_audit, 0003).
SET LOCAL ROLE sibyl_audit;
DROP FUNCTION sibyl.api_key_lookup(text);
CREATE FUNCTION sibyl.api_key_lookup(prefix text)
RETURNS TABLE (tenant_id uuid, id uuid, env text, secret_hash bytea, scopes text[], agent_id uuid,
               status text, expires_at timestamptz, rotation_grace_until timestamptz,
               monitor_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT k.tenant_id, k.id, k.env, k.secret_hash, k.scopes, k.agent_id, k.status, k.expires_at,
         k.rotation_grace_until, k.monitor_id
  FROM sibyl.api_key k WHERE k.prefix = api_key_lookup.prefix
$$;
GRANT EXECUTE ON FUNCTION sibyl.api_key_lookup(text) TO sibyl_app, sibyl_ingest;
RESET ROLE;
GRANT SELECT (monitor_id) ON sibyl.api_key TO sibyl_worker;

-- --- monitor_webhook ----------------------------------------------------------------------------

CREATE TABLE sibyl.monitor_webhook (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  monitor_id            uuid        NOT NULL,
  url                   text        NOT NULL,
  event_types           text[]      NOT NULL,
  state                 text        NOT NULL DEFAULT 'enabled',
  credential_id         uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  ciphertext            bytea       NOT NULL,
  nonce                 bytea       NOT NULL,
  tenant_key_id         uuid        NOT NULL,
  key_version           integer     NOT NULL,
  consecutive_failures  integer     NOT NULL DEFAULT 0,
  last_delivery_at      timestamptz,
  last_delivery_status  text,
  last_response_code    integer,
  disabled_reason       text,
  created_by_user_id    uuid        NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_monitor_webhook_monitor FOREIGN KEY (tenant_id, monitor_id)
    REFERENCES sibyl.monitor (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_monitor_webhook_key FOREIGN KEY (tenant_id, tenant_key_id)
    REFERENCES sibyl.tenant_key (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_monitor_webhook_created_by FOREIGN KEY (tenant_id, created_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_monitor_webhook_url CHECK (
    char_length(url) BETWEEN 8 AND 2048 AND sibyl.is_allowlisted_base_url(url)),
  CONSTRAINT ck_monitor_webhook_events CHECK (
    cardinality(event_types) BETWEEN 1 AND 9
    AND event_types <@ ARRAY['alert.fired', 'alert.updated', 'alert.resolved', 'incident.updated',
                             'action.held', 'action.decided', 'action.expired', 'drift.detected',
                             'run.failed']::text[]),
  CONSTRAINT ck_monitor_webhook_state CHECK (state IN ('enabled', 'disabled')),
  CONSTRAINT ck_monitor_webhook_sealed CHECK (octet_length(nonce) = 12 AND key_version >= 1),
  CONSTRAINT ck_monitor_webhook_failures CHECK (consecutive_failures >= 0),
  CONSTRAINT ck_monitor_webhook_last_status CHECK (
    last_delivery_status IS NULL OR last_delivery_status IN ('delivered', 'retrying', 'dead')),
  CONSTRAINT ck_monitor_webhook_disabled CHECK (
    disabled_reason IS NULL OR char_length(disabled_reason) <= 500)
);
CREATE INDEX ix_monitor_webhook_monitor ON sibyl.monitor_webhook (tenant_id, monitor_id, created_at);
CREATE INDEX ix_monitor_webhook_enabled ON sibyl.monitor_webhook (tenant_id) WHERE state = 'enabled';
SELECT sibyl.enable_tenant_rls('sibyl.monitor_webhook');
CREATE TRIGGER trg_monitor_webhook_updated_at BEFORE UPDATE ON sibyl.monitor_webhook
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- The sealed signing secret of one webhook of the current (RLS) tenant. Neither the api nor the
-- worker can SELECT the ciphertext columns.
CREATE FUNCTION sibyl.monitor_webhook_secret(p_webhook_id uuid)
RETURNS TABLE (credential_id uuid, ciphertext bytea, nonce bytea, key_version integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT w.credential_id, w.ciphertext, w.nonce, w.key_version
    FROM sibyl.monitor_webhook w
   WHERE w.tenant_id = sibyl.current_tenant() AND w.id = p_webhook_id
$$;
REVOKE EXECUTE ON FUNCTION sibyl.monitor_webhook_secret(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sibyl.monitor_webhook_secret(uuid) TO sibyl_app, sibyl_worker;

-- --- webhook_delivery ---------------------------------------------------------------------------

-- `event_key` de-duplicates (the outbox row id, `run:<run_id>`, or `ping:<uuid>`); `payload` is
-- the JSON body delivered (references and states only, <= 8 KB). `agent_id` names the agent the
-- event is about (erasure).
CREATE TABLE sibyl.webhook_delivery (
  tenant_id        uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id               uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  webhook_id       uuid        NOT NULL,
  monitor_id       uuid        NOT NULL,
  event_type       text        NOT NULL,
  event_key        text        NOT NULL,
  agent_id         uuid,
  payload          jsonb       NOT NULL,
  status           text        NOT NULL DEFAULT 'pending',
  attempts         integer     NOT NULL DEFAULT 0,
  next_attempt_at  timestamptz NOT NULL DEFAULT now(),
  last_attempt_at  timestamptz,
  response_code    integer,
  error            text,
  settled_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_webhook_delivery_webhook FOREIGN KEY (tenant_id, webhook_id)
    REFERENCES sibyl.monitor_webhook (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_webhook_delivery_monitor FOREIGN KEY (tenant_id, monitor_id)
    REFERENCES sibyl.monitor (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_webhook_delivery_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_webhook_delivery_event CHECK (
    event_type IN ('alert.fired', 'alert.updated', 'alert.resolved', 'incident.updated', 'action.held',
                   'action.decided', 'action.expired', 'drift.detected', 'run.failed', 'ping')),
  CONSTRAINT ck_webhook_delivery_key CHECK (char_length(event_key) BETWEEN 1 AND 200),
  CONSTRAINT ck_webhook_delivery_payload CHECK (
    jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 8192),
  CONSTRAINT ck_webhook_delivery_status CHECK (status IN ('pending', 'delivered', 'retrying', 'dead')),
  CONSTRAINT ck_webhook_delivery_attempts CHECK (attempts BETWEEN 0 AND 32),
  CONSTRAINT ck_webhook_delivery_settled CHECK (
    (status IN ('delivered', 'dead')) = (settled_at IS NOT NULL)),
  CONSTRAINT ck_webhook_delivery_error CHECK (error IS NULL OR char_length(error) <= 200)
);
CREATE UNIQUE INDEX ux_webhook_delivery_event ON sibyl.webhook_delivery (tenant_id, webhook_id, event_key);
CREATE INDEX ix_webhook_delivery_due ON sibyl.webhook_delivery (tenant_id, next_attempt_at)
  WHERE status IN ('pending', 'retrying');
CREATE INDEX ix_webhook_delivery_settled ON sibyl.webhook_delivery (tenant_id, settled_at)
  WHERE settled_at IS NOT NULL;
CREATE INDEX ix_webhook_delivery_agent ON sibyl.webhook_delivery (tenant_id, agent_id)
  WHERE agent_id IS NOT NULL;
SELECT sibyl.enable_tenant_rls('sibyl.webhook_delivery');
CREATE TRIGGER trg_webhook_delivery_updated_at BEFORE UPDATE ON sibyl.webhook_delivery
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- --- external_finding ---------------------------------------------------------------------------

-- `subject_id` names the incident (failover id), held action, agent or run; NULL for a fleet
-- finding. `agent_id` is derived by the api from the subject (never taken from the body).
-- `alert_requested` asks the worker for a watch-only alert; `alert_checked_at` is when it decided.
CREATE TABLE sibyl.external_finding (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  monitor_id            uuid        NOT NULL,
  api_key_id            uuid        NOT NULL,
  kind                  text        NOT NULL,
  subject_kind          text        NOT NULL,
  subject_id            uuid,
  agent_id              uuid,
  severity              text        NOT NULL,
  summary               text        NOT NULL,
  body                  jsonb       NOT NULL DEFAULT '{}'::jsonb,
  recommendation        text,
  advice                text,
  confidence            text,
  provider              text,
  model                 text,
  alert_requested       boolean     NOT NULL DEFAULT false,
  alert_checked_at      timestamptz,
  alert_id              uuid,
  feedback              text,
  feedback_by_user_id   uuid,
  feedback_at           timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_external_finding_monitor FOREIGN KEY (tenant_id, monitor_id)
    REFERENCES sibyl.monitor (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_external_finding_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_external_finding_alert FOREIGN KEY (tenant_id, alert_id)
    REFERENCES sibyl.alert (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_external_finding_feedback_by FOREIGN KEY (tenant_id, feedback_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_external_finding_kind CHECK (kind IN (
    'incident_explanation', 'held_action_review', 'semantic_drift', 'fleet_summary', 'anomaly',
    'safety', 'quality', 'cost', 'other')),
  CONSTRAINT ck_external_finding_subject_kind CHECK (
    subject_kind IN ('incident', 'held_action', 'agent', 'run', 'fleet')),
  CONSTRAINT ck_external_finding_subject CHECK (
    (subject_kind = 'fleet') = (subject_id IS NULL)
    AND (kind <> 'incident_explanation' OR subject_kind = 'incident')
    AND (kind <> 'held_action_review' OR subject_kind = 'held_action')
    AND (kind <> 'semantic_drift' OR subject_kind = 'agent')
    AND (kind <> 'fleet_summary' OR subject_kind = 'fleet')
    AND (subject_kind <> 'agent' OR agent_id = subject_id)),
  CONSTRAINT ck_external_finding_severity CHECK (severity IN ('info', 'warning', 'critical')),
  CONSTRAINT ck_external_finding_summary CHECK (char_length(summary) BETWEEN 1 AND 2000),
  CONSTRAINT ck_external_finding_body CHECK (
    jsonb_typeof(body) = 'object' AND octet_length(body::text) <= 32768),
  CONSTRAINT ck_external_finding_recommendation CHECK (
    recommendation IS NULL OR char_length(recommendation) <= 2000),
  CONSTRAINT ck_external_finding_advice CHECK (
    advice IS NULL OR (kind = 'held_action_review' AND advice IN ('approve', 'deny', 'needs_more_info'))),
  CONSTRAINT ck_external_finding_confidence CHECK (
    confidence IS NULL OR confidence IN ('low', 'medium', 'high')),
  CONSTRAINT ck_external_finding_provider CHECK (
    provider IS NULL OR provider ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  CONSTRAINT ck_external_finding_model CHECK (model IS NULL OR char_length(model) BETWEEN 1 AND 128),
  CONSTRAINT ck_external_finding_alert CHECK (
    (NOT alert_requested OR severity <> 'info') AND (alert_id IS NULL OR alert_checked_at IS NOT NULL)),
  CONSTRAINT ck_external_finding_feedback CHECK (
    (feedback IS NULL AND feedback_by_user_id IS NULL AND feedback_at IS NULL)
    OR (feedback IN ('useful', 'not_useful', 'wrong') AND feedback_by_user_id IS NOT NULL
        AND feedback_at IS NOT NULL))
);
CREATE INDEX ix_external_finding_list ON sibyl.external_finding (tenant_id, created_at DESC, id DESC);
CREATE INDEX ix_external_finding_subject ON sibyl.external_finding (tenant_id, subject_kind, subject_id);
CREATE INDEX ix_external_finding_monitor ON sibyl.external_finding (tenant_id, monitor_id, created_at DESC);
CREATE INDEX ix_external_finding_agent ON sibyl.external_finding (tenant_id, agent_id, created_at DESC)
  WHERE agent_id IS NOT NULL;
CREATE INDEX ix_external_finding_alert_due ON sibyl.external_finding (tenant_id, created_at)
  WHERE alert_requested AND alert_checked_at IS NULL;
SELECT sibyl.enable_tenant_rls('sibyl.external_finding');
CREATE TRIGGER trg_external_finding_updated_at BEFORE UPDATE ON sibyl.external_finding
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- --- grants ---------------------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON sibyl.monitor TO sibyl_app;
GRANT SELECT ON sibyl.monitor TO sibyl_worker;

GRANT SELECT (tenant_id, id, monitor_id, url, event_types, state, credential_id, tenant_key_id,
              key_version, consecutive_failures, last_delivery_at, last_delivery_status,
              last_response_code, disabled_reason, created_by_user_id, created_at, updated_at)
  ON sibyl.monitor_webhook TO sibyl_app, sibyl_worker;
GRANT INSERT ON sibyl.monitor_webhook TO sibyl_app;
GRANT UPDATE (state, disabled_reason, consecutive_failures, last_delivery_at, last_delivery_status,
              last_response_code, updated_at)
  ON sibyl.monitor_webhook TO sibyl_app, sibyl_worker;

GRANT SELECT, INSERT ON sibyl.webhook_delivery TO sibyl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sibyl.webhook_delivery TO sibyl_worker;

GRANT SELECT, INSERT ON sibyl.external_finding TO sibyl_app;
GRANT UPDATE (feedback, feedback_by_user_id, feedback_at, updated_at) ON sibyl.external_finding TO sibyl_app;
GRANT SELECT ON sibyl.external_finding TO sibyl_worker;
GRANT UPDATE (alert_id, alert_checked_at, updated_at) ON sibyl.external_finding TO sibyl_worker;

-- --- erasure cascade --------------------------------------------------------------------------------

-- 0019's single list plus the four monitor tables (ruling B27: the last redefinition carries every
-- tenant table). Findings and deliveries go before alert and agent; webhooks and monitors go after
-- api_key (monitor keys reference their monitor).

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
