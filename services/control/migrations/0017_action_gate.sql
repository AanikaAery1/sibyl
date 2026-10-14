-- 0017 lane AG-CORE: the Action Gate control plane (D48, docs/council/build/ACTION-GATE.md §3).
-- Single sources: sibyl_schemas ActionPolicyState / HeldActionState / ActionScopeKind /
-- ActionEffect / ActionSource, StateMachine.HELD_ACTION / ACTION_POLICY, OutboxTopic.ACTION,
-- the four D48 scopes and the nine action / action_policy audit actions (drift-tested).
--
-- Tables: action_policy (versioned per scope, approval state, tier-1 four-eyes), action_rule
-- (the policy's ordered rules, immutable), held_action (escalated actions waiting for a human,
-- state machine held_action, scrubbed args sealed as a payload_refs row), action_counter
-- (cumulative caps: one row per agent, counter key and tumbling window; the authoritative
-- check-and-increment is a single conditional upsert) and action_decision (one row per
-- cumulative decision, idempotent per (agent, call_id)).

-- --- catalogues -------------------------------------------------------------------------------

ALTER TABLE sibyl.state_edge DROP CONSTRAINT ck_state_edge_machine;
ALTER TABLE sibyl.state_edge ADD CONSTRAINT ck_state_edge_machine CHECK (
  machine IN ('routing', 'failover', 'approval', 'handoff', 'alert', 'erasure', 'tenant_key', 'kill_switch',
              'lifecycle', 'job', 'held_action', 'action_policy'));
INSERT INTO sibyl.state_edge (machine, from_state, to_state, trigger) VALUES
  ('held_action', '', 'pending', '*'),
  ('held_action', '', 'denied', '*'),
  ('held_action', 'pending', 'approved', '*'),
  ('held_action', 'pending', 'denied', '*'),
  ('held_action', 'pending', 'expired', '*'),
  ('held_action', 'pending', 'cancelled', '*'),
  ('action_policy', '', 'draft', '*'),
  ('action_policy', 'draft', 'approved', '*'),
  ('action_policy', 'draft', 'retired', '*'),
  ('action_policy', 'approved', 'superseded', '*'),
  ('action_policy', 'approved', 'retired', '*');

ALTER TABLE sibyl.outbox DROP CONSTRAINT ck_outbox_topic;
ALTER TABLE sibyl.outbox ADD CONSTRAINT ck_outbox_topic CHECK (
  topic IN ('policy', 'killswitch', 'graph', 'health', 'alert', 'provider_incident', 'incident', 'approval',
            'handoff', 'erasure', 'audit', 'agent', 'job', 'action'));

-- Held-action arguments are sealed like every captured payload (kind action_args).
ALTER TABLE sibyl.payload_refs DROP CONSTRAINT ck_payload_refs_kind;
ALTER TABLE sibyl.payload_refs ADD CONSTRAINT ck_payload_refs_kind CHECK (kind IN ('span_content', 'raw_batch',
  'prompt', 'checkpoint_state', 'handoff_packet', 'feature_snapshot', 'bom_export', 'anchor_export', 'comment',
  'model_artifact', 'model_card', 'action_args'));
ALTER TABLE sibyl.payload_refs DROP CONSTRAINT ck_payload_refs_source_kind;
ALTER TABLE sibyl.payload_refs ADD CONSTRAINT ck_payload_refs_source_kind CHECK (source_kind IN ('event',
  'checkpoint', 'packet', 'agent_version', 'bom', 'anchor', 'comment', 'export', 'held_action'));

-- actions:hold is grantable to API keys (gateway and SDK enforcement points).
ALTER TABLE sibyl.api_key DROP CONSTRAINT ck_api_key_scopes;
ALTER TABLE sibyl.api_key ADD CONSTRAINT ck_api_key_scopes CHECK (
  scopes <@ ARRAY['ingest:write', 'gateway:proxy', 'routing:read', 'handoff:write',
                  'agents:read', 'agents:write', 'killswitch:pull', 'actions:hold']::text[]
  AND cardinality(scopes) >= 1
  AND ('killswitch:pull' <> ALL (scopes) OR scopes = ARRAY['killswitch:pull']::text[]));

-- D48 scopes (sibyl_schemas Scope.ACTIONS_*; actions:hold is machine-only and has no role row).
INSERT INTO sibyl.role_permission (role_name, permission, scope_rule, step_up, self_audited) VALUES
  ('owner', 'actions:read', 'tenant', false, false),
  ('admin', 'actions:read', 'tenant', false, false),
  ('security_admin', 'actions:read', 'tenant', false, false),
  ('engineer', 'actions:read', 'tenant', false, false),
  ('operator', 'actions:read', 'tenant', false, false),
  ('auditor', 'actions:read', 'tenant', false, false),
  ('viewer', 'actions:read', 'tenant', false, false),
  ('owner', 'actions:decide', 'tenant', false, false),
  ('security_admin', 'actions:decide', 'tenant', false, false),
  ('operator', 'actions:decide', 'tenant', false, false),
  ('owner', 'action_policies:write', 'tenant', false, false),
  ('admin', 'action_policies:write', 'tenant', false, false),
  ('security_admin', 'action_policies:write', 'tenant', false, false);

INSERT INTO sibyl.audit_action
  (name, domain, actor_types, resource_type, required_fields, reason_required, is_evidence, severity)
VALUES
  ('action.allowed', 'action', '{api_key}', 'agent', '{agent_id,tool,call_id,policy_id,rule_id,sampled}', false,
   true, 'info'),
  ('action.blocked', 'action', '{api_key}', 'agent', '{agent_id,tool,call_id,policy_id,rule_id}', false, true,
   'warning'),
  ('action.escalated', 'action', '{api_key}', 'agent', '{agent_id,tool,call_id,policy_id,rule_id,held_action_id}',
   false, true, 'notice'),
  ('action.approved', 'action', '{human}', 'held_action',
   '{held_action_id,agent_id,tool,decided_by,decision_session_id,approvals,approvals_required,elapsed_s}', true,
   true, 'notice'),
  ('action.denied', 'action', '{human}', 'held_action',
   '{held_action_id,agent_id,tool,decided_by,decision_session_id,elapsed_s}', true, true, 'notice'),
  ('action.expired', 'action', '{system}', 'held_action', '{held_action_id,agent_id,tool,hold_timeout_s,decision}',
   false, true, 'warning'),
  ('action_policy.created', 'action', '{human}', 'action_policy',
   '{policy_id,version_no,scope_kind,scope_id,document_sha256}', true, true, 'notice'),
  ('action_policy.approved', 'action', '{human}', 'action_policy',
   '{policy_id,version_no,approved_by,four_eyes,supersedes,document_sha256}', true, true, 'notice'),
  ('action_policy.retired', 'action', '{human}', 'action_policy', '{policy_id,version_no}', true, true, 'notice');

-- --- action_policy ------------------------------------------------------------------------------

-- One version of a policy for one scope. The most specific approved policy applies to an agent
-- (agent > agent_group > tenant); approving a version supersedes the previous approved one of the
-- same scope. `document` is the normalised `sibyl-action-policy/1` document (policy_id and
-- version filled in), immutable once inserted; `four_eyes` = held actions need two approvers;
-- `approval_four_eyes` = approving this version needs someone other than its author (a tier-1
-- agent is in scope).
CREATE TABLE sibyl.action_policy (
  tenant_id            uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                   uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  name                 text        NOT NULL,
  scope_kind           text        NOT NULL,
  agent_id             uuid,
  agent_group_id       uuid,
  version_no           integer     NOT NULL,
  state                text        NOT NULL DEFAULT 'draft',
  document             jsonb       NOT NULL,
  document_sha256      bytea       NOT NULL,
  default_effect       text        NOT NULL,
  hold_timeout_s       integer     NOT NULL,
  four_eyes            boolean     NOT NULL DEFAULT false,
  approval_four_eyes   boolean     NOT NULL DEFAULT false,
  rule_count           integer     NOT NULL,
  created_by_user_id   uuid        NOT NULL,
  approved_by_user_id  uuid,
  approved_at          timestamptz,
  retired_by_user_id   uuid,
  retired_at           timestamptz,
  superseded_by        uuid,
  superseded_at        timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_action_policy_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_action_policy_group FOREIGN KEY (tenant_id, agent_group_id)
    REFERENCES sibyl.agent_group (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_action_policy_created_by FOREIGN KEY (tenant_id, created_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_action_policy_approved_by FOREIGN KEY (tenant_id, approved_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_action_policy_retired_by FOREIGN KEY (tenant_id, retired_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_action_policy_scope_kind CHECK (scope_kind IN ('tenant', 'agent_group', 'agent')),
  CONSTRAINT ck_action_policy_scope CHECK (
    (scope_kind = 'tenant' AND agent_id IS NULL AND agent_group_id IS NULL)
    OR (scope_kind = 'agent_group' AND agent_id IS NULL AND agent_group_id IS NOT NULL)
    OR (scope_kind = 'agent' AND agent_id IS NOT NULL AND agent_group_id IS NULL)),
  CONSTRAINT ck_action_policy_state CHECK (state IN ('draft', 'approved', 'superseded', 'retired')),
  CONSTRAINT ck_action_policy_default_effect CHECK (default_effect IN ('allow', 'escalate')),
  CONSTRAINT ck_action_policy_name CHECK (char_length(name) BETWEEN 1 AND 200),
  CONSTRAINT ck_action_policy_version CHECK (version_no >= 1),
  CONSTRAINT ck_action_policy_hold_timeout CHECK (hold_timeout_s BETWEEN 10 AND 86400),
  CONSTRAINT ck_action_policy_rule_count CHECK (rule_count BETWEEN 0 AND 256),
  CONSTRAINT ck_action_policy_document CHECK (jsonb_typeof(document) = 'object'
                                              AND octet_length(document::text) <= 65536),
  CONSTRAINT ck_action_policy_sha CHECK (octet_length(document_sha256) = 32),
  CONSTRAINT ck_action_policy_approved CHECK (
    (state NOT IN ('approved', 'superseded') OR (approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL))
    AND (state <> 'superseded' OR superseded_at IS NOT NULL)
    AND (state <> 'retired' OR (retired_by_user_id IS NOT NULL AND retired_at IS NOT NULL))),
  -- Tier-1 four-eyes: the author of a version never approves it.
  CONSTRAINT ck_action_policy_four_eyes CHECK (
    NOT approval_four_eyes OR approved_by_user_id IS NULL OR approved_by_user_id <> created_by_user_id)
);
CREATE UNIQUE INDEX ux_action_policy_version ON sibyl.action_policy
  (tenant_id, scope_kind, coalesce(agent_id, agent_group_id, '00000000-0000-0000-0000-000000000000'::uuid),
   version_no);
CREATE UNIQUE INDEX ux_action_policy_approved ON sibyl.action_policy
  (tenant_id, scope_kind, coalesce(agent_id, agent_group_id, '00000000-0000-0000-0000-000000000000'::uuid))
  WHERE state = 'approved';
CREATE INDEX ix_action_policy_list ON sibyl.action_policy (tenant_id, created_at DESC, id DESC);
CREATE INDEX ix_action_policy_agent ON sibyl.action_policy (tenant_id, agent_id) WHERE agent_id IS NOT NULL;
SELECT sibyl.enable_tenant_rls('sibyl.action_policy');
CREATE TRIGGER trg_action_policy_updated_at BEFORE UPDATE ON sibyl.action_policy
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();
CREATE TRIGGER trg_action_policy_state_edge BEFORE UPDATE OF state ON sibyl.action_policy
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('action_policy', 'state');

-- The policy's ordered rules (a projection of `document.rules` for queries and the console);
-- immutable: a change is a new policy version.
CREATE TABLE sibyl.action_rule (
  tenant_id    uuid        NOT NULL REFERENCES sibyl.tenant (id),
  policy_id    uuid        NOT NULL,
  position     integer     NOT NULL,
  rule_id      text        NOT NULL,
  tool         text        NOT NULL,
  effect       text        NOT NULL,
  reason       text        NOT NULL,
  when_expr    jsonb,
  cumulative   jsonb,
  data_class   jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, policy_id, position),
  CONSTRAINT uq_action_rule_rule_id UNIQUE (tenant_id, policy_id, rule_id),
  CONSTRAINT fk_action_rule_policy FOREIGN KEY (tenant_id, policy_id)
    REFERENCES sibyl.action_policy (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_action_rule_effect CHECK (effect IN ('allow', 'block', 'escalate')),
  CONSTRAINT ck_action_rule_position CHECK (position BETWEEN 1 AND 256),
  CONSTRAINT ck_action_rule_rule_id CHECK (rule_id ~ '^[A-Za-z0-9_.:-]{1,64}$'),
  CONSTRAINT ck_action_rule_tool CHECK (char_length(tool) BETWEEN 1 AND 256),
  CONSTRAINT ck_action_rule_reason CHECK (char_length(reason) BETWEEN 1 AND 500)
);
SELECT sibyl.enable_tenant_rls('sibyl.action_rule');
CREATE TRIGGER trg_action_rule_immutable BEFORE UPDATE ON sibyl.action_rule
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();

-- --- held_action --------------------------------------------------------------------------------

-- An escalated action waiting for a human (state machine held_action). The enforcement point
-- holds the call until `approved` (go ahead) or anything else (deny); `expires_at` = creation +
-- the policy's hold_timeout_s, after which the worker expires it as a deny. Arguments are
-- scrubbed and sealed as one payload_refs row (`args_payload_ref`); `args_sha256` is the RFC 8785
-- digest of the arguments as proposed, so the enforcement point can check that the call it
-- releases is the one approved. `approvals` lists the distinct humans who approved so far
-- (four-eyes: `approvals_required` = 2).
CREATE TABLE sibyl.held_action (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id              uuid        NOT NULL,
  policy_id             uuid,
  policy_version        integer,
  rule_id               text,
  call_id               text        NOT NULL,
  tool                  text        NOT NULL,
  source                text        NOT NULL,
  args_sha256           bytea       NOT NULL,
  args_payload_ref      uuid,
  args_bytes            integer     NOT NULL,
  server_effect         text        NOT NULL,
  reason                text        NOT NULL,
  sensitive             boolean     NOT NULL DEFAULT false,
  approvals_required    smallint    NOT NULL DEFAULT 1,
  approvals             jsonb       NOT NULL DEFAULT '[]'::jsonb,
  requested_by_key_id   uuid        NOT NULL,
  state                 text        NOT NULL DEFAULT 'pending',
  decision              text,
  decided_by_user_id    uuid,
  decided_at            timestamptz,
  decision_reason       text,
  resolved_by_timeout   boolean     NOT NULL DEFAULT false,
  hold_timeout_s        integer     NOT NULL,
  expires_at            timestamptz NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_held_action_call UNIQUE (tenant_id, agent_id, call_id),
  CONSTRAINT fk_held_action_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_held_action_policy FOREIGN KEY (tenant_id, policy_id)
    REFERENCES sibyl.action_policy (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_held_action_decided_by FOREIGN KEY (tenant_id, decided_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_held_action_state CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'cancelled')),
  CONSTRAINT ck_held_action_source CHECK (source IN ('sdk', 'gateway')),
  CONSTRAINT ck_held_action_server_effect CHECK (server_effect IN ('allow', 'block', 'escalate')),
  CONSTRAINT ck_held_action_call_id CHECK (call_id ~ '^[A-Za-z0-9._:-]{1,160}$'),
  CONSTRAINT ck_held_action_tool CHECK (char_length(tool) BETWEEN 1 AND 256),
  CONSTRAINT ck_held_action_reason CHECK (char_length(reason) BETWEEN 1 AND 500),
  CONSTRAINT ck_held_action_sha CHECK (octet_length(args_sha256) = 32),
  CONSTRAINT ck_held_action_args_bytes CHECK (args_bytes BETWEEN 0 AND 262144),
  CONSTRAINT ck_held_action_approvals CHECK (jsonb_typeof(approvals) = 'array'
                                             AND jsonb_array_length(approvals) <= approvals_required),
  CONSTRAINT ck_held_action_approvals_required CHECK (approvals_required BETWEEN 1 AND 2),
  CONSTRAINT ck_held_action_hold_timeout CHECK (hold_timeout_s BETWEEN 1 AND 86400),
  CONSTRAINT ck_held_action_policy CHECK ((policy_id IS NULL) = (policy_version IS NULL)),
  -- decision is the enforcement answer: allow only for an approved hold, deny for every other end.
  CONSTRAINT ck_held_action_decision CHECK (
    (state = 'pending' AND decision IS NULL)
    OR (state = 'approved' AND decision = 'allow' AND decided_by_user_id IS NOT NULL AND decided_at IS NOT NULL
        AND jsonb_array_length(approvals) = approvals_required)
    OR (state = 'denied' AND decision = 'deny' AND decided_at IS NOT NULL)
    OR (state = 'expired' AND decision = 'deny' AND resolved_by_timeout AND decided_at IS NOT NULL)
    OR (state = 'cancelled' AND decision = 'deny' AND decided_at IS NOT NULL))
);
CREATE INDEX ix_held_action_due ON sibyl.held_action (tenant_id, expires_at) WHERE state = 'pending';
CREATE INDEX ix_held_action_list ON sibyl.held_action (tenant_id, created_at DESC, id DESC);
CREATE INDEX ix_held_action_agent ON sibyl.held_action (tenant_id, agent_id, created_at DESC);
SELECT sibyl.enable_tenant_rls('sibyl.held_action');
CREATE TRIGGER trg_held_action_updated_at BEFORE UPDATE ON sibyl.held_action
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();
CREATE TRIGGER trg_held_action_state_edge BEFORE UPDATE OF state ON sibyl.held_action
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('held_action', 'state');

-- --- cumulative caps ------------------------------------------------------------------------------

-- One tumbling window per (agent, counter key, window length): window_start = epoch floor of the
-- decision time. `POST /action-decisions` increments with one conditional upsert
-- (value + amount <= max_value), so concurrent calls can never overshoot the cap.
CREATE TABLE sibyl.action_counter (
  tenant_id     uuid        NOT NULL REFERENCES sibyl.tenant (id),
  agent_id      uuid        NOT NULL,
  counter_key   text        NOT NULL,
  window_s      integer     NOT NULL,
  window_start  timestamptz NOT NULL,
  value         numeric     NOT NULL DEFAULT 0,
  max_value     numeric     NOT NULL,
  calls         integer     NOT NULL DEFAULT 0,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, agent_id, counter_key, window_s, window_start),
  CONSTRAINT fk_action_counter_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_action_counter_key CHECK (char_length(counter_key) BETWEEN 1 AND 512),
  CONSTRAINT ck_action_counter_window CHECK (window_s BETWEEN 1 AND 2678400),
  CONSTRAINT ck_action_counter_value CHECK (value >= 0 AND max_value > 0 AND value <= max_value AND calls >= 0)
);
CREATE INDEX ix_action_counter_window ON sibyl.action_counter (tenant_id, window_start);
SELECT sibyl.enable_tenant_rls('sibyl.action_counter');
CREATE TRIGGER trg_action_counter_updated_at BEFORE UPDATE ON sibyl.action_counter
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- One row per authoritative cumulative check-and-increment (`within_cap` is the answer, `effect`
-- the rule's within / on_exceed effect); a repeated call_id returns the stored answer.
CREATE TABLE sibyl.action_decision (
  tenant_id       uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id              uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id        uuid        NOT NULL,
  call_id         text        NOT NULL,
  tool            text        NOT NULL,
  policy_id       uuid,
  policy_version  integer,
  rule_id         text,
  effect          text        NOT NULL,
  reason          text        NOT NULL,
  counter_key     text,
  window_s        integer,
  window_start    timestamptz,
  amount          numeric,
  counter_value   numeric,
  counter_max     numeric,
  within_cap      boolean,
  args_sha256     bytea,
  source          text        NOT NULL,
  api_key_id      uuid        NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_action_decision_call UNIQUE (tenant_id, agent_id, call_id),
  CONSTRAINT fk_action_decision_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_action_decision_policy FOREIGN KEY (tenant_id, policy_id)
    REFERENCES sibyl.action_policy (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_action_decision_effect CHECK (effect IN ('allow', 'block', 'escalate')),
  CONSTRAINT ck_action_decision_source CHECK (source IN ('sdk', 'gateway')),
  CONSTRAINT ck_action_decision_call_id CHECK (call_id ~ '^[A-Za-z0-9._:-]{1,160}$'),
  CONSTRAINT ck_action_decision_sha CHECK (args_sha256 IS NULL OR octet_length(args_sha256) = 32),
  CONSTRAINT ck_action_decision_reason CHECK (char_length(reason) BETWEEN 1 AND 500)
);
CREATE INDEX ix_action_decision_agent ON sibyl.action_decision (tenant_id, agent_id, created_at);
SELECT sibyl.enable_tenant_rls('sibyl.action_decision');
CREATE TRIGGER trg_action_decision_immutable BEFORE UPDATE ON sibyl.action_decision
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();

-- --- grants ---------------------------------------------------------------------------------------

GRANT SELECT ON sibyl.action_policy, sibyl.action_rule, sibyl.held_action, sibyl.action_counter,
  sibyl.action_decision TO sibyl_app, sibyl_worker;
GRANT INSERT ON sibyl.action_policy, sibyl.action_rule, sibyl.held_action, sibyl.action_counter,
  sibyl.action_decision TO sibyl_app;
GRANT UPDATE (state, approved_by_user_id, approved_at, retired_by_user_id, retired_at, superseded_by,
              superseded_at, updated_at) ON sibyl.action_policy TO sibyl_app;
GRANT UPDATE (state, decision, decided_by_user_id, decided_at, decision_reason, approvals, resolved_by_timeout,
              updated_at) ON sibyl.held_action TO sibyl_app, sibyl_worker;
GRANT UPDATE (value, calls, max_value, updated_at) ON sibyl.action_counter TO sibyl_app;
GRANT DELETE ON sibyl.action_counter TO sibyl_worker;
GRANT REFERENCES ON sibyl.action_policy TO sibyl_migrate;

-- --- erasure cascade --------------------------------------------------------------------------------

-- 0011's single list plus the five Action Gate tables (before agent, agent_group and payload owners).
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
