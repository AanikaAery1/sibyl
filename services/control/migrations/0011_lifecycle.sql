-- 0011 lifecycle (DATAMODEL §4.8 erasure_request, legal_hold; §6.5 cascade extended per X4/R58;
-- API §12.1 idempotency_record; R63 restore re-shred from the off-database erasure ledger).

CREATE TABLE sibyl.erasure_request (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  scope_kind            text        NOT NULL,
  scope_ref             text,
  legal_basis           text        NOT NULL,
  requested_by          uuid,
  requested_at          timestamptz NOT NULL DEFAULT now(),
  state                 text        NOT NULL DEFAULT 'requested',
  approved_by           uuid,
  approved_at           timestamptz,
  hold_check_at         timestamptz,
  blocking_hold_ids     uuid[]      NOT NULL DEFAULT '{}',
  affected_objects      jsonb,
  execution_log         jsonb       NOT NULL DEFAULT '[]',
  completion_anchor_id  uuid,
  certificate_sha256    bytea,
  backups_expire_at     timestamptz,
  completed_at          timestamptz,
  error                 text,
  origin                text        NOT NULL DEFAULT 'api',
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT ck_erasure_request_origin CHECK (origin IN ('api', 'restore')),
  CONSTRAINT fk_erasure_request_requested_by FOREIGN KEY (tenant_id, requested_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_erasure_request_approved_by FOREIGN KEY (tenant_id, approved_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_erasure_request_scope_kind CHECK (scope_kind IN ('tenant', 'agent', 'subject')),
  CONSTRAINT ck_erasure_request_scope_ref CHECK (scope_kind = 'tenant' OR scope_ref IS NOT NULL),
  CONSTRAINT ck_erasure_request_legal_basis CHECK (legal_basis IN ('gdpr_art17', 'dpdp_s12', 'contract_end',
                                                                   'tenant_offboarding', 'other')),
  CONSTRAINT ck_erasure_request_state CHECK (state IN ('requested', 'hold_blocked', 'approved', 'executing',
    'keys_shredded', 'objects_deleted', 'derived_purged', 'verified', 'completed', 'rejected', 'cancelled')),
  CONSTRAINT ck_erasure_request_approver CHECK (approved_by IS NULL OR requested_by IS NULL OR approved_by <> requested_by),
  CONSTRAINT ck_erasure_request_certificate CHECK (certificate_sha256 IS NULL OR octet_length(certificate_sha256) = 32)
);
CREATE INDEX ix_erasure_request_state ON sibyl.erasure_request (tenant_id, state);
CREATE TRIGGER trg_erasure_request_state_edge BEFORE UPDATE OF state ON sibyl.erasure_request
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('erasure', 'state');
CREATE TRIGGER trg_erasure_request_requester_not_approver BEFORE INSERT OR UPDATE ON sibyl.erasure_request
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_requester_not_approver('requested_by', 'approved_by');

-- Restore re-application (R63) may reopen a request; only the sibyl_audit definers may.
INSERT INTO sibyl.state_edge (machine, from_state, to_state, trigger)
SELECT 'erasure', s, 'executing', 'restore'
FROM unnest(ARRAY['requested', 'hold_blocked', 'approved', 'keys_shredded', 'objects_deleted', 'derived_purged',
                  'verified', 'completed', 'rejected', 'cancelled']) AS s
UNION ALL SELECT 'erasure', 'executing', 'completed', 'restore';

CREATE FUNCTION sibyl.trg_erasure_restore_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_setting('app.transition_trigger', true) = 'restore' AND current_user <> 'sibyl_audit' THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: restore transitions are reserved to the restore hook' USING ERRCODE = 'SB031';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_erasure_restore_guard BEFORE UPDATE OF state ON sibyl.erasure_request
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_erasure_restore_guard();

-- Four-eyes in the database (G0 security M1). A request starts as requested/hold_blocked;
-- every state from approved on needs the approval fields and a known requester (the
-- requester-not-approver trigger rejects a self-approval). Only the restore definers, running
-- as sibyl_audit, may create or reopen a request without approval (origin = 'restore'). An
-- agent named as backup in another agent's approved chain cannot even be requested (G0-7).
CREATE FUNCTION sibyl.trg_erasure_request_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_chain uuid;
BEGIN
  IF current_user = 'sibyl_audit' THEN
    RETURN NEW;
  END IF;
  IF NEW.origin = 'restore' AND (TG_OP = 'INSERT' OR OLD.origin IS DISTINCT FROM 'restore') THEN
    RAISE EXCEPTION 'sibyl:erasure_not_approved: only the restore hook may mark an erasure request restored'
      USING ERRCODE = 'SB035';
  END IF;
  IF TG_OP = 'INSERT' AND NEW.state NOT IN ('requested', 'hold_blocked') THEN
    RAISE EXCEPTION 'sibyl:erasure_not_approved: an erasure request is created as requested or hold_blocked, not %', NEW.state
      USING ERRCODE = 'SB035';
  END IF;
  IF NEW.origin <> 'restore'
     AND NEW.state IN ('approved', 'executing', 'keys_shredded', 'objects_deleted', 'derived_purged', 'verified',
                       'completed')
     AND (NEW.approved_by IS NULL OR NEW.approved_at IS NULL OR NEW.requested_by IS NULL) THEN
    RAISE EXCEPTION 'sibyl:erasure_not_approved: erasure request % needs a requester, an approver and an approval time to be %',
      NEW.id, NEW.state USING ERRCODE = 'SB035';
  END IF;
  IF TG_OP = 'INSERT' AND NEW.scope_kind = 'agent'
     AND NEW.scope_ref ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
    SELECT c.id INTO v_chain FROM sibyl.fallback_step st
      JOIN sibyl.fallback_chain c ON c.tenant_id = st.tenant_id AND c.id = st.chain_id
     WHERE st.tenant_id = NEW.tenant_id AND st.backup_agent_id = NEW.scope_ref::uuid
       AND c.agent_id <> NEW.scope_ref::uuid AND c.status = 'approved'
     ORDER BY c.id LIMIT 1;
    IF FOUND THEN
      RAISE EXCEPTION 'sibyl:erasure_blocked_by_chain: agent % is the backup in approved fallback chain %', NEW.scope_ref, v_chain
        USING ERRCODE = 'SB034';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_erasure_request_guard BEFORE INSERT OR UPDATE ON sibyl.erasure_request
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_erasure_request_guard();

GRANT REFERENCES ON sibyl.erasure_request TO sibyl_migrate;
ALTER TABLE sibyl.tenant_key ADD CONSTRAINT fk_tenant_key_erasure_request FOREIGN KEY (tenant_id, erasure_request_id)
  REFERENCES sibyl.erasure_request (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

-- Explicit holds (R14). References to purgeable rows (incident, alert) are loose on purpose:
-- holds survive erasure, the rows they name do not.
CREATE TABLE sibyl.legal_hold (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  scope_kind            text        NOT NULL,
  scope_ref             text,
  provider_incident_id  uuid,
  alert_id              uuid,
  agent_ids             uuid[]      NOT NULL DEFAULT '{}',
  window_from           timestamptz NOT NULL,
  window_to             timestamptz,
  reason                text        NOT NULL,
  placed_by             uuid,
  placed_at             timestamptz NOT NULL DEFAULT now(),
  expires_at            timestamptz,
  state                 text        NOT NULL DEFAULT 'active',
  released_by           uuid,
  released_at           timestamptz,
  release_reason        text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_legal_hold_placed_by FOREIGN KEY (tenant_id, placed_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_legal_hold_released_by FOREIGN KEY (tenant_id, released_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_legal_hold_scope_kind CHECK (scope_kind IN ('tenant', 'agent', 'incident', 'subject')),
  CONSTRAINT ck_legal_hold_incident CHECK ((scope_kind = 'incident') = (provider_incident_id IS NOT NULL)),
  CONSTRAINT ck_legal_hold_scope_ref CHECK (scope_kind IN ('tenant', 'incident') OR scope_ref IS NOT NULL),
  CONSTRAINT ck_legal_hold_state CHECK (state IN ('active', 'released', 'expired')),
  CONSTRAINT ck_legal_hold_released CHECK (
    (state = 'released') = (released_at IS NOT NULL AND coalesce(btrim(release_reason), '') <> '')),
  CONSTRAINT ck_legal_hold_window CHECK (window_to IS NULL OR window_to >= window_from),
  CONSTRAINT ck_legal_hold_bounded CHECK (expires_at IS NULL OR expires_at <= placed_at + interval '2 years')
);
CREATE INDEX ix_legal_hold_active ON sibyl.legal_hold (tenant_id) WHERE state = 'active';

-- R14: opening a provider incident with tenant.hold_on_incident places a system hold.
CREATE FUNCTION sibyl.trg_provider_incident_auto_hold() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_hold uuid := sibyl.uuidv7();
BEGIN
  IF NOT (SELECT hold_on_incident FROM sibyl.tenant WHERE id = NEW.tenant_id) THEN
    RETURN NULL;
  END IF;
  INSERT INTO sibyl.legal_hold (tenant_id, id, scope_kind, provider_incident_id, agent_ids, window_from, reason)
  VALUES (NEW.tenant_id, v_hold, 'incident', NEW.id, NEW.affected_agent_ids, NEW.started_at - interval '1 hour',
          'automatic hold on provider incident (tenant.hold_on_incident)');
  PERFORM sibyl.audit_append(NEW.tenant_id, 'system', NULL, NULL, NULL, 'hold.placed', 'legal_hold', v_hold, NULL,
    NULL, jsonb_build_object('hold_id', v_hold, 'scope_kind', 'incident', 'scope_ref', NULL,
                             'incident_id', NEW.id, 'expires_at', NULL), NULL, now(), NULL);
  RETURN NULL;
END
$$;
CREATE TRIGGER trg_provider_incident_auto_hold AFTER INSERT ON sibyl.provider_incident
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_provider_incident_auto_hold();

-- Idempotency-Key replay store (API §2.6; W0-KER shape): one row per (tenant, route, key)
-- for 24 h, owned by the principal that first used it. Holds response bodies, so it is in
-- the erasure objects phase. Not partitioned: a partitioned unique key would have to
-- include created_at; the worker deletes rows past expires_at.
CREATE TABLE sibyl.idempotency_record (
  tenant_id         uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  route             text        NOT NULL,
  idempotency_key   text        NOT NULL,
  principal_kind    text        NOT NULL,
  principal_id      uuid        NOT NULL,
  request_sha256    bytea       NOT NULL,
  state             text        NOT NULL DEFAULT 'in_progress',
  status_code       smallint,
  response_headers  jsonb       NOT NULL DEFAULT '{}',
  response_body     jsonb,
  response_body_sha256 bytea,
  -- G0-8 fencing token: a new value on every (re)claim; complete/abandon match on it.
  claim_id          uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  created_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at        timestamptz NOT NULL DEFAULT clock_timestamp() + interval '24 hours',
  completed_at      timestamptz,
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_idempotency_record_key UNIQUE (tenant_id, route, idempotency_key),
  CONSTRAINT ck_idempotency_record_principal_kind CHECK (principal_kind IN ('user', 'api_key')),
  CONSTRAINT ck_idempotency_record_key CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  CONSTRAINT ck_idempotency_record_state CHECK (state IN ('in_progress', 'done')),
  CONSTRAINT ck_idempotency_record_sha256 CHECK (octet_length(request_sha256) = 32),
  -- G0-8: at most 64 KB of compact JSON body; a larger response keeps status, headers and
  -- response_body_sha256 only (the replay answers 409 idempotent_replay_unavailable).
  CONSTRAINT ck_idempotency_record_body CHECK (
    (response_body IS NULL OR octet_length(sibyl.jcs_text(response_body, false)) <= 65536)
    AND pg_column_size(response_headers) <= 8192),
  CONSTRAINT ck_idempotency_record_body_sha256 CHECK (
    response_body_sha256 IS NULL OR octet_length(response_body_sha256) = 32),
  CONSTRAINT ck_idempotency_record_done CHECK ((state = 'done') = (completed_at IS NOT NULL AND status_code IS NOT NULL)),
  CONSTRAINT ck_idempotency_record_expiry CHECK (expires_at > created_at)
);
CREATE INDEX ix_idempotency_record_expiry ON sibyl.idempotency_record (tenant_id, expires_at);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['erasure_request', 'legal_hold', 'idempotency_record'] LOOP
    PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', t)::regclass);
  END LOOP;
END
$$;
CREATE TRIGGER trg_erasure_request_updated_at BEFORE UPDATE ON sibyl.erasure_request
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();
CREATE TRIGGER trg_legal_hold_updated_at BEFORE UPDATE ON sibyl.legal_hold
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- Erasure cascade (DATAMODEL §6.5 + the 14 Step 4/5 tables, X4/R58). This function is the
-- single list: the worker executes it and the completeness test diffs it against the
-- catalogue, so a new tenant table that is neither here nor kept fails CI.
-- action: delete | routing_fn | anonymise | keep. agent_predicate uses $1 tenant, $2 agent;
-- NULL means "not touched by agent-scope erasure". subject_predicate uses $3 agent ids,
-- $4 window_from, $5 window_to (NULL = open) of the operator-resolved subject set (API
-- Phase 1 `agent_window`); subject scope stops after the objects phase (DATAMODEL §6.5 step 5).
-- tenant_pseudonym_key is kept as a row but its key is shredded with the tenant's keys.
CREATE FUNCTION sibyl.erasure_cascade()
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

-- Active legal holds that intersect an erasure scope (G0 security M1). A tenant hold blocks
-- everything; a tenant erasure is blocked by any hold; otherwise holds match by agent
-- (materialised agent_ids or an agent-scope ref) or by the same subject reference.
CREATE FUNCTION sibyl.erasure_blocking_holds(p_tenant uuid, p_scope_kind text, p_scope_ref text, p_agents uuid[])
RETURNS uuid[]
LANGUAGE sql STABLE AS $$
  SELECT coalesce(array_agg(h.id ORDER BY h.id), '{}') FROM sibyl.legal_hold h
   WHERE h.tenant_id = p_tenant AND h.state = 'active' AND (h.expires_at IS NULL OR h.expires_at > now())
     AND (p_scope_kind = 'tenant' OR h.scope_kind = 'tenant'
          OR h.agent_ids && coalesce(p_agents, '{}')
          OR (h.scope_kind = 'agent' AND h.scope_ref = ANY (coalesce(p_agents, '{}')::text[]))
          OR (p_scope_kind = 'subject' AND h.scope_kind = 'subject' AND h.scope_ref = p_scope_ref))
$$;

-- The operator-resolved subject set of a subject-scope request (affected_objects.subject_set).
CREATE FUNCTION sibyl.erasure_subject_set(p_affected jsonb, OUT agents uuid[], OUT window_from timestamptz,
                                          OUT window_to timestamptz)
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  v jsonb := p_affected->'subject_set';
BEGIN
  IF jsonb_typeof(v) IS DISTINCT FROM 'object' OR jsonb_typeof(v->'agent_ids') IS DISTINCT FROM 'array'
     OR jsonb_array_length(v->'agent_ids') = 0 OR jsonb_typeof(v->'window_from') IS DISTINCT FROM 'string' THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: a subject erasure needs a resolved subject_set (agent_ids, window_from)'
      USING ERRCODE = 'SB031';
  END IF;
  agents := ARRAY(SELECT jsonb_array_elements_text(v->'agent_ids')::uuid);
  window_from := (v->>'window_from')::timestamptz;
  window_to := (v->>'window_to')::timestamptz;
END
$$;

-- Executes one cascade phase for an executing erasure request, as the owner of the purged
-- tables (FORCE RLS still pins it to the transaction tenant). The request row is locked for
-- the transaction. p_restore (R63 re-application only) skips the hold check: the erasure
-- already happened before the backup was restored.
CREATE FUNCTION sibyl.erasure_execute_phase_internal(p_erasure_request_id uuid, p_phase text, p_restore boolean)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_tenant uuid := sibyl.current_tenant();
  er record;
  v_agent uuid;
  v_agents uuid[] := '{}';
  v_from timestamptz;
  v_to timestamptz;
  v_holds uuid[];
  r record;
  v_pred text;
  v_n bigint;
  v_counts jsonb := '{}';
  v_routing_done boolean := false;
  v_blocker record;
BEGIN
  SELECT * INTO er FROM sibyl.erasure_request WHERE tenant_id = v_tenant AND id = p_erasure_request_id FOR UPDATE;
  IF NOT FOUND OR p_phase NOT IN ('objects_deleted', 'derived_purged') THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: erasure phase % refused for request %', p_phase, p_erasure_request_id USING ERRCODE = 'SB031';
  END IF;
  PERFORM set_config('sibyl.erasure_request', p_erasure_request_id::text, true);
  IF NOT sibyl.erasure_delete_allowed(v_tenant) THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: erasure request % is not executing', p_erasure_request_id USING ERRCODE = 'SB031';
  END IF;
  IF er.scope_kind = 'agent' THEN
    v_agent := er.scope_ref::uuid;
    v_agents := ARRAY[v_agent];
  ELSIF er.scope_kind = 'subject' THEN
    SELECT s.agents, s.window_from, s.window_to INTO v_agents, v_from, v_to
      FROM sibyl.erasure_subject_set(er.affected_objects) s;
  END IF;
  IF NOT p_restore THEN
    v_holds := sibyl.erasure_blocking_holds(v_tenant, er.scope_kind, er.scope_ref, v_agents);
    IF cardinality(v_holds) > 0 THEN
      RAISE EXCEPTION 'sibyl:legal_hold_active: erasure request % is blocked by legal hold(s) %', p_erasure_request_id, v_holds
        USING ERRCODE = 'SB032';
    END IF;
  END IF;
  -- An agent named as the backup in another agent's approved chain cannot be erased (G0-7):
  -- refuse every phase up front, before anything is deleted.
  IF v_agent IS NOT NULL THEN
    SELECT c.id AS chain_id, c.agent_id INTO v_blocker
      FROM sibyl.fallback_step s
      JOIN sibyl.fallback_chain c ON c.tenant_id = s.tenant_id AND c.id = s.chain_id
     WHERE s.tenant_id = v_tenant AND s.backup_agent_id = v_agent AND c.agent_id <> v_agent AND c.status = 'approved'
     ORDER BY c.id LIMIT 1;
    IF FOUND THEN
      RAISE EXCEPTION 'sibyl:erasure_blocked_by_chain: agent % is the backup in approved fallback chain % of agent %',
        v_agent, v_blocker.chain_id, v_blocker.agent_id USING ERRCODE = 'SB034';
    END IF;
  END IF;
  SET CONSTRAINTS ALL DEFERRED;
  IF er.scope_kind = 'subject' THEN
    FOR r IN SELECT * FROM sibyl.erasure_cascade() c
              WHERE c.phase = p_phase AND c.subject_predicate IS NOT NULL ORDER BY c.ord LOOP
      EXECUTE format('DELETE FROM sibyl.%I WHERE tenant_id = $1 AND (%s)', r.table_name, r.subject_predicate)
        USING v_tenant, v_agent, v_agents, v_from, v_to;
      GET DIAGNOSTICS v_n = ROW_COUNT;
      v_counts := v_counts || jsonb_build_object(r.table_name, v_n);
    END LOOP;
    RETURN v_counts;
  END IF;
  IF v_agent IS NOT NULL AND p_phase = 'derived_purged' THEN
    -- G0-7: draft and retired chains of other agents keep a tombstone step.
    UPDATE sibyl.fallback_step s SET backup_agent_id = NULL, target_erased = true
      FROM sibyl.fallback_chain c
     WHERE s.tenant_id = v_tenant AND s.backup_agent_id = v_agent
       AND c.tenant_id = s.tenant_id AND c.id = s.chain_id AND c.agent_id <> v_agent;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n > 0 THEN
      v_counts := v_counts || jsonb_build_object('fallback_step_tombstoned', v_n);
    END IF;
  END IF;
  FOR r IN SELECT * FROM sibyl.erasure_cascade() c WHERE c.phase = p_phase ORDER BY c.ord LOOP
    IF v_agent IS NOT NULL AND (r.agent_predicate IS NULL OR r.action = 'anonymise') THEN
      CONTINUE;
    END IF;
    IF r.action = 'routing_fn' THEN
      IF NOT v_routing_done THEN
        v_n := sibyl.erasure_purge_routing(p_erasure_request_id, v_agent);
        v_counts := v_counts || jsonb_build_object('routing', v_n);
        v_routing_done := true;
      END IF;
    ELSIF r.action = 'delete' THEN
      v_pred := CASE WHEN v_agent IS NULL THEN 'true' ELSE r.agent_predicate END;
      EXECUTE format('DELETE FROM sibyl.%I WHERE tenant_id = $1 AND (%s)', r.table_name, v_pred)
        USING v_tenant, v_agent;
      GET DIAGNOSTICS v_n = ROW_COUNT;
      v_counts := v_counts || jsonb_build_object(r.table_name, v_n);
    ELSIF r.action = 'anonymise' AND r.table_name = 'app_user' THEN
      -- G0 H2: every user, whatever the status: no email, name, IdP subject or login time
      -- survives; the replacements are keyed pseudonyms (unlinkable once the key is shredded).
      UPDATE sibyl.app_user u
         SET email = 'erased+' || sibyl.pseudonym_hex(v_tenant, lower(u.email::text)) || '@invalid',
             subject = 'erased:' || sibyl.pseudonym_hex(v_tenant, u.subject),
             display_name = NULL, last_login_at = NULL, email_verified = false, status = 'deprovisioned'
       WHERE u.tenant_id = v_tenant AND NOT sibyl.app_user_is_erased(u.email::text, u.subject, u.display_name,
                                                                     u.last_login_at);
      DELETE FROM sibyl.app_user u WHERE u.tenant_id = v_tenant
         AND NOT EXISTS (SELECT 1 FROM sibyl.audit_events a WHERE a.tenant_id = v_tenant AND a.actor_id = u.id)
         AND NOT EXISTS (SELECT 1 FROM sibyl.legal_hold h WHERE h.tenant_id = v_tenant
                                AND u.id IN (h.placed_by, h.released_by))
         AND NOT EXISTS (SELECT 1 FROM sibyl.erasure_request e WHERE e.tenant_id = v_tenant
                                AND u.id IN (e.requested_by, e.approved_by));
      GET DIAGNOSTICS v_n = ROW_COUNT;
      v_counts := v_counts || jsonb_build_object('app_user_deleted', v_n);
    ELSIF r.action = 'anonymise' AND r.table_name = 'oidc_issuer' THEN
      UPDATE sibyl.oidc_issuer SET client_secret_ct = NULL, client_secret_key_id = NULL, status = 'disabled',
                                   role_claim_map = '{}', allowed_email_domains = '{}'
       WHERE tenant_id = v_tenant;
      DELETE FROM sibyl.oidc_issuer i WHERE i.tenant_id = v_tenant
         AND NOT EXISTS (SELECT 1 FROM sibyl.app_user u WHERE u.tenant_id = v_tenant AND u.oidc_issuer_id = i.id);
      GET DIAGNOSTICS v_n = ROW_COUNT;
      v_counts := v_counts || jsonb_build_object('oidc_issuer_deleted', v_n);
    END IF;
  END LOOP;
  RETURN v_counts;
END
$$;

CREATE FUNCTION sibyl.erasure_execute_phase(p_erasure_request_id uuid, p_phase text) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT sibyl.erasure_execute_phase_internal(p_erasure_request_id, p_phase, false)
$$;

CREATE FUNCTION sibyl.app_user_is_erased(p_email text, p_subject text, p_display_name text, p_last_login timestamptz)
RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT p_email ~ '^erased\+[0-9a-f]{64}@invalid$' AND p_subject ~ '^erased:[0-9a-f]{64}$'
         AND p_display_name IS NULL AND p_last_login IS NULL
$$;

-- Residue after the derived phase (the `verified` step reads this): rows left in purged
-- tables, and for tenant scope any user row still carrying personal data (checked on
-- content, not status), an OIDC client secret, or an unshredded pseudonym key.
CREATE FUNCTION sibyl.erasure_residue(p_erasure_request_id uuid)
RETURNS TABLE (table_name text, remaining bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_tenant uuid := sibyl.current_tenant();
  er record;
  v_agent uuid;
  v_agents uuid[] := '{}';
  v_from timestamptz;
  v_to timestamptz;
  r record;
  v_pred text;
  v_n bigint;
BEGIN
  SELECT * INTO er FROM sibyl.erasure_request WHERE tenant_id = v_tenant AND id = p_erasure_request_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: unknown erasure request %', p_erasure_request_id USING ERRCODE = 'SB031';
  END IF;
  IF er.scope_kind = 'agent' THEN
    v_agent := er.scope_ref::uuid;
  ELSIF er.scope_kind = 'subject' THEN
    SELECT s.agents, s.window_from, s.window_to INTO v_agents, v_from, v_to
      FROM sibyl.erasure_subject_set(er.affected_objects) s;
  END IF;
  FOR r IN SELECT * FROM sibyl.erasure_cascade() c WHERE c.action IN ('delete', 'routing_fn') ORDER BY c.ord LOOP
    v_pred := CASE er.scope_kind WHEN 'tenant' THEN 'true' WHEN 'agent' THEN r.agent_predicate
                                 ELSE r.subject_predicate END;
    CONTINUE WHEN v_pred IS NULL;
    EXECUTE format('SELECT count(*) FROM sibyl.%I WHERE tenant_id = $1 AND (%s)', r.table_name, v_pred)
      INTO v_n USING v_tenant, v_agent, v_agents, v_from, v_to;
    IF v_n > 0 THEN
      table_name := r.table_name; remaining := v_n; RETURN NEXT;
    END IF;
  END LOOP;
  IF er.scope_kind = 'tenant' THEN
    SELECT count(*) INTO v_n FROM sibyl.app_user u WHERE u.tenant_id = v_tenant
       AND NOT sibyl.app_user_is_erased(u.email::text, u.subject, u.display_name, u.last_login_at);
    IF v_n > 0 THEN table_name := 'app_user'; remaining := v_n; RETURN NEXT; END IF;
    SELECT count(*) INTO v_n FROM sibyl.oidc_issuer WHERE tenant_id = v_tenant AND client_secret_ct IS NOT NULL;
    IF v_n > 0 THEN table_name := 'oidc_issuer'; remaining := v_n; RETURN NEXT; END IF;
    SELECT count(*) INTO v_n FROM sibyl.tenant_pseudonym_key WHERE tenant_id = v_tenant AND shredded_at IS NULL;
    IF v_n > 0 THEN table_name := 'tenant_pseudonym_key'; remaining := v_n; RETURN NEXT; END IF;
  END IF;
END
$$;

GRANT SELECT ON sibyl.erasure_request, sibyl.legal_hold TO sibyl_app, sibyl_worker, sibyl_ingest, sibyl_audit,
  sibyl_routing;
GRANT INSERT, UPDATE ON sibyl.erasure_request, sibyl.legal_hold TO sibyl_app;
GRANT UPDATE ON sibyl.erasure_request TO sibyl_worker;
GRANT INSERT, UPDATE ON sibyl.legal_hold TO sibyl_worker;
GRANT INSERT, UPDATE (state, execution_log, completed_at, origin, affected_objects) ON sibyl.erasure_request
  TO sibyl_audit;
GRANT UPDATE (name, region_declared, unknown_agent_fail_mode, parent_tenant_id) ON sibyl.tenant TO sibyl_audit;
GRANT SELECT, INSERT, UPDATE ON sibyl.idempotency_record TO sibyl_app;
GRANT DELETE ON sibyl.idempotency_record TO sibyl_worker;
GRANT EXECUTE ON FUNCTION sibyl.erasure_cascade() TO sibyl_app, sibyl_worker, sibyl_audit;
SET LOCAL ROLE sibyl_routing;
GRANT SELECT ON sibyl.routing_state, sibyl.routing_transition TO sibyl_migrate;
RESET ROLE;
GRANT EXECUTE ON FUNCTION sibyl.erasure_execute_phase(uuid, text), sibyl.erasure_residue(uuid)
  TO sibyl_worker, sibyl_audit;
GRANT EXECUTE ON FUNCTION sibyl.erasure_execute_phase_internal(uuid, text, boolean) TO sibyl_audit;
GRANT EXECUTE ON FUNCTION sibyl.erasure_blocking_holds(uuid, text, text, uuid[]),
  sibyl.erasure_subject_set(jsonb), sibyl.app_user_is_erased(text, text, text, timestamptz)
  TO sibyl_audit, sibyl_worker, sibyl_app;

-- R63 restore hook (G0 security H1). The erasure ledger is append-only JSONL kept outside
-- Postgres; one entry per completed erasure, Ed25519-signed by a ledger key that never enters
-- the database (SIBYL_LEDGER_SIGNING_KEY_FILE; sibyl_control.migrate.ledger writes it):
--   {"seq": n, "prev_hash": hex, "tenant_id": uuid, "scope_kind": "tenant"|"agent"|"subject",
--    "scope_ref": text|null, "erasure_request_id": uuid, "key_ids": [uuid...],
--    "completed_at": rfc3339, "subject_set": {agent_ids, window_from, window_to}|null,
--    "sig": base64url(Ed25519(JCS(entry without "sig")))}
-- entry_hash = hex(sha256(JCS(entry))), prev_hash of the next entry = entry_hash, genesis
-- prev_hash is 64 zeros, seq starts at 0 and is gapless. A signed head {count, head_hash, at,
-- sig} sits alongside. Signatures are checked outside Postgres by
-- `python -m sibyl_control.migrate ledger-verify` (restore.sh runs it first); the database
-- re-checks the chain and that the ledger reaches the head the backup manifest recorded
-- (expected_count entries, entry expected_count-1 hashing to expected_head). A later, longer
-- ledger is the normal case: erasures completed after the backup are exactly what R63
-- re-applies. Any break raises SB061 and applies nothing. Re-application is idempotent.
SET LOCAL ROLE sibyl_audit;

CREATE FUNCTION sibyl.erasure_ledger_verify(p_ledger_jsonl text, p_expected_count integer, p_expected_head text)
RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_line text;
  v_entry jsonb;
  v_entries jsonb := '[]';
  v_zero text := repeat('0', 64);
  v_prev text := repeat('0', 64);
  v_head_at_expected text;
  v_count integer := 0;
  v_seq bigint;
  v_hash text;
BEGIN
  IF p_expected_count IS NULL OR p_expected_count < 0 OR coalesce(p_expected_head, '') !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'sibyl:ledger_invalid: an expected ledger head (count and 64-hex hash) is required' USING ERRCODE = 'SB061';
  END IF;
  FOR v_line IN SELECT l FROM regexp_split_to_table(coalesce(p_ledger_jsonl, ''), E'\n') WITH ORDINALITY AS s(l, n)
                 WHERE btrim(l) <> '' ORDER BY n LOOP
    BEGIN
      v_entry := v_line::jsonb;
      v_seq := (v_entry->>'seq')::bigint;
      v_hash := encode(sha256(convert_to(sibyl.jcs(v_entry), 'UTF8')), 'hex');
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'sibyl:ledger_invalid: erasure ledger entry % is not a canonical JSON object with an integer seq', v_count
        USING ERRCODE = 'SB061';
    END;
    IF jsonb_typeof(v_entry) <> 'object'
       OR NOT (v_entry ?& ARRAY['seq', 'prev_hash', 'tenant_id', 'scope_kind', 'scope_ref', 'erasure_request_id',
                                'key_ids', 'completed_at', 'subject_set', 'sig'])
       OR jsonb_typeof(v_entry->'sig') <> 'string' OR (v_entry->>'sig') !~ '^[A-Za-z0-9_-]{86}$'
       OR jsonb_typeof(v_entry->'key_ids') <> 'array'
       OR (v_entry->>'scope_kind') NOT IN ('tenant', 'agent', 'subject')
       OR ((v_entry->>'scope_kind') = 'subject') <> (jsonb_typeof(v_entry->'subject_set') = 'object')
       OR (v_entry->>'tenant_id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR (v_entry->>'erasure_request_id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
      RAISE EXCEPTION 'sibyl:ledger_invalid: erasure ledger entry % is malformed', v_count USING ERRCODE = 'SB061';
    END IF;
    IF v_seq <> v_count OR v_entry->>'prev_hash' <> v_prev THEN
      RAISE EXCEPTION 'sibyl:ledger_invalid: erasure ledger chain broken at seq %', v_count USING ERRCODE = 'SB061';
    END IF;
    v_entries := v_entries || jsonb_build_array(v_entry);
    v_prev := v_hash;
    v_count := v_count + 1;
    IF v_count = p_expected_count THEN
      v_head_at_expected := v_hash;
    END IF;
  END LOOP;
  IF v_count < p_expected_count THEN
    RAISE EXCEPTION 'sibyl:ledger_invalid: erasure ledger has % entries, the backup expects at least %', v_count, p_expected_count
      USING ERRCODE = 'SB061';
  END IF;
  IF coalesce(v_head_at_expected, v_zero) <> p_expected_head THEN
    RAISE EXCEPTION 'sibyl:ledger_invalid: erasure ledger does not reach the expected head at entry %', p_expected_count
      USING ERRCODE = 'SB061';
  END IF;
  RETURN v_entries;
END
$$;

CREATE FUNCTION sibyl.erasure_reapply_from_ledger(ledger_jsonl text, expected_count integer, expected_head_hash text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_entry jsonb;
  v_tenant uuid;
  v_request uuid;
  v_scope text;
  v_affected jsonb;
  v_state text;
  v_applied integer := 0;
  v_prev_trigger text := current_setting('app.transition_trigger', true);
  v_prev_tenant text := current_setting('app.tenant_id', true);
BEGIN
  FOR v_entry IN SELECT e FROM jsonb_array_elements(
                   sibyl.erasure_ledger_verify(ledger_jsonl, expected_count, expected_head_hash)) AS e LOOP
    v_tenant := (v_entry->>'tenant_id')::uuid;
    v_request := (v_entry->>'erasure_request_id')::uuid;
    v_scope := v_entry->>'scope_kind';
    CONTINUE WHEN NOT EXISTS (SELECT 1 FROM sibyl.tenant WHERE id = v_tenant);
    PERFORM set_config('app.tenant_id', v_tenant::text, true);
    IF v_scope = 'tenant' THEN
      PERFORM sibyl.erasure_reshred_restored(v_tenant, v_request, 'ledger:' || (v_entry->>'seq'));
    ELSE
      v_affected := CASE WHEN v_scope = 'subject' THEN jsonb_build_object('subject_set', v_entry->'subject_set') END;
      SELECT state INTO v_state FROM sibyl.erasure_request WHERE tenant_id = v_tenant AND id = v_request;
      IF NOT FOUND THEN
        INSERT INTO sibyl.erasure_request (tenant_id, id, scope_kind, scope_ref, legal_basis, state, origin,
                                           affected_objects, execution_log)
        VALUES (v_tenant, v_request, v_scope, v_entry->>'scope_ref', 'other', 'executing', 'restore', v_affected,
                jsonb_build_array(jsonb_build_object('step', 'restore_reapply', 'ledger_seq', (v_entry->>'seq')::bigint)));
      ELSE
        PERFORM set_config('app.transition_trigger', 'restore', true);
        UPDATE sibyl.erasure_request
           SET state = 'executing', origin = 'restore', affected_objects = coalesce(v_affected, affected_objects)
         WHERE tenant_id = v_tenant AND id = v_request;
      END IF;
    END IF;
    PERFORM sibyl.erasure_execute_phase_internal(v_request, 'objects_deleted', true);
    PERFORM sibyl.erasure_execute_phase_internal(v_request, 'derived_purged', true);
    PERFORM set_config('app.transition_trigger', 'restore', true);
    UPDATE sibyl.erasure_request
       SET state = 'completed', completed_at = coalesce(completed_at, (v_entry->>'completed_at')::timestamptz),
           execution_log = execution_log || jsonb_build_array(jsonb_build_object(
             'step', 'reapplied_from_ledger', 'ledger_seq', (v_entry->>'seq')::bigint))
     WHERE tenant_id = v_tenant AND id = v_request;
    IF v_scope = 'tenant' THEN
      UPDATE sibyl.tenant SET status = 'erased', name = NULL, region_declared = NULL,
                              unknown_agent_fail_mode = NULL, parent_tenant_id = NULL
       WHERE id = v_tenant;
    END IF;
    PERFORM set_config('app.transition_trigger', coalesce(v_prev_trigger, ''), true);
    v_applied := v_applied + 1;
  END LOOP;
  -- leave the caller's tenant context as it was (code review L6)
  PERFORM set_config('app.tenant_id', coalesce(v_prev_tenant, ''), true);
  RETURN v_applied;
END
$$;

GRANT EXECUTE ON FUNCTION sibyl.erasure_ledger_verify(text, integer, text) TO sibyl_migrate, sibyl_worker, sibyl_app;
GRANT EXECUTE ON FUNCTION sibyl.erasure_reapply_from_ledger(text, integer, text) TO sibyl_migrate;

RESET ROLE;
