-- 0008 routing & failover (DATAMODEL §4.4; R1, R38, R40, D13, D21, D22, R36).
-- routing_state and routing_transition are owned by the NOLOGIN sibyl_routing and written
-- only by routing_apply().

CREATE TABLE sibyl.fallback_chain (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id              uuid        NOT NULL,
  version_no            integer     NOT NULL,
  status                text        NOT NULL DEFAULT 'draft',
  requested_by_user_id  uuid        NOT NULL,
  approved_by_user_id   uuid,
  approved_at           timestamptz,
  retired_at            timestamptz,
  note                  text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_fallback_chain_version UNIQUE (tenant_id, agent_id, version_no),
  CONSTRAINT fk_fallback_chain_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_fallback_chain_requested_by FOREIGN KEY (tenant_id, requested_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_fallback_chain_approved_by FOREIGN KEY (tenant_id, approved_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_fallback_chain_status CHECK (status IN ('draft', 'approved', 'retired')),
  CONSTRAINT ck_fallback_chain_approved CHECK (
    status = 'draft' OR (approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL)),
  CONSTRAINT ck_fallback_chain_retired CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX ux_fallback_chain_approved ON sibyl.fallback_chain (tenant_id, agent_id) WHERE status = 'approved';

CREATE TABLE sibyl.fallback_step (
  tenant_id        uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id               uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  chain_id         uuid        NOT NULL,
  position         smallint    NOT NULL,
  kind             text        NOT NULL,
  provider_id      uuid,
  model_id         uuid,
  backup_agent_id  uuid,
  credential_id    uuid,
  risk             text        NOT NULL DEFAULT 'low',
  max_attempts     smallint    NOT NULL DEFAULT 1,
  params           jsonb       NOT NULL DEFAULT '{}',
  target_erased    boolean     NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_fallback_step_position UNIQUE (tenant_id, chain_id, position),
  CONSTRAINT fk_fallback_step_chain FOREIGN KEY (tenant_id, chain_id)
    REFERENCES sibyl.fallback_chain (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_fallback_step_provider FOREIGN KEY (tenant_id, provider_id)
    REFERENCES sibyl.provider (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_fallback_step_model FOREIGN KEY (tenant_id, model_id)
    REFERENCES sibyl.model (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_fallback_step_backup_agent FOREIGN KEY (tenant_id, backup_agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_fallback_step_credential FOREIGN KEY (tenant_id, credential_id)
    REFERENCES sibyl.provider_credential (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_fallback_step_kind CHECK (kind IN ('retry', 'alt_model_same_provider', 'alt_provider',
                                                   'backup_agent', 'degraded_safe_mode', 'human_queue')),
  CONSTRAINT ck_fallback_step_risk CHECK (risk IN ('low', 'medium', 'high')),
  CONSTRAINT ck_fallback_step_attempts CHECK (max_attempts BETWEEN 1 AND 10),
  CONSTRAINT ck_fallback_step_position CHECK (position >= 0),
  CONSTRAINT ck_fallback_step_alt_provider CHECK (kind <> 'alt_provider' OR provider_id IS NOT NULL),
  CONSTRAINT ck_fallback_step_alt_model CHECK (kind <> 'alt_model_same_provider' OR model_id IS NOT NULL),
  -- G0-7: a backup_agent step whose agent was erased keeps a tombstone (FK nulled).
  CONSTRAINT ck_fallback_step_backup_agent CHECK (
    (kind = 'backup_agent') = (backup_agent_id IS NOT NULL OR target_erased)),
  CONSTRAINT ck_fallback_step_tombstone CHECK (
    NOT target_erased OR (kind = 'backup_agent' AND backup_agent_id IS NULL))
);

CREATE TABLE sibyl.continuity_plan (
  tenant_id                uuid          NOT NULL REFERENCES sibyl.tenant (id),
  id                       uuid          NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id                 uuid          NOT NULL,
  rto_s                    integer       NOT NULL,
  rpo_s                    integer       NOT NULL,
  credential_mode          text          NOT NULL DEFAULT 'passthrough',
  degraded_mode            text          NOT NULL DEFAULT 'safe_no_tools',
  inline_fallback          boolean       NOT NULL,
  preemptive_mode          text          NOT NULL,
  approval_timeout_s       integer       NOT NULL DEFAULT 600,
  approval_timeout_policy  text          NOT NULL DEFAULT 'hold',
  fallback_chain_id        uuid,
  on_call_user_id          uuid,
  on_call_ref              text,
  budget_usd_month         numeric(12,4),
  max_inflight             integer,
  rps_limit                numeric(8,2),
  drill_schedule           text,
  last_drill_at            timestamptz,
  next_drill_at            timestamptz,
  approved_by_user_id      uuid,
  approved_at              timestamptz,
  expected_cadence_s       integer,
  row_version              integer       NOT NULL DEFAULT 1,
  created_at               timestamptz   NOT NULL DEFAULT now(),
  updated_at               timestamptz   NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_continuity_plan_agent UNIQUE (tenant_id, agent_id),
  CONSTRAINT fk_continuity_plan_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_continuity_plan_chain FOREIGN KEY (tenant_id, fallback_chain_id)
    REFERENCES sibyl.fallback_chain (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_continuity_plan_on_call FOREIGN KEY (tenant_id, on_call_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_continuity_plan_approved_by FOREIGN KEY (tenant_id, approved_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_continuity_plan_rto CHECK (rto_s > 0 AND rpo_s > 0),
  CONSTRAINT ck_continuity_plan_credential_mode CHECK (credential_mode IN ('passthrough', 'vaulted_fallback')),
  CONSTRAINT ck_continuity_plan_degraded_mode CHECK (degraded_mode IN ('continue', 'safe_no_tools', 'queue_only')),
  CONSTRAINT ck_continuity_plan_preemptive_mode CHECK (preemptive_mode IN ('auto', 'degrade_then_auto', 'approval')),
  CONSTRAINT ck_continuity_plan_timeout_policy CHECK (approval_timeout_policy IN ('hold', 'fail_safe')),
  CONSTRAINT ck_continuity_plan_timeout CHECK (approval_timeout_s > 0),
  -- R9 heartbeat (INT-1): the cadence the caller declares; NULL means no heartbeat rule.
  CONSTRAINT ck_continuity_plan_cadence CHECK (expected_cadence_s IS NULL OR expected_cadence_s > 0)
);

-- Tier defaults (D23/R38 RTO/RPO, R40 preemptive_mode, inline fallback off on tier 1) and the
-- plan invariants: approved chain of the same agent; tier-1 inline fallback needs an approver.
CREATE FUNCTION sibyl.trg_continuity_plan_rules() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_tier smallint;
BEGIN
  SELECT tier INTO v_tier FROM sibyl.agent WHERE tenant_id = NEW.tenant_id AND id = NEW.agent_id;
  IF TG_OP = 'INSERT' THEN
    NEW.rto_s := coalesce(NEW.rto_s, CASE v_tier WHEN 1 THEN 900 WHEN 2 THEN 3600 ELSE 14400 END);
    NEW.rpo_s := coalesce(NEW.rpo_s, CASE v_tier WHEN 1 THEN 60 WHEN 2 THEN 300 ELSE 900 END);
    NEW.preemptive_mode := coalesce(NEW.preemptive_mode,
      CASE v_tier WHEN 1 THEN 'approval' WHEN 2 THEN 'degrade_then_auto' ELSE 'auto' END);
    NEW.inline_fallback := coalesce(NEW.inline_fallback, v_tier <> 1);
  END IF;
  IF NEW.fallback_chain_id IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM sibyl.fallback_chain c
        WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.fallback_chain_id
          AND c.agent_id = NEW.agent_id AND c.status = 'approved') THEN
    RAISE EXCEPTION 'sibyl:continuity_plan_invalid: continuity_plan.fallback_chain_id must reference an approved chain of the same agent'
      USING ERRCODE = 'SB048';
  END IF;
  IF v_tier = 1 AND NEW.inline_fallback AND NEW.approved_by_user_id IS NULL THEN
    RAISE EXCEPTION 'sibyl:continuity_plan_invalid: tier-1 inline fallback requires an approver' USING ERRCODE = 'SB048';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_continuity_plan_rules BEFORE INSERT OR UPDATE ON sibyl.continuity_plan
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_continuity_plan_rules();

CREATE FUNCTION sibyl.fallback_kind_rank(p_kind text) RETURNS smallint
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT array_position(ARRAY['retry', 'alt_model_same_provider', 'alt_provider', 'backup_agent',
                              'degraded_safe_mode', 'human_queue'], p_kind)::smallint - 1
$$;

-- Chain shape (deferred so a multi-row reorder can pass): kind rank non-decreasing by
-- position, nothing after human_queue, backup agent is not the chain's own agent, vaulted
-- credential present when the plan says vaulted_fallback, approved chains frozen.
CREATE FUNCTION sibyl.trg_fallback_step_rules() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_row sibyl.fallback_step%ROWTYPE := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  v_chain record;
  v_bad integer;
BEGIN
  SELECT c.agent_id, c.status INTO v_chain FROM sibyl.fallback_chain c
   WHERE c.tenant_id = v_row.tenant_id AND c.id = v_row.chain_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN NULL;
  END IF;
  IF v_row.backup_agent_id IS NOT NULL AND v_row.backup_agent_id = v_chain.agent_id THEN
    RAISE EXCEPTION 'sibyl:fallback_chain_invalid: backup_agent_id must differ from the chain agent' USING ERRCODE = 'SB040';
  END IF;
  IF v_row.kind = 'alt_provider' AND v_row.credential_id IS NULL AND EXISTS (
       SELECT 1 FROM sibyl.continuity_plan p WHERE p.tenant_id = v_row.tenant_id
          AND p.agent_id = v_chain.agent_id AND p.credential_mode = 'vaulted_fallback') THEN
    RAISE EXCEPTION 'sibyl:fallback_chain_invalid: alt_provider step needs credential_id under vaulted_fallback' USING ERRCODE = 'SB040';
  END IF;
  SELECT count(*) INTO v_bad FROM (
    SELECT kind, lag(kind) OVER (ORDER BY position) AS prev_kind
      FROM sibyl.fallback_step WHERE tenant_id = v_row.tenant_id AND chain_id = v_row.chain_id) s
   WHERE s.prev_kind IS NOT NULL
     AND (sibyl.fallback_kind_rank(s.kind) < sibyl.fallback_kind_rank(s.prev_kind) OR s.prev_kind = 'human_queue');
  IF v_bad > 0 THEN
    RAISE EXCEPTION 'sibyl:fallback_chain_invalid: fallback steps must be non-decreasing by kind rank and end at human_queue'
      USING ERRCODE = 'SB040';
  END IF;
  RETURN NULL;
END
$$;
-- Steps change only while their chain is a draft (immediate; erasure excepted).
CREATE FUNCTION sibyl.trg_fallback_step_frozen() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_row sibyl.fallback_step%ROWTYPE := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  v_status text;
BEGIN
  SELECT status INTO v_status FROM sibyl.fallback_chain WHERE tenant_id = v_row.tenant_id AND id = v_row.chain_id;
  IF v_status IS DISTINCT FROM 'draft' AND NOT sibyl.erasure_delete_allowed(v_row.tenant_id) THEN
    RAISE EXCEPTION 'sibyl:fallback_chain_invalid: steps of a % chain are immutable', v_status USING ERRCODE = 'SB040';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;
CREATE TRIGGER trg_fallback_step_frozen BEFORE INSERT OR UPDATE OR DELETE ON sibyl.fallback_step
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_fallback_step_frozen();
CREATE CONSTRAINT TRIGGER trg_fallback_step_rules AFTER INSERT OR UPDATE OR DELETE ON sibyl.fallback_step
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sibyl.trg_fallback_step_rules();

-- Four-eyes for tier 1 (requester != approver), approved chains immutable except retirement.
CREATE FUNCTION sibyl.trg_fallback_chain_rules() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_tier smallint;
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.status <> 'draft' AND NOT sibyl.erasure_delete_allowed(OLD.tenant_id) THEN
      RAISE EXCEPTION 'sibyl:fallback_chain_invalid: only draft chains can be deleted' USING ERRCODE = 'SB040';
    END IF;
    RETURN OLD;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.status = 'retired' THEN
    RAISE EXCEPTION 'sibyl:fallback_chain_invalid: a retired chain is immutable' USING ERRCODE = 'SB040';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.status = 'approved'
     AND NOT (NEW.status = 'retired'
              AND (to_jsonb(OLD) - 'status' - 'retired_at' - 'updated_at')
                = (to_jsonb(NEW) - 'status' - 'retired_at' - 'updated_at')) THEN
    RAISE EXCEPTION 'sibyl:fallback_chain_invalid: an approved chain is immutable; create a new draft version' USING ERRCODE = 'SB040';
  END IF;
  IF NEW.status = 'approved' AND (TG_OP = 'INSERT' OR OLD.status = 'draft') THEN
    IF EXISTS (SELECT 1 FROM sibyl.fallback_step st
                WHERE st.tenant_id = NEW.tenant_id AND st.chain_id = NEW.id AND st.target_erased) THEN
      RAISE EXCEPTION 'sibyl:fallback_chain_invalid: chain % names an erased backup agent; replace the step', NEW.id
        USING ERRCODE = 'SB040';
    END IF;
    SELECT tier INTO v_tier FROM sibyl.agent WHERE tenant_id = NEW.tenant_id AND id = NEW.agent_id;
    IF v_tier = 1 AND NEW.approved_by_user_id = NEW.requested_by_user_id THEN
      RAISE EXCEPTION 'sibyl:self_approval: tier-1 chains need a second approver' USING ERRCODE = 'SB041';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_fallback_chain_rules BEFORE INSERT OR UPDATE OR DELETE ON sibyl.fallback_chain
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_fallback_chain_rules();

CREATE TABLE sibyl.failover (
  tenant_id                uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                       uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id                 uuid        NOT NULL,
  kind                     text        NOT NULL,
  state                    text        NOT NULL DEFAULT 'pending',
  step                     text        NOT NULL DEFAULT 'validate',
  attempt                  integer     NOT NULL DEFAULT 0,
  max_attempts             integer     NOT NULL DEFAULT 5,
  next_action_at           timestamptz NOT NULL DEFAULT now(),
  claimed_by               text,
  claim_lock_until         timestamptz,
  priority                 text        NOT NULL DEFAULT 'normal',
  idempotency_key          text        NOT NULL,
  request_idempotency_key  text,
  trigger_alert_id         uuid,
  rule_codes               text[]      NOT NULL DEFAULT '{}',
  health_snapshot_id       uuid,
  actor_kind               text        NOT NULL,
  actor_key_id             uuid,
  requested_by_user_id     uuid,
  approval_id              uuid,
  from_state               text        NOT NULL,
  to_state                 text,
  chosen_step_id           uuid,
  undo_plan                jsonb       NOT NULL DEFAULT '{}',
  step_results             jsonb       NOT NULL DEFAULT '{}',
  routing_transition_id    uuid,
  kill_switch_id           uuid,  -- lane S: the kill switch a `kill` saga applies
  cancel_requested         boolean     NOT NULL DEFAULT false,
  error                    text,
  finished_at              timestamptz,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_failover_idempotency UNIQUE (tenant_id, idempotency_key),
  CONSTRAINT fk_failover_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_failover_requested_by FOREIGN KEY (tenant_id, requested_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_failover_chosen_step FOREIGN KEY (tenant_id, chosen_step_id)
    REFERENCES sibyl.fallback_step (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_failover_kind CHECK (kind IN ('failover', 'preemptive', 'failback', 'undo', 'quarantine', 'release',
                                              'kill', 'degrade', 'recover', 'drill')),
  CONSTRAINT ck_failover_state CHECK (state IN ('pending', 'running', 'waiting_approval', 'done', 'cancelled', 'failed')),
  CONSTRAINT ck_failover_step CHECK (step IN ('validate', 'check_viability', 'write_routing', 'create_handoff_tasks',
                                              'mark_alert_actioned', 'done')),
  CONSTRAINT ck_failover_priority CHECK (priority IN ('immediate', 'normal')),
  CONSTRAINT ck_failover_actor_kind CHECK (actor_kind IN ('human', 'rule', 'policy', 'system', 'api_key')),
  -- G0-6: an API-key actor (break-glass or gateway key) is recorded with its key id. Loose
  -- reference, like audit_events.actor_key_id: the key may later be erased with its agent.
  CONSTRAINT ck_failover_actor_key CHECK ((actor_kind = 'api_key') = (actor_key_id IS NOT NULL)),
  CONSTRAINT ck_failover_claimed CHECK (state <> 'running' OR claimed_by IS NOT NULL),
  CONSTRAINT ck_failover_attempts CHECK (attempt >= 0 AND attempt <= max_attempts)
);
CREATE INDEX ix_failover_claim ON sibyl.failover (tenant_id, next_action_at) WHERE state IN ('pending', 'running');
CREATE UNIQUE INDEX ux_failover_live ON sibyl.failover (tenant_id, agent_id)
  WHERE state IN ('pending', 'running', 'waiting_approval');
CREATE INDEX ix_failover_state ON sibyl.failover (tenant_id, state, created_at DESC);
CREATE TRIGGER trg_failover_state_edge BEFORE UPDATE OF state ON sibyl.failover
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('failover', 'state');

CREATE TABLE sibyl.approval (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  failover_id           uuid        NOT NULL,
  agent_id              uuid        NOT NULL,
  requested_action      text        NOT NULL,
  risk                  text        NOT NULL,
  tier                  smallint    NOT NULL,
  requested_by_kind     text        NOT NULL,
  requested_by_rule_id  uuid,
  requested_by_user_id  uuid,
  alert_id              uuid,
  health_snapshot_id    uuid,
  evidence              jsonb       NOT NULL DEFAULT '{}',
  expires_at            timestamptz NOT NULL,
  timeout_policy        text        NOT NULL,
  state                 text        NOT NULL DEFAULT 'pending',
  decided_by_user_id    uuid,
  decided_at            timestamptz,
  decision_reason       text,
  resolved_by_timeout   boolean     NOT NULL DEFAULT false,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_approval_failover FOREIGN KEY (tenant_id, failover_id)
    REFERENCES sibyl.failover (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_approval_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_approval_requested_by FOREIGN KEY (tenant_id, requested_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_approval_decided_by FOREIGN KEY (tenant_id, decided_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_approval_requested_action CHECK (requested_action IN ('alt_provider_failover', 'backup_agent_failover',
    'preemptive_failover', 'quarantine', 'inline_fallback_enable')),
  CONSTRAINT ck_approval_risk CHECK (risk IN ('low', 'medium', 'high')),
  CONSTRAINT ck_approval_tier CHECK (tier BETWEEN 1 AND 3),
  CONSTRAINT ck_approval_requested_by_kind CHECK (requested_by_kind IN ('rule', 'human')),
  CONSTRAINT ck_approval_requester CHECK (
    (requested_by_kind = 'human') = (requested_by_user_id IS NOT NULL)),
  CONSTRAINT ck_approval_timeout_policy CHECK (timeout_policy IN ('hold', 'fail_safe')),
  CONSTRAINT ck_approval_state CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'cancelled')),
  CONSTRAINT ck_approval_decided CHECK (
    (state NOT IN ('approved', 'denied') OR (decided_at IS NOT NULL AND decided_by_user_id IS NOT NULL))
    AND (state <> 'expired' OR resolved_by_timeout)),
  CONSTRAINT ck_approval_evidence CHECK (pg_column_size(evidence) <= 8192)
);
CREATE UNIQUE INDEX ux_approval_pending ON sibyl.approval (tenant_id, failover_id) WHERE state = 'pending';
CREATE INDEX ix_approval_expiry ON sibyl.approval (tenant_id, state, expires_at);
CREATE INDEX ix_approval_agent ON sibyl.approval (tenant_id, agent_id, created_at DESC);
CREATE TRIGGER trg_approval_state_edge BEFORE UPDATE OF state ON sibyl.approval
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('approval', 'state');

ALTER TABLE sibyl.failover ADD CONSTRAINT fk_failover_approval FOREIGN KEY (tenant_id, approval_id)
  REFERENCES sibyl.approval (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

-- Requester != decider (R36 / API §6.4 self_approval); shared by approval, erasure_request.
CREATE FUNCTION sibyl.trg_requester_not_approver() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_req uuid := (to_jsonb(NEW)->>TG_ARGV[0])::uuid;
  v_dec uuid := (to_jsonb(NEW)->>TG_ARGV[1])::uuid;
BEGIN
  IF v_req IS NOT NULL AND v_dec IS NOT NULL AND v_req = v_dec THEN
    RAISE EXCEPTION 'sibyl:self_approval: requester and approver must differ (%)', TG_TABLE_NAME USING ERRCODE = 'SB041';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_approval_requester_not_approver BEFORE INSERT OR UPDATE ON sibyl.approval
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_requester_not_approver('requested_by_user_id', 'decided_by_user_id');

-- D22 layer (b): tier-1 agents with PII/residency exposure never fail safe without a human.
CREATE FUNCTION sibyl.trg_approval_fail_safe_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tier = 1 AND NEW.timeout_policy = 'fail_safe' AND sibyl.agent_pii_exposed(NEW.tenant_id, NEW.agent_id) THEN
    NEW.timeout_policy := 'hold';
    NEW.evidence := NEW.evidence || jsonb_build_object('timeout_policy_applied', 'hold_forced_d22');
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_approval_fail_safe_guard BEFORE INSERT ON sibyl.approval
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_approval_fail_safe_guard();

CREATE TABLE sibyl.kill_switch (
  tenant_id                uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                       uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  scope_kind               text        NOT NULL,
  scope_id                 uuid,
  state                    text        NOT NULL DEFAULT 'pulled',
  reason                   text        NOT NULL,
  pulled_by                uuid,
  pulled_by_key_id         uuid,
  pulled_at                timestamptz NOT NULL DEFAULT now(),
  step_up_session_id       uuid,
  routing_version_at_pull  bigint      NOT NULL,
  released_by              uuid,
  released_at              timestamptz,
  release_reason           text,
  release_session_id       uuid,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_kill_switch_pulled_by FOREIGN KEY (tenant_id, pulled_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_kill_switch_key FOREIGN KEY (tenant_id, pulled_by_key_id)
    REFERENCES sibyl.api_key (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_kill_switch_session FOREIGN KEY (tenant_id, step_up_session_id)
    REFERENCES sibyl.session (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_kill_switch_released_by FOREIGN KEY (tenant_id, released_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_kill_switch_release_session FOREIGN KEY (tenant_id, release_session_id)
    REFERENCES sibyl.session (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_kill_switch_scope_kind CHECK (scope_kind IN ('tenant', 'agent', 'provider')),
  CONSTRAINT ck_kill_switch_scope_id CHECK ((scope_kind = 'tenant') = (scope_id IS NULL)),
  CONSTRAINT ck_kill_switch_state CHECK (state IN ('pulled', 'released')),
  CONSTRAINT ck_kill_switch_puller CHECK (
    (pulled_by IS NOT NULL AND step_up_session_id IS NOT NULL) OR pulled_by_key_id IS NOT NULL),
  CONSTRAINT ck_kill_switch_released CHECK (
    (state = 'released') = (released_at IS NOT NULL AND released_by IS NOT NULL AND release_session_id IS NOT NULL))
);
CREATE UNIQUE INDEX ux_kill_switch_pulled ON sibyl.kill_switch
  (tenant_id, scope_kind, coalesce(scope_id, sibyl.nil_uuid())) WHERE state = 'pulled';
CREATE TRIGGER trg_kill_switch_state_edge BEFORE UPDATE OF state ON sibyl.kill_switch
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('kill_switch', 'state');
-- lane S: a `kill` saga names its kill switch (was step_results->>'kill_switch_id').
ALTER TABLE sibyl.failover ADD CONSTRAINT fk_failover_kill_switch FOREIGN KEY (tenant_id, kill_switch_id)
  REFERENCES sibyl.kill_switch (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;
CREATE INDEX ix_failover_kill_switch ON sibyl.failover (tenant_id, kill_switch_id)
  WHERE kill_switch_id IS NOT NULL;

CREATE TABLE sibyl.kill_switch_ack (
  tenant_id         uuid        NOT NULL REFERENCES sibyl.tenant (id),
  kill_switch_id    uuid        NOT NULL,
  gateway_id        text        NOT NULL,
  snapshot_version  bigint      NOT NULL,
  applied_at        timestamptz NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, kill_switch_id, gateway_id, snapshot_version),
  CONSTRAINT fk_kill_switch_ack_switch FOREIGN KEY (tenant_id, kill_switch_id)
    REFERENCES sibyl.kill_switch (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE
);
CREATE TRIGGER trg_kill_switch_ack_immutable BEFORE UPDATE OR DELETE ON sibyl.kill_switch_ack
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_kill_switch_ack_no_truncate BEFORE TRUNCATE ON sibyl.kill_switch_ack
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['fallback_chain', 'fallback_step', 'continuity_plan', 'failover', 'approval',
                           'kill_switch', 'kill_switch_ack'] LOOP
    PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', t)::regclass);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['fallback_chain', 'fallback_step', 'continuity_plan', 'failover', 'approval',
                           'kill_switch'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON sibyl.%I FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at()',
                   'trg_' || t || '_updated_at', t);
  END LOOP;
END
$$;

-- Privileges the NOLOGIN routing owner needs for its tables, FKs and routing_apply().
GRANT REFERENCES ON sibyl.tenant, sibyl.agent, sibyl.app_user, sibyl.fallback_step, sibyl.approval,
  sibyl.failover TO sibyl_routing;
GRANT SELECT ON sibyl.agent, sibyl.failover, sibyl.approval, sibyl.fallback_step TO sibyl_routing;

SET LOCAL ROLE sibyl_routing;

CREATE TABLE sibyl.routing_transition (
  tenant_id            uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                   uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id             uuid        NOT NULL,
  failover_id          uuid,
  from_state           text,
  to_state             text        NOT NULL,
  from_target          jsonb       NOT NULL,
  to_target            jsonb       NOT NULL,
  trigger              text        NOT NULL,
  actor_kind           text        NOT NULL,
  actor_user_id        uuid,
  actor_rule_id        uuid,
  actor_key_id         uuid,
  rule_codes           text[]      NOT NULL DEFAULT '{}',
  alert_ids            uuid[]      NOT NULL DEFAULT '{}',
  health_snapshot_id   uuid,
  approval_id          uuid,
  inverse_of           uuid,
  operator_hold_until  timestamptz,
  routing_version      bigint      NOT NULL,
  reason               text,
  audit_seq            bigint      NOT NULL,
  idempotency_key      text        NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_routing_transition_version UNIQUE (tenant_id, routing_version),
  CONSTRAINT uq_routing_transition_idempotency UNIQUE (tenant_id, idempotency_key),
  CONSTRAINT fk_routing_transition_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_routing_transition_failover FOREIGN KEY (tenant_id, failover_id)
    REFERENCES sibyl.failover (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_routing_transition_actor FOREIGN KEY (tenant_id, actor_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_routing_transition_approval FOREIGN KEY (tenant_id, approval_id)
    REFERENCES sibyl.approval (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_routing_transition_inverse FOREIGN KEY (tenant_id, inverse_of)
    REFERENCES sibyl.routing_transition (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_routing_transition_states CHECK (
    (from_state IS NULL OR from_state IN ('active', 'degraded', 'awaiting_approval', 'failed_over', 'failing_back',
                                          'quarantined', 'killed'))
    AND to_state IN ('active', 'degraded', 'awaiting_approval', 'failed_over', 'failing_back', 'quarantined', 'killed')),
  CONSTRAINT ck_routing_transition_trigger CHECK (trigger IN ('register', 'rule', 'approval', 'approval_timeout',
    'operator', 'policy', 'failback_probe', 'canary', 'undo', 'system')),
  CONSTRAINT ck_routing_transition_actor_kind CHECK (actor_kind IN ('human', 'rule', 'policy', 'system', 'api_key')),
  CONSTRAINT ck_routing_transition_key CHECK ((actor_kind = 'api_key') = (actor_key_id IS NOT NULL)),
  CONSTRAINT ck_routing_transition_human CHECK (
    actor_kind <> 'human' OR (actor_user_id IS NOT NULL AND coalesce(btrim(reason), '') <> '')),
  CONSTRAINT ck_routing_transition_register CHECK ((from_state IS NULL) = (trigger = 'register'))
);
CREATE INDEX ix_routing_transition_agent ON sibyl.routing_transition (tenant_id, agent_id, created_at DESC);
CREATE INDEX ix_routing_transition_created ON sibyl.routing_transition (tenant_id, created_at DESC);
CREATE UNIQUE INDEX ux_routing_transition_inverse ON sibyl.routing_transition (tenant_id, inverse_of)
  WHERE inverse_of IS NOT NULL;
SELECT sibyl.enable_tenant_rls('sibyl.routing_transition');
CREATE TRIGGER trg_routing_transition_state_edge BEFORE INSERT ON sibyl.routing_transition
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('routing', 'to_state');
CREATE TRIGGER trg_routing_transition_immutable BEFORE UPDATE OR DELETE ON sibyl.routing_transition
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_routing_transition_no_truncate BEFORE TRUNCATE ON sibyl.routing_transition
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();

CREATE TABLE sibyl.routing_state (
  tenant_id            uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                   uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id             uuid        NOT NULL,
  state                text        NOT NULL DEFAULT 'active',
  target_kind          text        NOT NULL DEFAULT 'primary',
  target_provider_id   uuid,
  target_model_id      uuid,
  target_agent_id      uuid,
  current_step_id      uuid,
  canary_pct           smallint    NOT NULL DEFAULT 100,
  routing_version      bigint      NOT NULL,
  last_transition_id   uuid,
  approval_id          uuid,
  operator_hold_until  timestamptz,
  state_since          timestamptz NOT NULL DEFAULT now(),
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_routing_state_agent UNIQUE (tenant_id, agent_id),
  CONSTRAINT fk_routing_state_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_routing_state_step FOREIGN KEY (tenant_id, current_step_id)
    REFERENCES sibyl.fallback_step (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_routing_state_transition FOREIGN KEY (tenant_id, last_transition_id)
    REFERENCES sibyl.routing_transition (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_routing_state_approval FOREIGN KEY (tenant_id, approval_id)
    REFERENCES sibyl.approval (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_routing_state_state CHECK (state IN ('active', 'degraded', 'awaiting_approval', 'failed_over',
                                                     'failing_back', 'quarantined', 'killed')),
  CONSTRAINT ck_routing_state_target_kind CHECK (target_kind IN ('primary', 'model', 'agent', 'human_queue')),
  CONSTRAINT ck_routing_state_canary_pct CHECK (canary_pct BETWEEN 0 AND 100),
  CONSTRAINT ck_routing_state_active CHECK (state <> 'active' OR target_kind = 'primary'),
  CONSTRAINT ck_routing_state_failed_over CHECK (state <> 'failed_over' OR target_kind <> 'primary'),
  CONSTRAINT ck_routing_state_awaiting CHECK (state <> 'awaiting_approval' OR approval_id IS NOT NULL),
  CONSTRAINT ck_routing_state_failing_back CHECK (state <> 'failing_back' OR canary_pct < 100)
);
CREATE INDEX ix_routing_state_state ON sibyl.routing_state (tenant_id, state);
CREATE INDEX ix_routing_state_hold ON sibyl.routing_state (tenant_id, operator_hold_until)
  WHERE operator_hold_until IS NOT NULL;
SELECT sibyl.enable_tenant_rls('sibyl.routing_state');
CREATE TRIGGER trg_routing_state_updated_at BEFORE UPDATE ON sibyl.routing_state
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

CREATE FUNCTION sibyl.routing_target(p_kind text, p_provider uuid, p_model uuid, p_agent uuid, p_step uuid)
RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object('kind', p_kind, 'provider_id', p_provider, 'model_id', p_model,
                            'agent_id', p_agent, 'step_id', p_step)
$$;

-- R1: the only writer of routing_state / routing_transition (DATAMODEL §5 signature).
-- Lock order (risk T5, G0 H2): audit lock (the tenant's audit_chain_head row) -> per-agent
-- routing lock -> routing_state row -> tenant row. Taking the audit lock first means a
-- transaction that already appended audit can call routing_apply without deadlocking against
-- a concurrent routing_apply; it also serialises idempotency-key use per tenant (G0 H1).
CREATE FUNCTION sibyl.routing_apply(
  p_tenant uuid, p_agent uuid, p_failover_id uuid, p_expected_from_state text, p_to_state text,
  p_to_target jsonb, p_trigger text, p_actor_kind text, p_actor_user_id uuid, p_actor_rule_id uuid,
  p_rule_codes text[], p_alert_ids uuid[], p_health_snapshot_id uuid, p_approval_id uuid, p_inverse_of uuid,
  p_operator_hold_until timestamptz, p_canary_pct smallint, p_reason text, p_idempotency_key text,
  p_audit_action text, p_audit_detail jsonb, p_audit_detail_canonical bytea, p_actor_session_id uuid,
  p_request_id uuid, p_actor_key_id uuid DEFAULT NULL
) RETURNS TABLE (transition_id uuid, routing_version bigint, audit_seq bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  rs sibyl.routing_state%ROWTYPE;
  v_from text;
  v_from_target jsonb;
  v_to_target jsonb;
  v_kind text;
  v_version bigint;
  v_tid uuid := sibyl.uuidv7();
  v_seq bigint;
  v_detail jsonb;
  v_hold timestamptz;
  v_canary smallint;
  v_existing record;
  v_constraint text;
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  IF p_idempotency_key IS NULL OR p_audit_action IS NULL THEN
    RAISE EXCEPTION 'sibyl:routing_arguments: routing_apply needs an idempotency key and an audit action' USING ERRCODE = 'SB014';
  END IF;
  -- G0: a break-glass kill is attributed to its API key (actor_kind api_key + key id), never system.
  IF (p_actor_kind = 'api_key') IS DISTINCT FROM (p_actor_key_id IS NOT NULL) THEN
    RAISE EXCEPTION 'sibyl:routing_arguments: actor_kind api_key needs p_actor_key_id, and only it' USING ERRCODE = 'SB014';
  END IF;
  PERFORM sibyl.audit_lock(p_tenant);
  PERFORM pg_advisory_xact_lock(hashtextextended('routing:' || p_agent::text, 0));

  SELECT * INTO rs FROM sibyl.routing_state s WHERE s.tenant_id = p_tenant AND s.agent_id = p_agent FOR UPDATE;
  -- G0 H1: a key replays only the same request (agent, target state, trigger).
  SELECT t.id, t.routing_version, t.audit_seq, t.agent_id, t.to_state, t.trigger INTO v_existing
    FROM sibyl.routing_transition t
   WHERE t.tenant_id = p_tenant AND t.idempotency_key = p_idempotency_key;
  IF FOUND THEN
    IF v_existing.agent_id <> p_agent OR v_existing.to_state <> p_to_state OR v_existing.trigger <> p_trigger THEN
      RAISE EXCEPTION 'sibyl:idempotency_key_reuse: idempotency key % was used for another routing request', p_idempotency_key
        USING ERRCODE = 'SB015';
    END IF;
    RETURN QUERY SELECT v_existing.id, v_existing.routing_version, v_existing.audit_seq;
    RETURN;
  END IF;

  IF rs.id IS NULL THEN
    v_from := NULL;
    v_from_target := sibyl.routing_target('primary', NULL, NULL, NULL, NULL);
  ELSE
    v_from := rs.state;
    v_from_target := sibyl.routing_target(rs.target_kind, rs.target_provider_id, rs.target_model_id,
                                          rs.target_agent_id, rs.current_step_id);
  END IF;
  IF v_from IS DISTINCT FROM p_expected_from_state THEN
    RAISE EXCEPTION 'sibyl:stale_precondition: expected %, found %', p_expected_from_state, v_from USING ERRCODE = 'SB011';
  END IF;
  -- D21: a hold after undo blocks rule/policy actors; humans, kill and system paths bypass.
  IF rs.operator_hold_until IS NOT NULL AND rs.operator_hold_until > now() AND p_actor_kind IN ('rule', 'policy') THEN
    RAISE EXCEPTION 'sibyl:operator_hold: until %', rs.operator_hold_until USING ERRCODE = 'SB012';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM sibyl.state_edge e WHERE e.machine = 'routing' AND e.from_state = coalesce(v_from, '')
                    AND e.to_state = p_to_state AND e.trigger = p_trigger) THEN
    RAISE EXCEPTION 'sibyl:invalid_transition: routing % -> % (trigger %)', coalesce(v_from, ''), p_to_state, p_trigger
      USING ERRCODE = 'SB010';
  END IF;
  IF p_actor_kind = 'human' AND (p_actor_user_id IS NULL OR coalesce(btrim(p_reason), '') = '') THEN
    RAISE EXCEPTION 'sibyl:reason_required: a human routing action needs an actor and a reason' USING ERRCODE = 'SB013';
  END IF;

  v_kind := CASE WHEN p_to_state = 'active' THEN 'primary'
                 ELSE coalesce(p_to_target->>'kind', v_from_target->>'kind') END;
  IF p_to_state = 'active' THEN
    v_to_target := sibyl.routing_target('primary', NULL, NULL, NULL, NULL);
  ELSIF p_to_target IS NULL OR p_to_target->>'kind' IS NULL THEN
    v_to_target := v_from_target;
  ELSE
    v_to_target := sibyl.routing_target(v_kind, (p_to_target->>'provider_id')::uuid, (p_to_target->>'model_id')::uuid,
                                        (p_to_target->>'agent_id')::uuid, (p_to_target->>'step_id')::uuid);
  END IF;
  v_hold := CASE WHEN p_operator_hold_until IS NOT NULL THEN p_operator_hold_until
                 WHEN p_trigger = 'operator' AND v_from = p_to_state THEN NULL
                 ELSE rs.operator_hold_until END;
  v_canary := CASE WHEN p_to_state = 'failing_back' THEN coalesce(p_canary_pct, rs.canary_pct, 10)
                   WHEN p_to_state IN ('active', 'failed_over') THEN 100
                   ELSE coalesce(p_canary_pct, rs.canary_pct, 100) END;
  IF p_to_state = 'failing_back' AND v_canary >= 100 THEN
    v_canary := 10;
  END IF;

  UPDATE sibyl.tenant t SET routing_version = t.routing_version + 1 WHERE t.id = p_tenant
    RETURNING t.routing_version INTO v_version;

  IF p_audit_detail IS NOT NULL AND p_audit_detail_canonical IS NOT NULL
     AND convert_from(p_audit_detail_canonical, 'UTF8')::jsonb IS DISTINCT FROM p_audit_detail THEN
    RAISE EXCEPTION 'sibyl:audit_canonical_mismatch: p_audit_detail_canonical does not encode p_audit_detail' USING ERRCODE = 'SB024';
  END IF;
  v_detail := jsonb_build_object('agent_id', p_agent, 'from_state', v_from, 'to_state', p_to_state,
                                 'from_target', v_from_target, 'to_target', v_to_target,
                                 'prev_target', v_from_target, 'new_target', v_to_target, 'trigger', p_trigger)
              || CASE WHEN p_audit_action = 'override.by_human'
                      THEN jsonb_build_object('automated_decision_overridden', NULL) ELSE '{}'::jsonb END
              || CASE WHEN p_inverse_of IS NOT NULL
                      THEN jsonb_build_object('undo_of_transition_id', p_inverse_of) ELSE '{}'::jsonb END
              || CASE WHEN p_operator_hold_until IS NOT NULL
                      THEN jsonb_build_object('operator_hold_until', sibyl.rfc3339(p_operator_hold_until))
                      ELSE '{}'::jsonb END
              || coalesce(p_audit_detail, '{}'::jsonb)
              || jsonb_build_object('transition_id', v_tid, 'routing_version', v_version);
  SELECT a.seq INTO v_seq FROM sibyl.audit_append(p_tenant, p_actor_kind, coalesce(p_actor_user_id, p_actor_rule_id),
    p_actor_key_id, p_actor_session_id, p_audit_action, 'agent', p_agent, NULL, p_reason, v_detail, NULL, now(),
    p_request_id) a;

  BEGIN
    INSERT INTO sibyl.routing_transition (tenant_id, id, agent_id, failover_id, from_state, to_state, from_target,
      to_target, trigger, actor_kind, actor_user_id, actor_rule_id, actor_key_id, rule_codes, alert_ids,
      health_snapshot_id, approval_id, inverse_of, operator_hold_until, routing_version, reason, audit_seq,
      idempotency_key)
    VALUES (p_tenant, v_tid, p_agent, p_failover_id, v_from, p_to_state, v_from_target, v_to_target, p_trigger,
      p_actor_kind, p_actor_user_id, p_actor_rule_id, p_actor_key_id, coalesce(p_rule_codes, '{}'),
      coalesce(p_alert_ids, '{}'),
      p_health_snapshot_id, p_approval_id, p_inverse_of, v_hold, v_version, p_reason, v_seq, p_idempotency_key);
  EXCEPTION WHEN unique_violation THEN
    -- Unreachable while the audit lock serialises the tenant; kept so a raw 23505 never leaks.
    GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
    IF v_constraint IS DISTINCT FROM 'uq_routing_transition_idempotency' THEN
      RAISE;
    END IF;
    RAISE EXCEPTION 'sibyl:idempotency_key_reuse: idempotency key % is already in use', p_idempotency_key
      USING ERRCODE = 'SB015';
  END;

  INSERT INTO sibyl.routing_state AS s (tenant_id, agent_id, state, target_kind, target_provider_id, target_model_id,
    target_agent_id, current_step_id, canary_pct, routing_version, last_transition_id, approval_id,
    operator_hold_until, state_since)
  VALUES (p_tenant, p_agent, p_to_state, v_to_target->>'kind', (v_to_target->>'provider_id')::uuid,
    (v_to_target->>'model_id')::uuid, (v_to_target->>'agent_id')::uuid, (v_to_target->>'step_id')::uuid, v_canary,
    v_version, v_tid, p_approval_id, v_hold, now())
  ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
    state = EXCLUDED.state, target_kind = EXCLUDED.target_kind, target_provider_id = EXCLUDED.target_provider_id,
    target_model_id = EXCLUDED.target_model_id, target_agent_id = EXCLUDED.target_agent_id,
    current_step_id = EXCLUDED.current_step_id, canary_pct = EXCLUDED.canary_pct,
    routing_version = EXCLUDED.routing_version, last_transition_id = EXCLUDED.last_transition_id,
    approval_id = EXCLUDED.approval_id, operator_hold_until = EXCLUDED.operator_hold_until,
    state_since = CASE WHEN s.state = EXCLUDED.state THEN s.state_since ELSE now() END;

  INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind, aggregate_id, payload, idempotency_key)
  VALUES (p_tenant, 'policy', 'policy_changed', 'agent', p_agent,
          jsonb_build_object('tenant_id', p_tenant, 'routing_version', v_version, 'agent_id', p_agent),
          'routing:' || v_tid::text);

  RETURN QUERY SELECT v_tid, v_version, v_seq;
END
$$;

-- Erasure of the function-only routing tables (DATAMODEL §6.5), tenant or agent scope.
CREATE FUNCTION sibyl.erasure_purge_routing(p_erasure_request_id uuid, p_agent uuid DEFAULT NULL)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_tenant uuid := sibyl.current_tenant();
  v_n bigint;
  v_m bigint;
BEGIN
  PERFORM set_config('sibyl.erasure_request', p_erasure_request_id::text, true);
  IF NOT sibyl.erasure_delete_allowed(v_tenant) THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: erasure request % is not executing for this tenant', p_erasure_request_id USING ERRCODE = 'SB031';
  END IF;
  SET CONSTRAINTS ALL DEFERRED;
  DELETE FROM sibyl.routing_state WHERE tenant_id = v_tenant AND (p_agent IS NULL OR agent_id = p_agent);
  GET DIAGNOSTICS v_n = ROW_COUNT;
  DELETE FROM sibyl.routing_transition WHERE tenant_id = v_tenant AND (p_agent IS NULL OR agent_id = p_agent);
  GET DIAGNOSTICS v_m = ROW_COUNT;
  RETURN v_n + v_m;
END
$$;

GRANT EXECUTE ON FUNCTION sibyl.routing_apply(uuid, uuid, uuid, text, text, jsonb, text, text, uuid, uuid, text[],
  uuid[], uuid, uuid, uuid, timestamptz, smallint, text, text, text, jsonb, bytea, uuid, uuid, uuid)
  TO sibyl_app, sibyl_worker, sibyl_ingest;
GRANT EXECUTE ON FUNCTION sibyl.erasure_purge_routing(uuid, uuid) TO sibyl_worker, sibyl_migrate;
GRANT EXECUTE ON FUNCTION sibyl.routing_target(text, uuid, uuid, uuid, uuid)
  TO sibyl_app, sibyl_worker, sibyl_ingest;
GRANT SELECT ON sibyl.routing_state, sibyl.routing_transition TO sibyl_app, sibyl_worker, sibyl_ingest;
GRANT REFERENCES ON sibyl.routing_transition TO sibyl_migrate;

RESET ROLE;

-- Back-references into the routing tables from migrate-owned tables.
ALTER TABLE sibyl.failover ADD CONSTRAINT fk_failover_transition FOREIGN KEY (tenant_id, routing_transition_id)
  REFERENCES sibyl.routing_transition (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

-- Grant matrix (DATAMODEL §3): api for plans/chains/actions; worker for sagas and approvals.
GRANT SELECT ON sibyl.continuity_plan, sibyl.fallback_chain, sibyl.fallback_step, sibyl.failover, sibyl.approval,
  sibyl.kill_switch, sibyl.kill_switch_ack TO sibyl_app, sibyl_worker, sibyl_ingest;
GRANT INSERT, UPDATE, DELETE ON sibyl.continuity_plan, sibyl.fallback_chain, sibyl.fallback_step TO sibyl_app;
GRANT INSERT, UPDATE ON sibyl.failover, sibyl.approval, sibyl.kill_switch TO sibyl_app;
GRANT INSERT ON sibyl.kill_switch_ack TO sibyl_app;
GRANT INSERT, UPDATE ON sibyl.failover, sibyl.approval TO sibyl_worker;
GRANT UPDATE (last_drill_at, next_drill_at, preemptive_mode, row_version) ON sibyl.continuity_plan TO sibyl_worker;
GRANT EXECUTE ON FUNCTION sibyl.fallback_kind_rank(text) TO sibyl_app, sibyl_worker, sibyl_ingest, sibyl_routing;
