-- 0009 alerts, health & queue (DATAMODEL §4.5–§4.6; R17 as amended by R51 write-on-change;
-- R29/D33 unverdicted queue; ML §10.1 items 6, 8, 9).

CREATE FUNCTION sibyl.failure_modes() RETURNS text[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT ARRAY['provider_outage', 'latency_degradation', 'quality_collapse', 'prompt_injection', 'policy_violation',
               'tool_failure', 'data_source_failure', 'infinite_loop', 'cost_runaway', 'permission_error',
               'model_deprecation', 'silent_drift']
$$;
GRANT EXECUTE ON FUNCTION sibyl.failure_modes() TO sibyl_app, sibyl_worker, sibyl_ingest, sibyl_audit, sibyl_routing;

-- Per-tenant copies of rules/v1 (R18). Per-tier caps/thresholds/hysteresis live in
-- thresholds->'tiers'; the scalar columns hold the tier-2 values as the display default.
CREATE TABLE sibyl.alert_rule (
  tenant_id              uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                     uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  code                   text        NOT NULL,
  short_code             text,
  kind                   text        NOT NULL,
  scope                  text        NOT NULL DEFAULT 'agent',
  metric                 text        NOT NULL,
  comparator             text        NOT NULL,
  thresholds             jsonb       NOT NULL,
  window_s               integer     NOT NULL,
  min_samples            integer     NOT NULL,
  trend_windows          smallint,
  hysteresis_in          smallint    NOT NULL DEFAULT 2,
  hysteresis_out         smallint    NOT NULL DEFAULT 6,
  cooldown_s             integer     NOT NULL DEFAULT 600,
  escalate_after_fires   integer     NOT NULL DEFAULT 3,
  escalate_window_s      integer     NOT NULL DEFAULT 3600,
  severity               text        NOT NULL,
  penalty                smallint    NOT NULL,
  horizon_s              integer     NOT NULL DEFAULT 0,
  tier_applicability     smallint[]  NOT NULL DEFAULT '{1,2,3}',
  collapses_to_provider  boolean     NOT NULL DEFAULT false,
  what_to_do_template    text        NOT NULL,
  enabled                boolean     NOT NULL DEFAULT true,
  overridden             boolean     NOT NULL DEFAULT false,
  origin                 text        NOT NULL DEFAULT 'seed',
  seed_version           text,
  yaml_sha256            bytea,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_alert_rule_code UNIQUE (tenant_id, code),
  CONSTRAINT ck_alert_rule_code CHECK (code ~ '^[a-z][a-z0-9_]{2,40}$'),
  CONSTRAINT ck_alert_rule_short_code CHECK (short_code IS NULL OR short_code ~ '^[RL][0-9]{1,2}$'),
  CONSTRAINT ck_alert_rule_kind CHECK (kind IN ('detected', 'leading')),
  CONSTRAINT ck_alert_rule_scope CHECK (scope IN ('agent', 'provider', 'platform')),
  CONSTRAINT ck_alert_rule_comparator CHECK (comparator IN ('above', 'below', 'ordinal', 'count', 'boolean', 'trend',
                                                            'proximity', 'composite')),
  CONSTRAINT ck_alert_rule_severity CHECK (severity IN ('info', 'warning', 'critical')),
  CONSTRAINT ck_alert_rule_origin CHECK (origin IN ('seed', 'custom')),
  CONSTRAINT ck_alert_rule_tiers CHECK (cardinality(tier_applicability) >= 1
                                        AND tier_applicability <@ ARRAY[1, 2, 3]::smallint[]),
  CONSTRAINT ck_alert_rule_numbers CHECK (window_s > 0 AND min_samples >= 0 AND hysteresis_in >= 1
    AND hysteresis_out >= 1 AND cooldown_s >= 0 AND penalty >= 0 AND horizon_s >= 0),
  CONSTRAINT ck_alert_rule_thresholds CHECK (jsonb_typeof(thresholds) = 'object' AND pg_column_size(thresholds) <= 8192),
  CONSTRAINT ck_alert_rule_yaml_sha256 CHECK (yaml_sha256 IS NULL OR octet_length(yaml_sha256) = 32)
);

CREATE TABLE sibyl.provider_incident (
  tenant_id               uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                      uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  provider_id             uuid        NOT NULL,
  state                   text        NOT NULL DEFAULT 'open',
  severity                text        NOT NULL,
  started_at              timestamptz NOT NULL DEFAULT now(),
  resolved_at             timestamptz,
  rule_codes              text[]      NOT NULL DEFAULT '{}',
  affected_agent_ids      uuid[]      NOT NULL DEFAULT '{}',
  affected_process_count  integer     NOT NULL DEFAULT 0,
  provider_status_id      uuid,
  summary                 text        NOT NULL,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_provider_incident_provider FOREIGN KEY (tenant_id, provider_id)
    REFERENCES sibyl.provider (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_provider_incident_status FOREIGN KEY (tenant_id, provider_status_id)
    REFERENCES sibyl.provider_status (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_provider_incident_state CHECK (state IN ('open', 'resolved')),
  CONSTRAINT ck_provider_incident_severity CHECK (severity IN ('info', 'warning', 'critical')),
  CONSTRAINT ck_provider_incident_resolved CHECK ((state = 'resolved') = (resolved_at IS NOT NULL))
);
CREATE UNIQUE INDEX ux_provider_incident_open ON sibyl.provider_incident (tenant_id, provider_id) WHERE state = 'open';
CREATE INDEX ix_provider_incident_state ON sibyl.provider_incident (tenant_id, state, started_at DESC);

CREATE TABLE sibyl.alert (
  tenant_id               uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                      uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  rule_id                 uuid        NOT NULL,
  scope                   text        NOT NULL,
  agent_id                uuid,
  provider_id             uuid,
  severity                text        NOT NULL,
  state                   text        NOT NULL DEFAULT 'open',
  dedupe_key              text        NOT NULL,
  provider_incident_id    uuid,
  suppressed_by_incident  boolean     NOT NULL DEFAULT false,
  first_fired_at          timestamptz NOT NULL DEFAULT now(),
  last_evaluated_at       timestamptz NOT NULL DEFAULT now(),
  resolved_at             timestamptz,
  fired_count             integer     NOT NULL DEFAULT 1,
  hold_suppressed_count   integer     NOT NULL DEFAULT 0,
  hold_suppressed_at      timestamptz,  -- lane S: last time a legal/operator hold suppressed it
  cooldown_until          timestamptz,
  escalation_level        smallint    NOT NULL DEFAULT 0,
  acked_by_user_id        uuid,
  acked_at                timestamptz,
  silenced_until          timestamptz,  -- lane P: an acked alert stays acked until then
  silenced_by_user_id     uuid,
  what_to_do              text        NOT NULL,
  evidence                jsonb       NOT NULL DEFAULT '{}',
  health_snapshot_id      uuid,
  failover_id             uuid,
  verdict                 text,
  verdict_label_id        uuid,
  verdict_wanted          boolean     NOT NULL DEFAULT false,
  outcome_observed        text,
  outcome_at              timestamptz,
  summary                 text        NOT NULL,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_alert_rule FOREIGN KEY (tenant_id, rule_id)
    REFERENCES sibyl.alert_rule (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_alert_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_alert_provider FOREIGN KEY (tenant_id, provider_id)
    REFERENCES sibyl.provider (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_alert_incident FOREIGN KEY (tenant_id, provider_incident_id)
    REFERENCES sibyl.provider_incident (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_alert_acked_by FOREIGN KEY (tenant_id, acked_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_alert_silenced_by FOREIGN KEY (tenant_id, silenced_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_alert_failover FOREIGN KEY (tenant_id, failover_id)
    REFERENCES sibyl.failover (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_alert_verdict_label FOREIGN KEY (tenant_id, verdict_label_id)
    REFERENCES sibyl.label (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_alert_scope CHECK (scope IN ('agent', 'provider', 'platform')),
  CONSTRAINT ck_alert_scope_target CHECK (
    (scope = 'agent' AND agent_id IS NOT NULL AND provider_id IS NULL)
    OR (scope = 'provider' AND provider_id IS NOT NULL AND agent_id IS NULL)
    OR (scope = 'platform' AND agent_id IS NULL AND provider_id IS NULL)),
  CONSTRAINT ck_alert_severity CHECK (severity IN ('info', 'warning', 'critical')),
  CONSTRAINT ck_alert_state CHECK (state IN ('open', 'acked', 'resolved')),
  CONSTRAINT ck_alert_verdict CHECK (verdict IN ('tp', 'fp', 'unsure')),
  CONSTRAINT ck_alert_verdict_label CHECK ((verdict IS NULL) = (verdict_label_id IS NULL)),
  CONSTRAINT ck_alert_outcome_observed CHECK (outcome_observed IN ('failed', 'recovered', 'unknown')),
  CONSTRAINT ck_alert_resolved CHECK ((state = 'resolved') = (resolved_at IS NOT NULL)),
  CONSTRAINT ck_alert_evidence CHECK (pg_column_size(evidence) <= 8192)
);
CREATE UNIQUE INDEX ux_alert_dedupe_live ON sibyl.alert (tenant_id, dedupe_key) WHERE state <> 'resolved';
CREATE INDEX ix_alert_state ON sibyl.alert (tenant_id, state, severity, first_fired_at DESC);
CREATE INDEX ix_alert_agent ON sibyl.alert (tenant_id, agent_id, first_fired_at DESC);
CREATE INDEX ix_alert_dedupe_history ON sibyl.alert (tenant_id, dedupe_key, resolved_at DESC);
CREATE INDEX ix_alert_incident ON sibyl.alert (tenant_id, provider_incident_id);
CREATE INDEX ix_alert_verdict ON sibyl.alert (tenant_id, verdict, first_fired_at) WHERE verdict IS NOT NULL;
CREATE INDEX ix_alert_unverdicted ON sibyl.alert (tenant_id, resolved_at DESC) WHERE state = 'resolved' AND verdict IS NULL;
CREATE INDEX ix_alert_silenced ON sibyl.alert (tenant_id, silenced_until) WHERE silenced_until IS NOT NULL;
CREATE TRIGGER trg_alert_state_edge BEFORE UPDATE OF state ON sibyl.alert
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('alert', 'state');

ALTER TABLE sibyl.failover ADD CONSTRAINT fk_failover_trigger_alert FOREIGN KEY (tenant_id, trigger_alert_id)
  REFERENCES sibyl.alert (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sibyl.approval ADD CONSTRAINT fk_approval_alert FOREIGN KEY (tenant_id, alert_id)
  REFERENCES sibyl.alert (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE sibyl.approval ADD CONSTRAINT fk_approval_rule FOREIGN KEY (tenant_id, requested_by_rule_id)
  REFERENCES sibyl.alert_rule (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

GRANT REFERENCES ON sibyl.alert_rule TO sibyl_routing;
SET LOCAL ROLE sibyl_routing;
ALTER TABLE sibyl.routing_transition ADD CONSTRAINT fk_routing_transition_rule FOREIGN KEY (tenant_id, actor_rule_id)
  REFERENCES sibyl.alert_rule (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;
RESET ROLE;

-- Append-only health evaluation history; written on change plus a 60 s heartbeat (R51).
CREATE TABLE sibyl.health_snapshot (
  tenant_id               uuid         NOT NULL,
  evaluated_at            timestamptz  NOT NULL,
  id                      uuid         NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id                uuid         NOT NULL,
  score                   smallint     NOT NULL,
  band                    text         NOT NULL,
  provisional             boolean      NOT NULL,
  events_seen             integer      NOT NULL,
  observation_coverage    numeric(4,3) NOT NULL,
  factors                 jsonb        NOT NULL DEFAULT '[]',
  horizons                jsonb        NOT NULL DEFAULT '{}',
  predicted_failure_mode  text,
  recommended_action      text,
  feature_snapshot_id     uuid,
  scoring_config_id       uuid         NOT NULL,
  policy_version         bigint       NOT NULL,
  routing_state_at        text         NOT NULL,
  window_start            timestamptz  NOT NULL,
  window_end              timestamptz  NOT NULL,
  grain_s                 smallint     NOT NULL,
  rules_source            text         NOT NULL DEFAULT 'rules/v1',
  write_reason            text         NOT NULL DEFAULT 'change',
  created_at              timestamptz  NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, evaluated_at, id),
  CONSTRAINT ck_health_snapshot_score CHECK (score BETWEEN 0 AND 100),
  CONSTRAINT ck_health_snapshot_band CHECK (band IN ('healthy', 'watch', 'degraded', 'failed')),
  CONSTRAINT ck_health_snapshot_coverage CHECK (observation_coverage BETWEEN 0 AND 1),
  CONSTRAINT ck_health_snapshot_factors CHECK (pg_column_size(factors) <= 8192),
  CONSTRAINT ck_health_snapshot_failure_mode CHECK (
    predicted_failure_mode IS NULL OR predicted_failure_mode = ANY (sibyl.failure_modes())),
  CONSTRAINT ck_health_snapshot_routing_state CHECK (routing_state_at IN ('active', 'degraded', 'awaiting_approval',
    'failed_over', 'failing_back', 'quarantined', 'killed')),
  CONSTRAINT ck_health_snapshot_write_reason CHECK (write_reason IN ('change', 'heartbeat')),
  CONSTRAINT ck_health_snapshot_window CHECK (window_start <= window_end)
) PARTITION BY RANGE (evaluated_at);
CREATE INDEX ix_health_snapshot_agent ON sibyl.health_snapshot (tenant_id, agent_id, evaluated_at DESC);

CREATE TABLE sibyl.handoff_task (
  tenant_id              uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                     uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id               uuid        NOT NULL,
  failover_id            uuid,
  routing_transition_id  uuid,
  task_id                uuid        NOT NULL,
  packet_id              uuid        NOT NULL,
  packet                 jsonb,
  packet_ref_id          uuid,
  packet_sha256          bytea       NOT NULL,
  fidelity               text        NOT NULL,
  failure_mode           text        NOT NULL,
  trigger_kind           text        NOT NULL,
  rule_code              text,
  alert_id               uuid,
  assembled_by           text        NOT NULL,
  state                  text        NOT NULL DEFAULT 'queued',
  priority               smallint    NOT NULL,
  deadline_at            timestamptz NOT NULL,
  claimed_by_user_id     uuid,
  claimed_at             timestamptz,
  claim_lock_until       timestamptz,
  reclaim_count          smallint    NOT NULL DEFAULT 0,
  accountable_user_id    uuid,
  accountable_role       text        REFERENCES sibyl.role (name),
  outcome                text,
  outcome_note           text,
  rating                 smallint    CHECK (rating BETWEEN 1 AND 5),  -- lane S: operator rating
  completed_at           timestamptz,
  next_action            text        NOT NULL,
  summary                text        NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_handoff_task_packet UNIQUE (tenant_id, packet_id),
  CONSTRAINT uq_handoff_task_failover_task UNIQUE (tenant_id, failover_id, task_id),
  CONSTRAINT fk_handoff_task_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_handoff_task_failover FOREIGN KEY (tenant_id, failover_id)
    REFERENCES sibyl.failover (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_handoff_task_transition FOREIGN KEY (tenant_id, routing_transition_id)
    REFERENCES sibyl.routing_transition (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_handoff_task_alert FOREIGN KEY (tenant_id, alert_id)
    REFERENCES sibyl.alert (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_handoff_task_claimed_by FOREIGN KEY (tenant_id, claimed_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_handoff_task_accountable FOREIGN KEY (tenant_id, accountable_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_handoff_task_packet_xor CHECK ((packet IS NULL) <> (packet_ref_id IS NULL)),
  CONSTRAINT ck_handoff_task_packet_size CHECK (pg_column_size(packet) <= 65536),
  CONSTRAINT ck_handoff_task_packet_sha256 CHECK (octet_length(packet_sha256) = 32),
  CONSTRAINT ck_handoff_task_fidelity CHECK (fidelity IN ('checkpoint', 'request_only')),
  CONSTRAINT ck_handoff_task_failure_mode CHECK (failure_mode = ANY (sibyl.failure_modes())),
  CONSTRAINT ck_handoff_task_assembled_by CHECK (assembled_by IN ('sdk', 'control_plane')),
  CONSTRAINT ck_handoff_task_state CHECK (state IN ('queued', 'claimed', 'completed', 'returned', 'expired')),
  CONSTRAINT ck_handoff_task_outcome CHECK (outcome IN ('resolved', 'escalated', 'abandoned', 'returned_to_agent',
                                                        'expired_unclaimed')),
  CONSTRAINT ck_handoff_task_claimed CHECK (
    state <> 'claimed' OR (claimed_by_user_id IS NOT NULL AND claim_lock_until IS NOT NULL)),
  CONSTRAINT ck_handoff_task_completed CHECK ((state = 'completed') = (completed_at IS NOT NULL)),
  CONSTRAINT ck_handoff_task_priority CHECK (priority BETWEEN 1 AND 3)
);
CREATE INDEX ix_handoff_task_queue ON sibyl.handoff_task (tenant_id, state, priority, deadline_at)
  WHERE state IN ('queued', 'claimed', 'expired');
CREATE INDEX ix_handoff_task_claimable ON sibyl.handoff_task (tenant_id, priority, deadline_at) WHERE state = 'queued';
CREATE INDEX ix_handoff_task_claimer ON sibyl.handoff_task (tenant_id, claimed_by_user_id, state);
CREATE TRIGGER trg_handoff_task_state_edge BEFORE UPDATE OF state ON sibyl.handoff_task
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('handoff', 'state');

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['alert_rule', 'provider_incident', 'alert', 'health_snapshot', 'handoff_task'] LOOP
    PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', t)::regclass);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['alert_rule', 'provider_incident', 'alert', 'handoff_task'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON sibyl.%I FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at()',
                   'trg_' || t || '_updated_at', t);
  END LOOP;
END
$$;
CREATE TRIGGER trg_health_snapshot_immutable BEFORE UPDATE OR DELETE ON sibyl.health_snapshot
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();

-- Grant matrix.
GRANT SELECT ON sibyl.alert_rule, sibyl.provider_incident, sibyl.alert, sibyl.health_snapshot, sibyl.handoff_task
  TO sibyl_app, sibyl_worker, sibyl_ingest;
GRANT INSERT, UPDATE, DELETE ON sibyl.alert_rule TO sibyl_app;
GRANT UPDATE ON sibyl.alert TO sibyl_app;
GRANT INSERT, UPDATE ON sibyl.alert, sibyl.provider_incident TO sibyl_worker;
GRANT INSERT ON sibyl.health_snapshot TO sibyl_worker;
GRANT INSERT, UPDATE ON sibyl.handoff_task TO sibyl_worker;
GRANT UPDATE ON sibyl.handoff_task TO sibyl_app;
