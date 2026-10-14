-- 0020 lane PLUG (wave 3, D50): plug-and-play monitoring, run tree and auto-discovery.
-- Single sources: sibyl_schemas audit action `agent.discovered`, DiscoveredVia.RUN_TREE,
-- Dialect.GEMINI (chair addition from GW-NATIVE), event attrs parent_run_id / step_index /
-- handoff_to_agent / system_fingerprint (sibyl-event/1, drift-tested).
--
-- 1. Audit action `agent.discovered`: ingest registers an agent first seen in telemetry
--    (lifecycle `discovered`, is_provisional) and records it as the sending API key.
-- 2. A discovered agent is never routed until an admin confirms it (POST /agents/{id}/claim
--    clears is_provisional): routing_transition refuses failover, failback, degraded and
--    approval states for provisional agents. register, active, quarantine and kill stay
--    allowed (kill and quarantine are safety actions and always win).
-- 3. Run-tree lookups: events by attrs->>'parent_run_id'.
-- 4. Provider dialect `gemini` (native Gemini protocol in the gateway).

-- --- 1. audit catalogue ------------------------------------------------------------------------

INSERT INTO sibyl.audit_action
  (name, domain, actor_types, resource_type, required_fields, reason_required, is_evidence, severity)
VALUES
  ('agent.discovered', 'registry', '{system,api_key}', 'agent',
   '{slug,api_key_id,default_fail_mode,discovered_via}', false, true, 'notice');

-- --- 2. discovered agents are never routed ------------------------------------------------------
-- routing_transition is owned by the NOLOGIN sibyl_routing (0008), which already reads agent.

SET LOCAL ROLE sibyl_routing;

CREATE FUNCTION sibyl.trg_routing_unconfirmed_agent() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
BEGIN
  IF NEW.to_state IN ('failed_over', 'failing_back', 'degraded', 'awaiting_approval')
     AND EXISTS (SELECT 1 FROM sibyl.agent a
                  WHERE a.tenant_id = NEW.tenant_id AND a.id = NEW.agent_id AND a.is_provisional) THEN
    RAISE EXCEPTION 'sibyl:agent_unconfirmed: agent % was discovered from telemetry and is not routed until an admin confirms it', NEW.agent_id
      USING ERRCODE = 'SB051';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER trg_routing_transition_unconfirmed BEFORE INSERT ON sibyl.routing_transition
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_routing_unconfirmed_agent();

RESET ROLE;

-- --- 3. run tree --------------------------------------------------------------------------------

CREATE INDEX ix_events_parent_run ON sibyl.events (tenant_id, ((attrs->>'parent_run_id')))
  WHERE attrs ? 'parent_run_id';

-- --- 4. gemini dialect --------------------------------------------------------------------------

ALTER TABLE sibyl.provider DROP CONSTRAINT ck_provider_dialect;
ALTER TABLE sibyl.provider ADD CONSTRAINT ck_provider_dialect
  CHECK (dialect IN ('openai_compatible', 'anthropic', 'gemini'));
