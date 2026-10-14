-- 0024 lane GAPS (wave 3B API gaps for the console).
--
-- Agent discovery fields, so `is_provisional` is not overloaded:
--   * discovered_via  how ingest first saw the agent (sibyl_schemas DiscoveredVia; null for an
--                     agent registered through the API),
--   * first_trace_id  the trace of the first telemetry that named it (null when unknown),
--   * confirmed_at    when an admin confirmed it (POST /agents/{id}/claim).
-- No backfill: agents discovered or claimed before this migration keep nulls (the audit trail
-- still holds agent.discovered and the claim's asset.updated).

ALTER TABLE sibyl.agent
  ADD COLUMN discovered_via text,
  ADD COLUMN first_trace_id uuid,
  ADD COLUMN confirmed_at   timestamptz,
  ADD CONSTRAINT ck_agent_discovered_via CHECK (discovered_via IS NULL OR discovered_via IN
    ('gateway_header', 'api_key_default', 'span_attr', 'a2a_card', 'mcp_list_tools',
     'egress_log', 'run_tree')),
  ADD CONSTRAINT ck_agent_confirmed CHECK (confirmed_at IS NULL OR NOT is_provisional);

-- The api claims a discovered agent (is_provisional -> false, confirmed_at = now()).
-- sibyl_app already holds table-level UPDATE on sibyl.agent (0004); ingest inserts only.
