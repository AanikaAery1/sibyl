-- 0021 lane AG-LIVE: Action Gate fields the console needs to run live (WAVE3.md, D48).
--
-- * held_action: `on_behalf_of` (frozen shape: {"kind":"user","id":uuid} | {"kind":"external",
--   "ref":text<=128}); the decision `history` (requested, refused attempts, four-eyes first
--   approvals, decision, expiry; bounded); `matched_paths`; the cumulative counter the control
--   plane's own evaluation named (`counter_*`), so an approved escalation counts toward its cap.
-- * action_policy: a stable `policy_id` shared by every version of one scope (the row `id` stays
--   the version id: the snapshot key and the document's own `policy_id`), `change_note` and the
--   approval trail `approvals`.
-- * action_counter: an approved escalation may carry a window past its cap (the conditional
--   upsert still refuses every automatic increment past it), so `value <= max_value` is dropped.
-- * audit_events: an expression index for the `agent_id` filter (rows about an agent name it in
--   `detail.agent_id` when their resource is a held action or a policy).
-- No new table: the erasure cascade (0017) already covers held_action and action_policy rows.

-- --- held_action ----------------------------------------------------------------------------------

ALTER TABLE sibyl.held_action
  ADD COLUMN on_behalf_of_kind     text,
  ADD COLUMN on_behalf_of_user_id  uuid,
  ADD COLUMN on_behalf_of_ref      text,
  ADD COLUMN history               jsonb    NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN matched_paths         text[]   NOT NULL DEFAULT '{}'::text[],
  ADD COLUMN counter_key           text,
  ADD COLUMN counter_amount        numeric,
  ADD COLUMN counter_max           numeric,
  ADD COLUMN counter_window_s      integer,
  ADD COLUMN counter_policy_id     uuid,
  ADD COLUMN counter_applied_at    timestamptz;

ALTER TABLE sibyl.held_action
  ADD CONSTRAINT ck_held_action_on_behalf_of CHECK (
    (on_behalf_of_kind IS NULL AND on_behalf_of_user_id IS NULL AND on_behalf_of_ref IS NULL)
    OR (on_behalf_of_kind = 'user' AND on_behalf_of_user_id IS NOT NULL AND on_behalf_of_ref IS NULL)
    OR (on_behalf_of_kind = 'external' AND on_behalf_of_user_id IS NULL
        AND on_behalf_of_ref IS NOT NULL AND on_behalf_of_ref ~ '^[^[:cntrl:]]{1,128}$')),
  -- 48 refused attempts at most, so the decision and the expiry always fit (audit has the rest).
  ADD CONSTRAINT ck_held_action_history CHECK (jsonb_typeof(history) = 'array'
                                               AND jsonb_array_length(history) <= 64),
  ADD CONSTRAINT ck_held_action_matched_paths CHECK (cardinality(matched_paths) <= 64),
  ADD CONSTRAINT ck_held_action_counter CHECK (
    (counter_key IS NULL AND counter_amount IS NULL AND counter_max IS NULL AND counter_window_s IS NULL
     AND counter_policy_id IS NULL AND counter_applied_at IS NULL)
    OR (counter_key IS NOT NULL AND counter_amount IS NOT NULL AND counter_max IS NOT NULL
        AND counter_window_s IS NOT NULL AND counter_policy_id IS NOT NULL
        AND char_length(counter_key) BETWEEN 1 AND 512 AND counter_amount >= 0 AND counter_max > 0
        AND counter_window_s BETWEEN 1 AND 2678400)),
  ADD CONSTRAINT fk_held_action_counter_policy FOREIGN KEY (tenant_id, counter_policy_id)
    REFERENCES sibyl.action_policy (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;
CREATE INDEX ix_held_action_on_behalf_of ON sibyl.held_action (tenant_id, on_behalf_of_user_id)
  WHERE on_behalf_of_user_id IS NOT NULL;

-- Holds made before this migration get their trail from the columns they already have.
UPDATE sibyl.held_action SET history = jsonb_build_array(jsonb_build_object(
    'at', sibyl.rfc3339(created_at), 'kind', CASE WHEN server_effect = 'block' THEN 'blocked' ELSE 'requested' END,
    'user_id', NULL, 'key_id', requested_by_key_id::text, 'reason', reason, 'step_up', false, 'code', NULL,
    'approvals', 0))
  || CASE WHEN state = 'pending' OR (server_effect = 'block' AND state = 'denied') THEN '[]'::jsonb
     ELSE jsonb_build_array(jsonb_build_object(
       'at', sibyl.rfc3339(decided_at), 'kind', state, 'user_id', decided_by_user_id::text, 'key_id', NULL,
       'reason', decision_reason, 'step_up', false, 'code', NULL,
       'approvals', jsonb_array_length(approvals))) END
 WHERE history = '[]'::jsonb;

GRANT UPDATE (history, counter_applied_at) ON sibyl.held_action TO sibyl_app;
GRANT UPDATE (history) ON sibyl.held_action TO sibyl_worker;

-- --- action_policy --------------------------------------------------------------------------------

ALTER TABLE sibyl.action_policy
  ADD COLUMN policy_id    uuid,
  ADD COLUMN change_note  text,
  ADD COLUMN approvals    jsonb NOT NULL DEFAULT '[]'::jsonb;

-- Every version of one scope shares the policy_id of the scope's first version.
UPDATE sibyl.action_policy p SET policy_id = f.id
  FROM (SELECT DISTINCT ON (tenant_id, scope_kind, coalesce(agent_id, agent_group_id))
               tenant_id, scope_kind, agent_id, agent_group_id, id
          FROM sibyl.action_policy
         ORDER BY tenant_id, scope_kind, coalesce(agent_id, agent_group_id), version_no) f
 WHERE p.tenant_id = f.tenant_id AND p.scope_kind = f.scope_kind
   AND p.agent_id IS NOT DISTINCT FROM f.agent_id AND p.agent_group_id IS NOT DISTINCT FROM f.agent_group_id;
UPDATE sibyl.action_policy SET approvals = jsonb_build_array(jsonb_build_object(
    'user_id', approved_by_user_id::text, 'at', sibyl.rfc3339(approved_at), 'reason', NULL))
 WHERE approved_by_user_id IS NOT NULL AND approvals = '[]'::jsonb;

ALTER TABLE sibyl.action_policy
  ALTER COLUMN policy_id SET NOT NULL,
  ADD CONSTRAINT ck_action_policy_change_note CHECK (change_note IS NULL
                                                     OR char_length(change_note) BETWEEN 1 AND 2000),
  ADD CONSTRAINT ck_action_policy_approvals CHECK (jsonb_typeof(approvals) = 'array'
                                                   AND jsonb_array_length(approvals) <= 4);
CREATE UNIQUE INDEX ux_action_policy_lineage_version ON sibyl.action_policy (tenant_id, policy_id, version_no);

-- The lineage is derived, never chosen: the scope's existing policy_id, else the new row's id.
CREATE FUNCTION sibyl.trg_action_policy_lineage() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.policy_id := coalesce(
    (SELECT p.policy_id FROM sibyl.action_policy p
      WHERE p.tenant_id = NEW.tenant_id AND p.scope_kind = NEW.scope_kind
        AND p.agent_id IS NOT DISTINCT FROM NEW.agent_id
        AND p.agent_group_id IS NOT DISTINCT FROM NEW.agent_group_id
      ORDER BY p.version_no LIMIT 1),
    NEW.id);
  RETURN NEW;
END $$;
CREATE TRIGGER trg_action_policy_lineage BEFORE INSERT ON sibyl.action_policy
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_action_policy_lineage();
CREATE TRIGGER trg_action_policy_lineage_frozen BEFORE UPDATE OF policy_id ON sibyl.action_policy
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();

GRANT UPDATE (approvals) ON sibyl.action_policy TO sibyl_app;

-- --- action_counter -------------------------------------------------------------------------------

ALTER TABLE sibyl.action_counter DROP CONSTRAINT ck_action_counter_value;
ALTER TABLE sibyl.action_counter ADD CONSTRAINT ck_action_counter_value
  CHECK (value >= 0 AND max_value > 0 AND calls >= 0);

-- --- audit_events ---------------------------------------------------------------------------------

SET LOCAL ROLE sibyl_audit;
CREATE INDEX ix_audit_events_detail_agent ON sibyl.audit_events (tenant_id, (detail ->> 'agent_id'), seq)
  WHERE detail ? 'agent_id';
RESET ROLE;
