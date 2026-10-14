-- CHANGE REQUEST for INT-1 (lane U, wave 2): proposed migration body. Applied by the lane U
-- tests only (as sibyl_migrate, CREATE OR REPLACE) until INT-1 ships it in a numbered migration.
--
-- Drops partitions past their class retention (partition_policy().retention, DATAMODEL §6.6
-- step 3) on behalf of the worker, which owns no table and cannot DETACH/DROP. Never touches
-- audit_events (export + partition_boundary anchor first, Phase 1.5). A payload_refs or
-- checkpoint partition holding any row under an active legal hold is kept. Row counts are
-- taken per tenant under that tenant's RLS context (FORCE RLS binds the definer too) and
-- returned so the worker can append retention.partition_dropped per tenant.
CREATE OR REPLACE FUNCTION sibyl.partition_retire_expired(p_now timestamptz DEFAULT now())
RETURNS TABLE (table_name text, partition_name text, tenant_id uuid, rows bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  r record;
  t record;
  v_n bigint;
  v_held boolean;
  v_tenants uuid[];
  v_counts bigint[];
  v_prev text := current_setting('app.tenant_id', true);
BEGIN
  FOR r IN SELECT pr.table_name AS tbl, pr.partition_name AS part
             FROM sibyl.partition_registry pr
             JOIN sibyl.partition_policy() pp ON pp.table_name = pr.table_name
            WHERE pr.state = 'attached' AND pr.table_name <> 'audit_events'
              AND pr.range_to <= p_now - pp.retention
            ORDER BY pr.table_name, pr.range_from LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended('partition:' || r.tbl, 0));
    v_held := false;
    v_tenants := '{}';
    v_counts := '{}';
    FOR t IN SELECT id FROM sibyl.tenant ORDER BY id LOOP
      PERFORM set_config('app.tenant_id', t.id::text, true);
      EXECUTE format('SELECT count(*) FROM sibyl.%I', r.part) INTO v_n;
      CONTINUE WHEN v_n = 0;
      IF r.tbl IN ('payload_refs', 'checkpoint') THEN
        EXECUTE format(
          'SELECT EXISTS (SELECT 1 FROM sibyl.%I p JOIN sibyl.legal_hold h ON h.tenant_id = p.tenant_id'
          ' WHERE h.state = ''active'' AND (h.expires_at IS NULL OR h.expires_at > now())'
          ' AND p.created_at >= h.window_from AND (h.window_to IS NULL OR p.created_at <= h.window_to)'
          ' AND (h.scope_kind = ''tenant'' OR p.agent_id = ANY (h.agent_ids)'
          ' OR (h.scope_kind = ''agent'' AND h.scope_ref = p.agent_id::text)))', r.part) INTO v_held;
        EXIT WHEN v_held;
      END IF;
      v_tenants := v_tenants || t.id;
      v_counts := v_counts || v_n;
    END LOOP;
    PERFORM set_config('app.tenant_id', coalesce(v_prev, ''), true);
    CONTINUE WHEN v_held;
    EXECUTE format('ALTER TABLE sibyl.%I DETACH PARTITION sibyl.%I', r.tbl, r.part);
    UPDATE sibyl.partition_registry SET state = 'detached', state_changed_at = now()
     WHERE partition_registry.table_name = r.tbl AND partition_registry.partition_name = r.part;
    EXECUTE format('DROP TABLE sibyl.%I', r.part);
    UPDATE sibyl.partition_registry SET state = 'dropped', state_changed_at = now()
     WHERE partition_registry.table_name = r.tbl AND partition_registry.partition_name = r.part;
    IF cardinality(v_tenants) = 0 THEN
      RETURN QUERY SELECT r.tbl, r.part, NULL::uuid, 0::bigint;
    ELSE
      RETURN QUERY SELECT r.tbl, r.part, u.tid, u.n FROM unnest(v_tenants, v_counts) AS u(tid, n);
    END IF;
  END LOOP;
  PERFORM set_config('app.tenant_id', coalesce(v_prev, ''), true);
END
$$;

REVOKE EXECUTE ON FUNCTION sibyl.partition_retire_expired(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sibyl.partition_retire_expired(timestamptz) TO sibyl_worker;
