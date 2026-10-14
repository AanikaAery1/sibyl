-- 0006 audit (DATAMODEL §4.8, §5; security-auditor §2.14–§4; R11). Tables and functions are
-- owned by the NOLOGIN sibyl_audit; no login role holds DML on them.

GRANT REFERENCES ON sibyl.tenant, sibyl.signing_key TO sibyl_audit;
GRANT INSERT ON sibyl.partition_registry TO sibyl_audit;
GRANT UPDATE (status) ON sibyl.tenant TO sibyl_audit;
GRANT UPDATE (status, ciphertext, nonce, revoked_at, revoke_reason) ON sibyl.provider_credential TO sibyl_audit;
GRANT SELECT ON sibyl.provider_credential TO sibyl_audit;

SET LOCAL ROLE sibyl_audit;

CREATE TABLE sibyl.audit_events (
  tenant_id         uuid        NOT NULL,
  recorded_at       timestamptz NOT NULL,
  seq               bigint      NOT NULL,
  id                uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  occurred_at       timestamptz,
  actor_type        text        NOT NULL,
  actor_id          uuid,
  actor_key_id      uuid,
  actor_session_id  uuid,
  action            text        NOT NULL,
  resource_type     text        NOT NULL,
  resource_id       uuid,
  resource_ref      text,
  severity          text        NOT NULL,
  reason            text,
  detail            jsonb       NOT NULL,
  detail_sha256     bytea       NOT NULL,
  envelope_sha256   bytea       NOT NULL,
  prev_hash         bytea       NOT NULL,
  hash              bytea       NOT NULL,
  chain_version     smallint    NOT NULL DEFAULT 1,
  request_id        uuid,
  is_evidence       boolean     NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, recorded_at, seq),
  CONSTRAINT uq_audit_events_id UNIQUE (tenant_id, id, recorded_at),
  CONSTRAINT ck_audit_events_actor_type CHECK (actor_type IN ('human', 'rule', 'policy', 'system', 'agent',
                                                               'api_key')),
  CONSTRAINT ck_audit_events_severity CHECK (severity IN ('info', 'notice', 'warning', 'critical')),
  -- G0 M2: one 8 KB rule, on canonical bytes; audit_append() raises SB023 before this backstop.
  CONSTRAINT ck_audit_events_detail CHECK (jsonb_typeof(detail) = 'object'
                                           AND octet_length(sibyl.jcs_text(detail, false)) <= 8192),
  CONSTRAINT ck_audit_events_hashes CHECK (octet_length(detail_sha256) = 32 AND octet_length(envelope_sha256) = 32
                                           AND octet_length(prev_hash) = 32 AND octet_length(hash) = 32),
  CONSTRAINT ck_audit_events_seq CHECK (seq >= 0)
) PARTITION BY RANGE (recorded_at);
CREATE INDEX ix_audit_events_seq ON sibyl.audit_events (tenant_id, seq);
CREATE INDEX ix_audit_events_resource ON sibyl.audit_events (tenant_id, resource_type, resource_id, seq);
CREATE INDEX ix_audit_events_action ON sibyl.audit_events (tenant_id, action, recorded_at);
CREATE INDEX ix_audit_events_evidence ON sibyl.audit_events (tenant_id, seq) WHERE is_evidence;
SELECT sibyl.enable_tenant_rls('sibyl.audit_events');
CREATE TRIGGER trg_audit_events_immutable BEFORE UPDATE OR DELETE ON sibyl.audit_events
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation('no_erasure');
CREATE TRIGGER trg_audit_events_no_truncate BEFORE TRUNCATE ON sibyl.audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();

CREATE TABLE sibyl.audit_anchors (
  tenant_id       uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id              uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  kind            text        NOT NULL,
  seq_from        bigint      NOT NULL,
  seq_to          bigint      NOT NULL,
  head_hash       bytea       NOT NULL,
  prev_anchor_id  uuid,
  signing_kid     text        NOT NULL REFERENCES sibyl.signing_key (kid),
  signature       bytea       NOT NULL,
  anchored_at     timestamptz NOT NULL DEFAULT now(),
  external_ref    text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_audit_anchors_seq_to UNIQUE (tenant_id, seq_to),
  CONSTRAINT fk_audit_anchors_prev FOREIGN KEY (tenant_id, prev_anchor_id)
    REFERENCES sibyl.audit_anchors (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_audit_anchors_kind CHECK (kind IN ('hourly', 'partition_boundary', 'erasure', 'export', 'rekey',
                                                   'break_glass')),
  CONSTRAINT ck_audit_anchors_range CHECK (seq_from >= 0 AND seq_from <= seq_to),
  CONSTRAINT ck_audit_anchors_head_hash CHECK (octet_length(head_hash) = 32)
);
SELECT sibyl.enable_tenant_rls('sibyl.audit_anchors');
CREATE TRIGGER trg_audit_anchors_immutable BEFORE UPDATE OR DELETE ON sibyl.audit_anchors
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation('no_erasure');
CREATE TRIGGER trg_audit_anchors_no_truncate BEFORE TRUNCATE ON sibyl.audit_anchors
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();

-- Per-tenant chain head (G0 security L2, code review H2). audit_append() locks this row
-- FOR UPDATE: under READ COMMITTED a second appender waits and re-reads the committed head;
-- under REPEATABLE READ or SERIALIZABLE it gets 40001 instead of forking the chain with a
-- duplicate seq. The same row lock is the "audit lock" that routing_apply() takes first, so
-- the lock order audit -> routing is structural. audit_verify() compares the walked tail
-- with this head and with the signed anchors, so tail truncation is detected.
CREATE TABLE sibyl.audit_chain_head (
  tenant_id   uuid        NOT NULL REFERENCES sibyl.tenant (id),
  seq         bigint      NOT NULL,
  hash        bytea       NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id),
  CONSTRAINT ck_audit_chain_head_seq CHECK (seq >= 0),
  CONSTRAINT ck_audit_chain_head_hash CHECK (octet_length(hash) = 32)
);
SELECT sibyl.enable_tenant_rls('sibyl.audit_chain_head');

-- The audit lock: callers that will append audit after taking other locks (routing_apply)
-- take this first. Idempotent within a transaction.
CREATE FUNCTION sibyl.audit_lock(p_tenant uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  PERFORM 1 FROM sibyl.audit_chain_head h WHERE h.tenant_id = p_tenant FOR UPDATE;
END
$$;

-- Keyed pseudonyms for personal identifiers (G0 security H2). One random HMAC key per tenant,
-- never readable by a login role, shredded with the tenant's keys: before the shred,
-- pseudonyms are stable (linkable within the tenant); after it they are unlinkable.
CREATE TABLE sibyl.tenant_pseudonym_key (
  tenant_id    uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id           uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  hmac_key     bytea,
  created_at   timestamptz NOT NULL DEFAULT now(),
  shredded_at  timestamptz,
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_tenant_pseudonym_key_tenant UNIQUE (tenant_id),
  CONSTRAINT ck_tenant_pseudonym_key_shredded CHECK ((hmac_key IS NULL) = (shredded_at IS NOT NULL)),
  CONSTRAINT ck_tenant_pseudonym_key_length CHECK (hmac_key IS NULL OR octet_length(hmac_key) = 32)
);
SELECT sibyl.enable_tenant_rls('sibyl.tenant_pseudonym_key');

CREATE FUNCTION sibyl.pseudonym_key_create(p_tenant uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  INSERT INTO sibyl.tenant_pseudonym_key (tenant_id, hmac_key) VALUES (p_tenant, gen_random_bytes(32))
  ON CONFLICT (tenant_id) DO NOTHING;
END
$$;

-- Hex HMAC-SHA-256 of p_value under the tenant key; after the shred (or with no key) a fresh
-- random key is used once and discarded, so the output is unlinkable.
CREATE FUNCTION sibyl.pseudonym_hex(p_tenant uuid, p_value text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_key bytea;
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  SELECT k.hmac_key INTO v_key FROM sibyl.tenant_pseudonym_key k WHERE k.tenant_id = p_tenant;
  RETURN encode(hmac(convert_to(coalesce(p_value, ''), 'UTF8'), coalesce(v_key, gen_random_bytes(32)),
                     'sha256'), 'hex');
END
$$;

-- For the api (deprovisioning, subject references): the case-folded email pseudonym.
CREATE FUNCTION sibyl.pseudonymise(p_value text) RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT sibyl.pseudonym_hex(sibyl.current_tenant(), lower(p_value))
$$;

-- The envelope (DATAMODEL §5): a flat object, sorted keys, RFC 3339 µs UTC, lowercase uuids,
-- literal nulls. Built once here and reused by audit_verify().
CREATE FUNCTION sibyl.audit_envelope(p_tenant uuid, p_seq bigint, p_chain_version smallint, p_actor_type text,
  p_actor_id uuid, p_actor_key_id uuid, p_actor_session_id uuid, p_action text, p_resource_type text,
  p_resource_id uuid, p_resource_ref text, p_reason text, p_occurred_at timestamptz,
  p_recorded_at timestamptz, p_request_id uuid) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT sibyl.jcs(jsonb_build_object(
    'action', p_action, 'actor_id', p_actor_id, 'actor_key_id', p_actor_key_id,
    'actor_session_id', p_actor_session_id, 'actor_type', p_actor_type, 'chain_version', p_chain_version,
    'occurred_at', sibyl.rfc3339(p_occurred_at), 'reason', p_reason,
    'recorded_at', sibyl.rfc3339(p_recorded_at), 'request_id', p_request_id, 'resource_id', p_resource_id,
    'resource_ref', p_resource_ref, 'resource_type', p_resource_type, 'seq', p_seq, 'tenant_id', p_tenant))
$$;

CREATE FUNCTION sibyl.audit_append(
  p_tenant uuid, p_actor_type text, p_actor_id uuid, p_actor_key_id uuid, p_actor_session_id uuid,
  p_action text, p_resource_type text, p_resource_id uuid, p_resource_ref text,
  p_reason text, p_detail jsonb, p_detail_canonical bytea,
  p_occurred_at timestamptz, p_request_id uuid
) RETURNS TABLE (seq bigint, hash bytea, recorded_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_action sibyl.audit_action%ROWTYPE;
  v_detail jsonb := coalesce(p_detail, '{}'::jsonb);
  v_canonical text;
  v_field text;
  v_seq bigint;
  v_prev bytea;
  v_recorded timestamptz;
  v_env_sha bytea;
  v_detail_sha bytea;
  v_hash bytea;
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  SELECT * INTO v_action FROM sibyl.audit_action a WHERE a.name = p_action;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'sibyl:audit_action_unknown: undeclared audit action %', p_action USING ERRCODE = 'SB020';
  END IF;
  IF p_actor_type IS NULL OR NOT (p_actor_type = ANY (v_action.actor_types)) THEN
    RAISE EXCEPTION 'sibyl:audit_actor_not_allowed: actor type % not allowed for %', p_actor_type, p_action USING ERRCODE = 'SB021';
  END IF;
  IF jsonb_typeof(v_detail) <> 'object' OR sibyl.has_content_key(v_detail) THEN
    RAISE EXCEPTION 'sibyl:audit_detail_invalid: audit detail must be an object of references, never content' USING ERRCODE = 'SB023';
  END IF;
  FOREACH v_field IN ARRAY v_action.required_fields LOOP
    IF NOT (v_detail ? v_field) THEN
      RAISE EXCEPTION 'sibyl:audit_field_missing: audit detail for % is missing %', p_action, v_field USING ERRCODE = 'SB022';
    END IF;
  END LOOP;
  IF v_action.reason_required AND p_actor_type = 'human' AND coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'sibyl:reason_required: a reason is required for % by a human', p_action USING ERRCODE = 'SB013';
  END IF;
  -- R11 / G0 M1: the database recomputes JCS (UTF-16 key order, integers only, so a
  -- non-integral number fails here with SB023 rather than later at verify) and requires the
  -- caller's canonical bytes to be exactly those bytes.
  v_canonical := sibyl.jcs(v_detail);
  IF p_detail_canonical IS NOT NULL AND p_detail_canonical IS DISTINCT FROM convert_to(v_canonical, 'UTF8') THEN
    RAISE EXCEPTION 'sibyl:audit_canonical_mismatch: p_detail_canonical is not the RFC 8785 encoding of p_detail' USING ERRCODE = 'SB024';
  END IF;
  -- G0 M2: the one size rule, on canonical bytes.
  IF octet_length(convert_to(v_canonical, 'UTF8')) > 8192 THEN
    RAISE EXCEPTION 'sibyl:audit_detail_invalid: audit detail exceeds 8 KB of canonical JSON' USING ERRCODE = 'SB023';
  END IF;
  v_detail_sha := sha256(convert_to(v_canonical, 'UTF8'));

  SELECT h.seq, h.hash INTO v_seq, v_prev FROM sibyl.audit_chain_head h WHERE h.tenant_id = p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    IF p_action <> 'audit.genesis' THEN
      RAISE EXCEPTION 'sibyl:audit_chain_genesis: audit chain for tenant % has no genesis row', p_tenant USING ERRCODE = 'SB025';
    END IF;
    v_seq := 0;
    v_prev := decode(repeat('00', 32), 'hex');
  ELSE
    IF p_action = 'audit.genesis' THEN
      RAISE EXCEPTION 'sibyl:audit_chain_genesis: audit chain for tenant % already has a genesis row', p_tenant USING ERRCODE = 'SB025';
    END IF;
    v_seq := v_seq + 1;
  END IF;
  v_recorded := clock_timestamp();
  v_env_sha := sibyl.sha256_text(sibyl.audit_envelope(p_tenant, v_seq, 1::smallint, p_actor_type, p_actor_id,
    p_actor_key_id, p_actor_session_id, p_action, p_resource_type, p_resource_id, p_resource_ref, p_reason,
    p_occurred_at, v_recorded, p_request_id));
  v_hash := sha256(v_prev || v_env_sha || v_detail_sha);

  INSERT INTO sibyl.audit_events (tenant_id, recorded_at, seq, occurred_at, actor_type, actor_id, actor_key_id,
    actor_session_id, action, resource_type, resource_id, resource_ref, severity, reason, detail,
    detail_sha256, envelope_sha256, prev_hash, hash, chain_version, request_id, is_evidence)
  VALUES (p_tenant, v_recorded, v_seq, p_occurred_at, p_actor_type, p_actor_id, p_actor_key_id,
    p_actor_session_id, p_action, p_resource_type, p_resource_id, p_resource_ref, v_action.severity, p_reason,
    v_detail, v_detail_sha, v_env_sha, v_prev, v_hash, 1, p_request_id, v_action.is_evidence);
  IF v_seq = 0 THEN
    INSERT INTO sibyl.audit_chain_head (tenant_id, seq, hash) VALUES (p_tenant, 0, v_hash);
  ELSE
    UPDATE sibyl.audit_chain_head h SET seq = v_seq, hash = v_hash, updated_at = v_recorded
     WHERE h.tenant_id = p_tenant;
  END IF;

  RETURN QUERY SELECT v_seq, v_hash, v_recorded;
END
$$;

-- Server-side chain walk (security-auditor §4 steps 2–4 minus anchor signatures, which need
-- the Ed25519 public key outside Postgres). Returns the first break. Kinds: gap,
-- prev_mismatch, content_mismatch, hash_mismatch, and (G0 F14) for a full walk truncated
-- (rows missing below the chain head or an anchor), head_mismatch (head row disagrees with
-- the last row) and anchor_mismatch (an anchor's head_hash disagrees with its row).
CREATE FUNCTION sibyl.audit_verify(p_tenant uuid, p_from_seq bigint DEFAULT 0, p_to_seq bigint DEFAULT NULL)
RETURNS TABLE (ok boolean, rows_checked bigint, first_break_seq bigint, kind text)
LANGUAGE plpgsql STABLE SET search_path = sibyl, pg_temp AS $$
DECLARE
  r sibyl.audit_events%ROWTYPE;
  v_running bytea;
  v_expected bigint := p_from_seq;
  v_count bigint := 0;
  v_env_sha bytea;
  v_detail_sha bytea;
  v_head record;
  v_anchor bigint;
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  IF p_from_seq = 0 THEN
    v_running := decode(repeat('00', 32), 'hex');
  ELSE
    SELECT e.hash INTO v_running FROM sibyl.audit_events e
     WHERE e.tenant_id = p_tenant AND e.seq = p_from_seq - 1;
    IF v_running IS NULL THEN
      RETURN QUERY SELECT false, 0::bigint, p_from_seq - 1, 'gap'::text;
      RETURN;
    END IF;
  END IF;
  FOR r IN SELECT * FROM sibyl.audit_events e
            WHERE e.tenant_id = p_tenant AND e.seq >= p_from_seq AND (p_to_seq IS NULL OR e.seq <= p_to_seq)
            ORDER BY e.seq LOOP
    IF r.seq <> v_expected THEN
      RETURN QUERY SELECT false, v_count, v_expected, 'gap'::text;
      RETURN;
    END IF;
    IF r.prev_hash <> v_running THEN
      RETURN QUERY SELECT false, v_count, r.seq, 'prev_mismatch'::text;
      RETURN;
    END IF;
    v_env_sha := sibyl.sha256_text(sibyl.audit_envelope(r.tenant_id, r.seq, r.chain_version, r.actor_type,
      r.actor_id, r.actor_key_id, r.actor_session_id, r.action, r.resource_type, r.resource_id, r.resource_ref,
      r.reason, r.occurred_at, r.recorded_at, r.request_id));
    v_detail_sha := sibyl.sha256_text(sibyl.jcs(r.detail));
    IF v_env_sha <> r.envelope_sha256 OR v_detail_sha <> r.detail_sha256 THEN
      RETURN QUERY SELECT false, v_count, r.seq, 'content_mismatch'::text;
      RETURN;
    END IF;
    IF sha256(r.prev_hash || v_env_sha || v_detail_sha) <> r.hash THEN
      RETURN QUERY SELECT false, v_count, r.seq, 'hash_mismatch'::text;
      RETURN;
    END IF;
    v_running := r.hash;
    v_expected := v_expected + 1;
    v_count := v_count + 1;
  END LOOP;
  IF p_to_seq IS NOT NULL AND v_expected <= p_to_seq THEN
    RETURN QUERY SELECT false, v_count, v_expected, 'gap'::text;
    RETURN;
  END IF;
  SELECT min(a.seq_to) INTO v_anchor FROM sibyl.audit_anchors a
    JOIN sibyl.audit_events e ON e.tenant_id = a.tenant_id AND e.seq = a.seq_to
   WHERE a.tenant_id = p_tenant AND a.seq_to >= p_from_seq AND a.seq_to < v_expected AND e.hash <> a.head_hash;
  IF v_anchor IS NOT NULL THEN
    RETURN QUERY SELECT false, v_count, v_anchor, 'anchor_mismatch'::text;
    RETURN;
  END IF;
  IF p_to_seq IS NULL THEN
    SELECT h.seq, h.hash INTO v_head FROM sibyl.audit_chain_head h WHERE h.tenant_id = p_tenant;
    SELECT max(a.seq_to) INTO v_anchor FROM sibyl.audit_anchors a WHERE a.tenant_id = p_tenant;
    IF greatest(v_head.seq, v_anchor) >= v_expected THEN
      RETURN QUERY SELECT false, v_count, v_expected, 'truncated'::text;
      RETURN;
    END IF;
    IF v_head.seq = v_expected - 1 AND v_head.hash <> v_running THEN
      RETURN QUERY SELECT false, v_count, v_head.seq, 'head_mismatch'::text;
      RETURN;
    END IF;
  END IF;
  RETURN QUERY SELECT true, v_count, NULL::bigint, NULL::text;
END
$$;

-- Shared crypto-shred body; not executable by any login role.
CREATE FUNCTION sibyl.shred_tenant_keys(p_tenant uuid, p_erasure_request_id uuid, p_purposes text[])
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  k record;
  v_count integer := 0;
  v_prev_trigger text := current_setting('app.transition_trigger', true);
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  PERFORM set_config('app.transition_trigger', 'shred', true);
  FOR k IN SELECT id, purpose, version FROM sibyl.tenant_key
            WHERE tenant_id = p_tenant AND state <> 'shredded' AND purpose = ANY (p_purposes)
            ORDER BY purpose, version FOR UPDATE LOOP
    UPDATE sibyl.tenant_key
       SET state = 'shredded', wrapped_dek = NULL, shredded_at = now(), erasure_request_id = p_erasure_request_id
     WHERE tenant_id = p_tenant AND id = k.id;
    PERFORM sibyl.audit_append(p_tenant, 'system', NULL, NULL, NULL, 'tenant_key.shredded', 'tenant_key', k.id,
      k.purpose || ':v' || k.version, NULL,
      jsonb_build_object('key_id', k.id, 'purpose', k.purpose, 'version', k.version,
                         'erasure_request_id', p_erasure_request_id),
      NULL, now(), NULL);
    v_count := v_count + 1;
  END LOOP;
  PERFORM set_config('app.transition_trigger', coalesce(v_prev_trigger, ''), true);
  -- G0 H2: the pseudonym key goes with the tenant's keys.
  UPDATE sibyl.tenant_pseudonym_key SET hmac_key = NULL, shredded_at = now()
   WHERE tenant_id = p_tenant AND hmac_key IS NOT NULL;
  IF 'payload' = ANY (p_purposes) THEN
    UPDATE sibyl.payload_refs SET state = 'shredded', shredded_at = now()
     WHERE tenant_id = p_tenant AND state <> 'shredded';
  END IF;
  IF 'credential' = ANY (p_purposes) THEN
    UPDATE sibyl.provider_credential
       SET status = 'shredded', ciphertext = NULL, nonce = NULL
     WHERE tenant_id = p_tenant AND status <> 'shredded';
  END IF;
  RETURN v_count;
END
$$;

-- DATAMODEL §5: the only path to tenant_key.state = 'shredded'.
CREATE FUNCTION sibyl.tenant_key_shred(p_erasure_request_id uuid) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  er record;
  v_tenant uuid := sibyl.current_tenant();
BEGIN
  SELECT * INTO er FROM sibyl.erasure_request WHERE tenant_id = v_tenant AND id = p_erasure_request_id FOR UPDATE;
  IF NOT FOUND OR er.state <> 'executing' OR er.scope_kind <> 'tenant' THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: shred refused: erasure request must be executing with tenant scope' USING ERRCODE = 'SB031';
  END IF;
  IF EXISTS (SELECT 1 FROM sibyl.legal_hold h WHERE h.tenant_id = v_tenant AND h.state = 'active') THEN
    RAISE EXCEPTION 'sibyl:legal_hold_active: shred refused: an active legal hold exists' USING ERRCODE = 'SB032';
  END IF;
  RETURN sibyl.shred_tenant_keys(v_tenant, p_erasure_request_id,
    CASE WHEN er.legal_basis = 'tenant_offboarding' THEN ARRAY['payload', 'credential', 'config']
         ELSE ARRAY['payload'] END);
END
$$;

-- R63: after restoring a pre-erasure backup, the operator replays the external erasure ledger
-- through this hook. It re-shreds every key of the tenant (no legal-hold check: the erasure
-- already happened), marks the tenant erasing, and (re)opens the request in `executing` so
-- the worker re-runs the purge cascade. Executable by sibyl_migrate (operator CLI) only.
CREATE FUNCTION sibyl.erasure_reshred_restored(p_tenant uuid, p_erasure_request_id uuid, p_restore_ref text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_state text;
  v_keys integer;
  v_prev_trigger text := current_setting('app.transition_trigger', true);
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  UPDATE sibyl.tenant SET status = 'erasing' WHERE id = p_tenant AND status <> 'erased';
  SELECT state INTO v_state FROM sibyl.erasure_request WHERE tenant_id = p_tenant AND id = p_erasure_request_id;
  IF NOT FOUND THEN
    INSERT INTO sibyl.erasure_request (tenant_id, id, scope_kind, legal_basis, state, origin, execution_log)
    VALUES (p_tenant, p_erasure_request_id, 'tenant', 'other', 'executing', 'restore',
            jsonb_build_array(jsonb_build_object('step', 'restore_reshred', 'restore_ref', p_restore_ref)));
  ELSE
    -- origin = 'restore' lets the worker finish a request the backup holds unapproved (G0 M1).
    PERFORM set_config('app.transition_trigger', 'restore', true);
    UPDATE sibyl.erasure_request SET state = 'executing', origin = 'restore'
     WHERE tenant_id = p_tenant AND id = p_erasure_request_id;
    PERFORM set_config('app.transition_trigger', coalesce(v_prev_trigger, ''), true);
  END IF;
  v_keys := sibyl.shred_tenant_keys(p_tenant, p_erasure_request_id, ARRAY['payload', 'credential', 'config']);
  PERFORM sibyl.audit_append(p_tenant, 'system', NULL, NULL, NULL, 'erasure.reshredded_after_restore', 'tenant',
    p_tenant, NULL, NULL,
    jsonb_build_object('erasure_request_id', p_erasure_request_id, 'keys_shredded', v_keys,
                       'restore_ref', p_restore_ref),
    NULL, now(), NULL);
  RETURN v_keys;
END
$$;

-- Monthly audit partitions are created by their owner.
CREATE FUNCTION sibyl.partition_ensure_audit(p_from timestamptz, p_to timestamptz) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_start timestamptz := sibyl.partition_period_start('month', p_from);
  v_end timestamptz;
  v_name text;
  v_created integer := 0;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('partition:audit_events', 0));
  WHILE v_start < p_to LOOP
    v_end := v_start + interval '1 month';
    v_name := 'audit_events_p' || to_char(v_start AT TIME ZONE 'UTC', 'YYYYMM');
    IF to_regclass('sibyl.' || v_name) IS NULL THEN
      EXECUTE format('CREATE TABLE sibyl.%I PARTITION OF sibyl.audit_events FOR VALUES FROM (%L) TO (%L)',
                     v_name, v_start, v_end);
      PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', v_name)::regclass);
      INSERT INTO sibyl.partition_registry (table_name, partition_name, grain, range_from, range_to)
      VALUES ('audit_events', v_name, 'month', v_start, v_end)
      ON CONFLICT (table_name, partition_name) DO NOTHING;
      v_created := v_created + 1;
    END IF;
    v_start := v_end;
  END LOOP;
  RETURN v_created;
END
$$;

REVOKE EXECUTE ON FUNCTION sibyl.shred_tenant_keys(uuid, uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sibyl.audit_append(uuid, text, uuid, uuid, uuid, text, text, uuid, text, text, jsonb,
  bytea, timestamptz, uuid) TO sibyl_app, sibyl_worker, sibyl_ingest, sibyl_routing, sibyl_migrate;
GRANT EXECUTE ON FUNCTION sibyl.audit_verify(uuid, bigint, bigint), sibyl.audit_envelope(uuid, bigint, smallint,
  text, uuid, uuid, uuid, text, text, uuid, text, text, timestamptz, timestamptz, uuid)
  TO sibyl_app, sibyl_worker, sibyl_ingest;
GRANT EXECUTE ON FUNCTION sibyl.tenant_key_shred(uuid) TO sibyl_worker;
GRANT EXECUTE ON FUNCTION sibyl.erasure_reshred_restored(uuid, uuid, text) TO sibyl_migrate;
GRANT EXECUTE ON FUNCTION sibyl.partition_ensure_audit(timestamptz, timestamptz) TO sibyl_migrate, sibyl_worker;
GRANT SELECT ON sibyl.audit_events, sibyl.audit_anchors, sibyl.audit_chain_head
  TO sibyl_app, sibyl_worker, sibyl_ingest, sibyl_migrate;
GRANT EXECUTE ON FUNCTION sibyl.audit_lock(uuid) TO sibyl_app, sibyl_worker, sibyl_ingest, sibyl_routing, sibyl_migrate;
GRANT SELECT (tenant_id, id, created_at, shredded_at) ON sibyl.tenant_pseudonym_key
  TO sibyl_app, sibyl_worker, sibyl_migrate;
GRANT EXECUTE ON FUNCTION sibyl.pseudonym_key_create(uuid), sibyl.pseudonym_hex(uuid, text) TO sibyl_migrate;
GRANT EXECUTE ON FUNCTION sibyl.pseudonymise(text) TO sibyl_app, sibyl_worker;
GRANT INSERT ON sibyl.audit_anchors TO sibyl_worker;

RESET ROLE;
