-- 0005 policy & security (DATAMODEL §4.7): tenant_key, redaction_profile, capture_policy,
-- provider_credential (+ provider_credential_meta view and column grants).

CREATE TABLE sibyl.tenant_key (
  tenant_id           uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                  uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  purpose             text        NOT NULL,
  version             integer     NOT NULL,
  algorithm           text        NOT NULL DEFAULT 'AES-256-GCM',
  wrapped_dek         bytea,
  kek_id              text        NOT NULL,
  state               text        NOT NULL DEFAULT 'active',
  activated_at        timestamptz NOT NULL DEFAULT now(),
  retired_at          timestamptz,
  shredded_at         timestamptz,
  erasure_request_id  uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_tenant_key_version UNIQUE (tenant_id, purpose, version),
  CONSTRAINT ck_tenant_key_purpose CHECK (purpose IN ('payload', 'credential', 'config')),
  CONSTRAINT ck_tenant_key_state CHECK (state IN ('active', 'retired', 'shredded')),
  CONSTRAINT ck_tenant_key_shredded_dek CHECK ((state = 'shredded') = (wrapped_dek IS NULL)),
  CONSTRAINT ck_tenant_key_shredded_request CHECK ((state = 'shredded') = (erasure_request_id IS NOT NULL)),
  CONSTRAINT ck_tenant_key_version CHECK (version >= 1)
);
CREATE UNIQUE INDEX ux_tenant_key_active ON sibyl.tenant_key (tenant_id, purpose) WHERE state = 'active';
CREATE TRIGGER trg_tenant_key_state_edge BEFORE UPDATE OF state ON sibyl.tenant_key
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('tenant_key', 'state');

-- `shredded` is reachable only inside tenant_key_shred() (owner sibyl_audit), whatever GUCs
-- the caller sets; the shredded row is then frozen.
CREATE FUNCTION sibyl.trg_tenant_key_shred_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state = 'shredded' THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: a shredded tenant_key is immutable' USING ERRCODE = 'SB031';
  END IF;
  IF NEW.state = 'shredded' AND current_user <> 'sibyl_audit' THEN
    RAISE EXCEPTION 'sibyl:erasure_refused: tenant_key can only be shredded by tenant_key_shred()' USING ERRCODE = 'SB031';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_tenant_key_shred_guard BEFORE UPDATE ON sibyl.tenant_key
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_tenant_key_shred_guard();

ALTER TABLE sibyl.oidc_issuer ADD CONSTRAINT fk_oidc_issuer_secret_key FOREIGN KEY (tenant_id, client_secret_key_id)
  REFERENCES sibyl.tenant_key (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

-- secrets_only baseline detector ids (API §10.3, registry v1 in sibyl-schemas).
CREATE FUNCTION sibyl.secrets_baseline_detector_ids() RETURNS text[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT ARRAY['sibyl_key', 'openai_key', 'anthropic_key', 'aws_access_key', 'aws_secret_key', 'gcp_sa_key',
               'azure_conn_string', 'github_token', 'slack_token', 'stripe_key', 'jwt', 'bearer_header',
               'basic_auth_url', 'dsn', 'pem_block', 'ssh_key', 'generic_secret_kv', 'high_entropy']
$$;

CREATE FUNCTION sibyl.redaction_covers_baseline(p_detectors jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT jsonb_typeof(p_detectors) = 'array'
     AND (SELECT coalesce(array_agg(d->>'id'), '{}') FROM jsonb_array_elements(p_detectors) AS d)
         @> sibyl.secrets_baseline_detector_ids()
$$;

-- Immutable, content-addressed (R15). content_canonical is the JCS text of
-- {"detectors": ..., "replacement_format": ...} computed by sibyl-schemas; the CHECKs prove
-- it is the same document (R11 pattern) and that content_hash is its sha256.
CREATE TABLE sibyl.redaction_profile (
  tenant_id           uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                  uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  name                text        NOT NULL,
  version_no          integer     NOT NULL,
  origin              text        NOT NULL,
  detectors           jsonb       NOT NULL,
  replacement_format  text        NOT NULL DEFAULT '[{kind}:{hash8}]',
  content_canonical   text        NOT NULL,
  content_hash        bytea       NOT NULL,
  created_by          uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_redaction_profile_version UNIQUE (tenant_id, name, version_no),
  CONSTRAINT fk_redaction_profile_created_by FOREIGN KEY (tenant_id, created_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_redaction_profile_origin CHECK (origin IN ('system', 'custom')),
  CONSTRAINT ck_redaction_profile_baseline CHECK (sibyl.redaction_covers_baseline(detectors)),
  CONSTRAINT ck_redaction_profile_canonical CHECK (
    content_canonical::jsonb = jsonb_build_object('detectors', detectors, 'replacement_format', replacement_format)),
  CONSTRAINT ck_redaction_profile_hash CHECK (content_hash = sibyl.sha256_text(content_canonical))
);
CREATE INDEX ix_redaction_profile_hash ON sibyl.redaction_profile (tenant_id, content_hash);

CREATE TABLE sibyl.capture_policy (
  tenant_id               uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                      uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  scope_kind              text        NOT NULL,
  agent_id                uuid,
  capture_mode            text        NOT NULL,
  redaction_profile_id    uuid        NOT NULL,
  payload_retention_days  integer     NOT NULL DEFAULT 30,
  max_payload_bytes       integer     NOT NULL DEFAULT 262144,
  header_allowlist        text[]      NOT NULL DEFAULT '{}',
  consequences_version    text        NOT NULL,
  chosen_by               uuid        NOT NULL,
  chosen_at               timestamptz NOT NULL DEFAULT now(),
  version_no              integer     NOT NULL,
  superseded_by           uuid,
  created_at              timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_capture_policy_version UNIQUE NULLS NOT DISTINCT (tenant_id, scope_kind, agent_id, version_no),
  CONSTRAINT fk_capture_policy_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_capture_policy_profile FOREIGN KEY (tenant_id, redaction_profile_id)
    REFERENCES sibyl.redaction_profile (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_capture_policy_chosen_by FOREIGN KEY (tenant_id, chosen_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_capture_policy_superseded_by FOREIGN KEY (tenant_id, superseded_by)
    REFERENCES sibyl.capture_policy (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_capture_policy_scope_kind CHECK (scope_kind IN ('tenant', 'agent')),
  CONSTRAINT ck_capture_policy_agent CHECK ((scope_kind = 'agent') = (agent_id IS NOT NULL)),
  CONSTRAINT ck_capture_policy_capture_mode CHECK (capture_mode IN ('full', 'redacted', 'metadata')),
  CONSTRAINT ck_capture_policy_retention CHECK (payload_retention_days BETWEEN 1 AND 365),
  CONSTRAINT ck_capture_policy_max_payload CHECK (max_payload_bytes BETWEEN 0 AND 16777216),
  CONSTRAINT ck_capture_policy_headers CHECK (
    NOT (header_allowlist && ARRAY['authorization', 'cookie', 'x-api-key', 'api-key', 'proxy-authorization',
                                   'set-cookie', 'x-sibyl-key']))
);
CREATE UNIQUE INDEX ux_capture_policy_active ON sibyl.capture_policy
  (tenant_id, scope_kind, coalesce(agent_id, sibyl.nil_uuid())) WHERE superseded_by IS NULL;

CREATE FUNCTION sibyl.capture_mode_rank(p_mode text) RETURNS smallint
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE p_mode WHEN 'metadata' THEN 0 WHEN 'redacted' THEN 1 WHEN 'full' THEN 2 END::smallint
$$;

-- An agent policy may be stricter than the active tenant policy, never looser (D12).
CREATE FUNCTION sibyl.trg_capture_policy_strictness() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  t record;
BEGIN
  IF NEW.scope_kind <> 'agent' THEN
    RETURN NEW;
  END IF;
  SELECT capture_mode, payload_retention_days INTO t FROM sibyl.capture_policy
   WHERE tenant_id = NEW.tenant_id AND scope_kind = 'tenant' AND superseded_by IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'sibyl:capture_policy_looser: agent capture policy requires an active tenant policy' USING ERRCODE = 'SB043';
  END IF;
  IF sibyl.capture_mode_rank(NEW.capture_mode) > sibyl.capture_mode_rank(t.capture_mode)
     OR NEW.payload_retention_days > t.payload_retention_days THEN
    RAISE EXCEPTION 'sibyl:capture_policy_looser: agent capture policy is looser than the tenant policy' USING ERRCODE = 'SB043';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_capture_policy_strictness BEFORE INSERT ON sibyl.capture_policy
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_capture_policy_strictness();

CREATE TABLE sibyl.provider_credential (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  provider_id           uuid        NOT NULL,
  name                  text        NOT NULL,
  purpose               text        NOT NULL DEFAULT 'fallback',
  base_url              text        NOT NULL,
  allowlist_basis       text        NOT NULL,
  auth_scheme           text        NOT NULL,
  ciphertext            bytea,
  nonce                 bytea,
  tenant_key_id         uuid        NOT NULL,
  key_version           integer     NOT NULL,
  secret_sha256         bytea       NOT NULL,
  secret_hint           char(4),
  status                text        NOT NULL DEFAULT 'active',
  rotated_from_id       uuid,
  rotation_grace_until  timestamptz,
  expires_at            timestamptz,
  last_used_at          timestamptz,
  last_verified_at      timestamptz,
  created_by            uuid        NOT NULL,
  revoked_at            timestamptz,
  revoke_reason         text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_provider_credential_provider FOREIGN KEY (tenant_id, provider_id)
    REFERENCES sibyl.provider (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_provider_credential_key FOREIGN KEY (tenant_id, tenant_key_id)
    REFERENCES sibyl.tenant_key (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_provider_credential_rotated_from FOREIGN KEY (tenant_id, rotated_from_id)
    REFERENCES sibyl.provider_credential (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_provider_credential_created_by FOREIGN KEY (tenant_id, created_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_provider_credential_purpose CHECK (purpose IN ('fallback', 'probe')),
  CONSTRAINT ck_provider_credential_base_url CHECK (sibyl.is_allowlisted_base_url(base_url)),
  CONSTRAINT ck_provider_credential_allowlist_basis CHECK (allowlist_basis IN ('known_provider', 'resolver_checked')),
  CONSTRAINT ck_provider_credential_status CHECK (status IN ('active', 'rotating', 'revoked', 'expired', 'shredded')),
  CONSTRAINT ck_provider_credential_ciphertext CHECK ((status IN ('revoked', 'shredded')) = (ciphertext IS NULL)),
  CONSTRAINT ck_provider_credential_nonce CHECK ((ciphertext IS NULL) = (nonce IS NULL)
                                                 AND (nonce IS NULL OR octet_length(nonce) = 12)),
  CONSTRAINT ck_provider_credential_secret_sha256 CHECK (octet_length(secret_sha256) = 32)
);
CREATE INDEX ix_provider_credential_provider ON sibyl.provider_credential (tenant_id, provider_id);
CREATE INDEX ix_provider_credential_active ON sibyl.provider_credential (tenant_id) WHERE status = 'active';

CREATE VIEW sibyl.provider_credential_meta WITH (security_invoker = true) AS
  SELECT tenant_id, id, provider_id, name, purpose, base_url, allowlist_basis, auth_scheme, tenant_key_id,
         key_version, secret_hint, status, rotated_from_id, rotation_grace_until, expires_at, last_used_at,
         last_verified_at, created_by, revoked_at, revoke_reason, created_at, updated_at
  FROM sibyl.provider_credential;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenant_key', 'redaction_profile', 'capture_policy', 'provider_credential'] LOOP
    PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', t)::regclass);
  END LOOP;
END
$$;
CREATE TRIGGER trg_tenant_key_updated_at BEFORE UPDATE ON sibyl.tenant_key
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();
CREATE TRIGGER trg_provider_credential_updated_at BEFORE UPDATE ON sibyl.provider_credential
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();
CREATE TRIGGER trg_redaction_profile_immutable BEFORE UPDATE OR DELETE ON sibyl.redaction_profile
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_redaction_profile_no_truncate BEFORE TRUNCATE ON sibyl.redaction_profile
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_capture_policy_immutable BEFORE UPDATE OR DELETE ON sibyl.capture_policy
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation('allow_supersede');
CREATE TRIGGER trg_capture_policy_no_truncate BEFORE TRUNCATE ON sibyl.capture_policy
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();

-- Key rotation (chair, POST /api/v1/tenant-keys/{purpose}/rotate): retire version n, insert
-- n+1 as active, one transaction. The new DEK is wrapped by the api (the KEK never enters
-- Postgres), so it is an argument. The handler writes the tenant_key.rotated audit row.
CREATE FUNCTION sibyl.tenant_key_rotate(p_purpose text, p_wrapped_dek bytea, p_kek_id text)
RETURNS TABLE (active_id uuid, retired_id uuid)
LANGUAGE plpgsql AS $$
DECLARE
  v_tenant uuid := sibyl.current_tenant();
  v_old record;
  v_new uuid;
  v_prev_trigger text := current_setting('app.transition_trigger', true);
BEGIN
  IF (SELECT status FROM sibyl.tenant WHERE id = v_tenant) IN ('erasing', 'erased') THEN
    RAISE EXCEPTION 'sibyl:tenant_erasing: keys cannot rotate during erasure' USING ERRCODE = 'SB033';
  END IF;
  IF p_wrapped_dek IS NULL OR coalesce(p_kek_id, '') = '' THEN
    RAISE EXCEPTION 'sibyl:tenant_create_invalid: rotation needs a wrapped DEK and a KEK id' USING ERRCODE = 'SB049';
  END IF;
  SELECT id, version INTO v_old FROM sibyl.tenant_key
   WHERE tenant_id = v_tenant AND purpose = p_purpose AND state = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'sibyl:invalid_transition: no active % key to rotate', p_purpose USING ERRCODE = 'SB010';
  END IF;
  PERFORM set_config('app.transition_trigger', 'rotate', true);
  UPDATE sibyl.tenant_key SET state = 'retired', retired_at = now() WHERE tenant_id = v_tenant AND id = v_old.id;
  PERFORM set_config('app.transition_trigger', coalesce(v_prev_trigger, ''), true);
  INSERT INTO sibyl.tenant_key (tenant_id, purpose, version, wrapped_dek, kek_id)
  VALUES (v_tenant, p_purpose, v_old.version + 1, p_wrapped_dek, p_kek_id) RETURNING id INTO v_new;
  RETURN QUERY SELECT v_new, v_old.id;
END
$$;
GRANT EXECUTE ON FUNCTION sibyl.tenant_key_rotate(text, bytea, text) TO sibyl_app, sibyl_worker;

-- Grant matrix. ciphertext/nonce are readable by sibyl_app only (DATAMODEL §4.7).
GRANT SELECT, INSERT ON sibyl.tenant_key TO sibyl_app;
GRANT UPDATE (state, retired_at) ON sibyl.tenant_key TO sibyl_app;
GRANT SELECT, INSERT ON sibyl.tenant_key TO sibyl_worker;
GRANT UPDATE (state, retired_at) ON sibyl.tenant_key TO sibyl_worker;
GRANT SELECT ON sibyl.tenant_key TO sibyl_ingest;
GRANT SELECT, UPDATE (state, wrapped_dek, shredded_at, erasure_request_id) ON sibyl.tenant_key TO sibyl_audit;
GRANT SELECT, INSERT ON sibyl.redaction_profile, sibyl.capture_policy TO sibyl_app;
GRANT UPDATE (superseded_by) ON sibyl.capture_policy TO sibyl_app;
GRANT SELECT ON sibyl.redaction_profile, sibyl.capture_policy TO sibyl_ingest, sibyl_worker;
GRANT SELECT, INSERT, UPDATE ON sibyl.provider_credential TO sibyl_app;
GRANT SELECT (tenant_id, id, provider_id, name, purpose, base_url, allowlist_basis, auth_scheme, tenant_key_id,
  key_version, secret_hint, status, rotated_from_id, rotation_grace_until, expires_at, last_used_at,
  last_verified_at, created_by, revoked_at, revoke_reason, created_at, updated_at)
  ON sibyl.provider_credential TO sibyl_worker, sibyl_ingest;
GRANT UPDATE (status, last_verified_at, updated_at) ON sibyl.provider_credential TO sibyl_worker;
GRANT SELECT ON sibyl.provider_credential_meta TO sibyl_app, sibyl_worker, sibyl_ingest;
GRANT EXECUTE ON FUNCTION sibyl.secrets_baseline_detector_ids(), sibyl.redaction_covers_baseline(jsonb),
  sibyl.capture_mode_rank(text) TO sibyl_app, sibyl_ingest, sibyl_worker, sibyl_audit, sibyl_routing;
