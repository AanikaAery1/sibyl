-- 0003 identity (DATAMODEL §4.1): agent_group, app_user, oidc_issuer, session, membership,
-- api_key. FKs into later domains (agent, tenant_key) are added in those migrations.
-- Every tenant table: tenant_id first, PK (tenant_id, id), composite FKs, one RLS policy.

CREATE TABLE sibyl.agent_group (
  tenant_id        uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id               uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  slug             text        NOT NULL,
  name             text        NOT NULL,
  description      text,
  parent_group_id  uuid,
  owner_user_id    uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_agent_group_slug UNIQUE (tenant_id, slug),
  CONSTRAINT fk_agent_group_parent FOREIGN KEY (tenant_id, parent_group_id)
    REFERENCES sibyl.agent_group (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE
);

CREATE TABLE sibyl.app_user (
  tenant_id        uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id               uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  oidc_issuer_id   uuid        NOT NULL,
  subject          text        NOT NULL,
  email            sibyl.citext NOT NULL,
  email_verified   boolean     NOT NULL DEFAULT false,
  display_name     text,
  status           text        NOT NULL DEFAULT 'invited',
  last_login_at    timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_app_user_subject UNIQUE (tenant_id, oidc_issuer_id, subject),
  CONSTRAINT ck_app_user_status CHECK (status IN ('invited', 'active', 'disabled', 'deprovisioned'))
);
CREATE INDEX ix_app_user_email ON sibyl.app_user (tenant_id, email);

ALTER TABLE sibyl.agent_group ADD CONSTRAINT fk_agent_group_owner FOREIGN KEY (tenant_id, owner_user_id)
  REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

CREATE TABLE sibyl.oidc_issuer (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  issuer_url            text        NOT NULL,
  client_id             text        NOT NULL,
  client_secret_ct      bytea,
  client_secret_key_id  uuid,
  allowed_email_domains text[]      NOT NULL DEFAULT '{}',
  role_claim            text,
  role_claim_map        jsonb       NOT NULL DEFAULT '{}',
  jit_default_role      text        REFERENCES sibyl.role (name),
  status                text        NOT NULL DEFAULT 'active',
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_oidc_issuer_url UNIQUE (tenant_id, issuer_url),
  CONSTRAINT ck_oidc_issuer_status CHECK (status IN ('active', 'disabled')),
  CONSTRAINT ck_oidc_issuer_jit_default_role CHECK (jit_default_role NOT IN ('owner', 'admin', 'security_admin')),
  CONSTRAINT ck_oidc_issuer_secret_key CHECK ((client_secret_ct IS NULL) = (client_secret_key_id IS NULL))
);

ALTER TABLE sibyl.app_user ADD CONSTRAINT fk_app_user_issuer FOREIGN KEY (tenant_id, oidc_issuer_id)
  REFERENCES sibyl.oidc_issuer (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

CREATE TABLE sibyl.session (
  tenant_id            uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                   uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  user_id              uuid        NOT NULL,
  token_hash           bytea       NOT NULL,
  issued_at            timestamptz NOT NULL DEFAULT now(),
  absolute_expires_at  timestamptz NOT NULL DEFAULT now() + interval '8 hours',
  idle_expires_at      timestamptz NOT NULL DEFAULT now() + interval '30 minutes',
  last_seen_at         timestamptz NOT NULL DEFAULT now(),
  step_up_at           timestamptz,
  ip_hash              bytea,
  ua_class             text,
  revoked_at           timestamptz,
  revoke_reason        text,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_session_user FOREIGN KEY (tenant_id, user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_session_token_hash CHECK (octet_length(token_hash) = 32)
);
-- Global lookup before the tenant is known (index-leading-tenant exception, see sibyl.session_resolve).
CREATE UNIQUE INDEX ux_session_token_hash ON sibyl.session (token_hash);
CREATE INDEX ix_session_idle ON sibyl.session (tenant_id, idle_expires_at) WHERE revoked_at IS NULL;

CREATE TABLE sibyl.membership (
  tenant_id    uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id           uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  user_id      uuid        NOT NULL,
  role_name    text        NOT NULL REFERENCES sibyl.role (name),
  scope_kind   text        NOT NULL DEFAULT 'tenant',
  scope_id     uuid,
  granted_by   uuid,
  expires_at   timestamptz,
  revoked_at   timestamptz,
  revoked_by   uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_membership_user FOREIGN KEY (tenant_id, user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_membership_group FOREIGN KEY (tenant_id, scope_id)
    REFERENCES sibyl.agent_group (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_membership_granted_by FOREIGN KEY (tenant_id, granted_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_membership_revoked_by FOREIGN KEY (tenant_id, revoked_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_membership_scope_kind CHECK (scope_kind IN ('tenant', 'agent_group')),
  CONSTRAINT ck_membership_tenant_roles CHECK (
    role_name NOT IN ('owner', 'admin', 'security_admin', 'auditor') OR scope_kind = 'tenant'),
  CONSTRAINT ck_membership_scope_id CHECK ((scope_kind = 'agent_group') = (scope_id IS NOT NULL))
);
CREATE UNIQUE INDEX ux_membership_grant ON sibyl.membership
  (tenant_id, user_id, role_name, scope_kind, coalesce(scope_id, sibyl.nil_uuid()));

-- At least one active owner per tenant once one exists (deferred; DATAMODEL §4.1).
-- Skipped while the tenant is erasing/erased (the erasure cascade removes memberships).
CREATE FUNCTION sibyl.trg_membership_owner_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_status text;
BEGIN
  IF OLD.role_name <> 'owner' OR OLD.revoked_at IS NOT NULL THEN
    RETURN NULL;
  END IF;
  SELECT status INTO v_status FROM sibyl.tenant WHERE id = OLD.tenant_id;
  IF v_status IN ('erasing', 'erased') THEN
    RETURN NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM sibyl.membership m
                  WHERE m.tenant_id = OLD.tenant_id AND m.role_name = 'owner'
                    AND m.revoked_at IS NULL AND (m.expires_at IS NULL OR m.expires_at > now())) THEN
    RAISE EXCEPTION 'sibyl:owner_required: tenant % must keep at least one active owner', OLD.tenant_id USING ERRCODE = 'SB042';
  END IF;
  RETURN NULL;
END
$$;
CREATE CONSTRAINT TRIGGER trg_membership_owner_guard AFTER UPDATE OR DELETE ON sibyl.membership
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sibyl.trg_membership_owner_guard();

-- api_key (R12, R13, R21/D30, R22, D20; API §12.4). Format sbl_<env>_<prefix12>_<secret> lives
-- in the api; the DB holds the 12-char prefix and the HMAC-SHA-256 of the secret.
CREATE TABLE sibyl.api_key (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                    uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id              uuid,
  name                  text        NOT NULL,
  env                   text        NOT NULL,
  prefix                char(12)    NOT NULL,
  secret_hash           bytea       NOT NULL,
  scopes                text[]      NOT NULL,
  status                text        NOT NULL DEFAULT 'active',
  expires_at            timestamptz NOT NULL,
  last_used_at          timestamptz,
  last_used_ip_hash     bytea,
  rotated_from_id       uuid,
  rotation_grace_until  timestamptz,
  created_by            uuid,
  revoked_at            timestamptz,
  revoked_by            uuid,
  revoke_reason         text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_api_key_rotated_from FOREIGN KEY (tenant_id, rotated_from_id)
    REFERENCES sibyl.api_key (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_api_key_created_by FOREIGN KEY (tenant_id, created_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_api_key_revoked_by FOREIGN KEY (tenant_id, revoked_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_api_key_env CHECK (env IN ('live', 'test')),
  CONSTRAINT ck_api_key_status CHECK (status IN ('active', 'rotating', 'revoked', 'expired')),
  CONSTRAINT ck_api_key_prefix CHECK (prefix ~ '^[A-Za-z0-9]{12}$'),
  CONSTRAINT ck_api_key_secret_hash CHECK (octet_length(secret_hash) = 32),
  CONSTRAINT ck_api_key_scopes CHECK (
    scopes <@ ARRAY['ingest:write', 'gateway:proxy', 'routing:read', 'handoff:write',
                    'agents:read', 'agents:write', 'killswitch:pull']::text[]
    AND cardinality(scopes) >= 1
    AND ('killswitch:pull' <> ALL (scopes) OR scopes = ARRAY['killswitch:pull']::text[])),
  CONSTRAINT ck_api_key_breakglass_tenant_level CHECK (
    scopes <> ARRAY['killswitch:pull']::text[] OR (agent_id IS NULL AND env = 'live')),
  CONSTRAINT ck_api_key_revoked CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CONSTRAINT ck_api_key_lifetime CHECK (expires_at <= created_at + interval '400 days')
);
-- Global prefix lookup before the tenant is known (see sibyl.api_key_resolve).
CREATE UNIQUE INDEX ux_api_key_prefix ON sibyl.api_key (prefix);
CREATE INDEX ix_api_key_agent ON sibyl.api_key (tenant_id, agent_id);
CREATE INDEX ix_api_key_active ON sibyl.api_key (tenant_id) WHERE status = 'active';

-- API §2.2 rule 3: at most two active break-glass keys per tenant.
CREATE FUNCTION sibyl.trg_api_key_breakglass_limit() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.scopes = ARRAY['killswitch:pull']::text[] AND NEW.status = 'active' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('breakglass:' || NEW.tenant_id::text, 0));
    IF (SELECT count(*) FROM sibyl.api_key k
         WHERE k.tenant_id = NEW.tenant_id AND k.id <> NEW.id AND k.status = 'active'
           AND k.scopes = ARRAY['killswitch:pull']::text[]) >= 2 THEN
      RAISE EXCEPTION 'sibyl:breakglass_limit: at most two active break-glass keys per tenant' USING ERRCODE = 'SB047';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_api_key_breakglass_limit BEFORE INSERT OR UPDATE OF status, scopes ON sibyl.api_key
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_api_key_breakglass_limit();

-- API §2.2 / G0 security L3: a key's grant is fixed at issue. In place, scopes may only
-- narrow and expiry only come sooner; binding, identity and secret never change. Widening,
-- rebinding or extending means rotation, which issues a new key.
CREATE FUNCTION sibyl.trg_api_key_immutable_fields() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.id <> OLD.id OR NEW.prefix <> OLD.prefix
     OR NEW.secret_hash <> OLD.secret_hash OR NEW.env <> OLD.env
     OR NEW.agent_id IS DISTINCT FROM OLD.agent_id OR NEW.created_at <> OLD.created_at
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.rotated_from_id IS DISTINCT FROM OLD.rotated_from_id
     OR NOT (NEW.scopes <@ OLD.scopes) OR NEW.expires_at > OLD.expires_at THEN
    RAISE EXCEPTION 'sibyl:key_field_immutable: api_key % may only narrow scopes or shorten expiry in place; rotate instead', OLD.id
      USING ERRCODE = 'SB044';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_api_key_immutable_fields BEFORE UPDATE ON sibyl.api_key
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_api_key_immutable_fields();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['agent_group', 'app_user', 'oidc_issuer', 'session', 'membership', 'api_key'] LOOP
    PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', t)::regclass);
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON sibyl.%I FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at()',
                   'trg_' || t || '_updated_at', t);
  END LOOP;
END
$$;

-- Pre-tenant lookups (DATAMODEL §6.1 step 1). Under FORCE RLS a lookup with no tenant set
-- sees nothing, so prefix/token resolution runs in a SECURITY DEFINER owned by the NOLOGIN
-- sibyl_audit, the one identity the policy lets read across tenants (reads only: WITH CHECK
-- still pins writes to the transaction tenant, and sibyl_audit holds SELECT only).
DROP POLICY rls_tenant_api_key ON sibyl.api_key;
CREATE POLICY rls_tenant_api_key ON sibyl.api_key
  USING (tenant_id = sibyl.current_tenant() OR current_user = 'sibyl_audit')
  WITH CHECK (tenant_id = sibyl.current_tenant());
DROP POLICY rls_tenant_session ON sibyl.session;
CREATE POLICY rls_tenant_session ON sibyl.session
  USING (tenant_id = sibyl.current_tenant() OR current_user = 'sibyl_audit')
  WITH CHECK (tenant_id = sibyl.current_tenant());
GRANT SELECT ON sibyl.api_key, sibyl.session TO sibyl_audit;

SET LOCAL ROLE sibyl_audit;

CREATE FUNCTION sibyl.api_key_lookup(prefix text)
RETURNS TABLE (tenant_id uuid, id uuid, env text, secret_hash bytea, scopes text[], agent_id uuid,
               status text, expires_at timestamptz, rotation_grace_until timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT k.tenant_id, k.id, k.env, k.secret_hash, k.scopes, k.agent_id, k.status, k.expires_at,
         k.rotation_grace_until
  FROM sibyl.api_key k WHERE k.prefix = api_key_lookup.prefix
$$;

CREATE FUNCTION sibyl.session_resolve(p_token_hash bytea)
RETURNS TABLE (tenant_id uuid, id uuid, user_id uuid, absolute_expires_at timestamptz,
               idle_expires_at timestamptz, step_up_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT s.tenant_id, s.id, s.user_id, s.absolute_expires_at, s.idle_expires_at, s.step_up_at, s.revoked_at
  FROM sibyl.session s WHERE s.token_hash = p_token_hash
$$;

GRANT EXECUTE ON FUNCTION sibyl.api_key_lookup(text) TO sibyl_app, sibyl_ingest;
GRANT EXECUTE ON FUNCTION sibyl.session_resolve(bytea) TO sibyl_app;

RESET ROLE;

-- Grant matrix (DATAMODEL §3 writer column). secret_hash is readable by app and ingest only.
GRANT SELECT, INSERT, UPDATE, DELETE ON sibyl.agent_group, sibyl.oidc_issuer TO sibyl_app;
GRANT SELECT, INSERT, UPDATE ON sibyl.app_user, sibyl.session, sibyl.membership, sibyl.api_key TO sibyl_app;
GRANT SELECT ON sibyl.agent_group, sibyl.app_user, sibyl.oidc_issuer, sibyl.membership
  TO sibyl_worker, sibyl_ingest;
GRANT SELECT, DELETE ON sibyl.session TO sibyl_worker;
GRANT SELECT ON sibyl.api_key TO sibyl_ingest;
GRANT UPDATE (last_used_at, last_used_ip_hash) ON sibyl.api_key TO sibyl_ingest;
GRANT SELECT (tenant_id, id, agent_id, name, env, prefix, scopes, status, expires_at, last_used_at,
  rotated_from_id, rotation_grace_until, created_by, revoked_at, revoked_by, revoke_reason,
  created_at, updated_at) ON sibyl.api_key TO sibyl_worker;
GRANT UPDATE (status, updated_at) ON sibyl.api_key TO sibyl_worker;
