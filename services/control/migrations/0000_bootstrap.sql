-- sibyl:run-as=admin
-- 0000 bootstrap. The only step that needs an administrative role (superuser locally,
-- rds_superuser / cloudsqlsuperuser in the cloud). Everything after this runs as the
-- non-superuser sibyl_migrate. Idempotent: roles are cluster-wide and shared by every
-- database on the cluster, so each statement tolerates a previous run.

-- Six roles (R58/X7). Login roles carry no password here; deployment sets them.
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT * FROM (VALUES
      ('sibyl_migrate', true),
      ('sibyl_app',     true),
      ('sibyl_ingest',  true),
      ('sibyl_worker',  true),
      ('sibyl_audit',   false),
      ('sibyl_routing', false)) AS v(name, can_login)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.name) THEN
      EXECUTE format('CREATE ROLE %I %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION',
                     r.name, CASE WHEN r.can_login THEN 'LOGIN' ELSE 'NOLOGIN' END);
    ELSE
      EXECUTE format('ALTER ROLE %I %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION',
                     r.name, CASE WHEN r.can_login THEN 'LOGIN' ELSE 'NOLOGIN' END);
    END IF;
  END LOOP;
END
$$;

-- sibyl_migrate creates the privileged tables and SECURITY DEFINER functions by
-- SET ROLE to their NOLOGIN owners; it does not inherit their privileges (PG16+ syntax).
GRANT sibyl_audit   TO sibyl_migrate WITH INHERIT FALSE, SET TRUE;
GRANT sibyl_routing TO sibyl_migrate WITH INHERIT FALSE, SET TRUE;

-- Lock down the public schema (DATAMODEL §7 migration 9 rule, applied first).
REVOKE ALL ON SCHEMA public FROM PUBLIC;

DO $$
BEGIN
  EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO sibyl_migrate, sibyl_app, sibyl_ingest, sibyl_worker',
                 current_database());
END
$$;

CREATE SCHEMA IF NOT EXISTS sibyl AUTHORIZATION sibyl_migrate;
REVOKE ALL ON SCHEMA sibyl FROM PUBLIC;
GRANT USAGE ON SCHEMA sibyl TO sibyl_app, sibyl_ingest, sibyl_worker, sibyl_audit, sibyl_routing;
GRANT CREATE ON SCHEMA sibyl TO sibyl_audit, sibyl_routing;

-- Extension allowlist (R58: pgcrypto, citext, pg_trgm, btree_gin, pgaudit; pgvector is Phase 3).
-- Extensions live in schema sibyl so SECURITY DEFINER bodies resolve them with
-- search_path = sibyl, pg_temp. pgaudit is created only where the server ships it.
CREATE EXTENSION IF NOT EXISTS pgcrypto  WITH SCHEMA sibyl;
CREATE EXTENSION IF NOT EXISTS citext    WITH SCHEMA sibyl;
CREATE EXTENSION IF NOT EXISTS pg_trgm   WITH SCHEMA sibyl;
CREATE EXTENSION IF NOT EXISTS btree_gin WITH SCHEMA sibyl;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pgaudit')
     AND current_setting('shared_preload_libraries') LIKE '%pgaudit%' THEN
    EXECUTE 'CREATE EXTENSION IF NOT EXISTS pgaudit';
  ELSE
    RAISE NOTICE 'pgaudit not available on this server; skipped (allowlisted, optional)';
  END IF;
END
$$;

-- Global (not per-schema) default privileges: a per-schema entry can only add to the global
-- PUBLIC EXECUTE default, never revoke it.
ALTER DEFAULT PRIVILEGES FOR ROLE sibyl_migrate REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE sibyl_audit   REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE sibyl_routing REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Session defaults for the service roles: tenant context is transaction-local only.
ALTER ROLE sibyl_app    SET search_path = sibyl, pg_temp;
ALTER ROLE sibyl_ingest SET search_path = sibyl, pg_temp;
ALTER ROLE sibyl_worker SET search_path = sibyl, pg_temp;
ALTER ROLE sibyl_migrate SET search_path = sibyl, pg_temp;

-- Migration ledger (owned by sibyl_migrate; the runner records version + checksum here).
CREATE TABLE IF NOT EXISTS sibyl.schema_migrations (
  version     integer     PRIMARY KEY,
  name        text        NOT NULL,
  checksum    text        NOT NULL,
  applied_at  timestamptz NOT NULL DEFAULT now(),
  applied_by  text        NOT NULL DEFAULT current_user
);
ALTER TABLE sibyl.schema_migrations OWNER TO sibyl_migrate;
GRANT SELECT ON sibyl.schema_migrations TO sibyl_app, sibyl_ingest, sibyl_worker;
