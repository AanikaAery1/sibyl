-- 0001 foundation: helper functions, shared trigger bodies, partition machinery.
-- Runs as sibyl_migrate. Signatures follow DATAMODEL §5 with D19 identifiers.
-- SQLSTATE class 'SB' is Sibyl's; codes are mapped in sibyl_control/migrate/errcodes.py.

-- R20: Postgres 17 has no native uuidv7(). 48-bit unix ms + version 7 + RFC 4122 variant,
-- random bits from gen_random_uuid(). Replace the body with the native one on PG 18.
CREATE FUNCTION sibyl.uuidv7() RETURNS uuid
LANGUAGE sql VOLATILE PARALLEL SAFE AS $$
  SELECT encode(
    set_bit(set_bit(
      overlay(uuid_send(gen_random_uuid())
              PLACING substring(int8send(floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
              FROM 1 FOR 6),
      52, 1), 53, 1), 'hex')::uuid
$$;

CREATE FUNCTION sibyl.nil_uuid() RETURNS uuid
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT '00000000-0000-0000-0000-000000000000'::uuid $$;

-- Tenant context. A transaction-local GUC; NULL (fail closed) when unset. With
-- app.tenant_strict = on (dev/CI, risk T1b) an unset tenant raises instead.
CREATE FUNCTION sibyl.current_tenant() RETURNS uuid
LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
DECLARE
  v text := NULLIF(current_setting('app.tenant_id', true), '');
BEGIN
  IF v IS NULL AND current_setting('app.tenant_strict', true) = 'on' THEN
    RAISE EXCEPTION 'sibyl:tenant_not_set: tenant context not set' USING ERRCODE = 'SB001';
  END IF;
  RETURN v::uuid;
END
$$;

CREATE FUNCTION sibyl.set_tenant(p_tenant uuid) RETURNS void
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
  IF p_tenant IS NULL THEN
    RAISE EXCEPTION 'sibyl:tenant_not_set: set_tenant(NULL) is not allowed' USING ERRCODE = 'SB001';
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant::text, true);
END
$$;

CREATE FUNCTION sibyl.assert_tenant(p_tenant uuid) RETURNS void
LANGUAGE plpgsql STABLE AS $$
BEGIN
  IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM sibyl.current_tenant() THEN
    RAISE EXCEPTION 'sibyl:tenant_mismatch: tenant % does not match the transaction tenant', p_tenant USING ERRCODE = 'SB002';
  END IF;
END
$$;

-- R60: commit-ordered cursor horizon. Every row with xid below it is committed or aborted.
CREATE FUNCTION sibyl.commit_horizon() RETURNS xid8
LANGUAGE sql VOLATILE AS $$ SELECT pg_snapshot_xmin(pg_current_snapshot()) $$;

-- RFC 8785 (JCS) for the subset Sibyl allows in hashed documents: objects, arrays, strings,
-- booleans, null and integers |n| <= 2^53-1. Floats are forbidden (W0-10), so number
-- serialisation needs no ECMAScript double formatting. Object members sort by the UTF-16
-- code units of their names (RFC 8785 §3.2.3), which differs from code-point order when a
-- name mixes astral characters with U+E000..U+FFFF; sibyl_schemas.canonical does the same.
CREATE FUNCTION sibyl.jcs_key_order(p text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT coalesce(string_agg(
           CASE WHEN c.cp < 65536 THEN decode(lpad(to_hex(c.cp), 4, '0'), 'hex')
                ELSE decode(lpad(to_hex(55296 + ((c.cp - 65536) >> 10)), 4, '0')
                            || lpad(to_hex(56320 + ((c.cp - 65536) & 1023)), 4, '0'), 'hex') END,
           ''::bytea ORDER BY c.i), ''::bytea)
  FROM (SELECT i, ascii(substr(p, i, 1)) AS cp FROM generate_series(1, length(p)) AS i) c
$$;

-- p_integers_only: true is JCS proper (raises SB023 on any non-integral or unsafe number);
-- false renders numbers as stored, for size rules on documents that are not hashed.
CREATE FUNCTION sibyl.jcs_text(p jsonb, p_integers_only boolean) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
  t text := jsonb_typeof(p);
  r text;
  n numeric;
BEGIN
  IF t = 'object' THEN
    SELECT '{' || coalesce(string_agg(to_json(e.key)::text || ':' || sibyl.jcs_text(e.value, p_integers_only), ','
                                      ORDER BY sibyl.jcs_key_order(e.key)), '') || '}'
      INTO r FROM jsonb_each(p) AS e;
    RETURN r;
  ELSIF t = 'array' THEN
    SELECT '[' || coalesce(string_agg(sibyl.jcs_text(a.elem, p_integers_only), ',' ORDER BY a.ord), '') || ']'
      INTO r FROM jsonb_array_elements(p) WITH ORDINALITY AS a(elem, ord);
    RETURN r;
  ELSIF t = 'string' THEN
    RETURN to_json(p #>> '{}')::text;
  ELSIF t = 'number' THEN
    IF NOT p_integers_only THEN
      RETURN p::text;
    END IF;
    n := (p #>> '{}')::numeric;
    IF n <> trunc(n) OR scale(n) > 0 OR abs(n) > 9007199254740991 THEN
      RAISE EXCEPTION 'sibyl:audit_detail_invalid: non-integer or unsafe number % in canonical document', n USING ERRCODE = 'SB023';
    END IF;
    RETURN n::text;
  ELSIF t = 'boolean' THEN
    RETURN p #>> '{}';
  END IF;
  RETURN 'null';
END
$$;

CREATE FUNCTION sibyl.jcs(p jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$ SELECT sibyl.jcs_text(p, true) $$;

-- Content-key denylist (G0 code review M4). Equal to sibyl_schemas.values.AUDIT_CONTENT_KEYS
-- (drift test); matched lowercased at any depth of audit detail and event attrs.
CREATE FUNCTION sibyl.audit_content_keys() RETURNS text[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT ARRAY['prompt', 'completion', 'messages', 'body', 'content', 'headers', 'input', 'output',
               'input_messages', 'output_messages']
$$;

-- INT-1: members that carry digests of content (sibyl-event/1 content_hashes.{input,output,
-- system}). Exempt from the denylist only as a flat object of lowercase-hex SHA-256 strings,
-- so content cannot hide under the name (sibyl_schemas.values.AUDIT_HASH_ONLY_KEYS).
CREATE FUNCTION sibyl.audit_hash_only_keys() RETURNS text[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT ARRAY['content_hashes']
$$;

CREATE FUNCTION sibyl.is_hash_only(p_key text, p jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT lower(p_key) = ANY (sibyl.audit_hash_only_keys())
     AND jsonb_typeof(p) = 'object'
     AND NOT EXISTS (SELECT 1 FROM jsonb_each(p) AS h
                      WHERE jsonb_typeof(h.value) <> 'string' OR (h.value #>> '{}') !~ '^[0-9a-f]{64}$')
$$;

CREATE FUNCTION sibyl.has_content_key(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
  t text := jsonb_typeof(p);
BEGIN
  IF t = 'object' THEN
    RETURN EXISTS (SELECT 1 FROM jsonb_each(p) AS e
                    WHERE NOT sibyl.is_hash_only(e.key, e.value)
                      AND (lower(e.key) = ANY (sibyl.audit_content_keys()) OR sibyl.has_content_key(e.value)));
  ELSIF t = 'array' THEN
    RETURN EXISTS (SELECT 1 FROM jsonb_array_elements(p) AS a(elem) WHERE sibyl.has_content_key(a.elem));
  END IF;
  RETURN false;
END
$$;

CREATE FUNCTION sibyl.sha256_text(p text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$ SELECT sha256(convert_to(p, 'UTF8')) $$;

CREATE FUNCTION sibyl.rfc3339(p timestamptz) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT to_char(p AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;

-- Histogram helpers (DATAMODEL §5): 40 log-spaced buckets, bucket i = [e^(i/3), e^((i+1)/3)) ms.
CREATE FUNCTION sibyl.hist_bucket(ms integer) RETURNS smallint
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN ms IS NULL OR ms < 1 THEN 0
              ELSE least(39, greatest(0, floor(3 * ln(ms::double precision))))::smallint END
$$;

CREATE FUNCTION sibyl.hist_add(a integer[], b integer[]) RETURNS integer[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT array_agg(coalesce(a[i], 0) + coalesce(b[i], 0) ORDER BY i)
  FROM generate_series(1, 40) AS i
$$;

CREATE AGGREGATE sibyl.hist_sum(integer[]) (
  SFUNC = sibyl.hist_add, STYPE = integer[], INITCOND = '{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}',
  PARALLEL = SAFE
);

CREATE FUNCTION sibyl.hist_quantile(h integer[], q real) RETURNS integer
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE
  total bigint := 0;
  running bigint := 0;
  i integer;
BEGIN
  IF h IS NULL THEN RETURN NULL; END IF;
  SELECT coalesce(sum(x), 0) INTO total FROM unnest(h) AS x;
  IF total = 0 THEN RETURN NULL; END IF;
  FOR i IN 1 .. cardinality(h) LOOP
    running := running + coalesce(h[i], 0);
    IF running >= q * total THEN
      RETURN round(exp(((i - 1) + 0.5) / 3.0))::integer;
    END IF;
  END LOOP;
  RETURN round(exp((cardinality(h) - 0.5) / 3.0))::integer;
END
$$;

CREATE FUNCTION sibyl.zero_hist() RETURNS integer[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT array_fill(0, ARRAY[40]) $$;

-- Provider base URL allowlist (DATAMODEL §5; G0 security review H3). https only; the
-- authority is parsed strictly (no userinfo, no percent-escapes, no backslash), IPv4 hosts in
-- every inet_aton spelling are normalised, IPv6 is allowed only inside global unicast
-- 2000::/3 (so IPv4-mapped, NAT64, 6to4 and Teredo never reach an embedded private address),
-- and every private, loopback, link-local, CGNAT, multicast, reserved and documentation range
-- is refused. Development hosts (sibyl-sim doubles, R55) are rows of base_url_dev_host, a
-- table only sibyl_migrate can write: no login role can widen the allowlist. The gateway
-- still re-checks the resolved address at connect time (DNS rebinding is out of reach here).
CREATE TABLE sibyl.base_url_dev_host (
  host        text        PRIMARY KEY,
  note        text        NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_base_url_dev_host_host CHECK (
    length(host) <= 253
    AND host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
);

CREATE FUNCTION sibyl.base_url_dev_hosts() RETURNS text[]
LANGUAGE sql STABLE PARALLEL SAFE SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT coalesce(array_agg(host), '{}') FROM sibyl.base_url_dev_host
$$;

-- inet_aton / WHATWG IPv4 parsing: 1-4 parts, each decimal, 0x-hex or 0-octal, the last part
-- filling the remaining bytes. NULL when the text is not a valid IPv4 number.
CREATE FUNCTION sibyl.ipv4_parse(p text) RETURNS inet
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
  parts text[] := string_to_array(lower(p), '.');
  n integer := cardinality(parts);
  part text;
  digits text;
  base integer;
  val numeric;
  total numeric := 0;
  i integer;
  j integer;
BEGIN
  IF n IS NULL OR n < 1 OR n > 4 THEN
    RETURN NULL;
  END IF;
  FOR i IN 1 .. n LOOP
    part := parts[i];
    IF part ~ '^0x[0-9a-f]{0,8}$' THEN
      digits := substr(part, 3); base := 16;
    ELSIF part ~ '^0[0-7]{1,11}$' THEN
      digits := substr(part, 2); base := 8;
    ELSIF part ~ '^[0-9]{1,10}$' THEN
      digits := part; base := 10;
    ELSE
      RETURN NULL;
    END IF;
    val := 0;
    FOR j IN 1 .. length(digits) LOOP
      val := val * base + (strpos('0123456789abcdef', substr(digits, j, 1)) - 1);
    END LOOP;
    IF i < n THEN
      IF val > 255 THEN RETURN NULL; END IF;
      total := total + val * (256::numeric ^ (4 - i));
    ELSE
      IF val >= 256::numeric ^ (5 - n) THEN RETURN NULL; END IF;
      total := total + val;
    END IF;
  END LOOP;
  RETURN (trunc(total / 16777216)::bigint || '.' || (trunc(total / 65536)::bigint % 256) || '.'
          || (trunc(total / 256)::bigint % 256) || '.' || (trunc(total)::bigint % 256))::inet;
END
$$;

CREATE FUNCTION sibyl.is_public_ip(ip inet) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT CASE family(ip)
    WHEN 4 THEN NOT (ip <<= ANY (ARRAY['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
      '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
      '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']::inet[]))
    ELSE ip <<= '2000::/3'::inet
         AND NOT (ip <<= ANY (ARRAY['2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20']::inet[]))
  END
$$;

CREATE FUNCTION sibyl.is_allowlisted_base_url(url text) RETURNS boolean
LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
DECLARE
  m text[];
  v_scheme text;
  v_authority text;
  v_host text;
  v_port text;
  ip inet;
  v_labels text[];
BEGIN
  IF url IS NULL THEN RETURN true; END IF;
  -- printable ASCII only (no whitespace, controls or IDN), and no backslash anywhere
  IF url !~ '^[!-~]+$' OR strpos(url, chr(92)) > 0 THEN RETURN false; END IF;
  m := regexp_match(url, '^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)([/?#].*)?$');
  IF m IS NULL THEN RETURN false; END IF;
  v_scheme := lower(m[1]);
  v_authority := m[2];
  IF v_authority = '' OR v_authority ~ '[@%]' THEN RETURN false; END IF;
  IF left(v_authority, 1) = '[' THEN
    m := regexp_match(v_authority, '^\[([0-9A-Fa-f:.]+)\](:([0-9]{1,5}))?$');
    IF m IS NULL THEN RETURN false; END IF;
    BEGIN
      ip := m[1]::inet;
    EXCEPTION WHEN invalid_text_representation THEN
      RETURN false;
    END;
    IF family(ip) <> 6 OR masklen(ip) <> 128 THEN RETURN false; END IF;
    v_host := '[' || host(ip) || ']';
    v_port := m[3];
  ELSE
    m := regexp_match(v_authority, '^([^:]+)(:([0-9]{1,5}))?$');
    IF m IS NULL THEN RETURN false; END IF;
    v_host := lower(m[1]);
    v_port := m[3];
    IF right(v_host, 1) = '.' THEN v_host := left(v_host, -1); END IF;  -- one trailing dot is the same name
    IF v_host = '' THEN RETURN false; END IF;
    v_labels := string_to_array(v_host, '.');
    IF v_labels[cardinality(v_labels)] ~ '^([0-9]+|0x[0-9a-f]*)$' THEN
      ip := sibyl.ipv4_parse(v_host);
      IF ip IS NULL THEN RETURN false; END IF;
      v_host := host(ip);
    ELSIF length(v_host) > 253
          OR v_host !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' THEN
      RETURN false;
    END IF;
  END IF;
  IF v_port IS NOT NULL AND v_port::integer NOT BETWEEN 1 AND 65535 THEN RETURN false; END IF;
  IF v_host = ANY (sibyl.base_url_dev_hosts()) THEN
    RETURN v_scheme IN ('http', 'https');
  END IF;
  IF v_scheme <> 'https' THEN RETURN false; END IF;
  IF ip IS NOT NULL THEN
    RETURN sibyl.is_public_ip(ip);
  END IF;
  -- a DNS name: fully qualified, never an internal or link-local name space
  RETURN strpos(v_host, '.') > 0
         AND v_host !~ '(^|\.)(localhost|localdomain|internal|local|home\.arpa|in-addr\.arpa|ip6\.arpa)$';
END
$$;

-- Shared trigger bodies -----------------------------------------------------------------

CREATE FUNCTION sibyl.trg_set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

-- An erasure transaction may delete otherwise-immutable rows of a tenant that is
-- genuinely under an executing erasure request (DATAMODEL §6.5). The request id is
-- carried in the transaction-local GUC sibyl.erasure_request and re-validated here.
CREATE FUNCTION sibyl.erasure_delete_allowed(p_tenant uuid) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE
  v uuid := NULLIF(current_setting('sibyl.erasure_request', true), '')::uuid;
BEGIN
  IF v IS NULL THEN RETURN false; END IF;
  RETURN EXISTS (
    SELECT 1 FROM sibyl.erasure_request er
     WHERE er.id = v AND er.tenant_id = p_tenant
       AND er.state IN ('executing', 'keys_shredded', 'objects_deleted', 'derived_purged'));
END
$$;

-- Append-only / immutable rows. TG_ARGV options:
--   'no_erasure'        DELETE is never allowed, not even by erasure (audit tables)
--   'allow_supersede'   UPDATE allowed when only superseded_by goes NULL -> value
--   'allow_activation'  UPDATE allowed when only activated_at/superseded_at go NULL -> value
CREATE FUNCTION sibyl.trg_block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  o jsonb;
  n jsonb;
BEGIN
  IF TG_LEVEL = 'STATEMENT' THEN
    RAISE EXCEPTION 'sibyl:immutable_row: % on %.% is not allowed (append-only)', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
      USING ERRCODE = 'SB030';
  END IF;
  IF TG_OP = 'DELETE' THEN
    IF NOT coalesce('no_erasure' = ANY (TG_ARGV), false) AND sibyl.erasure_delete_allowed(OLD.tenant_id) THEN
      RETURN OLD;
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    o := to_jsonb(OLD);
    n := to_jsonb(NEW);
    IF coalesce('allow_supersede' = ANY (TG_ARGV), false)
       AND (o - 'superseded_by' - 'updated_at') = (n - 'superseded_by' - 'updated_at')
       AND o->'superseded_by' = 'null'::jsonb AND n->'superseded_by' <> 'null'::jsonb THEN
      RETURN NEW;
    END IF;
    IF coalesce('allow_activation' = ANY (TG_ARGV), false)
       AND (o - 'activated_at' - 'superseded_at') = (n - 'activated_at' - 'superseded_at')
       AND (o->'activated_at' = n->'activated_at' OR o->'activated_at' = 'null'::jsonb)
       AND (o->'superseded_at' = n->'superseded_at' OR o->'superseded_at' = 'null'::jsonb) THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'sibyl:immutable_row: % on %.% is not allowed (immutable row)', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'SB030';
END
$$;

-- State machines as data (W0-11). TG_ARGV[0] = machine, TG_ARGV[1] = state column.
-- routing_transition is checked on INSERT with its own trigger column; every other machine
-- on UPDATE of its state column, with the handler's trigger name taken from
-- app.transition_trigger. Edges seeded with trigger '*' accept any trigger name.
CREATE FUNCTION sibyl.trg_state_edge() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_machine text := TG_ARGV[0];
  col text := TG_ARGV[1];
  v_from text;
  v_to text;
  v_trigger text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_from := coalesce(to_jsonb(NEW)->>'from_state', '');
    v_to := to_jsonb(NEW)->>'to_state';
    v_trigger := to_jsonb(NEW)->>'trigger';
  ELSE
    v_from := to_jsonb(OLD)->>col;
    v_to := to_jsonb(NEW)->>col;
    IF v_from IS NOT DISTINCT FROM v_to THEN
      RETURN NEW;
    END IF;
    v_trigger := coalesce(NULLIF(current_setting('app.transition_trigger', true), ''), '');
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM sibyl.state_edge e
       WHERE e.machine = v_machine AND e.from_state = v_from AND e.to_state = v_to
         AND (e.trigger = v_trigger OR e.trigger = '*')) THEN
    RAISE EXCEPTION 'sibyl:invalid_transition: % % -> % (trigger %)', v_machine, v_from, v_to, v_trigger
      USING ERRCODE = 'SB010';
  END IF;
  RETURN NEW;
END
$$;

-- RLS helper (DATAMODEL §7 migration 0): ENABLE + FORCE + exactly one policy rls_tenant_<table>.
-- SECURITY INVOKER: the caller must own the table.
CREATE FUNCTION sibyl.enable_tenant_rls(p_table regclass) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  rel text := (SELECT relname FROM pg_class WHERE oid = p_table);
BEGIN
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', p_table);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', p_table);
  EXECUTE format('CREATE POLICY %I ON %s USING (tenant_id = sibyl.current_tenant()) '
                 'WITH CHECK (tenant_id = sibyl.current_tenant())', 'rls_tenant_' || rel, p_table);
END
$$;

-- Infrastructure allowlist tables (DATAMODEL §3, R2) -----------------------------------

CREATE TABLE sibyl.tenant (
  id                       uuid        PRIMARY KEY DEFAULT sibyl.uuidv7(),
  slug                     text        NOT NULL,
  name                     text,
  status                   text        NOT NULL DEFAULT 'active',
  parent_tenant_id         uuid        REFERENCES sibyl.tenant (id),
  region_declared          text,
  unknown_agent_fail_mode  text,
  hold_on_incident         boolean     NOT NULL DEFAULT false,
  routing_version          bigint      NOT NULL DEFAULT 0,
  graph_version            bigint      NOT NULL DEFAULT 0,
  raw_retention_days       smallint    NOT NULL DEFAULT 7,
  audit_retention_days     smallint    NOT NULL DEFAULT 400,
  backup_retention_days    smallint    NOT NULL DEFAULT 7,
  ingest_rate_limit        jsonb       NOT NULL DEFAULT '{"events_per_s": 500, "burst": 5000}',
  max_agents               integer     NOT NULL DEFAULT 500,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_tenant_slug UNIQUE (slug),
  CONSTRAINT ck_tenant_slug CHECK (slug ~ '^[a-z][a-z0-9-]{1,62}$'),
  CONSTRAINT ck_tenant_status CHECK (status IN ('active', 'suspended', 'erasing', 'erased')),
  CONSTRAINT ck_tenant_unknown_agent_fail_mode CHECK (unknown_agent_fail_mode IN ('open', 'closed')),
  CONSTRAINT ck_tenant_live_columns CHECK (status = 'erased' OR (name IS NOT NULL AND unknown_agent_fail_mode IS NOT NULL)),
  CONSTRAINT ck_tenant_raw_retention_days CHECK (raw_retention_days BETWEEN 1 AND 30),
  CONSTRAINT ck_tenant_audit_retention_days CHECK (audit_retention_days >= 400),
  CONSTRAINT ck_tenant_backup_retention CHECK (backup_retention_days BETWEEN 1 AND 35),
  CONSTRAINT ck_tenant_ingest_rate_limit CHECK (
    jsonb_typeof(ingest_rate_limit->'events_per_s') = 'number'
    AND jsonb_typeof(ingest_rate_limit->'burst') = 'number'
    AND (ingest_rate_limit->>'events_per_s')::numeric BETWEEN 1 AND 100000
    AND (ingest_rate_limit->>'burst')::numeric BETWEEN 1 AND 1000000),
  CONSTRAINT ck_tenant_versions CHECK (routing_version >= 0 AND graph_version >= 0)
);
CREATE TRIGGER trg_tenant_updated_at BEFORE UPDATE ON sibyl.tenant
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- routing_version and graph_version never decrease (DATAMODEL §4.1).
CREATE FUNCTION sibyl.trg_tenant_versions_monotonic() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.routing_version < OLD.routing_version OR NEW.graph_version < OLD.graph_version THEN
    RAISE EXCEPTION 'sibyl:immutable_row: tenant versions are monotonic' USING ERRCODE = 'SB030';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_tenant_versions BEFORE UPDATE ON sibyl.tenant
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_tenant_versions_monotonic();

CREATE TABLE sibyl.role (
  name         text        PRIMARY KEY,
  description  text        NOT NULL,
  is_system    boolean     NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sibyl.role_permission (
  role_name     text        NOT NULL REFERENCES sibyl.role (name),
  permission    text        NOT NULL,
  scope_rule    text        NOT NULL DEFAULT 'tenant',
  step_up       boolean     NOT NULL DEFAULT false,
  self_audited  boolean     NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (role_name, permission),
  CONSTRAINT ck_role_permission_scope_rule CHECK (scope_rule IN ('tenant', 'scoped')),
  CONSTRAINT ck_role_permission_permission CHECK (permission ~ '^[a-z_]+:[a-z_*]+$')
);

CREATE TABLE sibyl.state_edge (
  machine     text        NOT NULL,
  from_state  text        NOT NULL,
  to_state    text        NOT NULL,
  trigger     text        NOT NULL,
  note        text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (machine, from_state, to_state, trigger),
  CONSTRAINT ck_state_edge_machine CHECK (machine IN ('routing', 'failover', 'approval', 'handoff', 'alert',
                                                      'erasure', 'tenant_key', 'kill_switch', 'lifecycle'))
);

CREATE TABLE sibyl.audit_action (
  name             text        PRIMARY KEY,
  domain           text        NOT NULL,
  actor_types      text[]      NOT NULL,
  resource_type    text        NOT NULL,
  required_fields  text[]      NOT NULL DEFAULT '{}',
  reason_required  boolean     NOT NULL DEFAULT false,
  is_evidence      boolean     NOT NULL DEFAULT true,
  severity         text        NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_audit_action_severity CHECK (severity IN ('info', 'notice', 'warning', 'critical')),
  CONSTRAINT ck_audit_action_actor_types CHECK (
    cardinality(actor_types) >= 1 AND actor_types <@ ARRAY['human', 'rule', 'policy', 'system', 'agent', 'api_key'])
);

CREATE TABLE sibyl.signing_key (
  kid              text        PRIMARY KEY,
  purpose          text        NOT NULL,
  algorithm        text        NOT NULL DEFAULT 'Ed25519',
  public_key       bytea       NOT NULL,
  private_key_ref  text        NOT NULL,
  state            text        NOT NULL DEFAULT 'active',
  activated_at     timestamptz NOT NULL DEFAULT now(),
  retiring_until   timestamptz,
  retired_at       timestamptz,
  custody_note     text        NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_signing_key_purpose CHECK (purpose IN ('snapshot', 'audit_anchor', 'agent_token')),
  CONSTRAINT ck_signing_key_state CHECK (state IN ('active', 'retiring', 'retired', 'compromised'))
);
CREATE UNIQUE INDEX ux_signing_key_active ON sibyl.signing_key (purpose) WHERE state = 'active';
CREATE TRIGGER trg_signing_key_updated_at BEFORE UPDATE ON sibyl.signing_key
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

CREATE TABLE sibyl.model_catalog (
  id                        uuid          PRIMARY KEY DEFAULT sibyl.uuidv7(),
  provider_kind             text          NOT NULL,
  model_name                text          NOT NULL,
  deprecated_on             date,
  retires_on                date,
  input_usd_per_1m          numeric(12,6),
  output_usd_per_1m         numeric(12,6),
  cached_input_usd_per_1m   numeric(12,6),
  context_window            integer,
  max_output_tokens         integer,
  capabilities              jsonb         NOT NULL DEFAULT '{}',
  source_version            text          NOT NULL,
  created_at                timestamptz   NOT NULL DEFAULT now(),
  updated_at                timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT uq_model_catalog UNIQUE (provider_kind, model_name),
  CONSTRAINT ck_model_catalog_provider_kind CHECK (
    provider_kind IN ('openai', 'anthropic', 'azure_openai', 'bedrock', 'vertex', 'ollama', 'custom'))
);
CREATE TRIGGER trg_model_catalog_updated_at BEFORE UPDATE ON sibyl.model_catalog
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

CREATE TABLE sibyl.partition_registry (
  table_name        text        NOT NULL,
  partition_name    text        NOT NULL,
  grain             text        NOT NULL,
  range_from        timestamptz NOT NULL,
  range_to          timestamptz NOT NULL,
  state             text        NOT NULL DEFAULT 'attached',
  row_estimate      bigint,
  bytes             bigint,
  exported_uri      text,
  anchor_id         uuid,
  state_changed_at  timestamptz NOT NULL DEFAULT now(),
  created_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (table_name, partition_name),
  CONSTRAINT ck_partition_registry_grain CHECK (grain IN ('day', '3day', 'month')),
  CONSTRAINT ck_partition_registry_state CHECK (state IN ('attached', 'detached', 'exported', 'dropped')),
  CONSTRAINT ck_partition_registry_range CHECK (range_from < range_to),
  CONSTRAINT ck_partition_registry_audit_drop CHECK (
    table_name <> 'audit_events' OR state <> 'dropped' OR (exported_uri IS NOT NULL AND anchor_id IS NOT NULL))
);

-- Cursor key only (R2, R60): last_xid/last_id is the commit-ordered position.
CREATE TABLE sibyl.consumer_offsets (
  consumer_group   text        NOT NULL,
  tenant_id        uuid        NOT NULL REFERENCES sibyl.tenant (id),
  topic            text        NOT NULL,
  last_xid         xid8        NOT NULL DEFAULT '0',
  last_id          uuid        NOT NULL DEFAULT sibyl.nil_uuid(),
  last_created_at  timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (consumer_group, tenant_id, topic)
);
CREATE TRIGGER trg_consumer_offsets_updated_at BEFORE UPDATE ON sibyl.consumer_offsets
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();

-- Offsets only move forward.
CREATE FUNCTION sibyl.trg_consumer_offsets_forward() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.last_xid, NEW.last_id) < (OLD.last_xid, OLD.last_id) THEN
    RAISE EXCEPTION 'sibyl:immutable_row: consumer offset moved backwards' USING ERRCODE = 'SB030';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_consumer_offsets_forward BEFORE UPDATE ON sibyl.consumer_offsets
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_consumer_offsets_forward();

CREATE SEQUENCE sibyl.policy_snapshot_issue_version_seq AS bigint;

CREATE TABLE sibyl.policy_snapshot_issue (
  version         bigint      PRIMARY KEY DEFAULT nextval('sibyl.policy_snapshot_issue_version_seq'),
  issued_at       timestamptz NOT NULL DEFAULT now(),
  sha256          bytea       NOT NULL,
  signer_kid      text        NOT NULL REFERENCES sibyl.signing_key (kid),
  tenant_versions jsonb       NOT NULL,
  agents_count    integer     NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_policy_snapshot_issue_sha256 CHECK (octet_length(sha256) = 32)
);
ALTER SEQUENCE sibyl.policy_snapshot_issue_version_seq OWNED BY sibyl.policy_snapshot_issue.version;

-- Partition machinery (DATAMODEL §6.6, X9) ----------------------------------------------

-- One row per partitioned table: key column, grain, how far ahead, class retention.
CREATE FUNCTION sibyl.partition_policy()
RETURNS TABLE (table_name text, grain text, ahead interval, retention interval)
LANGUAGE sql IMMUTABLE AS $$
  VALUES
    ('events',               'day',   interval '7 days',   interval '30 days'),
    ('events_rejected',      'day',   interval '7 days',   interval '3 days'),
    ('payload_refs',         'day',   interval '7 days',   interval '400 days'),
    ('checkpoint',           'day',   interval '7 days',   interval '400 days'),
    ('health_snapshot',      'day',   interval '7 days',   interval '3 days'),
    ('agent_metrics_1m',     'day',   interval '7 days',   interval '14 days'),
    ('agent_metrics_5m',     'day',   interval '7 days',   interval '90 days'),
    ('provider_metrics_5m',  'day',   interval '7 days',   interval '90 days'),
    ('outbox',               'day',   interval '7 days',   interval '7 days'),
    ('ml_prediction_shadow', 'day',   interval '7 days',   interval '30 days'),
    ('ingest_batch_seen',    '3day',  interval '9 days',   interval '3 days'),
    ('agent_metrics_1h',     'month', interval '2 months', interval '13 months'),
    ('health_1h',            'month', interval '2 months', interval '13 months'),
    ('prediction',           'month', interval '2 months', interval '400 days'),
    ('audit_events',         'month', interval '2 months', interval '400 days')
$$;

-- Period start containing p_ts for a grain, in UTC. 3day periods align to epoch days.
CREATE FUNCTION sibyl.partition_period_start(p_grain text, p_ts timestamptz) RETURNS timestamptz
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT CASE p_grain
    WHEN 'day'   THEN date_trunc('day', p_ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
    WHEN 'month' THEN date_trunc('month', p_ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
    WHEN '3day'  THEN ('1970-01-01'::date
                       + ((((p_ts AT TIME ZONE 'UTC')::date - '1970-01-01'::date) / 3) * 3))::timestamp
                      AT TIME ZONE 'UTC'
  END
$$;

CREATE FUNCTION sibyl.partition_period_step(p_grain text) RETURNS interval
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT CASE p_grain WHEN 'day' THEN interval '1 day' WHEN '3day' THEN interval '3 days'
                      ELSE interval '1 month' END
$$;

-- Creates missing partitions of p_table covering [p_from, p_to), each with the tenant RLS
-- policy (defence in depth: partitions get no grants, so only the parent is reachable).
-- SECURITY DEFINER as sibyl_migrate (owner of every partitioned parent but audit_events).
CREATE FUNCTION sibyl.partition_ensure(p_table text, p_from timestamptz, p_to timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_grain text;
  v_start timestamptz;
  v_end timestamptz;
  v_name text;
  v_created integer := 0;
BEGIN
  SELECT pp.grain INTO v_grain FROM sibyl.partition_policy() pp WHERE pp.table_name = p_table;
  IF v_grain IS NULL THEN
    RAISE EXCEPTION 'sibyl:partition_policy_unknown: table % is not partitioned by policy', p_table USING ERRCODE = 'SB050';
  END IF;
  -- G0 M8: concurrent callers (worker loop, migrate, a second replica) serialise per table
  -- instead of racing to CREATE TABLE and failing with 42P07.
  PERFORM pg_advisory_xact_lock(hashtextextended('partition:' || p_table, 0));
  IF p_table = 'audit_events' THEN
    RETURN sibyl.partition_ensure_audit(p_from, p_to);
  END IF;
  v_start := sibyl.partition_period_start(v_grain, p_from);
  WHILE v_start < p_to LOOP
    v_end := v_start + sibyl.partition_period_step(v_grain);
    v_name := p_table || '_p' || to_char(v_start AT TIME ZONE 'UTC',
                                         CASE v_grain WHEN 'month' THEN 'YYYYMM' ELSE 'YYYYMMDD' END);
    IF to_regclass('sibyl.' || v_name) IS NULL THEN
      -- INT-1: the rollup grains are upserted every tick; fillfactor 70 keeps those updates HOT.
      -- (A partitioned parent cannot hold storage parameters, so each partition gets them.)
      EXECUTE format('CREATE TABLE sibyl.%I PARTITION OF sibyl.%I FOR VALUES FROM (%L) TO (%L)%s',
                     v_name, p_table, v_start, v_end,
                     CASE WHEN p_table IN ('agent_metrics_1m', 'agent_metrics_5m', 'agent_metrics_1h')
                          THEN ' WITH (fillfactor = 70)' ELSE '' END);
      PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', v_name)::regclass);
      INSERT INTO sibyl.partition_registry (table_name, partition_name, grain, range_from, range_to)
      VALUES (p_table, v_name, v_grain, v_start, v_end)
      ON CONFLICT (table_name, partition_name) DO NOTHING;
      v_created := v_created + 1;
    END IF;
    v_start := v_end;
  END LOOP;
  RETURN v_created;
END
$$;

-- Hourly worker job and migrate-time call (risk T9b): from one period back to `ahead`.
CREATE FUNCTION sibyl.partition_ensure_ahead(p_now timestamptz DEFAULT now())
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  r record;
  v_total integer := 0;
BEGIN
  FOR r IN SELECT * FROM sibyl.partition_policy() LOOP
    IF to_regclass('sibyl.' || r.table_name) IS NOT NULL THEN
      v_total := v_total + sibyl.partition_ensure(
        r.table_name, p_now - sibyl.partition_period_step(r.grain), p_now + r.ahead);
    END IF;
  END LOOP;
  RETURN v_total;
END
$$;

-- How far each partitioned table is covered (attached partitions). The hourly `partitions`
-- worker loop (a G1 blocker) keeps this at least `ahead` in the future; health alerts on it.
-- There are deliberately no DEFAULT partitions: rows landing in one would block creating the
-- partition that later covers them.
CREATE FUNCTION sibyl.partition_horizon() RETURNS TABLE (table_name text, covered_until timestamptz)
LANGUAGE sql STABLE AS $$
  SELECT p.table_name,
         (SELECT max(r.range_to) FROM sibyl.partition_registry r
           WHERE r.table_name = p.table_name AND r.state = 'attached')
  FROM sibyl.partition_policy() p
$$;

-- Retention step 3 (DATAMODEL §6.6; lane U housekeeping CR to INT-1): detach and drop every
-- attached partition whose range ended more than its class retention ago, on behalf of the
-- worker (which owns no table and cannot DETACH/DROP). Never audit_events (export + boundary
-- anchor first, Phase 1.5). A payload_refs / checkpoint partition holding any row under an
-- active legal hold is kept. Row counts are taken per tenant under that tenant's RLS context
-- (FORCE RLS binds the definer too) and returned so the worker audits retention.partition_dropped
-- per tenant. SECURITY DEFINER as sibyl_migrate (owner of every partitioned parent but audit_events).
CREATE FUNCTION sibyl.partition_retire_expired(p_now timestamptz DEFAULT now())
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


-- Helper functions every service role (and the NOLOGIN definers) may call.
GRANT EXECUTE ON FUNCTION
  sibyl.uuidv7(), sibyl.nil_uuid(), sibyl.current_tenant(), sibyl.set_tenant(uuid),
  sibyl.assert_tenant(uuid), sibyl.commit_horizon(), sibyl.jcs(jsonb), sibyl.jcs_text(jsonb, boolean),
  sibyl.jcs_key_order(text), sibyl.audit_content_keys(), sibyl.audit_hash_only_keys(),
  sibyl.is_hash_only(text, jsonb), sibyl.has_content_key(jsonb), sibyl.sha256_text(text),
  sibyl.rfc3339(timestamptz), sibyl.hist_bucket(integer), sibyl.hist_add(integer[], integer[]),
  sibyl.hist_sum(integer[]), sibyl.hist_quantile(integer[], real), sibyl.zero_hist(),
  sibyl.is_allowlisted_base_url(text), sibyl.base_url_dev_hosts(), sibyl.ipv4_parse(text),
  sibyl.is_public_ip(inet), sibyl.erasure_delete_allowed(uuid), sibyl.partition_horizon(),
  sibyl.partition_policy(), sibyl.partition_period_start(text, timestamptz),
  sibyl.partition_period_step(text)
TO sibyl_app, sibyl_ingest, sibyl_worker, sibyl_audit, sibyl_routing;
GRANT EXECUTE ON FUNCTION sibyl.trg_set_updated_at(), sibyl.trg_block_mutation(), sibyl.trg_state_edge(),
  sibyl.enable_tenant_rls(regclass)
TO sibyl_audit, sibyl_routing;
GRANT EXECUTE ON FUNCTION sibyl.partition_ensure_ahead(timestamptz) TO sibyl_worker;
GRANT EXECUTE ON FUNCTION sibyl.partition_ensure(text, timestamptz, timestamptz) TO sibyl_worker;
GRANT EXECUTE ON FUNCTION sibyl.partition_retire_expired(timestamptz) TO sibyl_worker;

-- Allowlist tables: SELECT for every service role; writers per DATAMODEL §3.
GRANT SELECT ON sibyl.tenant, sibyl.role, sibyl.role_permission, sibyl.state_edge, sibyl.audit_action,
  sibyl.signing_key, sibyl.model_catalog, sibyl.partition_registry, sibyl.consumer_offsets,
  sibyl.policy_snapshot_issue
TO sibyl_app, sibyl_ingest, sibyl_worker, sibyl_audit, sibyl_routing;
GRANT INSERT, UPDATE (name, status, parent_tenant_id, region_declared, unknown_agent_fail_mode,
  hold_on_incident, raw_retention_days, audit_retention_days, backup_retention_days,
  ingest_rate_limit, max_agents) ON sibyl.tenant TO sibyl_app;
GRANT UPDATE (status, name, parent_tenant_id, region_declared, unknown_agent_fail_mode)
  ON sibyl.tenant TO sibyl_worker;
GRANT UPDATE (routing_version) ON sibyl.tenant TO sibyl_routing;
GRANT INSERT, UPDATE, DELETE ON sibyl.consumer_offsets TO sibyl_app, sibyl_worker;
GRANT UPDATE (state, row_estimate, bytes, exported_uri, anchor_id, state_changed_at)
  ON sibyl.partition_registry TO sibyl_worker;
GRANT INSERT, UPDATE, DELETE ON sibyl.model_catalog TO sibyl_worker;
GRANT INSERT ON sibyl.policy_snapshot_issue TO sibyl_app;
GRANT DELETE ON sibyl.policy_snapshot_issue TO sibyl_worker;
GRANT USAGE ON SEQUENCE sibyl.policy_snapshot_issue_version_seq TO sibyl_app;
