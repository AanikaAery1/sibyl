-- 0004 registry & graph (DATAMODEL §4.2, API §12.7 via_gateway).

CREATE TABLE sibyl.provider (
  tenant_id          uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                 uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  slug               text        NOT NULL,
  name               text        NOT NULL,
  provider_kind      text        NOT NULL,
  dialect            text        NOT NULL,
  base_url           text        NOT NULL,
  is_known_provider  boolean     NOT NULL DEFAULT false,
  status_feed_url    text,
  is_enabled         boolean     NOT NULL DEFAULT true,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_provider_slug UNIQUE (tenant_id, slug),
  CONSTRAINT ck_provider_provider_kind CHECK (
    provider_kind IN ('openai', 'anthropic', 'azure_openai', 'bedrock', 'vertex', 'ollama', 'custom')),
  CONSTRAINT ck_provider_dialect CHECK (dialect IN ('openai_compatible', 'anthropic')),
  CONSTRAINT ck_provider_base_url CHECK (sibyl.is_allowlisted_base_url(base_url))
);

CREATE TABLE sibyl.model (
  tenant_id          uuid          NOT NULL REFERENCES sibyl.tenant (id),
  id                 uuid          NOT NULL DEFAULT sibyl.uuidv7(),
  provider_id        uuid          NOT NULL,
  model_name         text          NOT NULL,
  catalog_id         uuid          REFERENCES sibyl.model_catalog (id),
  deprecated_on      date,
  retires_on         date,
  input_usd_per_1m   numeric(12,6),
  output_usd_per_1m  numeric(12,6),
  is_discovered      boolean       NOT NULL DEFAULT false,
  is_allowed         boolean       NOT NULL DEFAULT true,
  created_at         timestamptz   NOT NULL DEFAULT now(),
  updated_at         timestamptz   NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_model_name UNIQUE (tenant_id, provider_id, model_name),
  CONSTRAINT fk_model_provider FOREIGN KEY (tenant_id, provider_id)
    REFERENCES sibyl.provider (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE
);

CREATE TABLE sibyl.business_process (
  tenant_id      uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id             uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  slug           text        NOT NULL,
  name           text        NOT NULL,
  owner_user_id  uuid,
  criticality    text        NOT NULL,
  description    text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_business_process_slug UNIQUE (tenant_id, slug),
  CONSTRAINT fk_business_process_owner FOREIGN KEY (tenant_id, owner_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_business_process_criticality CHECK (criticality IN ('low', 'medium', 'high', 'critical'))
);

CREATE TABLE sibyl.agent (
  tenant_id            uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                   uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  slug                 text        NOT NULL,
  name                 text        NOT NULL,
  description          text,
  kind                 text        NOT NULL,
  framework            text,
  agent_group_id       uuid,
  owner_user_id        uuid,
  business_process_id  uuid,
  tier                 smallint    NOT NULL DEFAULT 3,
  risk_class           text        NOT NULL DEFAULT 'unclassified',
  lifecycle            text        NOT NULL DEFAULT 'discovered',
  is_provisional       boolean     NOT NULL DEFAULT false,
  fail_mode            text        NOT NULL,
  current_version_id   uuid,
  via_gateway          boolean     NOT NULL DEFAULT false,
  cost_center          text,
  tags                 text[]      NOT NULL DEFAULT '{}',
  -- Per-agent preemptive breaker (sre guard rail 5, lane P): set by the worker when it trips
  -- (audit preemptive.breaker_tripped); only a human clears it (preemptive.breaker_cleared).
  preemptive_breaker_tripped_at          timestamptz,
  preemptive_breaker_cleared_at          timestamptz,
  preemptive_breaker_cleared_by_user_id  uuid,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_agent_tenant_slug UNIQUE (tenant_id, slug),
  CONSTRAINT fk_agent_breaker_cleared_by FOREIGN KEY (tenant_id, preemptive_breaker_cleared_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_agent_breaker_cleared CHECK (
    preemptive_breaker_cleared_by_user_id IS NULL OR preemptive_breaker_cleared_at IS NOT NULL),
  CONSTRAINT fk_agent_group FOREIGN KEY (tenant_id, agent_group_id)
    REFERENCES sibyl.agent_group (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_agent_owner FOREIGN KEY (tenant_id, owner_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_agent_business_process FOREIGN KEY (tenant_id, business_process_id)
    REFERENCES sibyl.business_process (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_agent_slug CHECK (slug ~ '^([a-z0-9][a-z0-9_-]{0,62}|unclaimed/[0-9a-f]{8})$'),
  CONSTRAINT ck_agent_kind CHECK (kind IN ('chatbot', 'copilot', 'autonomous_agent', 'multi_agent',
                                           'rag_pipeline', 'mcp_server', 'model_endpoint', 'workflow')),
  CONSTRAINT ck_agent_tier CHECK (tier BETWEEN 1 AND 3),
  CONSTRAINT ck_agent_risk_class CHECK (risk_class IN ('unclassified', 'minimal', 'limited', 'high', 'unacceptable')),
  CONSTRAINT ck_agent_lifecycle CHECK (lifecycle IN ('discovered', 'proposed', 'approved', 'deployed', 'monitored', 'retired')),
  CONSTRAINT ck_agent_fail_mode CHECK (fail_mode IN ('open', 'closed'))
);
CREATE INDEX ix_agent_lifecycle_tier ON sibyl.agent (tenant_id, lifecycle, tier);
CREATE INDEX ix_agent_business_process ON sibyl.agent (tenant_id, business_process_id);
CREATE INDEX ix_agent_owner ON sibyl.agent (tenant_id, owner_user_id);
CREATE INDEX ix_agent_group ON sibyl.agent (tenant_id, agent_group_id);

ALTER TABLE sibyl.api_key ADD CONSTRAINT fk_api_key_agent FOREIGN KEY (tenant_id, agent_id)
  REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

-- Provisional (auto-registered) agents copy the tenant's unknown_agent_fail_mode; every
-- other agent must declare fail_mode (no default, DATAMODEL §4.2).
CREATE FUNCTION sibyl.trg_agent_defaults() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.fail_mode IS NULL AND NEW.is_provisional THEN
    SELECT t.unknown_agent_fail_mode INTO NEW.fail_mode FROM sibyl.tenant t WHERE t.id = NEW.tenant_id;
  END IF;
  IF NEW.fail_mode IS NULL THEN
    RAISE EXCEPTION 'sibyl:fail_mode_required: agent.fail_mode must be declared' USING ERRCODE = 'SB046';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_agent_defaults BEFORE INSERT ON sibyl.agent
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_agent_defaults();
CREATE TRIGGER trg_agent_lifecycle_edge BEFORE UPDATE OF lifecycle ON sibyl.agent
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('lifecycle', 'lifecycle');

CREATE TABLE sibyl.agent_version (
  tenant_id                 uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                        uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id                  uuid        NOT NULL,
  version_no                integer     NOT NULL,
  primary_model_id          uuid        NOT NULL,
  prompt_ref_id             uuid,
  prompt_sha256             bytea,
  config                    jsonb       NOT NULL DEFAULT '{}',
  declared_tool_ids         uuid[]      NOT NULL DEFAULT '{}',
  declared_data_source_ids  uuid[]      NOT NULL DEFAULT '{}',
  source                    text        NOT NULL,
  created_by_user_id        uuid,
  created_at                timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_agent_version_no UNIQUE (tenant_id, agent_id, version_no),
  CONSTRAINT fk_agent_version_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_agent_version_model FOREIGN KEY (tenant_id, primary_model_id)
    REFERENCES sibyl.model (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_agent_version_created_by FOREIGN KEY (tenant_id, created_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_agent_version_source CHECK (source IN ('sdk', 'api', 'gateway_observed')),
  CONSTRAINT ck_agent_version_config CHECK (pg_column_size(config) <= 4096),
  CONSTRAINT ck_agent_version_prompt_sha256 CHECK (prompt_sha256 IS NULL OR octet_length(prompt_sha256) = 32)
);

ALTER TABLE sibyl.agent ADD CONSTRAINT fk_agent_current_version FOREIGN KEY (tenant_id, current_version_id)
  REFERENCES sibyl.agent_version (tenant_id, id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE sibyl.agent_identity (
  tenant_id          uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                 uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id           uuid        NOT NULL,
  allowed_tools      text[]      NOT NULL DEFAULT '{}',
  allowed_models     text[]      NOT NULL DEFAULT '{}',
  allowed_providers  uuid[]      NOT NULL DEFAULT '{}',
  enforcement        text        NOT NULL DEFAULT 'observe',
  token_ttl_seconds  integer     NOT NULL DEFAULT 900,
  identity_version   integer     NOT NULL DEFAULT 1,
  tools_hash         bytea       NOT NULL,
  updated_by         uuid,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_agent_identity_agent UNIQUE (tenant_id, agent_id),
  CONSTRAINT fk_agent_identity_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_agent_identity_updated_by FOREIGN KEY (tenant_id, updated_by)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_agent_identity_enforcement CHECK (enforcement IN ('observe', 'block')),
  CONSTRAINT ck_agent_identity_ttl CHECK (token_ttl_seconds BETWEEN 60 AND 86400),
  CONSTRAINT ck_agent_identity_version CHECK (identity_version >= 1)
);

CREATE TABLE sibyl.ai_bom (
  tenant_id          uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                 uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_version_id   uuid        NOT NULL,
  format             text        NOT NULL DEFAULT 'cyclonedx-1.6',
  content            jsonb       NOT NULL,
  content_sha256     bytea       NOT NULL,
  generator_version  text        NOT NULL,
  generated_at       timestamptz NOT NULL DEFAULT now(),
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_ai_bom_agent_version FOREIGN KEY (tenant_id, agent_version_id)
    REFERENCES sibyl.agent_version (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_ai_bom_content CHECK (pg_column_size(content) <= 262144),
  CONSTRAINT ck_ai_bom_content_sha256 CHECK (octet_length(content_sha256) = 32)
);
CREATE INDEX ix_ai_bom_version ON sibyl.ai_bom (tenant_id, agent_version_id, generated_at DESC);

CREATE TABLE sibyl.lifecycle_transition (
  tenant_id      uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id             uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  agent_id       uuid        NOT NULL,
  from_stage     text,
  to_stage       text        NOT NULL,
  actor_user_id  uuid,
  reason         text,
  audit_seq      bigint      NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_lifecycle_transition_agent FOREIGN KEY (tenant_id, agent_id)
    REFERENCES sibyl.agent (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_lifecycle_transition_actor FOREIGN KEY (tenant_id, actor_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_lifecycle_transition_stages CHECK (
    (from_stage IS NULL OR from_stage IN ('discovered', 'proposed', 'approved', 'deployed', 'monitored', 'retired'))
    AND to_stage IN ('discovered', 'proposed', 'approved', 'deployed', 'monitored', 'retired'))
);
CREATE INDEX ix_lifecycle_transition_agent ON sibyl.lifecycle_transition (tenant_id, agent_id, created_at);

CREATE TABLE sibyl.tool (
  tenant_id       uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id              uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  slug            text        NOT NULL,
  name            text        NOT NULL,
  kind            text        NOT NULL,
  parent_tool_id  uuid,
  endpoint        text,
  permissions     jsonb       NOT NULL DEFAULT '{}',
  owner_user_id   uuid,
  is_approved     boolean     NOT NULL DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_tool_slug UNIQUE (tenant_id, slug),
  CONSTRAINT fk_tool_parent FOREIGN KEY (tenant_id, parent_tool_id)
    REFERENCES sibyl.tool (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_tool_owner FOREIGN KEY (tenant_id, owner_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_tool_kind CHECK (kind IN ('function', 'mcp_server', 'mcp_tool', 'http_api', 'code_interpreter', 'retrieval')),
  CONSTRAINT ck_tool_parent CHECK ((kind = 'mcp_tool') = (parent_tool_id IS NOT NULL))
);
CREATE INDEX ix_tool_parent ON sibyl.tool (tenant_id, parent_tool_id);

CREATE TABLE sibyl.data_source (
  tenant_id         uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  slug              text        NOT NULL,
  name              text        NOT NULL,
  kind              text        NOT NULL,
  classification    text        NOT NULL,
  residency_region  text,
  owner_user_id     uuid,
  attrs             jsonb       NOT NULL DEFAULT '{}',
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT uq_data_source_slug UNIQUE (tenant_id, slug),
  CONSTRAINT fk_data_source_owner FOREIGN KEY (tenant_id, owner_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_data_source_kind CHECK (kind IN ('vector_index', 'database', 'document_store', 'api',
                                                 'filesystem', 'saas', 'stream')),
  CONSTRAINT ck_data_source_classification CHECK (classification IN ('public', 'internal', 'confidential',
                                                                     'restricted', 'pii'))
);

CREATE TABLE sibyl.dependency_edge (
  tenant_id           uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                  uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  src_kind            text        NOT NULL,
  src_id              uuid        NOT NULL,
  dst_kind            text        NOT NULL,
  dst_id              uuid        NOT NULL,
  edge_type           text        NOT NULL,
  origin              text        NOT NULL,
  confidence          real        NOT NULL DEFAULT 1,
  attrs               jsonb       NOT NULL DEFAULT '{}',
  agent_version_id    uuid,
  valid_from          timestamptz NOT NULL DEFAULT now(),
  valid_to            timestamptz,
  created_by_user_id  uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_dependency_edge_version FOREIGN KEY (tenant_id, agent_version_id)
    REFERENCES sibyl.agent_version (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT fk_dependency_edge_created_by FOREIGN KEY (tenant_id, created_by_user_id)
    REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_dependency_edge_src_kind CHECK (src_kind IN ('agent', 'model', 'tool', 'data_source', 'provider')),
  CONSTRAINT ck_dependency_edge_dst_kind CHECK (dst_kind IN ('agent', 'model', 'tool', 'data_source', 'provider')),
  CONSTRAINT ck_dependency_edge_edge_type CHECK (edge_type IN ('uses_model', 'calls_tool', 'reads_data',
    'writes_data', 'delegates_to', 'fallback_to', 'served_by', 'exposes')),
  CONSTRAINT ck_dependency_edge_origin CHECK (origin IN ('declared', 'observed', 'inferred')),
  CONSTRAINT ck_dependency_edge_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT ck_dependency_edge_attrs CHECK (pg_column_size(attrs) <= 2048),
  CONSTRAINT ck_dependency_edge_valid CHECK (valid_to IS NULL OR valid_to >= valid_from)
);
CREATE UNIQUE INDEX ux_dependency_edge_open ON sibyl.dependency_edge
  (tenant_id, src_kind, src_id, dst_kind, dst_id, edge_type) WHERE valid_to IS NULL;
CREATE INDEX ix_dependency_edge_dst_open ON sibyl.dependency_edge (tenant_id, dst_kind, dst_id) WHERE valid_to IS NULL;
CREATE INDEX ix_dependency_edge_src_open ON sibyl.dependency_edge (tenant_id, src_kind, src_id) WHERE valid_to IS NULL;
CREATE INDEX ix_dependency_edge_dst_temporal ON sibyl.dependency_edge (tenant_id, dst_kind, dst_id, valid_from, valid_to);

-- Polymorphic ends must exist within the tenant (DATAMODEL §4.2).
CREATE FUNCTION sibyl.graph_node_exists(p_tenant uuid, p_kind text, p_id uuid) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
BEGIN
  RETURN CASE p_kind
    WHEN 'agent'       THEN EXISTS (SELECT 1 FROM sibyl.agent WHERE tenant_id = p_tenant AND id = p_id)
    WHEN 'model'       THEN EXISTS (SELECT 1 FROM sibyl.model WHERE tenant_id = p_tenant AND id = p_id)
    WHEN 'tool'        THEN EXISTS (SELECT 1 FROM sibyl.tool WHERE tenant_id = p_tenant AND id = p_id)
    WHEN 'data_source' THEN EXISTS (SELECT 1 FROM sibyl.data_source WHERE tenant_id = p_tenant AND id = p_id)
    WHEN 'provider'    THEN EXISTS (SELECT 1 FROM sibyl.provider WHERE tenant_id = p_tenant AND id = p_id)
    ELSE false END;
END
$$;

CREATE FUNCTION sibyl.trg_dependency_edge_check() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT sibyl.graph_node_exists(NEW.tenant_id, NEW.src_kind, NEW.src_id) THEN
    RAISE EXCEPTION 'sibyl:graph_node_missing: dependency_edge src %/% not found in tenant', NEW.src_kind, NEW.src_id USING ERRCODE = 'SB045';
  END IF;
  IF NOT sibyl.graph_node_exists(NEW.tenant_id, NEW.dst_kind, NEW.dst_id) THEN
    RAISE EXCEPTION 'sibyl:graph_node_missing: dependency_edge dst %/% not found in tenant', NEW.dst_kind, NEW.dst_id USING ERRCODE = 'SB045';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_dependency_edge_check BEFORE INSERT ON sibyl.dependency_edge
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_dependency_edge_check();

-- One graph_version bump and one outbox row per tenant per statement (SECURITY DEFINER: the
-- writing roles hold no UPDATE on tenant.graph_version).
CREATE FUNCTION sibyl.trg_graph_version_bump() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  r record;
  v_version bigint;
BEGIN
  FOR r IN SELECT DISTINCT tenant_id FROM changed_edges LOOP
    UPDATE sibyl.tenant SET graph_version = graph_version + 1 WHERE id = r.tenant_id
      RETURNING graph_version INTO v_version;
    INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind, aggregate_id, payload, idempotency_key)
    VALUES (r.tenant_id, 'graph', 'graph.changed', 'tenant', r.tenant_id,
            jsonb_build_object('tenant_id', r.tenant_id, 'graph_version', v_version),
            'graph:' || r.tenant_id || ':' || v_version);
  END LOOP;
  RETURN NULL;
END
$$;
CREATE TRIGGER trg_graph_version_bump_ins AFTER INSERT ON sibyl.dependency_edge
  REFERENCING NEW TABLE AS changed_edges FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_graph_version_bump();
CREATE TRIGGER trg_graph_version_bump_upd AFTER UPDATE ON sibyl.dependency_edge
  REFERENCING NEW TABLE AS changed_edges FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_graph_version_bump();

-- Every model has exactly one open served_by edge, written with the model row.
CREATE FUNCTION sibyl.trg_model_served_by() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO sibyl.dependency_edge (tenant_id, src_kind, src_id, dst_kind, dst_id, edge_type, origin)
  VALUES (NEW.tenant_id, 'model', NEW.id, 'provider', NEW.provider_id, 'served_by',
          CASE WHEN NEW.is_discovered THEN 'observed' ELSE 'declared' END)
  ON CONFLICT DO NOTHING;
  RETURN NULL;
END
$$;
CREATE TRIGGER trg_model_served_by AFTER INSERT ON sibyl.model
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_model_served_by();

-- Retiring an agent closes its open edges (history kept).
CREATE FUNCTION sibyl.trg_agent_retired_edges() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE sibyl.dependency_edge SET valid_to = now()
   WHERE tenant_id = NEW.tenant_id AND valid_to IS NULL
     AND ((src_kind = 'agent' AND src_id = NEW.id) OR (dst_kind = 'agent' AND dst_id = NEW.id));
  RETURN NULL;
END
$$;
CREATE TRIGGER trg_agent_retired_edges AFTER UPDATE OF lifecycle ON sibyl.agent
  FOR EACH ROW WHEN (NEW.lifecycle = 'retired' AND OLD.lifecycle <> 'retired')
  EXECUTE FUNCTION sibyl.trg_agent_retired_edges();

CREATE TABLE sibyl.blast_radius (
  tenant_id             uuid        NOT NULL REFERENCES sibyl.tenant (id),
  node_kind             text        NOT NULL,
  node_id               uuid        NOT NULL,
  graph_version         bigint      NOT NULL,
  max_depth             smallint    NOT NULL DEFAULT 3,
  affected_agent_ids    uuid[]      NOT NULL DEFAULT '{}',
  affected_process_ids  uuid[]      NOT NULL DEFAULT '{}',
  by_depth              jsonb       NOT NULL DEFAULT '{}',
  computed_at           timestamptz NOT NULL DEFAULT now(),
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, node_kind, node_id),
  CONSTRAINT ck_blast_radius_node_kind CHECK (node_kind IN ('agent', 'model', 'tool', 'data_source', 'provider'))
);

-- Upstream impact of a node: who (transitively, depth <= 3) depends on it via open edges.
CREATE FUNCTION sibyl.blast_radius_refresh(p_tenant uuid, p_node_kind text, p_node_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  v_version bigint;
BEGIN
  PERFORM sibyl.assert_tenant(p_tenant);
  SELECT graph_version INTO v_version FROM sibyl.tenant WHERE id = p_tenant;
  WITH RECURSIVE impact(kind, id, depth) AS (
    SELECT p_node_kind, p_node_id, 0
    UNION ALL
    SELECT e.src_kind, e.src_id, i.depth + 1
      FROM impact i
      JOIN sibyl.dependency_edge e
        ON e.tenant_id = p_tenant AND e.dst_kind = i.kind AND e.dst_id = i.id AND e.valid_to IS NULL
     WHERE i.depth < 3
  ) CYCLE kind, id SET is_cycle USING path,
  agents AS (
    SELECT id, min(depth) AS depth FROM impact WHERE kind = 'agent' AND NOT is_cycle AND depth > 0 GROUP BY id
  )
  INSERT INTO sibyl.blast_radius (tenant_id, node_kind, node_id, graph_version, affected_agent_ids,
                                  affected_process_ids, by_depth, computed_at)
  SELECT p_tenant, p_node_kind, p_node_id, v_version,
         coalesce((SELECT array_agg(id ORDER BY id) FROM agents), '{}'),
         coalesce((SELECT array_agg(DISTINCT a.business_process_id) FROM agents g
                    JOIN sibyl.agent a ON a.tenant_id = p_tenant AND a.id = g.id
                   WHERE a.business_process_id IS NOT NULL), '{}'),
         coalesce((SELECT jsonb_object_agg(depth::text, ids) FROM
                    (SELECT depth, jsonb_agg(id ORDER BY id) AS ids FROM agents GROUP BY depth) d), '{}'),
         now()
  ON CONFLICT (tenant_id, node_kind, node_id) DO UPDATE
    SET graph_version = EXCLUDED.graph_version, affected_agent_ids = EXCLUDED.affected_agent_ids,
        affected_process_ids = EXCLUDED.affected_process_ids, by_depth = EXCLUDED.by_depth,
        computed_at = EXCLUDED.computed_at;
END
$$;

CREATE TABLE sibyl.provider_status (
  tenant_id     uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id            uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  provider_id   uuid        NOT NULL,
  source        text        NOT NULL,
  component     text,
  status        text        NOT NULL,
  observed_at   timestamptz NOT NULL,
  incident_ref  text,
  raw           jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT fk_provider_status_provider FOREIGN KEY (tenant_id, provider_id)
    REFERENCES sibyl.provider (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE,
  CONSTRAINT ck_provider_status_source CHECK (source IN ('status_feed', 'probe', 'telemetry')),
  CONSTRAINT ck_provider_status_status CHECK (status IN ('operational', 'degraded_performance', 'partial_outage',
                                                         'major_outage', 'maintenance', 'unknown')),
  CONSTRAINT ck_provider_status_raw CHECK (raw IS NULL OR pg_column_size(raw) <= 8192)
);
CREATE INDEX ix_provider_status_observed ON sibyl.provider_status (tenant_id, provider_id, observed_at DESC);

-- D22 predicate (API synthesis): PII/residency exposure of an agent.
CREATE FUNCTION sibyl.agent_pii_exposed(p_tenant uuid, p_agent uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM sibyl.agent a WHERE a.tenant_id = p_tenant AND a.id = p_agent AND 'pii' = ANY (a.tags))
      OR EXISTS (SELECT 1 FROM sibyl.dependency_edge e
                   JOIN sibyl.data_source d ON d.tenant_id = e.tenant_id AND d.id = e.dst_id
                  WHERE e.tenant_id = p_tenant AND e.src_kind = 'agent' AND e.src_id = p_agent
                    AND e.dst_kind = 'data_source' AND e.valid_to IS NULL
                    AND (d.classification IN ('pii', 'restricted') OR d.residency_region IS NOT NULL))
$$;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['provider', 'model', 'business_process', 'agent', 'agent_version', 'agent_identity',
                           'ai_bom', 'lifecycle_transition', 'tool', 'data_source', 'dependency_edge',
                           'blast_radius', 'provider_status'] LOOP
    PERFORM sibyl.enable_tenant_rls(format('sibyl.%I', t)::regclass);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['provider', 'model', 'business_process', 'agent', 'agent_identity', 'tool',
                           'data_source', 'dependency_edge', 'blast_radius'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON sibyl.%I FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at()',
                   'trg_' || t || '_updated_at', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['agent_version', 'ai_bom', 'lifecycle_transition'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON sibyl.%I FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation()',
                   'trg_' || t || '_immutable', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON sibyl.%I FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation()',
                   'trg_' || t || '_no_truncate', t);
  END LOOP;
END
$$;

-- Grant matrix.
GRANT SELECT ON sibyl.provider, sibyl.model, sibyl.business_process, sibyl.agent, sibyl.agent_version,
  sibyl.agent_identity, sibyl.ai_bom, sibyl.lifecycle_transition, sibyl.tool, sibyl.data_source,
  sibyl.dependency_edge, sibyl.blast_radius, sibyl.provider_status
TO sibyl_app, sibyl_ingest, sibyl_worker;
GRANT INSERT, UPDATE, DELETE ON sibyl.provider, sibyl.model, sibyl.business_process, sibyl.tool,
  sibyl.data_source, sibyl.agent_identity TO sibyl_app;
GRANT INSERT, UPDATE ON sibyl.agent, sibyl.dependency_edge TO sibyl_app;
GRANT INSERT ON sibyl.agent_version, sibyl.lifecycle_transition TO sibyl_app;
GRANT INSERT, UPDATE, DELETE ON sibyl.blast_radius TO sibyl_app, sibyl_worker;
GRANT INSERT ON sibyl.agent, sibyl.agent_version, sibyl.model, sibyl.tool, sibyl.dependency_edge TO sibyl_ingest;
GRANT UPDATE (via_gateway, current_version_id) ON sibyl.agent TO sibyl_ingest;
GRANT UPDATE (preemptive_breaker_tripped_at) ON sibyl.agent TO sibyl_worker;
GRANT INSERT ON sibyl.ai_bom TO sibyl_worker;
GRANT INSERT, UPDATE ON sibyl.dependency_edge TO sibyl_worker;
GRANT INSERT, DELETE ON sibyl.provider_status TO sibyl_worker;
GRANT EXECUTE ON FUNCTION sibyl.graph_node_exists(uuid, text, uuid), sibyl.agent_pii_exposed(uuid, uuid)
  TO sibyl_app, sibyl_ingest, sibyl_worker, sibyl_routing, sibyl_audit;
GRANT EXECUTE ON FUNCTION sibyl.blast_radius_refresh(uuid, text, uuid) TO sibyl_app, sibyl_worker;
