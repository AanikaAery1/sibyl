-- 0012 outbox (DATAMODEL §4.9 amended by R58/X1–X2 and R60/T2).
-- ~12 coarse topics with fine event_type (the SSE `event:` name); NOTIFY on exactly two
-- channels with a constant per-tenant payload so Postgres coalesces duplicates in a
-- transaction (risk T3). Consumers page by the commit-ordered key (xid, id) below the
-- commit horizon, never by created_at.

CREATE TABLE sibyl.outbox (
  tenant_id        uuid        NOT NULL,
  id               uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  created_at       timestamptz NOT NULL DEFAULT now(),
  xid              xid8        NOT NULL DEFAULT pg_current_xact_id(),
  topic            text        NOT NULL,
  event_type       text        NOT NULL,
  aggregate_kind   text        NOT NULL,
  aggregate_id     uuid        NOT NULL,
  payload          jsonb       NOT NULL,
  idempotency_key  text        NOT NULL,
  PRIMARY KEY (tenant_id, id, created_at),
  -- G0 L1: this does NOT deduplicate. A partitioned unique key must include created_at, so two
  -- writes with the same idempotency_key at different instants both land. idempotency_key is
  -- a consumer-side dedupe key: consumers keep the keys they processed (or rely on the
  -- (xid, id) cursor, which delivers each row once); writers must not count on a conflict.
  CONSTRAINT uq_outbox_idempotency UNIQUE (tenant_id, idempotency_key, created_at),
  CONSTRAINT ck_outbox_topic CHECK (topic IN ('policy', 'killswitch', 'graph', 'health', 'alert', 'provider_incident',
                                              'incident', 'approval', 'handoff', 'erasure', 'audit', 'agent')),
  CONSTRAINT ck_outbox_event_type CHECK (event_type ~ '^[a-z_]+(\.[a-z_]+)*$'),
  -- G0 M2: 8 KB of compact JSON (the size the kernel measures), not the jsonb footprint.
  CONSTRAINT ck_outbox_payload CHECK (jsonb_typeof(payload) = 'object'
                                      AND octet_length(sibyl.jcs_text(payload, false)) <= 8192)
) PARTITION BY RANGE (created_at);
CREATE INDEX ix_outbox_cursor ON sibyl.outbox (tenant_id, xid, id);
CREATE INDEX ix_outbox_topic ON sibyl.outbox (tenant_id, topic, created_at);
SELECT sibyl.enable_tenant_rls('sibyl.outbox');

CREATE FUNCTION sibyl.outbox_channel(p_topic text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN p_topic IN ('policy', 'killswitch') THEN 'sibyl_policy' ELSE 'sibyl_outbox' END
$$;

CREATE FUNCTION sibyl.trg_outbox_notify() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT DISTINCT sibyl.outbox_channel(topic) AS channel, tenant_id FROM new_rows LOOP
    PERFORM pg_notify(r.channel, r.tenant_id::text);
  END LOOP;
  RETURN NULL;
END
$$;
CREATE TRIGGER trg_outbox_notify AFTER INSERT ON sibyl.outbox
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_outbox_notify();
CREATE TRIGGER trg_outbox_immutable BEFORE UPDATE ON sibyl.outbox
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();

-- R60 reader: rows strictly after the cursor and strictly below the commit horizon, so a
-- transaction that commits late can never be skipped. SSE Last-Event-ID = '<xid>|<id>'.
CREATE FUNCTION sibyl.outbox_read(p_after_xid xid8, p_after_id uuid, p_limit integer DEFAULT 1000,
                                  p_topics text[] DEFAULT NULL)
RETURNS SETOF sibyl.outbox
LANGUAGE sql STABLE AS $$
  SELECT o.* FROM sibyl.outbox o
   WHERE o.tenant_id = sibyl.current_tenant()
     AND (o.xid, o.id) > (p_after_xid, p_after_id)
     AND o.xid < sibyl.commit_horizon()
     AND (p_topics IS NULL OR o.topic = ANY (p_topics))
   ORDER BY o.xid, o.id
   LIMIT p_limit
$$;

GRANT SELECT ON sibyl.outbox TO sibyl_app, sibyl_worker;
GRANT DELETE ON sibyl.outbox TO sibyl_worker;
SELECT sibyl.grant_insert_except('sibyl.outbox', r, ARRAY['xid'])
  FROM unnest(ARRAY['sibyl_app', 'sibyl_worker', 'sibyl_ingest', 'sibyl_routing']) AS r;
GRANT EXECUTE ON FUNCTION sibyl.outbox_channel(text), sibyl.outbox_read(xid8, uuid, integer, text[])
  TO sibyl_app, sibyl_worker, sibyl_ingest, sibyl_routing;
