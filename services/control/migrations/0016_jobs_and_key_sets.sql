-- 0016 integration lane INT-1: async jobs (chair ruling B14) and the signing-key rotation chain
-- (B10). Single sources: sibyl_schemas StateMachine.JOB / JobState / JobKind / SigningKeyState and
-- OutboxTopic.JOB ("job.requested").

-- B14 job state machine: claim, finish, retry with back-off, fail a queued job (cancel/deadline).
-- A running job whose lease expired is re-claimed in place (running -> running needs no edge).
ALTER TABLE sibyl.state_edge DROP CONSTRAINT ck_state_edge_machine;
ALTER TABLE sibyl.state_edge ADD CONSTRAINT ck_state_edge_machine CHECK (
  machine IN ('routing', 'failover', 'approval', 'handoff', 'alert', 'erasure', 'tenant_key', 'kill_switch',
              'lifecycle', 'job'));
INSERT INTO sibyl.state_edge (machine, from_state, to_state, trigger) VALUES
  ('job', '', 'queued', '*'),
  ('job', 'queued', 'running', '*'),
  ('job', 'running', 'done', '*'),
  ('job', 'running', 'failed', '*'),
  ('job', 'running', 'queued', '*'),
  ('job', 'queued', 'failed', '*');

-- B14: `job.requested` travels on its own coarse topic (sibyl_outbox channel, never streamed).
ALTER TABLE sibyl.outbox DROP CONSTRAINT ck_outbox_topic;
ALTER TABLE sibyl.outbox ADD CONSTRAINT ck_outbox_topic CHECK (
  topic IN ('policy', 'killswitch', 'graph', 'health', 'alert', 'provider_incident', 'incident', 'approval',
            'handoff', 'erasure', 'audit', 'agent', 'job'));

-- One row per asynchronous unit of work. The api enqueues (state queued, an outbox
-- `job.requested` in the same transaction); the worker's jobs loop claims with SKIP LOCKED under
-- a lease, runs the job outside any transaction and finishes it fenced by `attempts`. `error`
-- holds a stable code only (never upstream text); details live in `result`.
CREATE TABLE sibyl.job (
  tenant_id          uuid        NOT NULL REFERENCES sibyl.tenant (id),
  id                 uuid        NOT NULL DEFAULT sibyl.uuidv7(),
  kind               text        NOT NULL,
  state              text        NOT NULL DEFAULT 'queued',
  params             jsonb       NOT NULL DEFAULT '{}'::jsonb,
  result             jsonb,
  error              text,
  attempts           integer     NOT NULL DEFAULT 0,
  max_attempts       integer     NOT NULL DEFAULT 5,
  run_after          timestamptz NOT NULL DEFAULT now(),
  lease_until        timestamptz,
  requested_by       uuid,
  requested_by_kind  text        NOT NULL,
  subject_kind       text,
  subject_id         uuid,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  started_at         timestamptz,
  finished_at        timestamptz,
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT ck_job_kind CHECK (kind IN ('credential_probe', 'agent_bom', 'audit_verify', 'audit_export',
                                         'data_export')),
  CONSTRAINT ck_job_state CHECK (state IN ('queued', 'running', 'done', 'failed')),
  CONSTRAINT ck_job_requested_by_kind CHECK (requested_by_kind IN ('human', 'api_key', 'system')),
  CONSTRAINT ck_job_requester CHECK ((requested_by_kind = 'system') = (requested_by IS NULL)),
  CONSTRAINT ck_job_params CHECK (jsonb_typeof(params) = 'object'
                                  AND octet_length(sibyl.jcs_text(params, false)) <= 8192),
  CONSTRAINT ck_job_result CHECK (result IS NULL OR (jsonb_typeof(result) = 'object'
                                  AND octet_length(sibyl.jcs_text(result, false)) <= 65536)),
  CONSTRAINT ck_job_error CHECK (error IS NULL OR error ~ '^[a-z][a-z0-9_]{0,63}$'),
  CONSTRAINT ck_job_max_attempts CHECK (max_attempts BETWEEN 1 AND 20),
  CONSTRAINT ck_job_attempts CHECK (attempts BETWEEN 0 AND max_attempts),
  CONSTRAINT ck_job_lease CHECK ((state = 'running') = (lease_until IS NOT NULL)),
  CONSTRAINT ck_job_finished CHECK ((state IN ('done', 'failed')) = (finished_at IS NOT NULL)),
  CONSTRAINT ck_job_subject CHECK ((subject_kind IS NULL) = (subject_id IS NULL)
                                   AND (subject_kind IS NULL OR subject_kind ~ '^[a-z_]{1,40}$'))
);
CREATE INDEX ix_job_runnable ON sibyl.job (tenant_id, run_after, id) WHERE state = 'queued';
CREATE INDEX ix_job_lease ON sibyl.job (tenant_id, lease_until) WHERE state = 'running';
CREATE INDEX ix_job_requested_by ON sibyl.job (tenant_id, requested_by, created_at);
-- At most one open job per (kind, subject): a second request returns the one in flight.
CREATE UNIQUE INDEX ux_job_open_subject ON sibyl.job (tenant_id, kind, subject_kind, subject_id)
  WHERE state IN ('queued', 'running') AND subject_id IS NOT NULL;
SELECT sibyl.enable_tenant_rls('sibyl.job');
CREATE TRIGGER trg_job_updated_at BEFORE UPDATE ON sibyl.job
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_set_updated_at();
CREATE TRIGGER trg_job_state_edge BEFORE UPDATE OF state ON sibyl.job
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_state_edge('job', 'state');

GRANT SELECT ON sibyl.job TO sibyl_app, sibyl_worker;
GRANT INSERT (tenant_id, id, kind, params, max_attempts, run_after, requested_by, requested_by_kind,
              subject_kind, subject_id)
  ON sibyl.job TO sibyl_app, sibyl_worker;
GRANT UPDATE (state, result, error, attempts, run_after, lease_until, started_at, finished_at)
  ON sibyl.job TO sibyl_worker;
GRANT DELETE ON sibyl.job TO sibyl_worker;

-- B14 credential probe: the worker still cannot SELECT credential ciphertext (only metadata
-- columns); it reads the sealed secret of exactly the credential named by a `credential_probe`
-- job it currently holds the lease on, in the caller's tenant (FORCE RLS binds the definer).
CREATE FUNCTION sibyl.probe_credential_sealed(p_job_id uuid)
RETURNS TABLE (credential_id uuid, ciphertext bytea, nonce bytea, key_version integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
  SELECT c.id, c.ciphertext, c.nonce, c.key_version
    FROM sibyl.job j
    JOIN sibyl.provider_credential c ON c.tenant_id = j.tenant_id AND c.id = j.subject_id
   WHERE j.tenant_id = sibyl.current_tenant() AND j.id = p_job_id
     AND j.kind = 'credential_probe' AND j.subject_kind = 'provider_credential'
     AND j.state = 'running' AND j.lease_until > now()
     AND c.status IN ('active', 'rotating') AND c.ciphertext IS NOT NULL
$$;
REVOKE EXECUTE ON FUNCTION sibyl.probe_credential_sealed(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sibyl.probe_credential_sealed(uuid) TO sibyl_worker;

-- B10: a successor key is pre-published (`next`, announced as the key set's next_key) before it
-- becomes `active`; at most one per purpose.
ALTER TABLE sibyl.signing_key DROP CONSTRAINT ck_signing_key_state;
ALTER TABLE sibyl.signing_key ADD CONSTRAINT ck_signing_key_state CHECK (
  state IN ('next', 'active', 'retiring', 'retired', 'compromised'));
CREATE UNIQUE INDEX ux_signing_key_next ON sibyl.signing_key (purpose) WHERE state = 'next';

-- B10: every issued key set, so a freshly pinned verifier can follow the whole chain
-- (`GET /api/v1/policy/keys?since=<sequence>`). `document` is the exact JCS text served and
-- signed (`{kid, alg, sig, body}`); rows are immutable. Allowlisted (not tenant-scoped).
CREATE TABLE sibyl.signing_key_set (
  purpose      text        NOT NULL,
  sequence     bigint      NOT NULL,
  signer_kid   text        NOT NULL REFERENCES sibyl.signing_key (kid),
  active_kid   text        NOT NULL REFERENCES sibyl.signing_key (kid),
  next_kid     text        REFERENCES sibyl.signing_key (kid),
  document     text        NOT NULL,
  body_sha256  bytea       NOT NULL,
  issued_at    timestamptz NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (purpose, sequence),
  CONSTRAINT ck_signing_key_set_purpose CHECK (purpose IN ('snapshot', 'audit_anchor', 'agent_token')),
  CONSTRAINT ck_signing_key_set_sequence CHECK (sequence BETWEEN 1 AND 9007199254740991),
  CONSTRAINT ck_signing_key_set_document CHECK (
    octet_length(document) <= 65536
    AND jsonb_typeof(document::jsonb) = 'object'
    AND document::jsonb ->> 'kid' = signer_kid
    AND (document::jsonb -> 'body' ->> 'sequence')::bigint = sequence),
  CONSTRAINT ck_signing_key_set_sha CHECK (octet_length(body_sha256) = 32)
);
CREATE TRIGGER trg_signing_key_set_immutable BEFORE UPDATE OR DELETE ON sibyl.signing_key_set
  FOR EACH ROW EXECUTE FUNCTION sibyl.trg_block_mutation();
CREATE TRIGGER trg_signing_key_set_no_truncate BEFORE TRUNCATE ON sibyl.signing_key_set
  FOR EACH STATEMENT EXECUTE FUNCTION sibyl.trg_block_mutation();
GRANT SELECT ON sibyl.signing_key_set TO sibyl_app, sibyl_ingest, sibyl_worker, sibyl_audit, sibyl_routing;
GRANT INSERT ON sibyl.signing_key_set TO sibyl_app, sibyl_worker;
