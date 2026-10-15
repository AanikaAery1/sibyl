-- Shared, transactionally reserved monthly budget ledger for agent provider calls.
-- This is a foundation: it MUST be wired into the gateway's pre-dispatch path
-- before the product may claim to enforce hard monthly spending limits.
--
-- Periods use UTC month starts. Do not automatically expire reservations:
-- a timed-out provider call can still be billed; reconcile uncertain outcomes.
-- On deleting an agent, cascading foreign keys remove derived budget records.

CREATE TABLE sibyl.agent_budget_period (
    tenant_id     uuid NOT NULL,
    agent_id      uuid NOT NULL,
    period_start  date NOT NULL,
    spent_usd     numeric(18,8) NOT NULL DEFAULT 0,
    reserved_usd  numeric(18,8) NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, period_start),
    CONSTRAINT fk_agent_budget_agent FOREIGN KEY (tenant_id, agent_id)
      REFERENCES sibyl.agent (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT ck_agent_budget_period_month CHECK
      (EXTRACT(DAY FROM period_start) = 1),
    CONSTRAINT ck_agent_budget_period_amount CHECK
      (spent_usd >= 0 AND reserved_usd >= 0)
);

CREATE TABLE sibyl.agent_budget_reservation (
    tenant_id     uuid NOT NULL,
    request_id    uuid NOT NULL,
    agent_id      uuid NOT NULL,
    period_start  date NOT NULL,
    reserved_usd  numeric(18,8) NOT NULL,
    actual_usd    numeric(18,8),
    state         text NOT NULL DEFAULT 'pending',
    created_at    timestamptz NOT NULL DEFAULT now(),
    settled_at    timestamptz,
    PRIMARY KEY (tenant_id, request_id),
    CONSTRAINT fk_agent_budget_period FOREIGN KEY (tenant_id, agent_id, period_start)
      REFERENCES sibyl.agent_budget_period (tenant_id, agent_id, period_start)
      ON DELETE CASCADE,
    CONSTRAINT ck_agent_budget_reservation_state CHECK
      (state IN ('pending', 'settled')),
    CONSTRAINT ck_agent_budget_reservation_amount CHECK
      (reserved_usd > 0 AND (actual_usd IS NULL OR actual_usd >= 0)),
    CONSTRAINT ck_agent_budget_reservation_terminal CHECK
      ((state = 'pending' AND actual_usd IS NULL AND settled_at IS NULL)
       OR (state = 'settled' AND actual_usd IS NOT NULL AND settled_at IS NOT NULL))
);
CREATE INDEX ix_agent_budget_pending ON sibyl.agent_budget_reservation
    (tenant_id, agent_id, created_at) WHERE state = 'pending';

SELECT sibyl.enable_tenant_rls('sibyl.agent_budget_period');
SELECT sibyl.enable_tenant_rls('sibyl.agent_budget_reservation');
GRANT SELECT, INSERT, UPDATE ON
    sibyl.agent_budget_period, sibyl.agent_budget_reservation TO sibyl_app;
