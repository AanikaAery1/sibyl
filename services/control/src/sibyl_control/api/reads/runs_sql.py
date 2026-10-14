"""SQL for the run tree (D50): runs are ``agent.invoke`` events grouped by ``task_id``.

A run has up to two invoke events: ``phase=start`` (sibyl-event, at entry) and ``phase=end``
(the ``invoke_agent`` span, with status, duration and counts). A run without an end event is
``running``. Children are runs whose ``attrs.parent_run_id`` names the run; steps are the
``gen_ai.request`` / ``tool.call`` events whose ``parent_run_id`` (else ``task_id``) is the run.
Every statement filters by the caller's agent groups (``$2``), like ``/events`` and ``/traces``.
All statements are constant fragments; no input reaches the SQL text.
"""

from __future__ import annotations

_SCOPE = (
    " FROM sibyl.events e"
    " LEFT JOIN sibyl.agent a ON a.tenant_id = e.tenant_id AND a.id = e.agent_id"
    " WHERE e.tenant_id = $1 AND ($2::uuid[] IS NULL OR a.agent_group_id = ANY ($2::uuid[]))"
)

# One row per run. Callers append WHERE conditions on the events (``e.``) before GROUP BY.
_GROUPED = (
    "SELECT e.task_id AS run_id,"
    " min(e.ts) FILTER (WHERE e.attrs->>'phase' = 'start') AS start_ts,"
    " max(e.ts) FILTER (WHERE e.attrs->>'phase' = 'end') AS end_ts,"
    " (array_agg(e.attrs ORDER BY e.ts DESC) FILTER (WHERE e.attrs->>'phase' = 'end'))[1]"
    "   AS end_attrs,"
    " (array_agg(e.status ORDER BY e.ts DESC) FILTER (WHERE e.attrs->>'phase' = 'end'))[1]"
    "   AS end_status,"
    " (array_agg(e.attrs ORDER BY e.ts))[1] AS first_attrs,"
    " (array_agg(e.agent_id ORDER BY e.ts DESC))[1] AS agent_id,"
    " (array_agg(e.trace_id ORDER BY e.ts) FILTER (WHERE e.trace_id IS NOT NULL))[1]"
    "   AS trace_id,"
    " max(e.attrs->>'parent_run_id') AS parent_run_id,"
    " max(e.attrs->>'handoff_to_agent') AS handoff_to_agent,"
    " max((e.attrs->>'step_index')::bigint) AS step_index"
    + _SCOPE
    + " AND e.event_type = 'agent.invoke' AND e.task_id IS NOT NULL"
)

_DERIVED = (
    "SELECT r.*,"
    " coalesce(r.start_ts, r.end_ts - make_interval(secs =>"
    "   coalesce((r.end_attrs->>'duration_ms')::float8, 0) / 1000)) AS started_at,"
    " CASE WHEN r.end_ts IS NULL THEN 'running'"
    "   ELSE coalesce(r.end_attrs->>'status', r.end_status, 'ok') END AS run_status"
    " FROM ("
)


def list_sql() -> str:
    """$3/$4 window on event ts, $5 agent; the outer filters are $6 root_only, $7 status.
    Ends in a WHERE so ``keyset_page`` can append its predicate."""
    return (
        "SELECT * FROM (" + _DERIVED + _GROUPED + " AND e.ts >= $3 AND e.ts < $4"  # noqa: S608
        " AND ($5::uuid IS NULL OR e.agent_id = $5)"
        " GROUP BY e.task_id) r) x"
        " WHERE (NOT $6::boolean OR x.parent_run_id IS NULL)"
        " AND ($7::text IS NULL OR x.run_status = $7)"
    )


RUNS_BY_ID = _DERIVED + _GROUPED + " AND e.task_id = ANY ($3::uuid[]) GROUP BY e.task_id) r"

CHILD_IDS = (
    "SELECT DISTINCT e.task_id" + _SCOPE + " AND e.event_type = 'agent.invoke'"
    " AND e.task_id IS NOT NULL AND e.attrs->>'parent_run_id' = ANY ($3::text[])"
)

STEPS = (
    "SELECT e.event_id, e.event_type, e.ts, e.task_id, e.call_id, e.status, e.provider,"
    " e.model, e.response_model, e.latency_ms, e.tokens_in, e.tokens_out, e.cost_usd,"
    " e.error_type, e.attrs" + _SCOPE + " AND e.event_type IN ('gen_ai.request', 'tool.call')"
    " AND (e.attrs->>'parent_run_id' = ANY ($3::text[]) OR e.task_id = ANY ($4::uuid[]))"
    " ORDER BY e.ts, e.event_id LIMIT $5"
)

AGENTS_BY_REF = (
    "SELECT id, slug FROM sibyl.agent WHERE tenant_id = $1"
    " AND ($2::uuid[] IS NULL OR agent_group_id = ANY ($2::uuid[]))"
    " AND (slug = ANY ($3::text[]) OR id::text = ANY ($3::text[]))"
)
