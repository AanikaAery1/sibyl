"""Runs (D50 run tree, ``payloads:read`` G like ``/events`` and ``/traces``): metadata only.

``GET /runs`` pages runs (newest first, keyset ``(started_at, run_id)``) seen in a window of
event time (``since``/``until``, default 24 h, at most 31 days). ``GET /runs/{run_id}`` returns
one run as a tree: its steps in order (model calls with requested vs served model, tool calls
with the Action Gate outcome, child runs), its child runs recursively and the handoffs it made.
The tree is bounded (``MAX_RUNS`` runs, ``MAX_STEPS`` steps, ``MAX_DEPTH`` levels) and says
``truncated`` when a bound cut it. A group-scoped caller sees only runs of agents in its groups.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...core.problems import ProblemError
from ...ingest.normalise.identity import unclaimed_slug
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import Outcome, PageQuery, keyset_page, run_read
from . import runs_sql as q
from . import runs_views as v
from .common import group_scope, window

router = APIRouter()
DEFAULT_WINDOW = timedelta(hours=24)
MAX_WINDOW = timedelta(days=31)
MAX_RUNS = 200
MAX_STEPS = 2000
MAX_DEPTH = 16
RunStatus = Literal["running", "ok", "error", "handed_off", "cancelled"]


@router.get(API_PREFIX + "/runs")
async def list_runs(
    ctx: Annotated[AuthContext, Depends(guard("listRuns"))],
    agent_id: Annotated[UUID | None, Query()] = None,
    root_only: Annotated[bool, Query()] = False,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    status: Annotated[RunStatus | None, Query()] = None,
    limit: Annotated[int | None, Query()] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    lo, hi = window(since, until, now=ctx.now, default=DEFAULT_WINDOW, maximum=MAX_WINDOW)
    page = PageQuery.of(
        limit,
        cursor,
        agent_id=agent_id,
        root_only=root_only,
        since=since,
        until=until,
        status=status,
    )
    groups = group_scope(ctx)

    async def work(conn: Any) -> Outcome:
        return await keyset_page(
            conn,
            ctx,
            select=q.list_sql(),
            args=[ctx.tenant_id, groups, lo, hi, agent_id, root_only, status],
            page=page,
            keys=("x.started_at", "x.run_id"),
            descending=True,
            serialize=v.run_summary,
        )

    return await run_read(ctx, work)


class _Tree:
    """Collects the runs and steps of one tree within the bounds."""

    def __init__(self) -> None:
        self.runs: dict[str, dict[str, Any]] = {}
        self.parent: dict[str, str] = {}
        self.truncated = False

    async def load_runs(self, conn: Any, ctx: AuthContext, groups: Any, root: UUID) -> None:
        frontier = [root]
        for _depth in range(MAX_DEPTH + 1):
            rows = await conn.fetch(q.RUNS_BY_ID, ctx.tenant_id, groups, frontier)
            for row in rows:
                summary = v.run_summary(row)
                self.runs[summary["run_id"]] = summary
            ids = [str(r) for r in frontier if str(r) in self.runs]
            children = await conn.fetch(q.CHILD_IDS, ctx.tenant_id, groups, ids)
            frontier = [r["task_id"] for r in children if str(r["task_id"]) not in self.runs]
            room = MAX_RUNS - len(self.runs)
            if len(frontier) > room:
                self.truncated = True
                frontier = frontier[: max(room, 0)]
            if not frontier:
                return
        self.truncated = True

    async def load_steps(
        self, conn: Any, ctx: AuthContext, groups: Any
    ) -> dict[str, list[dict[str, Any]]]:
        ids = list(self.runs)
        rows = await conn.fetch(
            q.STEPS, ctx.tenant_id, groups, ids, [UUID(i) for i in ids], MAX_STEPS + 1
        )
        if len(rows) > MAX_STEPS:
            self.truncated = True
            rows = rows[:MAX_STEPS]
        steps: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            attrs = row["attrs"] if isinstance(row["attrs"], dict) else {}
            owner = attrs.get("parent_run_id")
            if owner not in self.runs:
                owner = str(row["task_id"]) if row["task_id"] is not None else None
            if owner in self.runs:
                steps[owner].append(row)
        return steps


async def _agents(conn: Any, ctx: AuthContext, groups: Any, refs: set[str]) -> dict[str, UUID]:
    if not refs:
        return {}
    lookup = {ref: ref for ref in refs} | {unclaimed_slug(ref): ref for ref in refs}
    rows = await conn.fetch(q.AGENTS_BY_REF, ctx.tenant_id, groups, list(lookup))
    out: dict[str, UUID] = {}
    for row in rows:
        for key in (row["slug"], str(row["id"])):
            ref = lookup.get(key)
            if ref is not None and (ref not in out or key == ref):
                out[ref] = row["id"]
    return out


def _handoff_refs(tree: _Tree, steps: dict[str, list[Any]]) -> set[str]:
    refs = {r["handoff_to_agent"] for r in tree.runs.values() if r["handoff_to_agent"]}
    for rows in steps.values():
        for row in rows:
            attrs = row["attrs"] if isinstance(row["attrs"], dict) else {}
            if row["event_type"] == "tool.call" and attrs.get("handoff_to_agent"):
                refs.add(attrs["handoff_to_agent"])
    return refs


def _node(
    run_id: str,
    tree: _Tree,
    steps: dict[str, list[Any]],
    kids: dict[str, list[str]],
    agents: dict[str, UUID],
) -> dict[str, Any]:
    run = tree.runs[run_id]
    children = [_node(c, tree, steps, kids, agents) for c in kids.get(run_id, [])]
    ordered = [v.event_step(r) for r in steps.get(run_id, [])]
    ordered += [v.child_step(c) for c in children]
    ordered.sort(key=v.step_order)
    handoffs = []
    if run["handoff_to_agent"]:
        ref = run["handoff_to_agent"]
        handoffs.append(v.handoff(run_id, ref, "run", run["ended_at"], None, agents))
    for row in steps.get(run_id, []):
        attrs = row["attrs"] if isinstance(row["attrs"], dict) else {}
        ref = attrs.get("handoff_to_agent") if row["event_type"] == "tool.call" else None
        if ref:
            step = v.event_step(row)
            handoffs.append(v.handoff(run_id, ref, "tool", step["ts"], step["event_id"], agents))
    return {**run, "steps": ordered, "children": children, "handoffs": handoffs}


@router.get(API_PREFIX + "/runs/{run_id}")
async def get_run(run_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getRun"))]) -> Response:
    groups = group_scope(ctx)

    async def work(conn: Any) -> Outcome:
        tree = _Tree()
        await tree.load_runs(conn, ctx, groups, run_id)
        root = str(run_id)
        if root not in tree.runs:
            raise ProblemError("not_found")
        steps = await tree.load_steps(conn, ctx, groups)
        kids: dict[str, list[str]] = defaultdict(list)
        for rid, run in sorted(tree.runs.items(), key=lambda kv: kv[1]["started_at"] or ""):
            parent = run["parent_run_id"]
            if rid != root and parent in tree.runs:
                kids[parent].append(rid)
        agents = await _agents(conn, ctx, groups, _handoff_refs(tree, steps))
        body = _node(root, tree, steps, kids, agents)
        body.update(truncated=tree.truncated, run_count=len(tree.runs))
        return Outcome(body)

    return await run_read(ctx, work)
