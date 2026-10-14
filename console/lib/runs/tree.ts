/**
 * Run tree (D50) view model. The API builds the tree (`GET /runs/{run_id}`: ordered steps of
 * model calls, tool calls and child runs, the handoffs each run made, and `truncated` when a
 * bound cut it); this module only flattens it into what the screen renders, adds totals and
 * builds the run paths. Pure and unit-tested.
 */
import type { RunDetail, RunNode, RunStatus, RunStep, TelemetryEvent, ToolActionEffect } from "@/lib/api/monitor";

export type GateEffect = ToolActionEffect;

export interface GateOutcome {
  /** Null when the gate recorded a rule or a hold but no effect. */
  effect: GateEffect | null;
  ruleId: string | null;
  heldActionId: string | null;
}

export interface ModelCall {
  kind: "model";
  id: string;
  step: number | null;
  at: string | null;
  provider: string | null;
  requested: string | null;
  served: string | null;
  /** The API's `model_mismatch`: served is neither the requested model nor a snapshot of it; null when unknown. */
  mismatch: boolean | null;
  fingerprint: string | null;
  latencyMs: number | null;
  tokensIn: number | null;
  tokensOut: number | null;
  status: string | null;
  finish: string | null;
  costUsd: number | null;
}

export interface ToolCall {
  kind: "tool";
  id: string;
  step: number | null;
  at: string | null;
  tool: string;
  status: string | null;
  latencyMs: number | null;
  handoffTo: string | null;
  /** The registered agent the handoff went to, when the API resolved it. */
  handoffAgentId: string | null;
  gate: GateOutcome | null;
}

export interface RunView {
  id: string;
  agentId: string | null;
  agentName: string;
  parentId: string | null;
  step: number | null;
  status: RunStatus;
  errorType: string | null;
  startedAt: string | null;
  endedAt: string | null;
  durationMs: number | null;
  traceId: string | null;
  handoffTo: string | null;
  handoffAgentId: string | null;
  costUsd: number | null;
  items: RunItem[];
}

export interface ChildRun {
  kind: "run";
  id: string;
  step: number | null;
  at: string | null;
  run: RunView;
}

export type RunItem = ModelCall | ToolCall | ChildRun;

export interface RunTotals {
  runs: number;
  models: number;
  tools: number;
  handoffs: number;
  gated: number;
  held: number;
  blocked: number;
  mismatched: number;
}

export interface RunTree {
  root: RunView;
  totals: RunTotals;
  /** A size or depth bound cut the tree: some runs or steps are not shown. */
  truncated: boolean;
  /** Runs in the tree as the API counted them. */
  runCount: number;
}

const HELD_EFFECTS: ReadonlySet<string> = new Set(["held", "approved", "denied"]);

export const RUN_STATUS_LABEL: Readonly<Record<RunStatus, string>> = { running: "Running", ok: "OK", error: "Error", handed_off: "Handed off", cancelled: "Cancelled" };

export const runPath = (runId: string): string => `/runs/${runId}`;

export interface RunsQuery {
  agentId?: string | null;
  rootOnly?: boolean;
  status?: RunStatus | null;
  since?: string | null;
  until?: string | null;
  limit?: number;
  cursor?: string | null;
}

/** `GET /runs` with only the filters that are set (stable order, so SWR keys are stable). */
export function runsPath(q: RunsQuery = {}): string {
  const p = new URLSearchParams();
  if (q.agentId) p.set("agent_id", q.agentId);
  if (q.rootOnly) p.set("root_only", "true");
  if (q.status) p.set("status", q.status);
  if (q.since) p.set("since", q.since);
  if (q.until) p.set("until", q.until);
  p.set("limit", String(q.limit ?? 50));
  if (q.cursor) p.set("cursor", q.cursor);
  return `/runs?${p.toString()}`;
}

const STATUSES: ReadonlySet<string> = new Set(Object.keys(RUN_STATUS_LABEL));

/**
 * The runs list's filters from its URL (`agent_id`, `status`, `since`, `until`, `scope=all` for
 * child runs too, `cursor`). Top-level runs only unless asked; unknown values are dropped.
 */
export function runsQueryOf(get: (k: string) => string | null | undefined): RunsQuery {
  const status = get("status");
  return {
    agentId: get("agent_id") || null,
    rootOnly: get("scope") !== "all",
    status: status && STATUSES.has(status) ? (status as RunStatus) : null,
    since: get("since") || null,
    until: get("until") || null,
    limit: 50,
    cursor: get("cursor") || null,
  };
}

/** An agent's recent top-level runs (agent detail). */
export const recentRunsPath = (agentId: string): string => runsPath({ agentId, rootOnly: true, limit: 8 });

function stepItem(s: RunStep, i: number, owner: RunNode, children: ReadonlyMap<string, RunView>): RunItem | null {
  const id = s.event_id ?? `${owner.run_id}:${i}`;
  if (s.kind === "child_run") {
    const run = s.child_run_id ? children.get(s.child_run_id) : undefined;
    return run ? { kind: "run", id: run.id, step: s.step_index, at: s.ts, run } : null;
  }
  if (s.kind === "model_call") {
    const m = s.model_call;
    return {
      kind: "model",
      id,
      step: s.step_index,
      at: s.ts,
      provider: m?.provider ?? null,
      requested: m?.requested_model ?? null,
      served: m?.served_model ?? null,
      mismatch: m?.model_mismatch ?? null,
      fingerprint: m?.system_fingerprint ?? null,
      latencyMs: s.latency_ms ?? null,
      tokensIn: m?.tokens_in ?? null,
      tokensOut: m?.tokens_out ?? null,
      status: s.status ?? null,
      finish: m?.finish_reasons?.[0] ?? null,
      costUsd: m?.cost_usd ?? null,
    };
  }
  const t = s.tool_call;
  const handoffTo = t?.handoff_to_agent ?? null;
  const handoff = handoffTo ? owner.handoffs.find((h) => h.via === "tool" && (h.event_id === s.event_id || (!h.event_id && h.to_agent === handoffTo))) : undefined;
  const g = t?.action_gate ?? null;
  return {
    kind: "tool",
    id,
    step: s.step_index,
    at: s.ts,
    tool: t?.tool_name ?? "tool",
    status: s.status ?? null,
    latencyMs: s.latency_ms ?? null,
    handoffTo,
    handoffAgentId: handoff?.to_agent_id ?? null,
    gate: g ? { effect: g.effect ?? null, ruleId: g.rule_id ?? null, heldActionId: g.held_action_id ?? null } : null,
  };
}

function view(n: RunNode, parentHandoffs: RunNode["handoffs"]): RunView {
  const children = new Map(n.children.map((c) => [c.run_id, view(c, n.handoffs)] as const));
  const items = n.steps.map((s, i) => stepItem(s, i, n, children)).filter((x): x is RunItem => x !== null);
  // A child the steps do not mention (the API lists every child as a step; keep any stray one visible).
  const listed = new Set(items.filter((i) => i.kind === "run").map((i) => i.id));
  const stray: ChildRun[] = [...children.values()].filter((c) => !listed.has(c.id)).map((c) => ({ kind: "run", id: c.id, step: c.step, at: c.startedAt, run: c }));
  const ownHandoff = n.handoffs.find((h) => h.via === "run") ?? parentHandoffs.find((h) => h.via === "run" && h.from_run_id === n.run_id);
  return {
    id: n.run_id,
    agentId: n.agent_id ?? null,
    agentName: n.agent_name ?? "Run",
    parentId: n.parent_run_id ?? null,
    step: n.step_index ?? null,
    status: n.status,
    errorType: n.error_type ?? null,
    startedAt: n.started_at,
    endedAt: n.ended_at ?? null,
    durationMs: n.duration_ms ?? null,
    traceId: n.trace_id ?? null,
    handoffTo: n.handoff_to_agent ?? null,
    handoffAgentId: ownHandoff?.to_agent_id ?? null,
    costUsd: n.cost_usd ?? null,
    items: [...items, ...stray],
  };
}

export function flatten(root: RunView): RunItem[] {
  return root.items.flatMap((it) => (it.kind === "run" ? [it, ...flatten(it.run)] : [it]));
}

/** The view of one `RunDetail`, with totals over the whole tree. */
export function runTree(d: RunDetail): RunTree {
  const root = view(d, []);
  const flat = flatten(root);
  const tools = flat.filter((i): i is ToolCall => i.kind === "tool");
  const models = flat.filter((i): i is ModelCall => i.kind === "model");
  const childRuns = flat.filter((i): i is ChildRun => i.kind === "run");
  return {
    root,
    totals: {
      runs: 1 + childRuns.length,
      models: models.length,
      tools: tools.length,
      handoffs: tools.filter((t) => t.handoffTo).length + childRuns.filter((c) => c.run.handoffTo).length,
      gated: tools.filter((t) => t.gate).length,
      held: tools.filter((t) => t.gate?.effect && HELD_EFFECTS.has(t.gate.effect)).length,
      blocked: tools.filter((t) => t.gate?.effect === "block").length,
      mismatched: models.filter((m) => m.mismatch === true).length,
    },
    truncated: d.truncated,
    runCount: d.run_count,
  };
}

/** The top-level runs of a trace (agent.invoke without a parent), oldest first: where a trace link lands. */
export function rootRunsOf(spans: readonly TelemetryEvent[]): string[] {
  const out: string[] = [];
  for (const e of [...spans].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts))) {
    const parent = (e.attrs as Record<string, unknown> | null | undefined)?.parent_run_id;
    if (e.event_type !== "agent.invoke" || !e.task_id || (typeof parent === "string" && parent) || out.includes(e.task_id)) continue;
    out.push(e.task_id);
  }
  return out;
}
