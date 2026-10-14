/**
 * Runs from telemetry (D50), the way the control API projects them for `GET /runs` and
 * `GET /runs/{run_id}` (services/control/.../api/reads/runs.py). Pure and unit-tested; the demo
 * BFF serves its run routes through it so demo and live return the same shapes.
 *
 * A run is the `agent.invoke` events of one `task_id` (`phase` start/end; a run without an end
 * is `running`). Its parent is `attrs.parent_run_id`; its steps are the `gen_ai.request` and
 * `tool.call` events whose `parent_run_id` (else `task_id`) names it. The tree is bounded and
 * says `truncated` when a bound cut it.
 */
import type { RunDetail, RunHandoff, RunModelCall, RunNode, RunStatus, RunStep, RunSummary, RunToolCall, TelemetryEvent, ToolActionEffect } from "@/lib/api/monitor";

export const RUN_BOUNDS = { runs: 200, steps: 2000, depth: 16 } as const;
export const RUN_STATUSES: readonly RunStatus[] = ["running", "ok", "error", "handed_off", "cancelled"];

type Attrs = Record<string, unknown>;

const attrsOf = (e: TelemetryEvent): Attrs => (e.attrs ?? {}) as Attrs;
const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const int = (v: unknown): number | null => (typeof v === "number" && Number.isInteger(v) ? v : null);
const ms = (iso: string): number => Date.parse(iso);

const SNAPSHOT = /^[-@:](\d{2,}[0-9.-]*|v\d+(\.\d+)*|latest)$/;
const norm = (model: string): string => model.trim().toLowerCase().replace(/^models\//, "");

/** `served` is `requested` or a dated or pinned snapshot of it (`gpt-4o` → `gpt-4o-mini` is not). */
export function servedMatches(requested: string, served: string): boolean {
  const r = norm(requested);
  const s = norm(served);
  if (!r || !s || !s.startsWith(r)) return false;
  return s === r || SNAPSHOT.test(s.slice(r.length));
}

/** Fold the invoke events into one summary per run (the live `_GROUPED` + `_DERIVED` SQL). */
function runRows(events: readonly TelemetryEvent[]): Map<string, RunSummary> {
  const byRun = new Map<string, TelemetryEvent[]>();
  for (const e of events) {
    if (e.event_type !== "agent.invoke" || !e.task_id) continue;
    byRun.set(e.task_id, [...(byRun.get(e.task_id) ?? []), e]);
  }
  const out = new Map<string, RunSummary>();
  for (const [runId, evs] of byRun) out.set(runId, summarize(runId, [...evs].sort((a, b) => ms(a.ts) - ms(b.ts))));
  return out;
}

function summarize(runId: string, evs: readonly TelemetryEvent[]): RunSummary {
  const phase = (e: TelemetryEvent): string | null => str(attrsOf(e).phase);
  const starts = evs.filter((e) => phase(e) === "start");
  const ends = evs.filter((e) => phase(e) === "end");
  const last = ends.at(-1) ?? null;
  const end = last ? attrsOf(last) : {};
  const first = evs[0] ? attrsOf(evs[0]) : {};
  const maxOf = (k: string): string | null => evs.map((e) => str(attrsOf(e)[k])).filter((v): v is string => v !== null).sort().at(-1) ?? null;
  const steps = evs.map((e) => int(attrsOf(e).step_index)).filter((v): v is number => v !== null);
  const endTs = last?.ts ?? null;
  const duration = num(end.duration_ms);
  const startTs = starts[0]?.ts ?? (endTs ? new Date(ms(endTs) - (duration ?? 0)).toISOString() : null);
  const status = (endTs === null ? "running" : (str(end.status) ?? last?.status ?? "ok")) as RunStatus;
  return {
    run_id: runId,
    agent_id: [...evs].reverse().find((e) => e.agent_id)?.agent_id ?? null,
    agent_name: str(end.agent_name) ?? str(first.agent_name),
    parent_run_id: maxOf("parent_run_id"),
    step_index: steps.length ? Math.max(...steps) : null,
    status,
    error_type: status !== "ok" ? str(end.error_type) : null,
    started_at: startTs,
    ended_at: endTs,
    duration_ms: duration ?? (startTs && endTs ? ms(endTs) - ms(startTs) : null),
    trace_id: evs.find((e) => e.trace_id)?.trace_id ?? null,
    handoff_to_agent: maxOf("handoff_to_agent"),
    step_count: int(end.steps),
    tool_calls: int(end.tool_calls),
    model_calls: int(end.model_calls),
    cost_usd: num(end.cost_usd),
  };
}

export interface RunQuery {
  agentId?: string | null;
  rootOnly?: boolean;
  status?: RunStatus | null;
  /** Event-time window, epoch ms: [since, until). */
  since: number;
  until: number;
}

/** `GET /runs`: runs seen in the window, newest first (keyset `started_at`, `run_id`). */
export function listRuns(events: readonly TelemetryEvent[], q: RunQuery): RunSummary[] {
  const inWindow = events.filter((e) => ms(e.ts) >= q.since && ms(e.ts) < q.until && (!q.agentId || e.agent_id === q.agentId));
  return [...runRows(inWindow).values()]
    .filter((r) => (!q.rootOnly || !r.parent_run_id) &&(!q.status || r.status === q.status))
    .sort((a, b) => (b.started_at ?? "").localeCompare(a.started_at ?? "") || b.run_id.localeCompare(a.run_id));
}

function gateOf(a: Attrs): RunToolCall["action_gate"] {
  if (!("action_effect" in a) && !("action_rule_id" in a) && !("held_action_id" in a)) return null;
  return { effect: (str(a.action_effect) as ToolActionEffect | null) ?? null, rule_id: str(a.action_rule_id), held_action_id: str(a.held_action_id) };
}

function modelCall(e: TelemetryEvent, a: Attrs): RunModelCall {
  const usage = (a.usage ?? {}) as Attrs;
  const requested = str(a.request_model) ?? e.model ?? null;
  const served = str(a.response_model);
  return {
    call_id: e.call_id ?? null,
    provider: e.provider ?? str(a.provider),
    requested_model: requested,
    served_model: served,
    model_mismatch: requested && served ? !servedMatches(requested, served) : null,
    system_fingerprint: str(a.system_fingerprint),
    tokens_in: int(usage.input_tokens),
    tokens_out: int(usage.output_tokens),
    cost_usd: num(a.cost_usd),
    finish_reasons: Array.isArray(a.finish_reasons) ? a.finish_reasons.map(String) : null,
  };
}

function eventStep(e: TelemetryEvent): RunStep {
  const a = attrsOf(e);
  const isModel = e.event_type === "gen_ai.request";
  return {
    kind: isModel ? "model_call" : "tool_call",
    step_index: int(a.step_index),
    ts: e.ts,
    event_id: e.event_id,
    status: e.status ?? null,
    error_type: str(a.error_type),
    latency_ms: num(a.latency_ms),
    model_call: isModel ? modelCall(e, a) : null,
    tool_call: isModel ? null : { tool_name: str(a.tool_name), tool_type: str(a.tool_type), tool_call_id: str(a.tool_call_id), side_effect_class: str(a.side_effect_class), handoff_to_agent: str(a.handoff_to_agent), action_gate: gateOf(a) },
    child_run_id: null,
  };
}

function childStep(child: RunNode): RunStep {
  return { kind: "child_run", step_index: child.step_index ?? null, ts: child.started_at, event_id: null, status: child.status, error_type: child.error_type ?? null, latency_ms: child.duration_ms ?? null, model_call: null, tool_call: null, child_run_id: child.run_id };
}

const stepOrder = (x: RunStep, y: RunStep): number => {
  const rank = (s: RunStep): number => (s.step_index === null ? 1 : 0);
  return rank(x) - rank(y) || (x.step_index ?? 0) - (y.step_index ?? 0) || (x.ts ?? "").localeCompare(y.ts ?? "");
};

/** Resolves a handoff target (a slug or an id) to a registered agent's id, when there is one. */
export type AgentResolver = (ref: string) => string | null;

/** `GET /runs/{run_id}`: the run and its descendants as a tree, or null when the run is unknown. */
export function runDetail(events: readonly TelemetryEvent[], runId: string, resolve: AgentResolver): RunDetail | null {
  const rows = runRows(events);
  const root = rows.get(runId);
  if (!root) return null;
  let truncated = false;
  const kept = new Map<string, RunSummary>([[runId, root]]);
  let frontier = [runId];
  for (let depth = 0; frontier.length; depth++) {
    const ids = new Set(frontier);
    const next = [...rows.values()].filter((r) => typeof r.parent_run_id === "string" && ids.has(r.parent_run_id) && !kept.has(r.run_id));
    if (next.length && depth >= RUN_BOUNDS.depth) {
      truncated = true;
      break;
    }
    const room = RUN_BOUNDS.runs - kept.size;
    if (next.length > room) truncated = true;
    const take = next.slice(0, Math.max(room, 0));
    for (const r of take) kept.set(r.run_id, r);
    frontier = take.map((r) => r.run_id);
  }

  const owned = events
    .filter((e) => e.event_type === "gen_ai.request" || e.event_type === "tool.call")
    .map((e) => {
      const parent = str(attrsOf(e).parent_run_id);
      return { e, owner: parent && kept.has(parent) ? parent : e.task_id && kept.has(e.task_id) ? e.task_id : null };
    })
    .filter((x): x is { e: TelemetryEvent; owner: string } => x.owner !== null)
    .sort((x, y) => ms(x.e.ts) - ms(y.e.ts));
  if (owned.length > RUN_BOUNDS.steps) truncated = true;
  const steps = new Map<string, TelemetryEvent[]>();
  for (const { e, owner } of owned.slice(0, RUN_BOUNDS.steps)) steps.set(owner, [...(steps.get(owner) ?? []), e]);

  const node = (id: string): RunNode => {
    const run = kept.get(id) as RunSummary;
    const kids = [...kept.values()].filter((r) => r.run_id !== runId && r.parent_run_id === id).sort((a, b) => (a.started_at ?? "").localeCompare(b.started_at ?? ""));
    const children = kids.map((k) => node(k.run_id));
    const own = (steps.get(id) ?? []).map(eventStep);
    const handoff = (ref: string, via: RunHandoff["via"], ts: string | null, eventId: string | null): RunHandoff => ({ from_run_id: id, to_agent: ref, to_agent_id: resolve(ref), via, ts, event_id: eventId });
    const handoffs = [
      ...(run.handoff_to_agent ? [handoff(run.handoff_to_agent, "run", run.ended_at ?? null, null)] : []),
      ...own.filter((s) => s.tool_call?.handoff_to_agent).map((s) => handoff(s.tool_call?.handoff_to_agent as string, "tool", s.ts, s.event_id ?? null)),
    ];
    return { ...run, steps: [...own, ...children.map(childStep)].sort(stepOrder), children, handoffs };
  };
  return { ...node(runId), truncated, run_count: kept.size };
}
