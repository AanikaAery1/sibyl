/**
 * Telemetry and runs in demo mode (`GET /events`, `GET /traces/{trace_id}`, `GET /runs`,
 * `GET /runs/{run_id}`): run trees as the SDK reports them (D50), with the frozen attrs
 * `parent_run_id`, `step_index`, `handoff_to_agent`, `system_fingerprint`, projected into runs by
 * lib/runs/project.ts exactly as the API does. Action Gate outcomes ride on tool calls as
 * `attrs.action_effect` / `action_rule_id` / `held_action_id` (what ingest maps them to).
 *
 * Also auto-discovery (an agent first seen as a handoff target or a span attribute registers as
 * `discovered`, provisional, with `discovered_via` and `first_trace_id`) and
 * `POST /agents/{id}/claim` (sets `confirmed_at`, clears `is_provisional`).
 */
import "server-only";
import { ProblemError, notFound } from "@/lib/api/problem";
import type { DiscoveredVia, RunDetail, RunStatus, RunSummary, TelemetryEvent } from "@/lib/api/monitor";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { RUN_STATUSES, listRuns, runDetail } from "@/lib/runs/project";
import { MINUTE, SECOND, hexFor, idFor, iso } from "./core";
import { requireScope } from "./actions";
import { newRuntime } from "./build";
import { agentId, type AgentSpec } from "./fixtures";
import { monitorState, onSeed } from "./monitor-state";
import { appendAudit, emit, type AgentRt, type World } from "./world";

type Attrs = Record<string, unknown>;

interface RunCtx {
  w: World;
  trace: string;
  at: number;
  events: TelemetryEvent[];
}

function ev(c: RunCtx, type: TelemetryEvent["event_type"], offsetMs: number, o: { agent?: string | null; task?: string | null; attrs: Attrs; provider?: string; model?: string; status?: TelemetryEvent["status"] }): void {
  const n = c.events.length;
  c.events.push({
    event_id: idFor(`event:${c.w.slug}:${c.trace}:${n}`),
    event_type: type,
    ts: iso(c.at + offsetMs),
    agent_id: o.agent ? agentId(c.w.slug, o.agent) : null,
    status: o.status ?? "ok",
    trace_id: c.trace,
    span_id: hexFor(`span:${c.trace}:${n}`, 16),
    task_id: o.task ?? null,
    call_id: null,
    provider: o.provider ?? null,
    model: o.model ?? null,
    attrs: o.attrs,
    payload_ref: null,
  });
}

const runId = (c: RunCtx, name: string): string => idFor(`run:${c.w.slug}:${c.trace}:${name}`);

function invoke(c: RunCtx, agent: string, name: string, task: string, start: number, o: { parent?: string; step?: number; handoff?: string; end?: number; status?: "ok" | "error"; models?: number; tools?: number; cost?: number } = {}): void {
  const link = { ...(o.parent ? { parent_run_id: o.parent, parent_task_id: o.parent } : {}), ...(o.step !== undefined ? { step_index: o.step } : {}), ...(o.handoff ? { handoff_to_agent: o.handoff } : {}) };
  ev(c, "agent.invoke", start, { agent, task, attrs: { phase: "start", agent_name: name, ...link } });
  if (o.end !== undefined) {
    ev(c, "agent.invoke", o.end, { agent, task, status: o.status ?? "ok", attrs: { phase: "end", agent_name: name, status: o.status ?? "ok", duration_ms: o.end - start, model_calls: o.models ?? 0, tool_calls: o.tools ?? 0, cost_usd: o.cost ?? 0, ...link } });
  }
}

function model(c: RunCtx, agent: string, parent: string, step: number, at: number, m: { provider: string; requested: string; served: string; fingerprint?: string; latency: number; tin: number; tout: number; finish?: string; cost: number }): void {
  ev(c, "gen_ai.request", at, {
    agent,
    task: parent,
    provider: m.provider,
    model: m.requested,
    attrs: { operation: "chat", provider: m.provider, request_model: m.requested, response_model: m.served, status: "ok", latency_ms: m.latency, usage: { input_tokens: m.tin, output_tokens: m.tout }, finish_reasons: [m.finish ?? "stop"], cost_usd: m.cost, ...(m.fingerprint ? { system_fingerprint: m.fingerprint } : {}), parent_run_id: parent, step_index: step, contributions: ["sdk"], merge_state: "sdk_only" },
  });
}

function tool(c: RunCtx, agent: string, parent: string, step: number, at: number, t: { name: string; latency: number; status?: "ok" | "error"; handoff?: string; effect?: string; rule?: string; held?: string | null }): void {
  ev(c, "tool.call", at, {
    agent,
    task: parent,
    status: t.status ?? "ok",
    attrs: {
      tool_name: t.name,
      tool_type: "function",
      status: t.status ?? "ok",
      latency_ms: t.latency,
      parent_run_id: parent,
      step_index: step,
      ...(t.handoff ? { handoff_to_agent: t.handoff } : {}),
      ...(t.effect ? { action_effect: t.effect, action_rule_id: t.rule ?? null, held_action_id: t.held ?? null } : {}),
    },
  });
}

const FP = (w: World, s: string): string => `fp_${hexFor(`fp:${w.slug}:${s}`, 10)}`;

/** A finished single-agent run with a handoff to the pricer (OpenAI Agents SDK), before the scenario. */
function quoteRun(w: World): TelemetryEvent[] {
  const c: RunCtx = { w, trace: hexFor(`trace:${w.slug}:quote-run`, 32), at: w.anchorAt - 25 * MINUTE, events: [] };
  const root = runId(c, "root");
  const pricer = runId(c, "pricer");
  invoke(c, "quote-assistant", "Quote assistant", root, 0, { end: 9_400, models: 2, tools: 2, cost: 0.0062 });
  model(c, "quote-assistant", root, 0, 300, { provider: "openai", requested: "gpt-5-mini", served: "gpt-5-mini-2025-08-07", fingerprint: FP(w, "quote-assistant"), latency: 1840, tin: 2410, tout: 212, finish: "tool_calls", cost: 0.0011 });
  tool(c, "quote-assistant", root, 1, 2_300, { name: "rfq.parse", latency: 120 });
  tool(c, "quote-assistant", root, 2, 2_500, { name: "transfer_to_freight_pricer", latency: 8, handoff: "freight-pricer" });
  invoke(c, "freight-pricer", "Freight pricer", pricer, 2_600, { parent: root, step: 3, end: 6_900, models: 1, tools: 1, cost: 0.0019 });
  tool(c, "freight-pricer", pricer, 0, 2_700, { name: "rates.lane_lookup", latency: 210 });
  model(c, "freight-pricer", pricer, 1, 3_000, { provider: "openai", requested: "gpt-5-mini", served: "gpt-5-mini-2025-08-07", fingerprint: FP(w, "freight-pricer"), latency: 1500, tin: 1820, tout: 160, cost: 0.0008 });
  model(c, "quote-assistant", root, 4, 7_000, { provider: "openai", requested: "gpt-5-mini", served: "gpt-5-mini-2025-08-07", fingerprint: FP(w, "quote-assistant"), latency: 2100, tin: 2950, tout: 388, cost: 0.0024 });
  return c.events;
}

onSeed((w, s) => {
  if (w.slug === "meridian") s.events = [...s.events, ...quoteRun(w)];
});

/** 0:20 · claim CLM-204655: the payout tool call is blocked by the Action Gate inside the run. */
export function blockedPayoutRun(w: World, at: number): void {
  const c: RunCtx = { w, trace: hexFor(`trace:${w.slug}:clm-204655`, 32), at: at - 6 * SECOND, events: [] };
  const root = runId(c, "root");
  invoke(c, "claims-triage", "Claims triage", root, 0, { end: 6_400, status: "error", models: 2, tools: 2, cost: 0.019 });
  model(c, "claims-triage", root, 0, 200, { provider: "anthropic", requested: "claude-sonnet-4-5", served: "claude-sonnet-4-5-20250929", latency: 3100, tin: 4200, tout: 330, finish: "tool_use", cost: 0.0092 });
  tool(c, "claims-triage", root, 1, 3_400, { name: "claims.lookup", latency: 140, effect: "allow" });
  tool(c, "claims-triage", root, 2, 5_950, { name: "payments.transfer", latency: 6, status: "error", effect: "block", rule: "transfer-limit" });
  model(c, "claims-triage", root, 3, 6_000, { provider: "anthropic", requested: "claude-sonnet-4-5", served: "claude-sonnet-4-5-20250929", latency: 380, tin: 4400, tout: 90, cost: 0.0098 });
  monitorState(w).events = [...monitorState(w).events, ...c.events];
}

const PAYOUT_SPEC: AgentSpec = { slug: "payout-agent", name: "Payout agent", kind: "autonomous_agent", tier: 3, risk_class: "unclassified", provider: "openai", model: "gpt-5", modelClass: "large", framework: "langgraph", process: "Claims handling", owner: "admin", pii: false, sdk: true, fail_mode: "closed", rpm: 3, baseErr: 0.004, baseP95: 5200, costPerCall: 0.009, description: "First seen as a handoff target inside a claims-triage run (discovered from the run tree)." };
const CRM_SPEC: AgentSpec = { slug: "crm-enricher", name: "CRM enricher", kind: "workflow", tier: 3, risk_class: "unclassified", provider: "openai", model: "gpt-5-mini", modelClass: "small", framework: "crewai", process: "Quote-to-cash", owner: "admin", pii: true, sdk: true, fail_mode: "open", rpm: 5, baseErr: 0.004, baseP95: 2400, costPerCall: 0.0012, description: "First seen in telemetry from the sales team's CrewAI service (gen_ai.agent.name span attribute)." };

/** How and where ingest first saw an agent (the API's `discovered_via` / `first_trace_id`). */
export function recordDiscovery(w: World, id: string, via: DiscoveredVia, trace: string | null, at: number): void {
  const s = monitorState(w);
  if (!s.discovery.has(id)) s.discovery.set(id, { via, firstTraceId: trace, at });
}

/** The three discovery fields every agent read carries (all null for an API-registered agent). */
export function discoveryOf(w: World, rt: AgentRt): { discovered_via: DiscoveredVia | null; first_trace_id: string | null; confirmed_at: string | null } {
  const s = monitorState(w);
  const d = s.discovery.get(rt.id);
  const confirmed = s.claimed.get(rt.id);
  return { discovered_via: d?.via ?? null, first_trace_id: d?.firstTraceId ?? null, confirmed_at: confirmed === undefined ? null : iso(confirmed) };
}

function discoverAgent(w: World, spec: AgentSpec, via: "run_tree" | "span_attr", at: number, trace: string | null): AgentRt | null {
  if (w.agents.has(agentId(w.slug, spec.slug))) return null;
  const rt = newRuntime(w, spec, at, true);
  w.agents.set(rt.id, rt);
  recordDiscovery(w, rt.id, via, trace, at);
  appendAudit(w, { action: "agent.discovered", actor_type: "api_key", resource_type: "agent", resource_id: rt.id, resource_ref: spec.slug, detail: { slug: spec.slug, api_key_id: idFor(`apikey:${w.slug}:claims-triage-sdk`), default_fail_mode: spec.fail_mode, discovered_via: via, ...(trace ? { first_trace_id: trace } : {}) } }, at);
  emit(w, "graph.changed", { tenant_id: w.tenantId, graph_version: 13, agent_id: rt.id }, at);
  return rt;
}

/**
 * 0:46 · claim CLM-204871 as a LangGraph run: intake and coverage nodes, then a handoff to a
 * payout agent Sibyl has never seen (registered as discovered), whose transfer is held by the
 * Action Gate. Served on the fallback (claims-triage failed over at 0:42).
 */
export function heldPayoutRun(w: World, at: number): void {
  const c: RunCtx = { w, trace: hexFor(`trace:${w.slug}:clm-204871`, 32), at: at - 4 * SECOND, events: [] };
  const held = [...w.heldActions.values()].find((h) => h.call_id === "clm-204871-pay-1");
  const root = runId(c, "root");
  const intake = runId(c, "intake");
  const coverage = runId(c, "coverage");
  const payout = runId(c, "payout");
  const fb = { provider: "openai", requested: "gpt-5", served: "gpt-5-2025-08-07", fingerprint: FP(w, "claims-fallback") };
  invoke(c, "claims-triage", "Claims triage", root, 0);
  invoke(c, "claims-triage", "intake", intake, 50, { parent: root, step: 0, end: 1_500, models: 1, tools: 1, cost: 0.004 });
  tool(c, "claims-triage", intake, 0, 100, { name: "claims.lookup", latency: 130, effect: "allow" });
  model(c, "claims-triage", intake, 1, 260, { ...fb, latency: 1150, tin: 3900, tout: 240, cost: 0.004 });
  invoke(c, "claims-triage", "coverage_check", coverage, 1_550, { parent: root, step: 1, end: 3_000, models: 1, tools: 1, cost: 0.003 });
  tool(c, "claims-triage", coverage, 0, 1_600, { name: "kb.search", latency: 240 });
  model(c, "claims-triage", coverage, 1, 1_860, { ...fb, latency: 1080, tin: 2800, tout: 180, cost: 0.003 });
  tool(c, "claims-triage", root, 2, 3_050, { name: "transfer_to_payout_agent", latency: 5, handoff: "payout-agent" });
  invoke(c, "payout-agent", "Payout agent", payout, 3_100, { parent: root, step: 3, handoff: "payout-agent", end: 3_800, models: 1, tools: 1, cost: 0.002 });
  tool(c, "payout-agent", payout, 0, 3_150, { name: "payee.verify", latency: 180 });
  // The payout agent asked for gpt-5; the provider answered from gpt-5-mini (model_mismatch in the tree).
  model(c, "payout-agent", payout, 1, 3_350, { provider: "openai", requested: "gpt-5", served: "gpt-5-mini-2025-08-07", fingerprint: FP(w, "payout-agent"), latency: 420, tin: 1500, tout: 120, finish: "stop", cost: 0.002 });
  tool(c, "claims-triage", root, 4, 3_900, { name: "payments.transfer", latency: 4, effect: "held", rule: held?.rule_id ?? "transfer-review", held: held?.id ?? null });
  monitorState(w).events = [...monitorState(w).events, ...c.events];
  discoverAgent(w, PAYOUT_SPEC, "run_tree", at, c.trace);
}

/** 0:56 · a CrewAI service reports spans for an agent nobody registered. */
export function discoverCrm(w: World, at: number): void {
  discoverAgent(w, CRM_SPEC, "span_attr", at, null);
}

export function isProvisional(w: World, rt: AgentRt): boolean {
  return rt.discovered && !monitorState(w).claimed.has(rt.id);
}

export function claimAgent(w: World, p: BffPrincipal, id: string, t: number): AgentRt {
  requireScope(p, "agents:write");
  const rt = w.agents.get(id);
  if (!rt) throw notFound("Agent");
  if (!isProvisional(w, rt)) throw new ProblemError(409, "not_provisional", "Already confirmed", "This agent is not provisional; there is nothing to confirm.");
  monitorState(w).claimed.set(rt.id, t);
  appendAudit(w, { action: "asset.updated", actor_type: "human", actor_id: p.userId, resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, detail: { fields_changed: ["confirmed_at", "is_provisional"], profile_hash: hexFor(`profile:${rt.id}:claimed`, 64) } }, t);
  emit(w, "graph.changed", { tenant_id: w.tenantId, graph_version: 14, agent_id: rt.id }, t);
  return rt;
}

export function listEvents(w: World, p: BffPrincipal, q: URLSearchParams, t: number): TelemetryEvent[] {
  requireScope(p, "agents:read");
  const eq = (k: string, v: string | null | undefined): boolean => !q.get(k) || q.get(k) === v;
  const from = q.get("from") ? Date.parse(q.get("from") ?? "") : null;
  const to = q.get("to") ? Date.parse(q.get("to") ?? "") : t;
  return monitorState(w)
    .events.filter((e) => Date.parse(e.ts) <= to && (from === null || Date.parse(e.ts) >= from))
    .filter((e) => eq("agent_id", e.agent_id) && eq("event_type", e.event_type) && eq("status", e.status) && eq("trace_id", e.trace_id) && eq("task_id", e.task_id))
    .sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
}

const DAY_MS = 24 * 60 * MINUTE;

function windowOf(q: URLSearchParams, t: number): { since: number; until: number } {
  const at = (k: string): number | null => {
    const raw = q.get(k);
    if (raw === null) return null;
    const v = Date.parse(raw);
    if (Number.isNaN(v)) throw new ProblemError(422, "validation_failed", "Bad timestamp", `\`${k}\` must be an RFC 3339 timestamp.`, { errors: [{ pointer: `/${k}`, code: "invalid", message: "Timestamp" }] });
    return v;
  };
  const until = at("until") ?? t;
  const since = at("since") ?? until - DAY_MS;
  if (since >= until || until - since > 31 * DAY_MS) throw new ProblemError(422, "validation_failed", "Bad window", "`since` must be before `until`, at most 31 days apart.", { errors: [{ pointer: "/since", code: "invalid", message: "Window" }] });
  return { since, until };
}

const seenBy = (w: World, t: number): TelemetryEvent[] => monitorState(w).events.filter((e) => Date.parse(e.ts) <= t);

/** `GET /runs` (filters agent_id, status, root_only, since/until; newest first). */
export function listRunsAt(w: World, p: BffPrincipal, q: URLSearchParams, t: number): RunSummary[] {
  requireScope(p, "agents:read");
  const status = q.get("status");
  if (status !== null && !RUN_STATUSES.includes(status as RunStatus)) throw new ProblemError(422, "validation_failed", "Unknown status", `status is one of ${RUN_STATUSES.join(", ")}.`, { errors: [{ pointer: "/status", code: "enum", message: RUN_STATUSES.join(" | ") }] });
  return listRuns(seenBy(w, t), { ...windowOf(q, t), agentId: q.get("agent_id"), rootOnly: q.get("root_only") === "true", status: status as RunStatus | null });
}

/** `GET /runs/{run_id}`: the tree, handoff targets resolved to registered agents by slug or id. */
export function runAt(w: World, p: BffPrincipal, runId: string, t: number): RunDetail {
  requireScope(p, "agents:read");
  const resolve = (ref: string): string | null => (w.agents.has(ref) ? ref : w.agents.has(agentId(w.slug, ref)) ? agentId(w.slug, ref) : null);
  const detail = runDetail(seenBy(w, t), runId, resolve);
  if (!detail) throw notFound("Run");
  return detail;
}

export function traceOf(w: World, p: BffPrincipal, traceId: string, t: number): { trace_id: string; spans: TelemetryEvent[] } {
  requireScope(p, "agents:read");
  const spans = monitorState(w).events.filter((e) => e.trace_id === traceId && Date.parse(e.ts) <= t);
  if (!spans.length) throw notFound("Trace");
  return { trace_id: traceId, spans };
}
