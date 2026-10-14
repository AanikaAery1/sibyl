/**
 * Runs (D50): the API-shaped projection the demo serves (lib/runs/project.ts), the run tree view
 * model over `RunDetail` (lib/runs/tree.ts), run paths, discovery state (lib/agents/discovery.ts)
 * and onboarding snippets (lib/onboarding/instrument.ts).
 */
import { expect, test } from "@playwright/test";
import type { RunDetail, TelemetryEvent } from "@/lib/api/monitor";
import { RUN_BOUNDS, listRuns, runDetail, servedMatches } from "@/lib/runs/project";
import { recentRunsPath, rootRunsOf, runPath, runTree, runsPath, runsQueryOf, type ChildRun, type ModelCall, type ToolCall } from "@/lib/runs/tree";
import { DISCOVERED_VIA_LABEL, awaitingConfirmation, discoveryState, tracePagePath } from "@/lib/agents/discovery";
import { FRAMEWORKS, discoveredOnly, frameworkById, modesFor, snippetFor } from "@/lib/onboarding/instrument";

let n = 0;
const T0 = Date.UTC(2026, 9, 10, 9, 0, 0);
const at = (sec: number): string => new Date(T0 + sec * 1000).toISOString();
const ev = (type: TelemetryEvent["event_type"], sec: number, attrs: Record<string, unknown>, over: Partial<TelemetryEvent> = {}): TelemetryEvent => ({
  event_id: `e${n++}`,
  event_type: type,
  ts: at(sec),
  trace_id: "t1",
  status: "ok",
  ...over,
  attrs,
});

const TRACE: TelemetryEvent[] = [
  ev("agent.invoke", 0, { phase: "start", agent_name: "Claims triage" }, { task_id: "root", agent_id: "a-root" }),
  ev("agent.invoke", 1, { phase: "start", agent_name: "intake", parent_run_id: "root", step_index: 0 }, { task_id: "intake", agent_id: "a-root" }),
  ev("tool.call", 1.5, { tool_name: "claims.lookup", latency_ms: 130, parent_run_id: "intake", step_index: 0, action_effect: "allow" }),
  ev("gen_ai.request", 2, { provider: "openai", request_model: "gpt-5", response_model: "gpt-5-2025-08-07", latency_ms: 900, usage: { input_tokens: 100, output_tokens: 20 }, parent_run_id: "intake", step_index: 1, finish_reasons: ["stop"] }),
  ev("agent.invoke", 3, { phase: "end", agent_name: "intake", parent_run_id: "root", step_index: 0, duration_ms: 2000, status: "ok", model_calls: 1, tool_calls: 1 }, { task_id: "intake", agent_id: "a-root" }),
  ev("tool.call", 4, { tool_name: "transfer_to_payout_agent", latency_ms: 5, parent_run_id: "root", step_index: 1, handoff_to_agent: "payout-agent" }),
  ev("agent.invoke", 5, { phase: "start", agent_name: "Payout agent", parent_run_id: "root", step_index: 2, handoff_to_agent: "payout-agent" }, { task_id: "payout", agent_id: "a-payout" }),
  ev("gen_ai.request", 6, { provider: "openai", request_model: "gpt-4o", response_model: "gpt-4o-mini", latency_ms: 300, parent_run_id: "payout", step_index: 0 }),
  ev("agent.invoke", 6.5, { phase: "end", agent_name: "Payout agent", parent_run_id: "root", step_index: 2, status: "error", error_type: "ToolError", duration_ms: 1500 }, { task_id: "payout", agent_id: "a-payout", status: "error" }),
  ev("tool.call", 7, { tool_name: "payments.transfer", latency_ms: 4, parent_run_id: "root", step_index: 3, action_effect: "held", action_rule_id: "transfer-review", held_action_id: "h1" }),
  ev("agent.invoke", 30, { phase: "start", agent_name: "Later" }, { task_id: "r2", trace_id: "t2", agent_id: "a-other" }),
];

const WINDOW = { since: T0 - 60_000, until: T0 + 3_600_000 };
const resolve = (ref: string): string | null => (ref === "payout-agent" ? "a-payout" : null);

test("served model matches the request or a dated/pinned snapshot of it, never a sibling", () => {
  expect(servedMatches("gpt-4o", "gpt-4o-2024-08-06")).toBe(true);
  expect(servedMatches("claude-sonnet-4-5", "claude-sonnet-4-5-20250929")).toBe(true);
  expect(servedMatches("gemini-2.5-flash", "models/gemini-2.5-flash-002")).toBe(true);
  expect(servedMatches("gpt-4o", "GPT-4o")).toBe(true);
  expect(servedMatches("gpt-4o", "gpt-4o-mini")).toBe(false);
  expect(servedMatches("gpt-5", "gpt-5-mini-2025-08-07")).toBe(false);
});

test("GET /runs: one summary per run, newest first, root_only / agent / status / window filters", () => {
  expect(listRuns(TRACE, WINDOW).map((r) => r.run_id)).toEqual(["r2", "payout", "intake", "root"]);
  expect(listRuns(TRACE, { ...WINDOW, rootOnly: true }).map((r) => r.run_id)).toEqual(["r2", "root"]);
  expect(listRuns(TRACE, { ...WINDOW, agentId: "a-payout" }).map((r) => r.run_id)).toEqual(["payout"]);
  expect(listRuns(TRACE, { ...WINDOW, status: "error" }).map((r) => r.run_id)).toEqual(["payout"]);
  expect(listRuns(TRACE, { ...WINDOW, status: "running" }).map((r) => r.run_id)).toEqual(["r2", "root"]);
  expect(listRuns(TRACE, { since: T0 + 20_000, until: T0 + 60_000 }).map((r) => r.run_id)).toEqual(["r2"]);
});

test("a run summary merges start and end: status, error type, duration, counts, parent, handoff", () => {
  const byId = new Map(listRuns(TRACE, WINDOW).map((r) => [r.run_id, r]));
  expect(byId.get("intake")).toMatchObject({ agent_name: "intake", parent_run_id: "root", step_index: 0, status: "ok", error_type: null, duration_ms: 2000, model_calls: 1, tool_calls: 1, started_at: at(1), ended_at: at(3), trace_id: "t1" });
  expect(byId.get("payout")).toMatchObject({ status: "error", error_type: "ToolError", handoff_to_agent: "payout-agent", agent_id: "a-payout" });
  expect(byId.get("root")).toMatchObject({ status: "running", ended_at: null, parent_run_id: null });
});

test("GET /runs/{id}: ordered steps of model calls, tool calls and child runs, with handoffs resolved", () => {
  const d = runDetail(TRACE, "root", resolve) as RunDetail;
  expect(d.run_count).toBe(3);
  expect(d.truncated).toBe(false);
  expect(d.steps.map((s) => [s.kind, s.step_index])).toEqual([
    ["child_run", 0],
    ["tool_call", 1],
    ["child_run", 2],
    ["tool_call", 3],
  ]);
  expect(d.steps[3]?.tool_call?.action_gate).toEqual({ effect: "held", rule_id: "transfer-review", held_action_id: "h1" });
  expect(d.handoffs).toEqual([{ from_run_id: "root", to_agent: "payout-agent", to_agent_id: "a-payout", via: "tool", ts: at(4), event_id: d.steps[1]?.event_id }]);
  const payout = d.children.find((c) => c.run_id === "payout");
  expect(payout?.handoffs[0]).toMatchObject({ via: "run", to_agent_id: "a-payout" });
  expect(payout?.steps[0]?.model_call).toMatchObject({ requested_model: "gpt-4o", served_model: "gpt-4o-mini", model_mismatch: true });
  const intake = d.children.find((c) => c.run_id === "intake");
  expect(intake?.steps.map((s) => s.kind)).toEqual(["tool_call", "model_call"]);
  expect(intake?.steps[1]?.model_call).toMatchObject({ model_mismatch: false, tokens_in: 100, tokens_out: 20, finish_reasons: ["stop"] });
  expect(intake?.steps[0]?.tool_call?.action_gate).toEqual({ effect: "allow", rule_id: null, held_action_id: null });
  expect(runDetail(TRACE, "nope", resolve)).toBeNull();
});

test("a subtree read starts at the child; the tree says truncated past the run bound", () => {
  expect(runDetail(TRACE, "payout", resolve)?.run_count).toBe(1);
  const wide: TelemetryEvent[] = [ev("agent.invoke", 0, { phase: "start" }, { task_id: "p" })];
  for (let i = 0; i < RUN_BOUNDS.runs + 5; i++) wide.push(ev("agent.invoke", 1, { phase: "start", parent_run_id: "p", step_index: i }, { task_id: `c${i}` }));
  const d = runDetail(wide, "p", resolve) as RunDetail;
  expect(d.truncated).toBe(true);
  expect(d.run_count).toBe(RUN_BOUNDS.runs);
});

test("the view model flattens the API tree: child runs, mismatch, gate, handoff target, totals", () => {
  const tree = runTree(runDetail(TRACE, "root", resolve) as RunDetail);
  expect(tree.root).toMatchObject({ id: "root", agentName: "Claims triage", status: "running", parentId: null });
  expect(tree.root.items.map((i) => [i.kind, i.step])).toEqual([
    ["run", 0],
    ["tool", 1],
    ["run", 2],
    ["tool", 3],
  ]);
  const handoff = tree.root.items[1] as ToolCall;
  expect(handoff).toMatchObject({ handoffTo: "payout-agent", handoffAgentId: "a-payout" });
  const payout = (tree.root.items[2] as ChildRun).run;
  expect(payout).toMatchObject({ status: "error", errorType: "ToolError", handoffAgentId: "a-payout" });
  expect(payout.items[0] as ModelCall).toMatchObject({ kind: "model", mismatch: true, requested: "gpt-4o", served: "gpt-4o-mini" });
  expect((tree.root.items[3] as ToolCall).gate).toEqual({ effect: "held", ruleId: "transfer-review", heldActionId: "h1" });
  expect(tree.totals).toEqual({ runs: 3, models: 2, tools: 3, handoffs: 2, gated: 2, held: 1, blocked: 0, mismatched: 1 });
  expect(tree.truncated).toBe(false);
  expect(tree.runCount).toBe(3);
});

test("the view keeps a gate record without an effect and passes truncated through", () => {
  const d: RunDetail = {
    run_id: "x",
    status: "ok",
    started_at: at(0),
    steps: [{ kind: "tool_call", step_index: null, ts: at(1), event_id: null, tool_call: { tool_name: null, action_gate: { effect: null, rule_id: "r1" } } }],
    children: [],
    handoffs: [],
    truncated: true,
    run_count: 200,
  };
  const tree = runTree(d);
  expect(tree.root.items[0]).toMatchObject({ kind: "tool", id: "x:0", tool: "tool", gate: { effect: null, ruleId: "r1", heldActionId: null } });
  expect(tree.root.agentName).toBe("Run");
  expect(tree.truncated).toBe(true);
  expect(tree.totals.gated).toBe(1);
});

test("run paths: filters in a stable order, top-level unless scope=all, unknown status dropped", () => {
  expect(runPath("abc")).toBe("/runs/abc");
  expect(recentRunsPath("a1")).toBe("/runs?agent_id=a1&root_only=true&limit=8");
  expect(runsPath()).toBe("/runs?limit=50");
  const params = new URLSearchParams("agent_id=a1&status=error&since=2026-10-10T00:00:00.000Z&cursor=Mg");
  expect(runsPath(runsQueryOf((k) => params.get(k)))).toBe("/runs?agent_id=a1&root_only=true&status=error&since=2026-10-10T00%3A00%3A00.000Z&limit=50&cursor=Mg");
  expect(runsQueryOf((k) => ({ scope: "all", status: "bogus" })[k] ?? null)).toMatchObject({ rootOnly: false, status: null });
});

test("a trace link resolves to its top-level runs, oldest first", () => {
  expect(rootRunsOf(TRACE)).toEqual(["root", "r2"]);
  expect(rootRunsOf([])).toEqual([]);
  expect(tracePagePath("t1")).toBe("/traces/t1");
});

test("discovery state comes from discovered_via and confirmed_at, never is_provisional alone", () => {
  expect(discoveryState({ discovered_via: "run_tree", confirmed_at: null })).toBe("awaiting");
  expect(discoveryState({ discovered_via: "span_attr", confirmed_at: "2026-10-10T09:00:00Z" })).toBe("confirmed");
  expect(discoveryState({ discovered_via: null, confirmed_at: null })).toBeNull();
  expect(discoveryState({})).toBeNull();
  // A young registered agent is provisional (health) but was never discovered.
  expect(awaitingConfirmation({ discovered_via: null, ...{ is_provisional: true } })).toBe(false);
  expect(Object.keys(DISCOVERED_VIA_LABEL)).toHaveLength(7);
});

const ENV = { endpoint: "https://ingest.example", gateway: "https://gw.example", keyHint: "sbl_live_…", agent: "quote-worker" };

test("every framework has one-line and zero-code; only native protocols get the gateway", () => {
  expect(FRAMEWORKS.map((f) => f.id)).toEqual(["openai", "anthropic", "gemini", "langchain", "openai-agents", "crewai"]);
  expect(modesFor(frameworkById("openai"))).toEqual(["one-line", "zero-code", "gateway"]);
  expect(modesFor(frameworkById("crewai"))).toEqual(["one-line", "zero-code"]);
  expect(frameworkById("nope").id).toBe("openai");
  expect(() => snippetFor("langchain", "gateway", ENV)).toThrow(/no gateway/);
});

test("snippets: instrument() one line, sibyl-run zero code, native gateway base URLs", () => {
  const one = snippetFor("anthropic", "one-line", ENV);
  expect(one.install).toBe('pip install "sibyl-sdk[anthropic]"');
  expect(one.code).toContain("sibyl.instrument()");
  expect(snippetFor("crewai", "zero-code", ENV).code).toContain("sibyl-run app.py");
  expect(snippetFor("crewai", "zero-code", ENV).code).toContain('SIBYL_ENDPOINT="https://ingest.example"');
  expect(snippetFor("openai", "gateway", ENV).code).toContain('base_url="https://gw.example/v1"');
  expect(snippetFor("anthropic", "gateway", ENV).code).toContain('base_url="https://gw.example"');
  expect(snippetFor("gemini", "gateway", ENV).code).toContain('"base_url": "https://gw.example"');
  expect(snippetFor("openai", "gateway", ENV).code).toContain("X-Sibyl-Agent");
});

test("discovered filter keeps lifecycle discovered only", () => {
  expect(discoveredOnly([{ lifecycle: "discovered", id: 1 }, { lifecycle: "monitored", id: 2 }]).map((a) => a.id)).toEqual([1]);
});
