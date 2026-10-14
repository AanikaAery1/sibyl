/** Model drift display logic (lib/drift/view.ts). */
import { expect, test } from "@playwright/test";
import type { AgentDrift, DriftKeySummary } from "@/lib/api/monitor";
import { DRIFT_HISTORY, agentDriftPath, driftHistoryHasMore, excessFill, featureStatusText, filterAndSort, formatStat, hintsByAgent, parseDriftQuery, servedHistory, summaryOf, watchMark } from "@/lib/drift/view";

test("agent drift history pages with since and limit (default 48, at most 500)", () => {
  expect(agentDriftPath("a1")).toBe("/agents/a1/drift");
  expect(agentDriftPath("a1", { since: "2026-10-10T00:00:00.000Z" })).toBe("/agents/a1/drift?since=2026-10-10T00%3A00%3A00.000Z");
  expect(agentDriftPath("a1", { limit: 96 })).toBe("/agents/a1/drift?limit=96");
  expect(agentDriftPath("a1", { limit: 9999 })).toBe("/agents/a1/drift?limit=500");
  expect(agentDriftPath("a1", { limit: DRIFT_HISTORY.default })).toBe("/agents/a1/drift");
  expect(driftHistoryHasMore(48, 48)).toBe(true);
  expect(driftHistoryHasMore(30, 48)).toBe(false);
  expect(driftHistoryHasMore(500, 500)).toBe(false);
});

const row = (over: Partial<DriftKeySummary>): DriftKeySummary => ({ baseline_id: over.agent_id ?? "b", agent_id: "a", agent_name: "Agent", provider: "openai", model: "gpt-5", state: "frozen", verdict: "none", identity_changed: false, max_ratio: 0, ...over });

test("statistics keep enough digits to compare with small thresholds", () => {
  expect(formatStat(null)).toBe("—");
  expect(formatStat(0)).toBe("0");
  expect(formatStat(0.31234)).toBe("0.312");
  expect(formatStat(0.00134)).toBe("0.0013");
  expect(formatStat(1.5)).toBe("1.50");
});

test("excess bar fills to the drift line and marks the watch line", () => {
  expect(excessFill({ excess: 0.125, drift: 0.25, status: "ok" })).toBe(0.5);
  expect(excessFill({ excess: 0.5, drift: 0.25, status: "ok" })).toBe(1);
  expect(excessFill({ excess: null, drift: 0.25, status: "ok" })).toBeNull();
  expect(excessFill({ excess: 0.1, drift: 0.25, status: "insufficient_samples" })).toBeNull();
  expect(watchMark({ watch: 0.1, drift: 0.25 })).toBeCloseTo(0.4);
});

test("undecided features explain why", () => {
  expect(featureStatusText({ status: "insufficient_samples", n_window: 12 })).toContain("12");
  expect(featureStatusText({ status: "ok" })).toBeNull();
});

test("filters come from the URL with a safe default", () => {
  const q = (s: string) => parseDriftQuery(new URLSearchParams(s));
  expect(q("filter=identity&q= copilot ")).toEqual({ filter: "identity", q: "copilot" });
  expect(q("filter=bogus").filter).toBe("all");
});

test("worst first: drift, model changed, watch, calm, then collecting", () => {
  const rows = [
    row({ agent_id: "calm", agent_name: "Calm" }),
    row({ agent_id: "collect", agent_name: "Collect", state: "collecting", verdict: null }),
    row({ agent_id: "watch", agent_name: "Watch", verdict: "watch", max_ratio: 0.5 }),
    row({ agent_id: "id", agent_name: "Ident", identity_changed: true }),
    row({ agent_id: "drift", agent_name: "Drift", verdict: "drift", max_ratio: 1.4 }),
  ];
  expect(filterAndSort(rows, { filter: "all", q: "" }).map((r) => r.agent_id)).toEqual(["drift", "id", "watch", "calm", "collect"]);
  expect(filterAndSort(rows, { filter: "identity", q: "" }).map((r) => r.agent_id)).toEqual(["id"]);
  expect(filterAndSort(rows, { filter: "all", q: "watch" }).map((r) => r.agent_id)).toEqual(["watch"]);
});

test("summary is the API's when given, counted otherwise", () => {
  const rows = [row({ verdict: "drift" }), row({ state: "collecting", verdict: null }), row({ identity_changed: true })];
  expect(summaryOf(rows)).toEqual({ baselines: 3, collecting: 1, frozen: 2, drift: 1, watch: 0, identity_changed: 1 });
  const given = { baselines: 9, collecting: 0, frozen: 9, drift: 0, watch: 0, identity_changed: 0 };
  expect(summaryOf(rows, given)).toBe(given);
});

test("fleet tile hints take the worst frozen verdict per agent and ignore collecting keys", () => {
  const hints = hintsByAgent([row({ agent_id: "a", verdict: "watch" }), row({ agent_id: "a", verdict: "drift", model: "x" }), row({ agent_id: "a", state: "collecting", verdict: null, identity_changed: true }), row({ agent_id: "b", identity_changed: true })]);
  expect(hints.get("a")).toEqual({ verdict: "drift", identity: false });
  expect(hints.get("b")).toEqual({ verdict: "none", identity: true });
});

test("served history lists the baseline's models and fingerprints, then new ones from the latest report", () => {
  const d = {
    agent_id: "a",
    baselines: [
      { id: "b1", agent_id: "a", provider: "openai", model: "gpt-5", state: "frozen", window_start: "", sample_count: 5000, served_models: ["gpt-5-2025-08-07"], fingerprints: ["fp_old"] },
      { id: "b0", agent_id: "a", provider: "openai", model: "gpt-5", state: "superseded", window_start: "", sample_count: 5000, served_models: ["ignored"] },
    ],
    latest: [{ id: "r", baseline_id: "b1", evaluated_at: "", verdict: "none", behaviour_evaluated: true, identity_changed: true, max_ratio: 0, sample_count: 600, agent_id: "a", provider: "openai", model: "gpt-5", features: [], identity: [{ kind: "new_fingerprint", value: "fp_new", count: 41, requested_model: "gpt-5" }] }],
    history: [],
    open_alerts: [],
  } as AgentDrift;
  expect(servedHistory(d).map((r) => [r.kind, r.value, r.seen, r.finding])).toEqual([
    ["model", "gpt-5-2025-08-07", "baseline", null],
    ["fingerprint", "fp_old", "baseline", null],
    ["fingerprint", "fp_new", "new", "new_fingerprint"],
  ]);
});
