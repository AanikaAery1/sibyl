/** Sentinel display and setup-form logic (lib/sentinel/view.ts). */
import { expect, test } from "@playwright/test";
import type { SentinelConfig } from "@/lib/api/monitor";
import { adviceOf, bodyRows, budgetUsage, formFromConfig, formatUsd, ifMatchFor, sentinelProblemText, subjectHref, testFailureText, toPut, validateForm } from "@/lib/sentinel/view";

const CFG: SentinelConfig = {
  configured: true,
  enabled: true,
  provider: "gemini",
  model: "gemini-2.5-flash",
  has_key: true,
  key_hint: "…k3Qz",
  daily_budget_usd: "5.0000",
  sampling_rate: 0.25,
  tasks: ["incident_explanation", "fleet_summary"],
  version: 3,
  advisory: true,
  usage_today: { day: "2026-10-10", spent_usd: "1.2500", calls: 9, findings: 7, skipped_budget: 1, skipped_sampling: 4 },
};

test("subjects link to the screen where a person decides", () => {
  expect(subjectHref({ subject_kind: "incident", subject_id: "i1", agent_id: null })).toBe("/incidents/i1");
  expect(subjectHref({ subject_kind: "held_action", subject_id: "h1", agent_id: "a" })).toBe("/held-actions/h1");
  expect(subjectHref({ subject_kind: "agent", subject_id: null, agent_id: "a1" })).toBe("/agents/a1");
  expect(subjectHref({ subject_kind: "agent", subject_id: null, agent_id: null })).toBeNull();
  expect(subjectHref({ subject_kind: "fleet", subject_id: null, agent_id: null })).toBe("/fleet");
});

test("money keeps four places under a dollar", () => {
  expect(formatUsd("0.0123")).toBe("$0.0123");
  expect(formatUsd(12.5)).toBe("$12.50");
  expect(formatUsd(null)).toBe("—");
  expect(formatUsd("abc")).toBe("—");
});

test("budget usage: share of the daily budget, skips summed, exhausted at the cap", () => {
  expect(budgetUsage(CFG)).toEqual({ spent: 1.25, budget: 5, share: 0.25, exhausted: false, calls: 9, findings: 7, skipped: 5 });
  expect(budgetUsage({ ...CFG, usage_today: { ...CFG.usage_today!, spent_usd: "5.00" } }).exhausted).toBe(true);
  expect(budgetUsage(null)).toMatchObject({ spent: 0, budget: null, share: null, exhausted: false });
});

test("the form starts from the config, never with the key, and percent sampling", () => {
  const f = formFromConfig(CFG);
  expect(f).toMatchObject({ enabled: true, provider: "gemini", model: "gemini-2.5-flash", apiKey: "", budget: "5", samplingPct: "25" });
  expect(formFromConfig(null)).toMatchObject({ enabled: false, provider: "anthropic", model: "claude-haiku-4-5", tasks: ["incident_explanation", "held_action_review", "semantic_drift", "fleet_summary"] });
});

test("validation: key to enable, sane numbers, a task, and an audited reason", () => {
  const base = { ...formFromConfig(null), enabled: true, reason: "pilot on haiku" };
  expect(validateForm(base, false).apiKey).toBeTruthy();
  expect(validateForm(base, true).apiKey).toBeUndefined();
  expect(validateForm({ ...base, apiKey: "short" }, false).apiKey).toBeTruthy();
  expect(validateForm({ ...base, budget: "-1" }, true).budget).toBeTruthy();
  expect(validateForm({ ...base, samplingPct: "101" }, true).samplingPct).toBeTruthy();
  expect(validateForm({ ...base, tasks: [] }, true).tasks).toBeTruthy();
  expect(validateForm({ ...base, reason: "x" }, true).reason).toBeTruthy();
  expect(validateForm(base, true)).toEqual({});
});

test("PUT body: decimal-string budget, 0..1 sampling, key only when typed, tasks in canonical order", () => {
  const f = { ...formFromConfig(CFG), budget: "2.5", samplingPct: "12.5", tasks: ["fleet_summary", "incident_explanation"] as const, reason: " switch provider " };
  const put = toPut({ ...f, tasks: [...f.tasks] });
  expect(put).toMatchObject({ daily_budget_usd: "2.50", sampling_rate: 0.125, tasks: ["incident_explanation", "fleet_summary"], reason: "switch provider" });
  expect("api_key" in put).toBe(false);
  expect(toPut({ ...f, tasks: [...f.tasks], apiKey: "  sk-live-abcdefghijklmnop " }).api_key).toBe("sk-live-abcdefghijklmnop");
});

test("If-Match: the GET's ETag (\"0\" before the first save), else the version it was built from", () => {
  expect(ifMatchFor(CFG, '"4"')).toBe('"4"');
  expect(ifMatchFor({ version: 0 }, '"0"')).toBe('"0"');
  expect(ifMatchFor(CFG, null)).toBe('"3"');
  expect(ifMatchFor({ version: 0 }, null)).toBe('"0"');
  expect(ifMatchFor(null, null)).toBe('"0"');
});

test("a failed connection test is explained from its error code and HTTP status", () => {
  const fail = (error: string | null, http_status: number) => testFailureText({ ok: false, error, http_status });
  expect(testFailureText({ ok: true, error: null, http_status: 200 })).toBeNull();
  expect(fail("http_error", 401)).toContain("rejected the key (HTTP 401)");
  expect(fail("http_error", 404)).toContain("does not know this model");
  expect(fail("http_error", 429)).toContain("rate limiting");
  expect(fail("http_error", 503)).toContain("server error (HTTP 503)");
  expect(fail("http_error", 418)).toBe("The provider answered HTTP 418.");
  expect(fail("transport", 0)).toContain("could not reach");
  expect(fail("timeout", 0)).toContain("did not answer in time");
  expect(fail("egress_refused", 0)).toContain("egress allowlist");
  expect(fail("refused", 200)).toContain("declined");
  expect(fail("bad_output", 200)).toContain("not with the expected reply");
  expect(fail("malformed_response", 200)).toContain("could not be read");
  expect(fail("config", 0)).toContain("provider, model and base URL");
  expect(fail("llm_error", 0)).toContain("unexpected");
  expect(fail("something_new", 0)).toBe("The test failed (something_new).");
});

test("config problems: 409 not set up and 503 no vault are explained; others keep the API detail", () => {
  expect(sentinelProblemText(409, "not_active")).toContain("not set up yet");
  expect(sentinelProblemText(503, "service_unavailable")).toContain("key vault is not configured");
  expect(sentinelProblemText(412, "precondition_failed")).toContain("changed since you opened it");
  expect(sentinelProblemText(422, "validation_failed")).toBeNull();
});

test("structured body rows in reading order; advice only on held-action reviews", () => {
  const body = { output: { severity: "warning", summary: "s", confidence: "medium", risks: ["a", "b"], advice: "deny", reasoning: "r", injection_like: false } };
  expect(bodyRows(body).map((r) => r.key)).toEqual(["advice", "reasoning", "risks", "injection_like", "confidence"]);
  expect(bodyRows(body).find((r) => r.key === "risks")?.items).toEqual(["a", "b"]);
  expect(bodyRows(body).find((r) => r.key === "injection_like")?.flag).toBe(false);
  expect(bodyRows(undefined)).toEqual([]);
  expect(adviceOf({ kind: "held_action_review", body })).toBe("deny");
  expect(adviceOf({ kind: "incident_explanation", body })).toBeNull();
});
