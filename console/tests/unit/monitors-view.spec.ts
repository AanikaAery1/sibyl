/** External monitors and the unified findings feed (lib/monitors/view.ts). */
import { expect, test } from "@playwright/test";
import type { Finding, Monitor, MonitorWebhook } from "@/lib/api/external-monitors";
import {
  EMPTY_REGISTER,
  EMPTY_WEBHOOK,
  KEY_PLACEHOLDER,
  externalBodyRows,
  filterMonitors,
  findingSubjectHref,
  findingsFeedPath,
  latestBySource,
  monitorCounts,
  monitorIfMatch,
  monitorProblemText,
  plainText,
  revokeReasonError,
  setupSnippets,
  sourceLabel,
  sourceOf,
  subjectFindingsPath,
  toCreate,
  toWebhookCreate,
  validateRegister,
  validateWebhook,
  watchedLabel,
  webhookHealth,
  webhookTestText,
} from "@/lib/monitors/view";

const hook = (over: Partial<MonitorWebhook> = {}): MonitorWebhook => ({
  id: "w1",
  monitor_id: "m1",
  url: "https://hooks.example.com/sibyl",
  event_types: ["alert.fired"],
  state: "enabled",
  last_delivery_status: "delivered",
  created_at: "2026-10-01T00:00:00Z",
  ...over,
});

const monitor = (over: Partial<Monitor> = {}): Monitor => ({
  id: "m1",
  name: "Claude ops reviewer",
  kind: "mcp",
  owner_user_id: "u1",
  all_groups: true,
  group_ids: [],
  state: "active",
  rate_limit_per_min: 60,
  version: 1,
  keys: [],
  webhooks: [],
  findings_24h: 3,
  created_at: "2026-10-01T00:00:00Z",
  advisory: true,
  ...over,
});

test("feed paths: both sources by default, one when picked, subject lookups encoded", () => {
  expect(findingsFeedPath()).toBe("/findings?limit=100");
  expect(findingsFeedPath({ source: "external", kind: "held_action_review" })).toBe("/findings?limit=100&source=external&kind=held_action_review");
  expect(findingsFeedPath({ monitorId: "m 1", limit: 20 })).toBe("/findings?limit=20&monitor_id=m+1");
  expect(subjectFindingsPath("held_action", "h/1")).toBe("/findings?subject_kind=held_action&subject_id=h%2F1&limit=10");
  expect(sourceOf("sentinel")).toBe("sentinel");
  expect(sourceOf("external")).toBe("external");
  expect(sourceOf("monitor")).toBeNull();
  expect(sourceOf(null)).toBeNull();
});

test("source labels say who wrote a finding", () => {
  expect(sourceLabel({ source: "sentinel", monitor_name: null })).toBe("Sentinel");
  expect(sourceLabel({ source: "external", monitor_name: "PagerDuty bridge" })).toBe("Monitor: PagerDuty bridge");
  expect(sourceLabel({ source: "external", monitor_name: null })).toBe("Monitor: unnamed");
  expect(sourceLabel({ source: "external", monitor_name: "‮evil‬" })).toBe("Monitor: evil");
});

test("subjects link to their screens, runs included", () => {
  expect(findingSubjectHref({ subject_kind: "run", subject_id: "r1", agent_id: null })).toBe("/runs/r1");
  expect(findingSubjectHref({ subject_kind: "run", subject_id: null, agent_id: null })).toBeNull();
  expect(findingSubjectHref({ subject_kind: "held_action", subject_id: "h1", agent_id: null })).toBe("/held-actions/h1");
  expect(findingSubjectHref({ subject_kind: "agent", subject_id: null, agent_id: "a1" })).toBe("/agents/a1");
  expect(findingSubjectHref({ subject_kind: "fleet", subject_id: null, agent_id: null })).toBe("/fleet");
});

test("untrusted text: direction overrides and controls removed, length capped, markup left as text", () => {
  expect(plainText("ok‮txt.exe‬")).toBe("oktxt.exe");
  expect(plainText("a\u0000b\u0007c\nd\te")).toBe("abc\nd\te");
  expect(plainText("<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
  expect(plainText("x".repeat(20), 10)).toBe(`${"x".repeat(9)}…`);
  expect(plainText(null)).toBe("");
  expect(plainText(42)).toBe("42");
});

test("a monitor's free-form body becomes labelled plain-text rows", () => {
  const rows = externalBodyRows({ summary: "skip", evidence: ["a", 2, null], escalate: true, detail: { nested: { x: 1 } }, page_url: "javascript:alert(1)" });
  expect(rows.map((r) => r.key)).toEqual(["evidence", "escalate", "detail", "page_url"]);
  expect(rows[0]).toMatchObject({ label: "Evidence", items: ["a", "2", "—"] });
  expect(rows[1]).toMatchObject({ flag: true });
  expect(rows[2]?.text).toContain('"nested"');
  expect(rows[3]).toMatchObject({ label: "Page url", text: "javascript:alert(1)" });
  expect(externalBodyRows({ output: { likely_cause: "x" } })[0]).toMatchObject({ key: "likely_cause", text: "x" });
  expect(externalBodyRows(null)).toEqual([]);
  expect(externalBodyRows(Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`k${i}`, i])))).toHaveLength(40);
});

test("webhook health is the worst enabled delivery", () => {
  expect(webhookHealth([])).toBe("none");
  expect(webhookHealth([hook({ state: "disabled" })])).toBe("disabled");
  expect(webhookHealth([hook(), hook({ last_delivery_status: null })])).toBe("pending");
  expect(webhookHealth([hook(), hook({ last_delivery_status: "retrying" })])).toBe("retrying");
  expect(webhookHealth([hook({ last_delivery_status: "retrying" }), hook({ last_delivery_status: "dead" })])).toBe("dead");
  expect(webhookHealth([hook(), hook({ state: "disabled", last_delivery_status: "dead" })])).toBe("delivered");
});

test("watched groups by name, unknown ids counted", () => {
  const names = new Map([["g1", "Claims"], ["g2", "Logistics"]]);
  expect(watchedLabel({ all_groups: true, group_ids: [] }, names)).toBe("All agent groups");
  expect(watchedLabel({ all_groups: false, group_ids: ["g1", "g2"] }, names)).toBe("Claims, Logistics");
  expect(watchedLabel({ all_groups: false, group_ids: ["g1", "g9"] }, names)).toBe("Claims + 1 more");
  expect(watchedLabel({ all_groups: false, group_ids: ["g8", "g9"] }, names)).toBe("2 groups");
  expect(watchedLabel({ all_groups: false, group_ids: [] }, names)).toBe("No groups");
});

test("counts and the list order: live monitors first, newest first, revoked last", () => {
  const rows = [
    monitor({ id: "a", state: "revoked", created_at: "2026-10-09T00:00:00Z", findings_24h: 0 }),
    monitor({ id: "b", state: "paused", created_at: "2026-10-02T00:00:00Z", findings_24h: 1, webhooks: [hook({ last_delivery_status: "dead" })] }),
    monitor({ id: "c", created_at: "2026-10-05T00:00:00Z", webhooks: [hook({ last_delivery_status: "retrying" }), hook({ state: "disabled", last_delivery_status: "dead" })] }),
  ];
  expect(monitorCounts(rows)).toEqual({ total: 3, active: 1, paused: 1, revoked: 1, findings24h: 4, failingWebhooks: 2 });
  expect(filterMonitors(rows, "all").map((m) => m.id)).toEqual(["c", "b", "a"]);
  expect(filterMonitors(rows, "paused").map((m) => m.id)).toEqual(["b"]);
});

test("If-Match prefers the ETag, else the version", () => {
  expect(monitorIfMatch(monitor({ version: 4 }), '"5"')).toBe('"5"');
  expect(monitorIfMatch(monitor({ version: 4 }), null)).toBe('"4"');
  expect(monitorIfMatch(null, null)).toBe('"1"');
});

test("register: name, groups, rate and an audited reason are checked; the body is the contract's", () => {
  expect(validateRegister(EMPTY_REGISTER)).toMatchObject({ name: expect.any(String), reason: expect.any(String) });
  const ok = { ...EMPTY_REGISTER, name: "  Claude ops reviewer ", reason: "Second opinion on held payouts." };
  expect(validateRegister(ok)).toEqual({});
  expect(validateRegister({ ...ok, name: "bad\u0001name" }).name).toBeDefined();
  expect(validateRegister({ ...ok, allGroups: false }).groups).toBeDefined();
  expect(validateRegister({ ...ok, rateLimit: "0" }).rateLimit).toBeDefined();
  expect(validateRegister({ ...ok, rateLimit: "601" }).rateLimit).toBeDefined();
  expect(validateRegister({ ...ok, rateLimit: "2.5" }).rateLimit).toBeDefined();
  expect(toCreate(ok, "test")).toEqual({ name: "Claude ops reviewer", kind: "mcp", description: null, all_groups: true, rate_limit_per_min: 60, issue_key: true, key_env: "test", reason: "Second opinion on held payouts." });
  expect(toCreate({ ...ok, allGroups: false, groupIds: ["g1", "g1", "g2"], description: " d " }, "live")).toMatchObject({ all_groups: false, group_ids: ["g1", "g2"], description: "d", key_env: "live" });
});

test("webhooks: https only, no credentials in the URL, at least one event", () => {
  expect(validateWebhook({ ...EMPTY_WEBHOOK, url: "https://hooks.example.com/x" })).toEqual({});
  expect(validateWebhook({ ...EMPTY_WEBHOOK, url: "http://hooks.example.com/x" }).url).toContain("https only");
  expect(validateWebhook({ ...EMPTY_WEBHOOK, url: "not a url" }).url).toBeDefined();
  expect(validateWebhook({ ...EMPTY_WEBHOOK, url: "https://u:p@hooks.example.com" }).url).toContain("credentials");
  expect(validateWebhook({ ...EMPTY_WEBHOOK, url: "https://hooks.example.com", events: [] }).events).toBeDefined();
  expect(validateWebhook({ ...EMPTY_WEBHOOK, url: "https://hooks.example.com", reason: "short" }).reason).toBeDefined();
  expect(toWebhookCreate({ url: " https://h.example.com ", events: ["action.held", "alert.fired"], reason: "" })).toEqual({ url: "https://h.example.com", event_types: ["alert.fired", "action.held"] });
});

test("revoke needs a reason", () => {
  expect(revokeReasonError("too short")).not.toBeNull();
  expect(revokeReasonError("Replaced by the v2 reviewer")).toBeNull();
});

test("test deliveries and problems in words", () => {
  expect(webhookTestText({ ok: true, http_status: 204, error: null, latency_ms: 182 })).toBe("Delivered: the receiver answered HTTP 204 in 182 ms.");
  expect(webhookTestText({ ok: false, http_status: 0, error: "egress_refused", latency_ms: 3 })).toContain("egress");
  expect(webhookTestText({ ok: false, http_status: 500, error: "http_error", latency_ms: 40 })).toContain("HTTP 500");
  expect(webhookTestText({ ok: false, http_status: 0, error: null, latency_ms: 0 })).toBe("The test delivery failed.");
  expect(monitorProblemText(409, "conflict")).toContain("already exists");
  expect(monitorProblemText(409, "invalid_transition")).toContain("revoked");
  expect(monitorProblemText(412, "precondition_failed")).toContain("Reload");
  expect(monitorProblemText(422, "base_url_not_allowlisted")).toContain("allowlist");
  expect(monitorProblemText(422, "validation_failed")).toBeNull();
});

test("setup snippets use sibyl-mcp's env names and the key only when it is shown", () => {
  const mcp = setupSnippets("mcp", { apiUrl: "https://sibyl.example.com/", secret: "sbl_test_abc" });
  expect(mcp.map((s) => s.id)).toEqual(["claude-desktop", "claude-code", "python"]);
  const desktop = JSON.parse(mcp[0]?.code ?? "{}") as { mcpServers: { sibyl: { command: string; env: Record<string, string> } } };
  expect(desktop.mcpServers.sibyl).toEqual({ command: "sibyl-mcp", env: { SIBYL_API_URL: "https://sibyl.example.com", SIBYL_MONITOR_KEY: "sbl_test_abc" } });
  expect(mcp[1]?.code).toContain("claude mcp add sibyl");
  expect(mcp[2]?.code).toContain("from sibyl.monitor import Client");
  const hidden = setupSnippets("api", { apiUrl: "https://s", secret: null });
  expect(hidden.map((s) => s.id)).toEqual(["python", "claude-code"]);
  expect(hidden.every((s) => s.code.includes(KEY_PLACEHOLDER))).toBe(true);
  expect(setupSnippets("webhook", { apiUrl: "https://s", secret: null })[0]?.code).toContain("verify_webhook");
});

test("decision screens: the newest Sentinel finding and the newest per monitor, at most three monitors", () => {
  const f = (id: string, source: Finding["source"], monitor: string | null): Finding => ({ id, source, monitor_id: monitor, monitor_name: monitor, kind: "held_action_review", subject_kind: "held_action", severity: "info", summary: id, created_at: "2026-10-10T00:00:00Z", advisory: true });
  const rows = [f("e1", "external", "a"), f("s1", "sentinel", null), f("e2", "external", "a"), f("e3", "external", "b"), f("s2", "sentinel", null), f("e4", "external", "c"), f("e5", "external", "d")];
  const out = latestBySource(rows);
  expect(out.sentinel?.id).toBe("s1");
  expect(out.external.map((x) => x.id)).toEqual(["e1", "e3", "e4"]);
  expect(latestBySource([])).toEqual({ sentinel: null, external: [] });
});
