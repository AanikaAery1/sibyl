/**
 * The Action Gate boundary (lib/action-gate/wire.ts, lib/action-gate/paths.ts): API objects in
 * the generated contract's shape → the console's definite views, request bodies, the simulate
 * answer, and the list/filter rules the screens use.
 */
import { expect, test } from "@playwright/test";
import type { ActionPolicyDocument, ApiActionPolicy, ApiHeldAction } from "@/lib/api/action-gate";
import { DRAFT_POLICY_ID } from "@/lib/api/action-gate";
import { evaluate } from "@/lib/action-gate/evaluate";
import { HELD_VIEW_STATES, heldListPath, policyInView, policyListPath } from "@/lib/action-gate/paths";
import { actingFor, approvalsLeft, createBody, draftDocument, draftSimulateBody, heldListRow, heldOrder, onBehalfOf, onBehalfUser, ruleViews, simulateAnswer, summaryCounts, toHeld, toPolicy } from "@/lib/action-gate/wire";

const V3 = "0192aaaa-0000-7000-8000-000000000003";
const LINEAGE = "0192aaaa-0000-7000-8000-000000000002";
const AGENT = "0192bbbb-0000-7000-8000-000000000001";
const ME = "0192767f-0000-7000-8000-0000000000a1";
const OTHER = "0192767f-0000-7000-8000-0000000000a2";

const DOC: ActionPolicyDocument = {
  schema: "sibyl-action-policy/1",
  policy_id: V3,
  version: 3,
  default_effect: "allow",
  tool_allowlist_enforced: false,
  tool_allowlist: null,
  sensitive_tools: ["payments.transfer"],
  external_tools: [],
  hold_timeout_s: 900,
  rules: [
    { rule_id: "transfer-review", tool: "payments.transfer", when: { gt: ["/amount", 50000] }, effect: "escalate", reason: "Needs a person" },
    { rule_id: "refund-burst", tool: "refunds.issue", cumulative: { count: true, max: 5, window_s: 60 }, effect: "allow", reason: "At most 5 a minute" },
  ],
};

const API_POLICY: ApiActionPolicy = {
  id: V3,
  policy_id: LINEAGE,
  name: "Claims payouts",
  scope: { kind: "agent", id: AGENT, label: "Claims triage" },
  scope_kind: "agent",
  scope_id: AGENT,
  version_no: 3,
  state: "approved",
  document: DOC as unknown as Record<string, unknown>,
  rules: ruleViews(DOC),
};

const MINIMAL_HELD: ApiHeldAction = {
  held_action_id: "0192cccc-0000-7000-8000-000000000001",
  agent_id: AGENT,
  call_id: "clm-1",
  tool: "payments.transfer",
  state: "pending",
  decision: null,
  expires_at: "2026-10-10T04:00:00Z",
};

test("a minimal list row becomes a definite held action with the documented defaults", () => {
  const h = toHeld(MINIMAL_HELD);
  expect(h).toMatchObject({
    id: MINIMAL_HELD.held_action_id,
    held_action_id: MINIMAL_HELD.held_action_id,
    policy_id: null,
    policy_version: null,
    rule_id: null,
    args: null,
    approvals: [],
    approvals_required: 1,
    four_eyes: false,
    matched_paths: [],
    history: [],
    on_behalf_of: null,
    counter: null,
    decided_at: null,
    created_at: MINIMAL_HELD.expires_at,
  });
});

test("approvals_required wins over four_eyes; four_eyes alone implies two approvers", () => {
  expect(toHeld({ ...MINIMAL_HELD, four_eyes: true }).approvals_required).toBe(2);
  expect(toHeld({ ...MINIMAL_HELD, approvals_required: 2 }).four_eyes).toBe(true);
  const h = toHeld({ ...MINIMAL_HELD, approvals_required: 2, approvals: [{ user_id: OTHER, at: "2026-10-10T03:40:00Z" }] });
  expect(approvalsLeft(h)).toBe(1);
  expect(approvalsLeft({ ...h, state: "approved" })).toBe(0);
});

test("on_behalf_of is read in its wire form (user | external), tolerating the generator's kind names", () => {
  expect(onBehalfOf({ kind: "user", id: ME })).toEqual({ kind: "user", id: ME });
  expect(onBehalfOf({ kind: "external", ref: "crm:4411" })).toEqual({ kind: "external", ref: "crm:4411" });
  expect(onBehalfOf({ kind: "OnBehalfOfUser", id: ME })).toEqual({ kind: "user", id: ME });
  expect(onBehalfOf({ kind: "user" })).toBeNull();
  expect(onBehalfOf(null)).toBeNull();
  const raw = { ...MINIMAL_HELD, on_behalf_of: { kind: "user", id: ME } } as unknown as ApiHeldAction;
  const h = toHeld(raw);
  expect(onBehalfUser(h)).toBe(ME);
  const name = (id: string): string => (id === OTHER ? "On-call Operator" : "a colleague");
  expect(actingFor(h.on_behalf_of, ME, name)).toBe("acting for you");
  expect(actingFor({ kind: "user", id: OTHER }, ME, name)).toBe("acting for On-call Operator");
  expect(actingFor({ kind: "external", ref: "crm:4411" }, ME, name)).toBe("acting for crm:4411");
  expect(actingFor(null, ME, name)).toBeNull();
});

test("history entries keep every API member and unknown kinds (the old `escalated`) are dropped", () => {
  const history = [
    { at: "2026-10-10T03:30:00Z", kind: "requested", user_id: null, key_id: null, reason: "Needs a person", step_up: false, code: null, approvals: null },
    { at: "2026-10-10T03:31:00Z", kind: "refused", user_id: ME, key_id: null, reason: "mine", step_up: false, code: "self_approval", approvals: null },
    { at: "2026-10-10T03:32:00Z", kind: "escalated", user_id: null, key_id: null, reason: null, step_up: false, code: null, approvals: null },
    { at: "2026-10-10T03:33:00Z", kind: "approval", user_id: OTHER, key_id: null, reason: "checked", step_up: true, code: null, approvals: 1 },
  ] as ApiHeldAction["history"];
  const h = toHeld({ ...MINIMAL_HELD, history });
  expect(h.history.map((e) => e.kind)).toEqual(["requested", "refused", "approval"]);
  expect(h.history[1]).toMatchObject({ code: "self_approval", user_id: ME });
  expect(h.history[2]).toMatchObject({ approvals: 1, step_up: true });
});

test("a list row carries neither arguments nor the trail, as the API lists it", () => {
  const full = toHeld({ ...MINIMAL_HELD, args: { amount: 75000 }, history: [{ at: "2026-10-10T03:30:00Z", kind: "requested", user_id: null, key_id: null, reason: null, step_up: false, code: null, approvals: null }] });
  expect(full.args).toEqual({ amount: 75000 });
  const row = heldListRow(full);
  expect(row.args).toBeNull();
  expect("history" in row).toBe(false);
  expect(full.history).toHaveLength(1);
  // Read back through the boundary, a list row has an empty trail.
  expect(toHeld(row as ApiHeldAction).history).toEqual([]);
});

test("waiting rows sort first by deadline, then decided rows newest first", () => {
  const a = toHeld({ ...MINIMAL_HELD, held_action_id: "a", expires_at: "2026-10-10T05:00:00Z" });
  const b = toHeld({ ...MINIMAL_HELD, held_action_id: "b", expires_at: "2026-10-10T04:00:00Z" });
  const c = toHeld({ ...MINIMAL_HELD, held_action_id: "c", state: "denied", decided_at: "2026-10-10T03:00:00Z" });
  const d = toHeld({ ...MINIMAL_HELD, held_action_id: "d", state: "approved", decided_at: "2026-10-10T03:10:00Z" });
  expect([c, a, d, b].sort(heldOrder).map((h) => h.id)).toEqual(["b", "a", "d", "c"]);
});

test("an API policy becomes a definite record with its document narrowed", () => {
  const p = toPolicy(API_POLICY);
  expect(p).toMatchObject({ id: V3, policy_id: LINEAGE, version_no: 3, state: "approved", scope_kind: "agent", four_eyes: false, approval_four_eyes: false, approvals: [], change_note: null, approved_by: null, default_effect: "allow", hold_timeout_s: 900 });
  expect(p.document).toEqual(DOC);
  // The document's policy_id is the version id, not the stable id.
  expect(p.document.policy_id).toBe(p.id);
  expect(p.document.policy_id).not.toBe(p.policy_id);
});

test("a policy whose document is missing members falls back to its columns and rule rows", () => {
  const p = toPolicy({ ...API_POLICY, document: {}, default_effect: "allow", hold_timeout_s: 600 });
  expect(p.document).toMatchObject({ schema: "sibyl-action-policy/1", policy_id: V3, version: 3, default_effect: "allow", hold_timeout_s: 600, sensitive_tools: [], tool_allowlist: null });
  expect(p.document.rules).toEqual(DOC.rules);
});

test("create body: flat scope, the change note doubles as the audit reason, tenant scope has no id", () => {
  const body = createBody({ name: "  Claims payouts ", scopeKind: "agent", scopeId: AGENT, document: DOC, changeNote: " Lower the threshold to ₹40,000 ", fourEyes: true, basedOnId: V3 });
  expect(body).toMatchObject({ name: "Claims payouts", scope_kind: "agent", scope_id: AGENT, four_eyes: true, change_note: "Lower the threshold to ₹40,000", reason: "Lower the threshold to ₹40,000", based_on_id: V3 });
  expect(body).not.toHaveProperty("scope");
  const tenant = createBody({ name: "Egress", scopeKind: "tenant", scopeId: AGENT, document: DOC, changeNote: "short", fourEyes: false, basedOnId: null });
  expect(tenant.scope_id).toBeNull();
  expect(tenant).not.toHaveProperty("reason");
  expect(tenant).not.toHaveProperty("based_on_id");
});

test("draft simulate body and the draft document use the control plane's placeholder id", () => {
  const body = draftSimulateBody({ document: DOC, scopeKind: "agent_group", scopeId: "g1", tool: "refunds.issue", args: { amount: 1 }, counters: {} });
  expect(body).toEqual({ document: DOC, scope_kind: "agent_group", scope_id: "g1", tool: "refunds.issue", args: { amount: 1 } });
  expect(draftSimulateBody({ document: DOC, scopeKind: "tenant", scopeId: "x", tool: "t", args: {}, counters: { k: 2 } })).toEqual({ document: DOC, scope_kind: "tenant", tool: "t", args: {}, counters: { k: 2 } });
  const doc = draftDocument({ rules: DOC.rules });
  expect(doc).toMatchObject({ policy_id: DRAFT_POLICY_ID, version: 1, default_effect: "escalate", hold_timeout_s: 900, sensitive_tools: [] });
});

test("the simulate answer mirrors simulate.py: a draft decides with policy_id null; the counter shows the window total", () => {
  const draft = draftDocument({ ...DOC });
  const key = `${DRAFT_POLICY_ID}/refund-burst`;
  const d = evaluate(draft, "refunds.issue", { amount: 1 }, { [key]: 3 });
  const a = simulateAnswer(d, { [key]: 3 }, null, "2026-10-10T03:30:00Z");
  expect(a).toMatchObject({ effect: "allow", rule_id: "refund-burst", policy_id: null, policy_version: null, policy_state: null, evaluated_at: "2026-10-10T03:30:00Z", counter: { key, amount: "1", max: "5", window_s: 60, value: "3", window_start: null } });
  const stored = simulateAnswer(evaluate(DOC, "payments.transfer", { amount: 75000 }), null, "approved", "2026-10-10T03:30:00Z");
  expect(stored).toMatchObject({ effect: "escalate", policy_id: V3, policy_version: 3, policy_state: "approved", counter: null, sensitive: true, matched_paths: ["/amount"] });
});

test("held views filter on the server with repeated state and ask for arguments; policies narrow on the client", () => {
  expect(heldListPath("waiting")).toBe("/held-actions?limit=100&state=pending&include=args");
  expect(heldListPath("decided")).toBe("/held-actions?limit=100&state=approved&state=denied&state=expired&state=cancelled&include=args");
  expect(new URLSearchParams(heldListPath("decided").split("?")[1]).getAll("state")).toEqual([...HELD_VIEW_STATES.decided]);
  expect(heldListPath("all")).toBe("/held-actions?limit=100&include=args");
  expect(HELD_VIEW_STATES.decided).not.toContain("pending");
  expect(policyListPath("current")).not.toContain("state=");
  expect(policyListPath("all")).toContain("include_history=true");
  expect(["draft", "approved", "retired", "superseded"].filter((s) => policyInView({ state: s as "draft" }, "current"))).toEqual(["draft", "approved"]);
});

test("the action summary becomes per-agent counts and a total", () => {
  const { byAgent, total } = summaryCounts({
    from: "2026-10-09T03:30:00Z",
    to: "2026-10-10T03:30:00Z",
    data: [{ agent_id: AGENT, blocked: 2, escalated: 1, approved: 1, denied: 0, expired: 0 }],
    total: { blocked: 2, escalated: 1, approved: 1, denied: 0, expired: 0 },
  });
  expect(byAgent.get(AGENT)).toEqual({ blocked: 2, escalated: 1, approved: 1, denied: 0, expired: 0 });
  expect(total.blocked + total.escalated).toBe(3);
});
