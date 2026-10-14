/**
 * Simulate: the console's port of `sibyl_schemas.action_gate.evaluate` (lib/action-gate/evaluate.ts),
 * which decides demo events, the demo `POST /action-policies/{id}/simulate` and the editor's
 * draft preview. Cases mirror the Python evaluator's semantics and the four demo scenarios.
 */
import { expect, test } from "@playwright/test";
import type { ActionPolicyDocument } from "@/lib/api/action-gate";
import { createHash } from "node:crypto";
import { ALLOWLIST_RULE_ID, ERROR_RULE_ID, counterKey, evaluate, evaluateAll, holds, predicatePaths, resolvePointer, toolMatches } from "@/lib/action-gate/evaluate";
import { jcs, sha256Hex } from "@/lib/action-gate/sha256";

const CLAIMS: ActionPolicyDocument = {
  schema: "sibyl-action-policy/1",
  policy_id: "0192aaaa-0000-7000-8000-000000000001",
  version: 3,
  default_effect: "allow",
  tool_allowlist_enforced: false,
  tool_allowlist: null,
  sensitive_tools: ["payments.transfer"],
  external_tools: ["email.*"],
  hold_timeout_s: 900,
  rules: [
    { rule_id: "transfer-limit", tool: "payments.transfer", when: { gt: ["/amount", 100000] }, effect: "block", reason: "Above the ₹1,00,000 single-transfer limit" },
    { rule_id: "transfer-review", tool: "payments.transfer", when: { all: [{ gt: ["/amount", 50000] }, { in: ["/currency", ["INR"]] }] }, effect: "escalate", reason: "Transfers above ₹50,000 need a human" },
    { rule_id: "refund-burst", tool: "refunds.issue", cumulative: { count: true, max: 5, window_s: 60 }, effect: "allow", reason: "At most 5 refunds a minute" },
    { rule_id: "pii-external", tool: "email.*", data_class: { secrets: true, pii: ["email", "phone", "national_id"] }, effect: "block", reason: "Personal data may not leave through external email" },
  ],
};

test("an over-limit transfer (₹2,50,000 against ₹1,00,000) is blocked by the first matching rule", () => {
  const d = evaluate(CLAIMS, "payments.transfer", { amount: 250000, currency: "INR", payee: "Apex Freight" });
  expect(d).toMatchObject({ effect: "block", rule_id: "transfer-limit", matched_paths: ["/amount"], policy_version: 3, sensitive: true });
});

test("a mid-size transfer escalates, with every path the rule read", () => {
  const d = evaluate(CLAIMS, "payments.transfer", { amount: 75000, currency: "INR" });
  expect(d).toMatchObject({ effect: "escalate", rule_id: "transfer-review", matched_paths: ["/amount", "/currency"], hold_timeout_s: 900 });
});

test("an under-limit transfer falls through to the default, tightened to escalate for a sensitive tool", () => {
  const d = evaluate(CLAIMS, "payments.transfer", { amount: 1200, currency: "INR" });
  expect(d.effect).toBe("escalate");
  expect(d.rule_id).toBeNull();
  expect(d.reason).toBe("no rule matched; default escalate (sensitive tool)");
  expect(evaluate(CLAIMS, "kb.search", { q: "x" })).toMatchObject({ effect: "allow", reason: "no rule matched; default allow" });
});

test("PII to an external email tool is blocked with the leaf that carried it", () => {
  const d = evaluate(CLAIMS, "email.send_external", { to: "partner@outside.example", body: "Claimant phone +91 98200 12345, PAN ABCDE1234F" });
  expect(d.effect).toBe("block");
  expect(d.rule_id).toBe("pii-external");
  expect(d.matched_paths).toEqual(expect.arrayContaining(["/to", "/body"]));
  expect(evaluate(CLAIMS, "email.send_external", { to: "ops", body: "Shipment delayed" }).rule_id).toBeNull();
});

test("a scrubbed secret placeholder counts as a secret for data-class rules", () => {
  const d = evaluate(CLAIMS, "email.send_external", { body: "key [SECRET:1a2b3c4d]" });
  expect(d).toMatchObject({ effect: "block", rule_id: "pii-external", matched_paths: ["/body"] });
});

test("a cumulative cap: within the cap keeps the rule's effect, the burst that crosses it escalates", () => {
  const key = `${CLAIMS.policy_id}/refund-burst`;
  expect(evaluate(CLAIMS, "refunds.issue", { amount: 900 }, { [key]: 4 })).toMatchObject({ effect: "allow", needs_counter: { counter_key: key, max: "5", increment: "1", within_effect: "allow", exceed_effect: "escalate" } });
  const over = evaluate(CLAIMS, "refunds.issue", { amount: 900 }, { [key]: 5 });
  expect(over).toMatchObject({ effect: "escalate", rule_id: "refund-burst", reason: "At most 5 refunds a minute (cap 5 per 60s exceeded)" });
  expect(evaluate(CLAIMS, "refunds.issue", { amount: 900 })).toMatchObject({ effect: "escalate", reason: "At most 5 refunds a minute (cumulative counter pending)" });
});

test("counters are keyed by the policy version id and rule id, never by the rule id alone", () => {
  // The old console keyed by rule id: such a counter is not the one the control plane reads.
  expect(evaluate(CLAIMS, "refunds.issue", { amount: 900 }, { "refund-burst": 0 })).toMatchObject({ effect: "escalate", reason: "At most 5 refunds a minute (cumulative counter pending)" });
});

test("a cap with `per` buckets the counter by sha256(JCS(value))[:32]; an absent value gets `~`", () => {
  const per: ActionPolicyDocument = { ...CLAIMS, rules: [{ rule_id: "per-customer", tool: "refunds.issue", cumulative: { count: true, max: 2, window_s: 3600, per: "/customer" }, effect: "allow", reason: "Two refunds a customer an hour" }] };
  const rule = per.rules[0] as ActionPolicyDocument["rules"][number];
  // sha256('"C-1"') — the JCS form of the string is its JSON string.
  expect(counterKey(per, rule, { customer: "C-1" })).toBe(`${CLAIMS.policy_id}/per-customer/${createHash("sha256").update('"C-1"').digest("hex").slice(0, 32)}`);
  expect(counterKey(per, rule, { customer: { b: 1, a: [2, "x"] } })).toBe(`${CLAIMS.policy_id}/per-customer/${createHash("sha256").update('{"a":[2,"x"],"b":1}').digest("hex").slice(0, 32)}`);
  expect(counterKey(per, rule, {})).toBe(`${CLAIMS.policy_id}/per-customer/~`);
  const key = counterKey(per, rule, { customer: "C-1" });
  expect(evaluate(per, "refunds.issue", { customer: "C-1" }, { [key]: 1 }).effect).toBe("allow");
  expect(evaluate(per, "refunds.issue", { customer: "C-1" }, { [key]: 2 }).effect).toBe("escalate");
});

test("the pure SHA-256 matches node:crypto, including multi-block and non-ASCII input", () => {
  for (const text of ["", "abc", "₹1,00,000 — रिफंड", "x".repeat(55), "y".repeat(56), "z".repeat(1000)]) {
    expect(sha256Hex(text)).toBe(createHash("sha256").update(text, "utf8").digest("hex"));
  }
  expect(jcs({ b: 1, a: [true, null, 1.5, "q"] })).toBe('{"a":[true,null,1.5,"q"],"b":1}');
});

test("type confusion is indeterminate: it can never satisfy an allow rule, but it still blocks", () => {
  expect(evaluate(CLAIMS, "payments.transfer", { amount: "a lot", currency: "INR" })).toMatchObject({ effect: "block", rule_id: "transfer-limit", reason: "Above the ₹1,00,000 single-transfer limit (arguments indeterminate)" });
  const allowOnly: ActionPolicyDocument = { ...CLAIMS, sensitive_tools: [], default_effect: "escalate", rules: [{ rule_id: "small", tool: "pay", when: { le: ["/amount", 10] }, effect: "allow", reason: "small" }] };
  expect(evaluate(allowOnly, "pay", { amount: "5 dollars" }).effect).toBe("escalate");
  expect(evaluate(allowOnly, "pay", { amount: "5" }).effect).toBe("allow");
});

test("an enforced allowlist blocks unknown tools before any rule", () => {
  const locked: ActionPolicyDocument = { ...CLAIMS, tool_allowlist_enforced: true, tool_allowlist: ["payments.*"] };
  expect(evaluate(locked, "shell.exec", {})).toMatchObject({ effect: "block", rule_id: ALLOWLIST_RULE_ID });
  expect(evaluate(locked, "payments.transfer", { amount: 250000 }).rule_id).toBe("transfer-limit");
});

test("look-alike tool names are normalised (NFKC, trimmed) so they cannot dodge a rule", () => {
  expect(evaluate(CLAIMS, " ｐａｙｍｅｎｔｓ.transfer ", { amount: 250000 }).rule_id).toBe("transfer-limit");
});

test("evaluation is total: a broken policy fails closed instead of throwing", () => {
  const broken = { ...CLAIMS, rules: [{ rule_id: "x", tool: "pay", when: { nope: 1 }, effect: "allow", reason: "r" }] } as unknown as ActionPolicyDocument;
  expect(evaluate(broken, "pay", {})).toMatchObject({ effect: "block", rule_id: ERROR_RULE_ID });
});

test("several policies: the most restrictive decision wins", () => {
  const tenant: ActionPolicyDocument = { ...CLAIMS, policy_id: "t", rules: [{ rule_id: "freeze", tool: "payments.*", effect: "block", reason: "Payments frozen" }] };
  expect(evaluateAll([CLAIMS, tenant], "payments.transfer", { amount: 75000, currency: "INR" })).toMatchObject({ effect: "block", rule_id: "freeze" });
  expect(evaluateAll([], "anything", {})).toMatchObject({ effect: "allow", reason: "no action policy applies" });
});

test("building blocks: JSON pointers, globs, paths", () => {
  expect(resolvePointer({ a: { "b/c": [10, 20] } }, "/a/b~1c/1")).toEqual([true, 20]);
  expect(resolvePointer({ a: [1] }, "/a/01")).toEqual([false, undefined]);
  expect(toolMatches("email.*", "email.send.external")).toBe(true);
  expect(toolMatches("pay?", "pays")).toBe(true);
  expect(toolMatches("payments.transfer", "paymentsXtransfer")).toBe(false);
  expect(holds({ exists: "/x" }, { x: null })).toBe(true);
  expect(holds({ eq: ["/flag", true] }, { flag: 1 })).toBe(false);
  expect(holds({ le: ["/amount", 5] }, { amount: "4.5" })).toBe(true);
  expect(predicatePaths({ all: [{ le: ["/a", 1] }, { not: { exists: "/b" } }, { eq: ["/a", 2] }] })).toEqual(["/a", "/b"]);
});
