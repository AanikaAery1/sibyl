/**
 * The policy editor's structured form ↔ the `sibyl-action-policy/1` JSON AST
 * (lib/action-gate/predicate-form.ts): round-trips both ways, typed values, advanced fallback,
 * and the validation the server would apply.
 */
import { expect, test } from "@playwright/test";
import type { ActionPolicyDocument, ActionRule, Predicate } from "@/lib/api/action-gate";
import { emptyCondition, formToDocument, formToPredicate, formToRule, policyToForm, predicateToForm, ruleToForm, type WhenForm } from "@/lib/action-gate/predicate-form";
import { regexProblem, validatePolicyDocument } from "@/lib/action-gate/validate";

const roundTrip = (p: Predicate): Predicate | undefined => {
  const back = formToPredicate(predicateToForm(p));
  if (!back.ok) throw new Error(JSON.stringify(back.errors));
  return back.value;
};

const RULES: ActionRule[] = [
  { rule_id: "transfer-limit", tool: "payments.transfer", when: { gt: ["/amount", 100000] }, effect: "block", reason: "Above the ₹1,00,000 single-transfer limit" },
  { rule_id: "transfer-mid", tool: "payments.transfer", when: { all: [{ gt: ["/amount", 50000] }, { in: ["/currency", ["INR", "USD"]] }] }, effect: "escalate", reason: "Mid-size transfers need a human" },
  { rule_id: "refund-burst", tool: "refunds.issue", cumulative: { count: true, max: 5, window_s: 60, per: "/customer_id", on_exceed: "escalate" }, effect: "allow", reason: "Refund burst cap" },
  { rule_id: "daily-sum", tool: "payments.*", cumulative: { sum: "/amount", max: 500000, window_s: 86400 }, effect: "allow", reason: "Daily total" },
  { rule_id: "pii-out", tool: "email.*", data_class: { secrets: true, pii: ["email", "phone", "national_id"] }, effect: "block", reason: "No personal data to external email" },
  { rule_id: "ref-format", tool: "payments.transfer", when: { not: { matches: ["/reference", "CLM-[0-9]{6}"] } }, effect: "escalate", reason: "Unrecognised claim reference" },
  { rule_id: "any-of", tool: "crm.*", when: { any: [{ eq: ["/region", "EU"] }, { exists: "/gdpr_subject" }, { ne: ["/consent", true] }] }, effect: "escalate", reason: "EU data" },
];

const DOC: Omit<ActionPolicyDocument, "policy_id" | "version"> = {
  schema: "sibyl-action-policy/1",
  default_effect: "allow",
  tool_allowlist_enforced: true,
  tool_allowlist: ["payments.*", "refunds.issue", "email.*", "crm.*"],
  sensitive_tools: ["payments.transfer"],
  external_tools: ["email.*"],
  hold_timeout_s: 900,
  rules: RULES,
};

test("every leaf operator survives JSON → form → JSON unchanged", () => {
  const leaves: Predicate[] = [
    { eq: ["/currency", "INR"] },
    { ne: ["/approved", false] },
    { eq: ["/note", null] },
    { lt: ["/amount", 10.5] },
    { le: ["/amount", 100000] },
    { gt: ["/amount", -1] },
    { ge: ["/count", 0] },
    { in: ["/currency", ["INR", "USD"]] },
    { not_in: ["/bank_code", [101, 202]] },
    { matches: ["/iban", "[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}"] },
    { exists: "/customer_id" },
    { not: { le: ["/amount", 5] } },
  ];
  for (const leaf of leaves) expect(roundTrip(leaf)).toEqual(leaf);
});

test("groups survive the round-trip, including a one-condition group", () => {
  const single: Predicate = { all: [{ le: ["/amount", 1] }] };
  expect(roundTrip(single)).toEqual(single);
  const any: Predicate = { any: [{ eq: ["/a", "x"] }, { not: { exists: "/b" } }] };
  expect(roundTrip(any)).toEqual(any);
});

test("the string \"10\" and the number 10 stay distinct", () => {
  const asString = predicateToForm({ eq: ["/code", "10"] });
  const asNumber = predicateToForm({ eq: ["/code", 10] });
  expect(asString.kind === "group" && asString.conditions[0]?.valueType).toBe("string");
  expect(asNumber.kind === "group" && asNumber.conditions[0]?.valueType).toBe("number");
  expect(roundTrip({ eq: ["/code", "10"] })).toEqual({ eq: ["/code", "10"] });
  expect(roundTrip({ eq: ["/code", 10] })).toEqual({ eq: ["/code", 10] });
});

test("predicates the form cannot represent are kept verbatim as advanced", () => {
  const nested: Predicate = { all: [{ any: [{ eq: ["/a", 1] }, { eq: ["/b", 2] }] }, { le: ["/amount", 3] }] };
  const negatedGroup: Predicate = { not: { all: [{ eq: ["/a", 1] }] } };
  const mixedList: Predicate = { in: ["/x", ["a", 1]] };
  for (const p of [nested, negatedGroup, mixedList]) {
    const f = predicateToForm(p);
    expect(f.kind).toBe("advanced");
    expect(roundTrip(p)).toEqual(p);
  }
});

test("every rule shape round-trips through the form (when, cumulative, data class)", () => {
  RULES.forEach((rule, i) => {
    const back = formToRule(ruleToForm(rule), i);
    expect(back.ok && back.value).toEqual(rule);
  });
});

test("a whole policy round-trips and form → JSON → form is stable", () => {
  const form = policyToForm(DOC);
  const doc = formToDocument(form);
  expect(doc.ok && doc.value).toEqual(DOC);
  if (!doc.ok) return;
  expect(policyToForm(doc.value)).toEqual(form);
});

test("number fields accept Indian digit grouping (1,00,000) and refuse words", () => {
  const when: WhenForm = { kind: "group", combinator: "all", grouped: false, conditions: [{ ...emptyCondition(), value: "1,00,000" }] };
  const ok = formToPredicate(when);
  expect(ok.ok && ok.value).toEqual({ le: ["/amount", 100000] });
  const bad = formToPredicate({ ...when, conditions: [{ ...emptyCondition(), value: "one lakh" }] });
  expect(bad.ok).toBe(false);
  if (!bad.ok) expect(bad.errors[0]).toEqual({ path: "/when/0/value", message: "Enter a number" });
});

test("an empty list is refused with a pointer to the field", () => {
  const r = formToPredicate({ kind: "group", combinator: "all", grouped: false, conditions: [{ ...emptyCondition(), op: "in", valueType: "string", list: [" "] }] });
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.errors.map((e) => e.path)).toEqual(["/when/0/list"]);
});

test("validation mirrors the model: ids, globs, pointers, duplicates, holds, allowlist", () => {
  const bad = {
    ...DOC,
    hold_timeout_s: 5,
    tool_allowlist: [],
    rules: [
      { ...RULES[0], rule_id: "Bad Id" },
      { ...RULES[0], tool: "payments transfer" },
      { ...RULES[1], rule_id: "transfer-limit", when: { le: ["amount", 5] } },
      { ...RULES[2], cumulative: { count: true as const, sum: "/x", max: 1, window_s: 0 } },
      { ...RULES[4], data_class: { secrets: false, pii: [] } },
    ],
  } as Omit<ActionPolicyDocument, "policy_id" | "version">;
  const paths = validatePolicyDocument(bad).map((e) => e.path);
  expect(paths).toEqual(
    expect.arrayContaining(["/hold_timeout_s", "/tool_allowlist", "/rules/0/rule_id", "/rules/1/tool", "/rules/2/when/le/0", "/rules/3/cumulative", "/rules/3/cumulative/window_s", "/rules/4/data_class", "/rules/2/rule_id"]),
  );
  expect(validatePolicyDocument(DOC)).toEqual([]);
});

test("unsafe regexes are refused before they reach the server", () => {
  expect(regexProblem("(a+)+$")).toMatch(/Nested/);
  expect(regexProblem("(?=x)y")).toMatch(/lookaround/);
  expect(regexProblem("(a)\\1")).toMatch(/Backreferences/);
  expect(regexProblem("[")).toMatch(/valid/);
  expect(regexProblem("CLM-[0-9]{6}")).toBeNull();
});
