/**
 * The structured editor's model ↔ the policy's JSON AST (pure; unit-tested for round-trips).
 *
 * A rule's `when` maps onto one condition group: `all` or `any` over leaf comparisons, each
 * optionally negated (`{"not": leaf}`). Anything deeper (nested groups, negated groups) keeps
 * the original JSON and is shown read-only as "advanced", so the form never silently rewrites
 * a predicate it cannot represent. Values carry an explicit type so "10" and 10 stay distinct.
 */
import type { ActionEffect, ActionPolicyDocument, ActionRule, CumulativeCap, PiiId, Predicate, Scalar } from "@/lib/api/action-gate";
import { POLICY_SCHEMA_ID } from "@/lib/api/action-gate";
import { validatePolicyDocument, type FieldError } from "./validate";

export type LeafOp = "eq" | "ne" | "lt" | "le" | "gt" | "ge" | "in" | "not_in" | "matches" | "exists";
export type ValueType = "number" | "string" | "boolean" | "null";

export const LEAF_OPS: readonly LeafOp[] = ["le", "lt", "ge", "gt", "eq", "ne", "in", "not_in", "matches", "exists"];
export const OP_LABEL: Readonly<Record<LeafOp, string>> = {
  le: "≤ at most",
  lt: "< below",
  ge: "≥ at least",
  gt: "> above",
  eq: "= equals",
  ne: "≠ not equal",
  in: "in allowlist",
  not_in: "not in list",
  matches: "matches regex",
  exists: "is present",
};
const NUMERIC: ReadonlySet<LeafOp> = new Set(["lt", "le", "gt", "ge"]);
const LIST: ReadonlySet<LeafOp> = new Set(["in", "not_in"]);

export interface Condition {
  path: string;
  op: LeafOp;
  negate: boolean;
  valueType: ValueType;
  /** Single value (eq/ne/compare/matches), as typed. */
  value: string;
  /** List values (in/not_in), as typed. */
  list: string[];
}

export type WhenForm =
  | { kind: "none" }
  | { kind: "group"; combinator: "all" | "any"; grouped: boolean; conditions: Condition[] }
  | { kind: "advanced"; json: Predicate };

export interface CapForm {
  enabled: boolean;
  measure: "sum" | "count";
  sum: string;
  max: string;
  window_s: string;
  per: string;
  on_exceed: "escalate" | "block";
  /** The source document spelled `on_exceed` out (kept on the way back so round-trips are exact). */
  onExceedExplicit: boolean;
}

export interface RuleForm {
  rule_id: string;
  tool: string;
  when: WhenForm;
  cap: CapForm;
  dataClass: { enabled: boolean; secrets: boolean; pii: PiiId[] };
  effect: ActionEffect;
  reason: string;
}

export interface PolicyForm {
  default_effect: "allow" | "escalate";
  tool_allowlist_enforced: boolean;
  tool_allowlist: string[] | null;
  sensitive_tools: string[];
  external_tools: string[];
  hold_timeout_s: string;
  rules: RuleForm[];
}

export type Result<T> = { ok: true; value: T } | { ok: false; errors: FieldError[] };

// ── leaf ↔ condition ───────────────────────────────────────────────────────

function typeOf(v: Scalar): ValueType {
  return v === null ? "null" : typeof v === "number" ? "number" : typeof v === "boolean" ? "boolean" : "string";
}

const text = (v: Scalar): string => (v === null ? "" : String(v));

function leafToCondition(node: Predicate, negate: boolean): Condition | null {
  const base = { negate, value: "", list: [] as string[] };
  if ("exists" in node) return { ...base, path: node.exists, op: "exists", valueType: "string" };
  for (const op of ["eq", "ne", "lt", "le", "gt", "ge", "matches"] as const) {
    if (op in node) {
      const [path, v] = (node as Record<string, [string, Scalar]>)[op] as [string, Scalar];
      return { ...base, path, op, valueType: typeOf(v), value: text(v) };
    }
  }
  for (const op of ["in", "not_in"] as const) {
    if (op in node) {
      const [path, vs] = (node as Record<string, [string, Scalar[]]>)[op] as [string, Scalar[]];
      const types = new Set(vs.map(typeOf));
      if (types.size !== 1 || types.has("null") || types.has("boolean")) return null;
      return { ...base, path, op, valueType: [...types][0] as ValueType, list: vs.map(text) };
    }
  }
  return null;
}

const isGroup = (n: Predicate): boolean => "all" in n || "any" in n || "not" in n;

function toCondition(node: Predicate): Condition | null {
  if ("not" in node) return isGroup(node.not) ? null : leafToCondition(node.not, true);
  return isGroup(node) ? null : leafToCondition(node, false);
}

/** JSON AST → the form; predicates the form cannot represent come back as `advanced`. */
export function predicateToForm(node: Predicate | undefined): WhenForm {
  if (node === undefined) return { kind: "none" };
  if ("all" in node || "any" in node) {
    const kids = "all" in node ? node.all : node.any;
    const conditions = kids.map(toCondition);
    if (conditions.every((c): c is Condition => c !== null)) return { kind: "group", combinator: "all" in node ? "all" : "any", grouped: true, conditions };
    return { kind: "advanced", json: node };
  }
  const single = toCondition(node);
  return single ? { kind: "group", combinator: "all", grouped: false, conditions: [single] } : { kind: "advanced", json: node };
}

function parseScalar(raw: string, type: ValueType): Scalar | undefined {
  if (type === "null") return null;
  if (type === "boolean") return raw === "true" ? true : raw === "false" ? false : undefined;
  if (type === "number") {
    const t = raw.trim().replaceAll(",", "");
    if (!/^[+-]?\d+(\.\d+)?$/.test(t)) return undefined;
    const n = Number(t);
    return Number.isFinite(n) ? n : undefined;
  }
  return raw;
}

function conditionToLeaf(c: Condition, at: string): Result<Predicate> {
  const errors: FieldError[] = [];
  let leaf: Predicate | null = null;
  if (c.op === "exists") leaf = { exists: c.path };
  else if (LIST.has(c.op)) {
    const items = c.list.map((v) => v.trim()).filter((v) => v !== "");
    const values = items.map((v) => parseScalar(v, c.valueType));
    if (items.length === 0) errors.push({ path: `${at}/list`, message: "Add at least one value" });
    if (values.some((v) => v === undefined)) errors.push({ path: `${at}/list`, message: `Every value must be a ${c.valueType}` });
    leaf = c.op === "in" ? { in: [c.path, values as Scalar[]] } : { not_in: [c.path, values as Scalar[]] };
  } else {
    const type = NUMERIC.has(c.op) ? "number" : c.op === "matches" ? "string" : c.valueType;
    const v = parseScalar(c.value, type);
    if (v === undefined) errors.push({ path: `${at}/value`, message: type === "number" ? "Enter a number" : `Enter a ${type}` });
    const pair = [c.path, v as Scalar] as [string, Scalar];
    leaf = { [c.op]: pair } as unknown as Predicate;
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, value: c.negate ? { not: leaf } : leaf };
}

/** The form → JSON AST (undefined when the rule has no conditions). */
export function formToPredicate(when: WhenForm, at = "/when"): Result<Predicate | undefined> {
  if (when.kind === "none") return { ok: true, value: undefined };
  if (when.kind === "advanced") return { ok: true, value: when.json };
  if (when.conditions.length === 0) return { ok: true, value: undefined };
  const leaves = when.conditions.map((c, i) => conditionToLeaf(c, `${at}/${i}`));
  const errors = leaves.flatMap((r) => (r.ok ? [] : r.errors));
  if (errors.length) return { ok: false, errors };
  const nodes = leaves.map((r) => (r.ok ? r.value : null)) as Predicate[];
  if (nodes.length === 1 && !when.grouped) return { ok: true, value: nodes[0] };
  return { ok: true, value: when.combinator === "all" ? { all: nodes } : { any: nodes } };
}

export function emptyCondition(): Condition {
  return { path: "/amount", op: "le", negate: false, valueType: "number", value: "", list: [] };
}

// ── rule and policy ────────────────────────────────────────────────────────

const OFF_CAP: CapForm = { enabled: false, measure: "sum", sum: "/amount", max: "", window_s: "86400", per: "", on_exceed: "escalate", onExceedExplicit: false };

export function ruleToForm(rule: ActionRule): RuleForm {
  const c = rule.cumulative;
  return {
    rule_id: rule.rule_id,
    tool: rule.tool,
    when: predicateToForm(rule.when),
    cap: c
      ? { enabled: true, measure: c.count ? "count" : "sum", sum: c.sum ?? "", max: String(c.max), window_s: String(c.window_s), per: c.per ?? "", on_exceed: c.on_exceed ?? "escalate", onExceedExplicit: c.on_exceed !== undefined }
      : OFF_CAP,
    dataClass: rule.data_class ? { enabled: true, secrets: rule.data_class.secrets, pii: [...rule.data_class.pii] } : { enabled: false, secrets: true, pii: [] },
    effect: rule.effect,
    reason: rule.reason,
  };
}

function capFromForm(f: CapForm, at: string): Result<CumulativeCap | undefined> {
  if (!f.enabled) return { ok: true, value: undefined };
  const max = parseScalar(f.max, "number");
  const window = parseScalar(f.window_s, "number");
  const errors: FieldError[] = [];
  if (typeof max !== "number") errors.push({ path: `${at}/max`, message: "Enter a number" });
  if (typeof window !== "number" || !Number.isInteger(window)) errors.push({ path: `${at}/window_s`, message: "Enter whole seconds" });
  if (errors.length) return { ok: false, errors };
  const cap: CumulativeCap = { ...(f.measure === "count" ? { count: true as const } : { sum: f.sum }), max: max as number, window_s: window as number };
  return { ok: true, value: { ...cap, ...(f.per.trim() ? { per: f.per.trim() } : {}), ...(f.on_exceed === "block" || f.onExceedExplicit ? { on_exceed: f.on_exceed } : {}) } };
}

export function formToRule(f: RuleForm, i: number): Result<ActionRule> {
  const at = `/rules/${i}`;
  const when = formToPredicate(f.when, `${at}/when`);
  const cap = capFromForm(f.cap, `${at}/cumulative`);
  const errors = [...(when.ok ? [] : when.errors), ...(cap.ok ? [] : cap.errors)];
  if (!when.ok || !cap.ok) return { ok: false, errors };
  const rule: ActionRule = {
    rule_id: f.rule_id.trim(),
    tool: f.tool.trim(),
    ...(when.value !== undefined ? { when: when.value } : {}),
    ...(cap.value !== undefined ? { cumulative: cap.value } : {}),
    ...(f.dataClass.enabled ? { data_class: { secrets: f.dataClass.secrets, pii: [...f.dataClass.pii] } } : {}),
    effect: f.effect,
    reason: f.reason.trim(),
  };
  return { ok: true, value: rule };
}

export function policyToForm(doc: Omit<ActionPolicyDocument, "policy_id" | "version">): PolicyForm {
  return {
    default_effect: doc.default_effect,
    tool_allowlist_enforced: doc.tool_allowlist_enforced,
    tool_allowlist: doc.tool_allowlist ? [...doc.tool_allowlist] : null,
    sensitive_tools: [...doc.sensitive_tools],
    external_tools: [...doc.external_tools],
    hold_timeout_s: String(doc.hold_timeout_s),
    rules: doc.rules.map(ruleToForm),
  };
}

/** The form → a document body (without policy_id/version, which the server assigns), fully validated. */
export function formToDocument(f: PolicyForm): Result<Omit<ActionPolicyDocument, "policy_id" | "version">> {
  const rules = f.rules.map(formToRule);
  const errors = rules.flatMap((r) => (r.ok ? [] : r.errors));
  const hold = parseScalar(f.hold_timeout_s, "number");
  if (typeof hold !== "number" || !Number.isInteger(hold)) errors.push({ path: "/hold_timeout_s", message: "Enter whole seconds" });
  if (errors.length) return { ok: false, errors };
  const doc = {
    schema: POLICY_SCHEMA_ID,
    default_effect: f.default_effect,
    tool_allowlist_enforced: f.tool_allowlist_enforced,
    tool_allowlist: f.tool_allowlist ? f.tool_allowlist.map((t) => t.trim()).filter(Boolean) : null,
    sensitive_tools: f.sensitive_tools.map((t) => t.trim()).filter(Boolean),
    external_tools: f.external_tools.map((t) => t.trim()).filter(Boolean),
    hold_timeout_s: hold as number,
    rules: rules.map((r) => (r.ok ? r.value : null)) as ActionRule[],
  };
  const invalid = validatePolicyDocument(doc);
  return invalid.length ? { ok: false, errors: invalid } : { ok: true, value: doc };
}

/** One-line description of a condition for read-only views ("/amount ≤ 100000"). */
export function describeCondition(c: Condition): string {
  const neg = c.negate ? "not " : "";
  if (c.op === "exists") return `${neg}${c.path} is present`;
  if (LIST.has(c.op)) return `${neg}${c.path} ${c.op === "in" ? "in" : "not in"} [${c.list.join(", ")}]`;
  const sym: Record<string, string> = { eq: "=", ne: "≠", lt: "<", le: "≤", gt: ">", ge: "≥", matches: "matches" };
  const v = c.valueType === "string" && c.op !== "matches" ? `"${c.value}"` : c.op === "matches" ? `/${c.value}/` : c.value || c.valueType;
  return `${neg}${c.path} ${sym[c.op] ?? c.op} ${v}`;
}

export function isNumericOp(op: LeafOp): boolean {
  return NUMERIC.has(op);
}

export function isListOp(op: LeafOp): boolean {
  return LIST.has(op);
}
