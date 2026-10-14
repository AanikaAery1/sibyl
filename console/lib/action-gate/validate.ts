/**
 * The `sibyl-action-policy/1` constraints the pydantic model enforces (models/action_policy.py),
 * checked in the console so the editor can explain a problem before the server refuses it.
 * Pure; returns JSON-pointer-addressed errors instead of throwing.
 */
import type { ActionPolicyDocument, ActionRule, Predicate } from "@/lib/api/action-gate";
import { PII_DETECTOR_IDS } from "@/lib/api/action-gate";

export const POINTER_RE = /^(\/([^~/]|~[01])*)*$/;
export const TOOL_GLOB_RE = /^[A-Za-z0-9_.:/@*?[\]-]{1,128}$/;
export const RULE_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
export const MAX_PATTERN_LENGTH = 256;
export const MAX_PREDICATE_DEPTH = 16;
export const MAX_PREDICATE_NODES = 256;
export const MAX_RULES = 256;
export const MAX_WINDOW_S = 31 * 86400;
export const MAX_SET_ITEMS = 1000;

export interface FieldError {
  path: string;
  message: string;
}

/** A conservative stand-in for the server's safe-regex admission (no backrefs, lookaround or nested repeats). */
export function regexProblem(pattern: string): string | null {
  if (pattern.length === 0) return "Enter a pattern";
  if (pattern.length > MAX_PATTERN_LENGTH) return `At most ${MAX_PATTERN_LENGTH} characters`;
  try {
    new RegExp(pattern);
  } catch {
    return "Not a valid regular expression";
  }
  if (/\\[1-9]|\(\?<?[=!]|\(\?\(/.test(pattern)) return "Backreferences and lookaround are not allowed";
  if (/\([^()]*[+*}][^()]*\)[+*{]/.test(pattern)) return "Nested repeats like (a+)+ are not allowed";
  return null;
}

function shape(node: Predicate): { depth: number; count: number } {
  let depth = 0;
  let count = 0;
  const stack: Array<[Predicate, number]> = [[node, 1]];
  while (stack.length) {
    const [cur, level] = stack.pop() as [Predicate, number];
    count += 1;
    depth = Math.max(depth, level);
    const kids = "all" in cur ? cur.all : "any" in cur ? cur.any : "not" in cur ? [cur.not] : [];
    for (const k of kids) stack.push([k, level + 1]);
  }
  return { depth, count };
}

function checkPredicate(node: Predicate, at: string, out: FieldError[]): void {
  const keys = Object.keys(node);
  if (keys.length !== 1) {
    out.push({ path: at, message: "Each condition has exactly one operator" });
    return;
  }
  const pointer = (p: unknown, where: string): void => {
    if (typeof p !== "string" || !POINTER_RE.test(p) || p.length > 256) out.push({ path: where, message: "Use a JSON pointer such as /amount" });
  };
  if ("exists" in node) return pointer(node.exists, `${at}/exists`);
  if ("all" in node || "any" in node) {
    const kids = "all" in node ? node.all : node.any;
    if (kids.length === 0 || kids.length > 64) out.push({ path: at, message: "A group holds 1 to 64 conditions" });
    kids.forEach((k, i) => checkPredicate(k, `${at}/${"all" in node ? "all" : "any"}/${i}`, out));
    return;
  }
  if ("not" in node) return checkPredicate(node.not, `${at}/not`, out);
  const op = keys[0] as "eq" | "ne" | "lt" | "le" | "gt" | "ge" | "in" | "not_in" | "matches";
  const pair = (node as Record<string, unknown>)[op];
  if (!Array.isArray(pair) || pair.length !== 2) {
    out.push({ path: `${at}/${op}`, message: "Expected [pointer, value]" });
    return;
  }
  pointer(pair[0], `${at}/${op}/0`);
  const value: unknown = pair[1];
  if (["lt", "le", "gt", "ge"].includes(op) && (typeof value !== "number" || !Number.isFinite(value))) out.push({ path: `${at}/${op}/1`, message: "Compare against a number" });
  if ((op === "in" || op === "not_in") && (!Array.isArray(value) || value.length === 0 || value.length > MAX_SET_ITEMS)) out.push({ path: `${at}/${op}/1`, message: "List 1 to 1000 values" });
  if (op === "matches") {
    const problem = typeof value === "string" ? regexProblem(value) : "Enter a pattern";
    if (problem) out.push({ path: `${at}/${op}/1`, message: problem });
  }
}

function checkRule(rule: ActionRule, i: number, out: FieldError[]): void {
  const at = `/rules/${i}`;
  if (!RULE_ID_RE.test(rule.rule_id)) out.push({ path: `${at}/rule_id`, message: "Lowercase letters, digits, . _ - (start with a letter or digit)" });
  if (!TOOL_GLOB_RE.test(rule.tool)) out.push({ path: `${at}/tool`, message: "A tool name or glob such as payments.* (letters, digits, . _ : / @ * ? -)" });
  if (!["allow", "escalate", "block"].includes(rule.effect)) out.push({ path: `${at}/effect`, message: "Choose allow, escalate or block" });
  if (!rule.reason || rule.reason.trim().length === 0 || rule.reason.length > 500) out.push({ path: `${at}/reason`, message: "Give a reason (shown to people and recorded in the audit), up to 500 characters" });
  if (rule.when !== undefined) {
    checkPredicate(rule.when, `${at}/when`, out);
    const { depth, count } = shape(rule.when);
    if (depth > MAX_PREDICATE_DEPTH) out.push({ path: `${at}/when`, message: `Nested deeper than ${MAX_PREDICATE_DEPTH}` });
    if (count > MAX_PREDICATE_NODES) out.push({ path: `${at}/when`, message: `More than ${MAX_PREDICATE_NODES} conditions` });
  }
  const cap = rule.cumulative;
  if (cap) {
    if ((cap.sum === undefined) === (cap.count === undefined)) out.push({ path: `${at}/cumulative`, message: "Cap either a sum or a count" });
    if (cap.sum !== undefined && !POINTER_RE.test(cap.sum)) out.push({ path: `${at}/cumulative/sum`, message: "Use a JSON pointer such as /amount" });
    if (cap.per !== undefined && !POINTER_RE.test(cap.per)) out.push({ path: `${at}/cumulative/per`, message: "Use a JSON pointer such as /customer_id" });
    if (!Number.isFinite(cap.max) || cap.max < 0) out.push({ path: `${at}/cumulative/max`, message: "A cap of 0 or more" });
    if (!Number.isInteger(cap.window_s) || cap.window_s < 1 || cap.window_s > MAX_WINDOW_S) out.push({ path: `${at}/cumulative/window_s`, message: "A window of 1 second to 31 days" });
  }
  const dc = rule.data_class;
  if (dc) {
    if (dc.pii.some((p) => !(PII_DETECTOR_IDS as readonly string[]).includes(p))) out.push({ path: `${at}/data_class/pii`, message: "Unknown PII detector" });
    if (new Set(dc.pii).size !== dc.pii.length) out.push({ path: `${at}/data_class/pii`, message: "Each detector once" });
    if (!dc.secrets && dc.pii.length === 0) out.push({ path: `${at}/data_class`, message: "Pick secrets or at least one PII detector" });
  }
}

function checkTools(list: readonly string[] | null, at: string, out: FieldError[]): void {
  (list ?? []).forEach((t, i) => {
    if (!TOOL_GLOB_RE.test(t)) out.push({ path: `${at}/${i}`, message: `'${t}' is not a valid tool name or glob` });
  });
}

/** Every problem with a document, addressed by JSON pointer; empty when the server would accept it. */
export function validatePolicyDocument(doc: Omit<ActionPolicyDocument, "policy_id" | "version">): FieldError[] {
  const out: FieldError[] = [];
  if (!["allow", "escalate"].includes(doc.default_effect)) out.push({ path: "/default_effect", message: "Default is allow or escalate" });
  if (!Number.isInteger(doc.hold_timeout_s) || doc.hold_timeout_s < 10 || doc.hold_timeout_s > 86400) out.push({ path: "/hold_timeout_s", message: "Hold for 10 seconds to 24 hours" });
  if (doc.tool_allowlist_enforced && (doc.tool_allowlist === null || doc.tool_allowlist.length === 0)) out.push({ path: "/tool_allowlist", message: "An enforced allowlist needs at least one tool" });
  checkTools(doc.tool_allowlist, "/tool_allowlist", out);
  checkTools(doc.sensitive_tools, "/sensitive_tools", out);
  checkTools(doc.external_tools, "/external_tools", out);
  if (doc.rules.length > MAX_RULES) out.push({ path: "/rules", message: `At most ${MAX_RULES} rules` });
  doc.rules.forEach((r, i) => checkRule(r, i, out));
  const ids = doc.rules.map((r) => r.rule_id);
  ids.forEach((id, i) => {
    if (ids.indexOf(id) !== i) out.push({ path: `/rules/${i}/rule_id`, message: `Rule id '${id}' is used twice` });
  });
  return out;
}
