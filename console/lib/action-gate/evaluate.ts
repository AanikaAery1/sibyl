/**
 * A TypeScript port of `sibyl_schemas.action_gate.evaluate` (pure; unit-tested), used for:
 *  - the demo engine's decisions and `POST /action-policies/{id}/simulate` in demo mode;
 *  - the editor's preview of a draft that has not been saved yet (the server re-checks on save).
 *
 * Same order and semantics as the Python evaluator: tool allowlist (when enforced) → rules in
 * order, first match wins → `default_effect`, tightened to `escalate` for sensitive tools.
 * Predicates are three-valued: a wrong-typed value is indeterminate and can match a block or
 * escalate rule but never an allow rule. Total: an internal error is a fail-closed block.
 *
 * Known approximations (the control plane stays authoritative): numbers are JS doubles rather
 * than Decimals, and the data-class check uses a subset of the PII and secret detectors.
 */
import type { ActionEffect, ActionPolicyDocument, ActionRule, CumulativeCap, DataClassRule, Predicate, Scalar } from "@/lib/api/action-gate";
import { findPii, looksSecret } from "./detect";
import { jcs, sha256Hex } from "./sha256";

export type Verdict = boolean | null;
/** Current window totals keyed like the control plane: `<policy version id>/<rule_id>[/<per hash>]`. */
export type Counters = Readonly<Record<string, number>>;

/** `sibyl_schemas.action_gate.CounterNeed`: the authoritative check-and-increment a cumulative rule needs. */
export interface CounterNeed {
  counter_key: string;
  rule_id: string;
  increment: string;
  max: string;
  window_s: number;
  within_effect: ActionEffect;
  exceed_effect: ActionEffect;
}

/** `sibyl_schemas.action_gate.Decision` (the evaluator's answer; not an API object). */
export interface Decision {
  effect: ActionEffect;
  rule_id: string | null;
  reason: string;
  matched_paths: string[];
  needs_counter: CounterNeed | null;
  policy_id: string | null;
  policy_version: number | null;
  sensitive: boolean;
  hold_timeout_s: number | null;
}

export const ALLOWLIST_RULE_ID = "sibyl:tool_allowlist";
export const ERROR_RULE_ID = "sibyl:evaluator_error";
const MAX_MATCH_SUBJECT = 1024;
const MAX_TOOL_NAME = 256;
const MAX_SCAN_CHARS = 256 * 1024;
const MAX_SCAN_NODES = 10_000;
const MAX_SCAN_DEPTH = 64;
const DECIMAL_RE = /^[+-]?[0-9]{1,30}(\.[0-9]{1,18})?$/;
const INDEX_RE = /^(0|[1-9][0-9]{0,9})$/;
const RANK: Readonly<Record<ActionEffect, number>> = { allow: 0, escalate: 1, block: 2 };

// ── values ─────────────────────────────────────────────────────────────────

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** A finite number: JSON numbers (never booleans) and plain decimal strings. */
export function toNumber(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string" && DECIMAL_RE.test(value)) return Number(value);
  return null;
}

function jsonEq(left: unknown, right: unknown): boolean {
  if (typeof left === "boolean" || typeof right === "boolean") return typeof left === "boolean" && typeof right === "boolean" && left === right;
  if (left === null || right === null) return left === null && right === null;
  if (typeof left === "string" || typeof right === "string") return typeof left === "string" && typeof right === "string" && left === right;
  const a = toNumber(left);
  const b = toNumber(right);
  return a !== null && b !== null && a === b;
}

const unescapeToken = (t: string): string => t.replaceAll("~1", "/").replaceAll("~0", "~");
const escapeToken = (t: string): string => t.replaceAll("~", "~0").replaceAll("/", "~1");

/** RFC 6901 lookup: [found, value]. Array indices must be canonical integers. */
export function resolvePointer(args: unknown, pointer: string): [boolean, unknown] {
  if (pointer === "") return [true, args];
  let node: unknown = args;
  for (const raw of pointer.slice(1).split("/")) {
    const token = unescapeToken(raw);
    if (isObject(node)) {
      if (!Object.hasOwn(node, token)) return [false, undefined];
      node = node[token];
    } else if (Array.isArray(node)) {
      if (!INDEX_RE.test(token) || Number(token) >= node.length) return [false, undefined];
      node = node[Number(token)];
    } else {
      return [false, undefined];
    }
  }
  return [true, node];
}

// ── predicates ─────────────────────────────────────────────────────────────

export type Op = "eq" | "ne" | "lt" | "le" | "gt" | "ge" | "in" | "not_in" | "matches" | "exists" | "all" | "any" | "not";

export function operatorOf(node: Predicate): Op {
  const keys = Object.keys(node);
  if (keys.length !== 1) throw new TypeError("a predicate node has exactly one operator");
  return keys[0] as Op;
}

function compare(op: "lt" | "le" | "gt" | "ge", pair: [string, number], args: unknown): Verdict {
  const [found, value] = resolvePointer(args, pair[0]);
  if (!found) return false;
  const n = toNumber(value);
  const bound = toNumber(pair[1]);
  if (n === null || bound === null) return null;
  return op === "lt" ? n < bound : op === "le" ? n <= bound : op === "gt" ? n > bound : n >= bound;
}

function matches(pair: [string, string], args: unknown): Verdict {
  const [found, value] = resolvePointer(args, pair[0]);
  if (!found) return false;
  if (typeof value !== "string" || value.length > MAX_MATCH_SUBJECT) return null;
  return new RegExp(`^(?:${pair[1]})$`).test(value);
}

function kleeneAll(results: Iterable<Verdict>): Verdict {
  let unknown = false;
  for (const r of results) {
    if (r === false) return false;
    unknown = unknown || r === null;
  }
  return unknown ? null : true;
}

function kleeneAny(results: Iterable<Verdict>): Verdict {
  let unknown = false;
  for (const r of results) {
    if (r === true) return true;
    unknown = unknown || r === null;
  }
  return unknown ? null : false;
}

function* lazy(children: readonly Predicate[], args: unknown): Generator<Verdict> {
  for (const c of children) yield holds(c, args);
}

/** Evaluate one predicate node against the arguments (three-valued). */
export function holds(node: Predicate, args: unknown): Verdict {
  if ("exists" in node) return resolvePointer(args, node.exists)[0];
  if ("eq" in node || "ne" in node) {
    const [path, want] = "eq" in node ? node.eq : node.ne;
    const [found, value] = resolvePointer(args, path);
    if (!found) return false;
    return jsonEq(value, want) === "eq" in node;
  }
  if ("in" in node || "not_in" in node) {
    const [path, options] = "in" in node ? node.in : node.not_in;
    const [found, value] = resolvePointer(args, path);
    if (!found) return false;
    const member = options.some((o: Scalar) => jsonEq(value, o));
    return member === "in" in node;
  }
  if ("lt" in node) return compare("lt", node.lt, args);
  if ("le" in node) return compare("le", node.le, args);
  if ("gt" in node) return compare("gt", node.gt, args);
  if ("ge" in node) return compare("ge", node.ge, args);
  if ("matches" in node) return matches(node.matches, args);
  if ("all" in node) return kleeneAll(lazy(node.all, args));
  if ("any" in node) return kleeneAny(lazy(node.any, args));
  if ("not" in node) {
    const inner = holds(node.not, args);
    return inner === null ? null : !inner;
  }
  throw new TypeError("unknown predicate operator");
}

function pointerOf(node: Predicate): string | null {
  if ("exists" in node) return node.exists;
  for (const k of ["eq", "ne", "lt", "le", "gt", "ge", "in", "not_in", "matches"] as const) {
    if (k in node) return (node as Record<string, [string, unknown]>)[k]?.[0] ?? null;
  }
  return null;
}

function childrenOf(node: Predicate): Predicate[] {
  if ("all" in node) return node.all;
  if ("any" in node) return node.any;
  if ("not" in node) return [node.not];
  return [];
}

/** Every pointer the predicate reads, in first-seen (depth-first) order. */
export function predicatePaths(node: Predicate): string[] {
  const seen: string[] = [];
  const stack: Predicate[] = [node];
  while (stack.length) {
    const cur = stack.pop() as Predicate;
    const p = pointerOf(cur);
    if (p !== null && !seen.includes(p)) seen.push(p);
    stack.push(...[...childrenOf(cur)].reverse());
  }
  return seen;
}

// ── tools ──────────────────────────────────────────────────────────────────

const globCache = new Map<string, RegExp>();

function globRe(pattern: string): RegExp {
  const hit = globCache.get(pattern);
  if (hit) return hit;
  const body = [...pattern].map((ch) => (ch === "*" ? "[\\s\\S]*" : ch === "?" ? "[\\s\\S]" : ch.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&"))).join("");
  const re = new RegExp(`^${body}$`, "u");
  globCache.set(pattern, re);
  return re;
}

/** `*` is any run of characters (dots included), `?` one character; all else literal. */
export function toolMatches(pattern: string, tool: string): boolean {
  return globRe(pattern).test(tool);
}

/** NFKC and surrounding whitespace removed, so a look-alike spelling cannot dodge a rule. */
export function normaliseTool(tool: unknown): string {
  if (typeof tool !== "string") return "";
  const name = tool.normalize("NFKC").trim();
  return name.length <= MAX_TOOL_NAME ? name : name.slice(0, MAX_TOOL_NAME);
}

const anyTool = (patterns: readonly string[] | null | undefined, tool: string): boolean => Boolean(patterns?.length) && (patterns ?? []).some((p) => toolMatches(p, tool));

// ── data class ─────────────────────────────────────────────────────────────

const pointerFrom = (parts: readonly string[]): string => parts.map((p) => `/${escapeToken(p)}`).join("");

/** [path, text] for every string leaf, string key and integer leaf; false when a scan budget was exceeded. */
function leaves(args: unknown): [Array<[string, string]>, boolean] {
  const out: Array<[string, string]> = [];
  let chars = 0;
  let nodes = 0;
  const stack: Array<[unknown, string[]]> = [[args, []]];
  while (stack.length) {
    const [node, parts] = stack.pop() as [unknown, string[]];
    nodes += 1;
    if (nodes > MAX_SCAN_NODES || parts.length > MAX_SCAN_DEPTH) return [out, false];
    if (typeof node === "string") {
      chars += node.length;
      out.push([pointerFrom(parts), node]);
    } else if (typeof node === "number" && Number.isInteger(node)) {
      out.push([pointerFrom(parts), String(node)]);
    } else if (isObject(node)) {
      for (const [key, value] of Object.entries(node)) {
        chars += key.length;
        out.push([pointerFrom([...parts, key]), key]);
        stack.push([value, [...parts, key]]);
      }
    } else if (Array.isArray(node)) {
      node.forEach((v, i) => stack.push([v, [...parts, String(i)]]));
    }
    if (chars > MAX_SCAN_CHARS) return [out, false];
  }
  return [out, true];
}

function dataClass(rule: DataClassRule, args: unknown): [Verdict, string[]] {
  const [found, complete] = leaves(args);
  const hits: string[] = [];
  for (const [path, text] of found) {
    if (hits.includes(path)) continue;
    if ((rule.pii.length && findPii(text, rule.pii).length) || (rule.secrets && looksSecret(text))) hits.push(path);
  }
  if (hits.length) return [true, hits];
  return [complete ? false : null, []];
}

// ── cumulative ─────────────────────────────────────────────────────────────

const exceedEffect = (cap: CumulativeCap): ActionEffect => (cap.on_exceed === "block" ? "block" : "escalate");

export function mostRestrictive(a: ActionEffect, b: ActionEffect): ActionEffect {
  return RANK[a] >= RANK[b] ? a : b;
}

interface Base {
  policy_id: string | null;
  policy_version: number | null;
  sensitive: boolean;
  hold_timeout_s: number | null;
  matched_paths: string[];
}

const decision = (effect: ActionEffect, rule_id: string | null, reason: string, base: Base, needs_counter: CounterNeed | null = null): Decision => ({ effect, rule_id, reason, needs_counter, ...base });

/**
 * `<policy_id>/<rule_id>[/<sha256(JCS(per value))[:32]>]` (`counter_key` in sibyl_schemas): the
 * document's `policy_id` is the version id. A `per` value that is absent gets its own bucket (`~`).
 */
export function counterKey(policy: Pick<ActionPolicyDocument, "policy_id">, rule: ActionRule, args: unknown): string {
  const base = `${policy.policy_id}/${rule.rule_id}`;
  const per = rule.cumulative?.per;
  if (per === undefined) return base;
  const [found, value] = resolvePointer(args, per);
  if (!found) return `${base}/~`;
  let material: string;
  try {
    material = jcs(value);
  } catch {
    material = String(value);
  }
  return `${base}/${sha256Hex(material).slice(0, 32)}`;
}

/** The counter a cumulative rule would move for these arguments, or null when the amount is unreadable. */
export function capNeed(policy: ActionPolicyDocument, rule: ActionRule, args: unknown): CounterNeed | null {
  const cap = rule.cumulative;
  if (!cap) return null;
  let increment: number | null = 1;
  if (!cap.count) {
    const [found, value] = resolvePointer(args, cap.sum ?? "");
    increment = found ? toNumber(value) : null;
  }
  if (increment === null || increment < 0) return null;
  return {
    counter_key: counterKey(policy, rule, args),
    rule_id: rule.rule_id,
    increment: String(increment),
    max: String(cap.max),
    window_s: cap.window_s,
    within_effect: rule.effect,
    exceed_effect: exceedEffect(cap),
  };
}

function cumulative(policy: ActionPolicyDocument, rule: ActionRule, cap: CumulativeCap, args: unknown, counters: Counters | null, base: Base): Decision {
  const exceed = exceedEffect(cap);
  const need = capNeed(policy, rule, args);
  if (need === null) return decision(exceed, rule.rule_id, `${rule.reason} (cumulative amount unreadable)`, base);
  const current = counters && Object.hasOwn(counters, need.counter_key) ? toNumber(counters[need.counter_key]) : null;
  if (current === null) return decision(exceed, rule.rule_id, `${rule.reason} (cumulative counter pending)`, base, need);
  if (current + Number(need.increment) > cap.max) return decision(exceed, rule.rule_id, `${rule.reason} (cap ${cap.max} per ${cap.window_s}s exceeded)`, base);
  return decision(rule.effect, rule.rule_id, rule.reason, base, need);
}

// ── evaluate ───────────────────────────────────────────────────────────────

function evalRule(policy: ActionPolicyDocument, rule: ActionRule, tool: string, args: unknown, counters: Counters | null, base: Base): Decision | null {
  let verdict: Verdict = rule.when === undefined ? true : holds(rule.when, args);
  let paths = rule.when === undefined ? [] : predicatePaths(rule.when);
  if (verdict !== false && rule.data_class !== undefined) {
    if (!anyTool(policy.external_tools, tool)) return null;
    const [hit, hitPaths] = dataClass(rule.data_class, args);
    verdict = kleeneAll([verdict, hit]);
    paths = [...paths, ...hitPaths.filter((p) => !paths.includes(p))];
  }
  if (verdict === false) return null;
  const withPaths = { ...base, matched_paths: paths };
  const cap = rule.cumulative;
  if (verdict === null) {
    const effect = cap === undefined ? rule.effect : mostRestrictive(rule.effect, exceedEffect(cap));
    if (effect === "allow") return null;
    return decision(effect, rule.rule_id, `${rule.reason} (arguments indeterminate)`, withPaths);
  }
  if (cap !== undefined) return cumulative(policy, rule, cap, args, counters, withPaths);
  return decision(rule.effect, rule.rule_id, rule.reason, withPaths);
}

function evaluateUnsafe(policy: ActionPolicyDocument, toolIn: unknown, args: unknown, counters: Counters | null): Decision {
  const tool = normaliseTool(toolIn);
  const sensitive = anyTool(policy.sensitive_tools, tool);
  const base: Base = { policy_id: policy.policy_id, policy_version: policy.version, sensitive, hold_timeout_s: policy.hold_timeout_s, matched_paths: [] };
  if (policy.tool_allowlist_enforced && !anyTool(policy.tool_allowlist, tool)) {
    return decision("block", ALLOWLIST_RULE_ID, `tool '${tool.slice(0, 80)}' is not in the agent's tool allowlist`, base);
  }
  for (const rule of policy.rules) {
    if (!toolMatches(rule.tool, tool)) continue;
    const decided = evalRule(policy, rule, tool, args, counters, base);
    if (decided) return decided;
  }
  const effect = sensitive ? mostRestrictive(policy.default_effect, "escalate") : policy.default_effect;
  return decision(effect, null, `no rule matched; default ${effect}${sensitive ? " (sensitive tool)" : ""}`, base);
}

/** Decide one proposed tool call. Pure, deterministic and total (any internal failure blocks). */
export function evaluate(policy: ActionPolicyDocument, tool: string, args: unknown, counters: Counters | null = null): Decision {
  try {
    return evaluateUnsafe(policy, tool, args, counters);
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    return { effect: "block", rule_id: ERROR_RULE_ID, reason: `action gate evaluation failed (${name}); failing closed`, matched_paths: [], needs_counter: null, policy_id: policy?.policy_id ?? null, policy_version: policy?.version ?? null, sensitive: false, hold_timeout_s: null };
  }
}

/** Several applicable policies (agent, group, tenant): the most restrictive decision wins; ties keep the earlier. */
export function evaluateAll(policies: readonly ActionPolicyDocument[], tool: string, args: unknown, counters: Counters | null = null): Decision {
  let best: Decision | null = null;
  for (const p of policies) {
    const d = evaluate(p, tool, args, counters);
    if (!best || RANK[d.effect] > RANK[best.effect]) best = d;
  }
  return best ?? { effect: "allow", rule_id: null, reason: "no action policy applies", matched_paths: [], needs_counter: null, policy_id: null, policy_version: null, sensitive: false, hold_timeout_s: null };
}
