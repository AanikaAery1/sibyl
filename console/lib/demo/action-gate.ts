/**
 * Action Gate in demo mode, answering in the live API's shapes and with its rules
 * (services/control/.../api/action_gate): scopes, reasons (≥ 10 characters), step-up for
 * sensitive tools (approve and deny), the held-action state machine (pending → approved |
 * denied | expired), `on_behalf_of` (that user never approves: 409 self_approval), four-eyes
 * holds that need two distinct approvers (409 duplicate_approver), policy versions per scope
 * (draft → approved, superseding the scope's approved version; the author of a version with a
 * tier-1 agent in scope cannot approve it), and dry-run simulate for stored versions and unsaved
 * drafts. Decisions come from the same evaluator the editor previews with (lib/action-gate).
 */
import "server-only";
import { ProblemError, notFound } from "@/lib/api/problem";
import type { ActionPolicyCreate, ActionPolicyDocument, ActionPolicyDraftSimulate, ActionPolicyRecord, ActionSimulate, ActionSummary, HeldAction, HeldActionDecisionBody, HeldHistoryEntry, OnBehalfOf, PolicyDecisionBody, PolicyScope, PolicyScopeKind, SimulateResult } from "@/lib/api/action-gate";
import { ACTION_AUDIT } from "@/lib/api/action-gate";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { capNeed, evaluateAll, type Counters, type Decision } from "@/lib/action-gate/evaluate";
import { validatePolicyDocument } from "@/lib/action-gate/validate";
import { POLICY_STATE_ORDER, draftDocument, heldListRow, simulateAnswer } from "@/lib/action-gate/wire";
import { iso } from "./core";
import type { DemoRequest, DemoResult } from "./handlers";
import { page } from "./page";
import { requireScope, requireStepUp } from "./actions";
import { appendAudit, canonical, emit, nextId, sha256, type AgentRt, type World } from "./world";
import { groupId, policyRecord } from "./action-gate-seed";

export { groupId, seedActionPolicies } from "./action-gate-seed";

const DAY_MS = 24 * 60 * 60 * 1000;
const SCOPE_ORDER: Readonly<Record<PolicyScopeKind, number>> = { tenant: 0, agent_group: 1, agent: 2 };
const SCOPE_KINDS = new Set<PolicyScopeKind>(["tenant", "agent_group", "agent"]);
const HELD_STATES: ReadonlySet<string> = new Set(["pending", "approved", "denied", "expired", "cancelled"]);

function reasonOf(raw: unknown, pointer = "/reason", min = 10): string {
  const r = typeof raw === "string" ? raw.trim() : "";
  if (r.length < min) {
    throw new ProblemError(422, "validation_failed", "Reason too short", `Give a reason of at least ${min} characters; it is written to the audit log.`, { errors: [{ pointer, code: "min_length", message: `At least ${min} characters` }] });
  }
  return r;
}

// ── which policies apply ───────────────────────────────────────────────────

function appliesTo(w: World, rec: ActionPolicyRecord, rt: AgentRt): boolean {
  if (rec.scope_kind === "tenant") return true;
  if (rec.scope_kind === "agent") return rec.scope_id === rt.id;
  return rec.scope_id === groupId(w, rt.spec.process);
}

/** The agent's approved policies, most specific scope first. */
export function approvedPoliciesFor(w: World, rt: AgentRt): ActionPolicyRecord[] {
  return [...w.actionPolicies.values()].filter((r) => r.state === "approved" && appliesTo(w, r, rt)).sort((a, b) => SCOPE_ORDER[b.scope_kind] - SCOPE_ORDER[a.scope_kind]);
}

/** Current window totals for every cumulative rule of these documents, keyed like the control plane. */
function countersFor(w: World, docs: readonly ActionPolicyDocument[], args: unknown, t: number): Record<string, number> {
  const out: Record<string, number> = {};
  for (const doc of docs) {
    for (const rule of doc.rules) {
      const need = capNeed(doc, rule, args);
      if (!need) continue;
      const windowMs = need.window_s * 1000;
      const hits = w.actionCounters.get(need.counter_key) ?? [];
      out[need.counter_key] = hits.filter((h) => h.at > t - windowMs && h.at <= t).reduce((s, h) => s + h.inc, 0);
    }
  }
  return out;
}

function addHit(w: World, key: string, inc: number, t: number): void {
  w.actionCounters.set(key, [...(w.actionCounters.get(key) ?? []), { at: t, inc }]);
}

export interface ProposedCall {
  tool: string;
  args: Record<string, unknown>;
  source: "sdk" | "gateway";
  call_id: string;
}

/** Every approved policy for the agent, most restrictive wins; the counter moves only within the cap. */
export function decideCall(w: World, rt: AgentRt, call: ProposedCall, t: number): { d: Decision; rec: ActionPolicyRecord | null } {
  const recs = approvedPoliciesFor(w, rt);
  const docs = recs.map((r) => r.document);
  const d = evaluateAll(docs, call.tool, call.args, countersFor(w, docs, call.args, t));
  const rec = recs.find((r) => r.id === d.policy_id) ?? null;
  const need = d.needs_counter;
  if (need && d.effect === need.within_effect) addHit(w, need.counter_key, Number(need.increment), t);
  return { d, rec };
}

const argsDigest = (args: unknown): string => sha256(canonical(args));

function entry(kind: HeldHistoryEntry["kind"], at: number, over: Partial<HeldHistoryEntry> = {}): HeldHistoryEntry {
  return { at: iso(at), kind, user_id: null, key_id: null, reason: null, step_up: false, code: null, approvals: null, ...over };
}

/**
 * An enforcement point's call: decide, then record it. `block` is audited, `escalate` creates a
 * held action, an allowed call is audited for sensitive tools only (spec: sampled otherwise).
 */
export function gate(w: World, rt: AgentRt, call: ProposedCall, t: number, opts: { onBehalfOf?: OnBehalfOf | null } = {}): { decision: Decision; held: HeldAction | null } {
  const { d: decision, rec } = decideCall(w, rt, call, t);
  const detail = { agent_id: rt.id, call_id: call.call_id, tool: call.tool, effect: decision.effect, rule_id: decision.rule_id, policy_id: decision.policy_id, policy_version: decision.policy_version, matched_paths: decision.matched_paths, args_sha256: argsDigest(call.args), source: call.source };
  if (decision.effect === "block") {
    appendAudit(w, { action: ACTION_AUDIT.blocked, actor_type: "policy", resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, reason: decision.reason, detail, severity: "warning" }, t);
    emit(w, "action.blocked", { agent_id: rt.id, tool: call.tool, rule_id: decision.rule_id }, t);
    return { decision, held: null };
  }
  if (decision.effect === "allow") {
    if (decision.sensitive) appendAudit(w, { action: ACTION_AUDIT.allowed, actor_type: "policy", resource_type: "agent", resource_id: rt.id, resource_ref: rt.spec.slug, reason: decision.reason, detail }, t);
    return { decision, held: null };
  }
  const timeout = decision.hold_timeout_s ?? 900;
  const required = rec?.four_eyes ? 2 : 1;
  const rule = rec?.document.rules.find((r) => r.rule_id === decision.rule_id);
  const need = rec && rule ? capNeed(rec.document, rule, call.args) : null;
  const id = nextId(w, "held-action");
  const held: HeldAction = {
    held_action_id: id,
    id,
    agent_id: rt.id,
    policy_id: decision.policy_id,
    policy_version: decision.policy_version,
    rule_id: decision.rule_id,
    call_id: call.call_id,
    tool: call.tool,
    source: call.source,
    args_sha256: detail.args_sha256,
    args_payload_ref: nextId(w, "payload"),
    args: call.args,
    server_effect: "escalate",
    reason: decision.reason,
    sensitive: decision.sensitive,
    approvals_required: required,
    approvals: [],
    state: "pending",
    decision: null,
    decided_by: null,
    decided_at: null,
    decision_reason: null,
    resolved_by_timeout: false,
    hold_timeout_s: timeout,
    expires_at: iso(t + timeout * 1000),
    created_at: iso(t),
    on_behalf_of: opts.onBehalfOf ?? null,
    matched_paths: decision.matched_paths,
    four_eyes: required >= 2,
    counter: need ? { key: need.counter_key, amount: need.increment, max: need.max, window_s: need.window_s, applied_at: null } : null,
    history: [entry("requested", t, { reason: decision.reason })],
  };
  w.heldActions.set(id, held);
  appendAudit(w, { action: ACTION_AUDIT.escalated, actor_type: "policy", resource_type: "held_action", resource_id: id, resource_ref: rt.spec.slug, reason: decision.reason, detail: { ...detail, held_action_id: id, expires_at: held.expires_at, approvals_required: required }, severity: "warning" }, t);
  emit(w, "action.held", { held_action_id: id, agent_id: rt.id, tool: call.tool, expires_at: held.expires_at }, t);
  return { decision, held };
}

// ── held actions ───────────────────────────────────────────────────────────

/** A refused attempt: recorded on the trail and audited, then the 409 stands. */
function refuse(w: World, p: BffPrincipal, held: HeldAction, code: "self_approval" | "duplicate_approver", reason: string, t: number, detail: string): never {
  w.heldActions.set(held.id, { ...held, history: [...held.history, entry("refused", t, { user_id: p.userId, reason, code })] });
  appendAudit(w, { action: "access.denied", actor_type: "human", actor_id: p.userId, resource_type: "held_action", resource_id: held.id, resource_ref: w.agents.get(held.agent_id)?.spec.slug ?? null, reason: code, detail: { agent_id: held.agent_id, tool: held.tool, code }, severity: "warning" }, t);
  throw new ProblemError(409, code, code === "self_approval" ? "Self-approval refused" : "Second approval needed", detail);
}

export function decideHeld(w: World, p: BffPrincipal, id: string, body: HeldActionDecisionBody, t: number): HeldAction {
  requireScope(p, "actions:decide");
  const held = w.heldActions.get(id);
  if (!held) throw notFound("Held action");
  if (body?.action !== "approve" && body?.action !== "deny") throw new ProblemError(422, "validation_failed", "Unknown action", "Choose approve or deny.", { errors: [{ pointer: "/action", code: "enum", message: "approve | deny" }] });
  const reason = reasonOf(body.reason);
  if (held.sensitive) requireStepUp(p, t);
  const expired = Date.parse(held.expires_at) <= t;
  if (held.state !== "pending" || expired) {
    throw new ProblemError(409, "action_not_pending", "No longer waiting", `held action is ${expired && held.state === "pending" ? "past its hold timeout" : held.state}`, { state: held.state });
  }
  const rt = w.agents.get(held.agent_id);
  const audit = (action: string, extra: Record<string, unknown>): void => {
    appendAudit(w, { action, actor_type: "human", actor_id: p.userId, resource_type: "held_action", resource_id: id, resource_ref: rt?.spec.slug ?? null, reason, detail: { held_action_id: id, agent_id: held.agent_id, tool: held.tool, call_id: held.call_id, decided_by: p.userId, elapsed_s: Math.round((t - Date.parse(held.created_at)) / 1000), ...extra } }, t);
  };

  if (body.action === "deny") {
    const next: HeldAction = { ...held, state: "denied", decision: "deny", decided_by: p.userId, decided_at: iso(t), decision_reason: reason, history: [...held.history, entry("denied", t, { user_id: p.userId, reason, step_up: held.sensitive, approvals: held.approvals.length })] };
    w.heldActions.set(id, next);
    audit(ACTION_AUDIT.denied, {});
    emit(w, "action.decided", { held_action_id: id, agent_id: held.agent_id, state: next.state }, t);
    return next;
  }

  if (held.on_behalf_of?.kind === "user" && held.on_behalf_of.id === p.userId) refuse(w, p, held, "self_approval", reason, t, "the agent acted on your behalf: someone else must approve");
  if (held.approvals.some((a) => a.user_id === p.userId)) refuse(w, p, held, "duplicate_approver", reason, t, "a second approval must come from someone else");

  const approvals = [...held.approvals, { user_id: p.userId, session_id: null, at: iso(t) }];
  const final = approvals.length >= held.approvals_required;
  const trail = entry(final ? "approved" : "approval", t, { user_id: p.userId, reason, step_up: held.sensitive, approvals: approvals.length });
  const counted = final && held.counter !== null;
  if (counted && held.counter) addHit(w, held.counter.key, Number(held.counter.amount), t);
  const next: HeldAction = final
    ? { ...held, approvals, state: "approved", decision: "allow", decided_by: p.userId, decided_at: iso(t), decision_reason: reason, counter: held.counter ? { ...held.counter, applied_at: iso(t) } : null, history: [...held.history, trail] }
    : { ...held, approvals, history: [...held.history, trail] };
  w.heldActions.set(id, next);
  audit(ACTION_AUDIT.approved, { approvals: approvals.length, approvals_required: held.approvals_required, ...(held.counter ? { counted_toward_cap: counted } : {}) });
  if (final) emit(w, "action.decided", { held_action_id: id, agent_id: held.agent_id, state: next.state }, t);
  return next;
}

/** Worker loop: pending holds past `hold_timeout_s` are denied by default (state `expired`). */
export function expireHeld(w: World, t: number): void {
  for (const held of w.heldActions.values()) {
    if (held.state !== "pending" || Date.parse(held.expires_at) > t) continue;
    const at = Date.parse(held.expires_at);
    w.heldActions.set(held.id, { ...held, state: "expired", decision: "deny", decided_at: iso(at), resolved_by_timeout: true, decision_reason: "hold timeout; default deny", history: [...held.history, entry("expired", at, { reason: "hold timeout; default deny", approvals: held.approvals.length })] });
    appendAudit(w, { action: ACTION_AUDIT.expired, actor_type: "system", resource_type: "held_action", resource_id: held.id, resource_ref: w.agents.get(held.agent_id)?.spec.slug ?? null, reason: "hold timeout; default deny", detail: { held_action_id: held.id, agent_id: held.agent_id, tool: held.tool, call_id: held.call_id, hold_timeout_s: held.hold_timeout_s } }, at);
    emit(w, "action.decided", { held_action_id: held.id, agent_id: held.agent_id, state: "expired" }, at);
  }
}

// ── policies ───────────────────────────────────────────────────────────────

function scopeOf(w: World, kind: unknown, id: string | null | undefined): { scope: PolicyScope; tier1: boolean } {
  const agents = [...w.agents.values()];
  const invalid = (pointer: string, message: string): ProblemError => new ProblemError(422, "validation_failed", message, message, { errors: [{ pointer, code: "invalid", message }] });
  if (kind === "tenant") {
    if (id) throw invalid("/scope_id", "a tenant-scope policy takes no scope_id");
    return { scope: { kind: "tenant", id: null, label: "All agents" }, tier1: agents.some((a) => a.spec.tier === 1) };
  }
  if (kind === "agent") {
    const rt = w.agents.get(id ?? "");
    if (!rt) throw notFound("Agent");
    return { scope: { kind: "agent", id: rt.id, label: rt.spec.name }, tier1: rt.spec.tier === 1 };
  }
  if (kind === "agent_group") {
    const members = agents.filter((a) => groupId(w, a.spec.process) === id);
    if (!members.length || !id) throw notFound("Agent group");
    return { scope: { kind: "agent_group", id, label: members[0]?.spec.process ?? "Group" }, tier1: members.some((a) => a.spec.tier === 1) };
  }
  throw invalid("/scope_kind", "scope_kind is tenant, agent_group or agent");
}

const sameScope = (a: Pick<ActionPolicyRecord, "scope_kind" | "scope_id">, b: Pick<PolicyScope, "kind" | "id">): boolean => a.scope_kind === b.kind && (a.scope_id ?? null) === (b.id ?? null);

export function createPolicy(w: World, p: BffPrincipal, body: ActionPolicyCreate, t: number): ActionPolicyRecord {
  requireScope(p, "action_policies:write");
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (name.length < 1 || name.length > 200) throw new ProblemError(422, "validation_failed", "Name required", "Name the policy (1 to 200 characters).", { errors: [{ pointer: "/name", code: "length", message: "1 to 200 characters" }] });
  const reason = reasonOf(body.reason ?? body.change_note, body.reason ? "/reason" : "/change_note");
  const { scope, tier1 } = scopeOf(w, body.scope_kind, body.scope_id);
  const document = draftDocument(body.document ?? {});
  const errors = validatePolicyDocument(document);
  if (errors.length) throw new ProblemError(422, "validation_failed", "The policy is not valid", errors[0]?.message ?? "Fix the highlighted fields.", { errors: errors.map((e) => ({ pointer: `/document${e.path}`, code: "invalid", message: e.message })) });
  const versions = [...w.actionPolicies.values()].filter((r) => sameScope(r, scope));
  if (body.based_on_id) {
    const base = w.actionPolicies.get(body.based_on_id);
    if (!base) throw notFound("Action policy");
    if (!sameScope(base, scope)) throw new ProblemError(422, "validation_failed", "Different scope", "based_on_id must be a version of the same scope.", { errors: [{ pointer: "/based_on_id", code: "invalid", message: "Not a version of this scope" }] });
  }
  const id = nextId(w, "action-policy-version");
  const first = versions.slice().sort((a, b) => a.version_no - b.version_no)[0];
  const versionNo = Math.max(0, ...versions.map((r) => r.version_no)) + 1;
  const { schema, default_effect, tool_allowlist_enforced, tool_allowlist, sensitive_tools, external_tools, hold_timeout_s, rules } = document;
  const rec = policyRecord({ id, lineage: first?.policy_id ?? id, versionNo, name, scope, state: "draft", body: { schema, default_effect, tool_allowlist_enforced, tool_allowlist, sensitive_tools, external_tools, hold_timeout_s, rules }, fourEyes: body.four_eyes === true, approvalFourEyes: tier1, changeNote: body.change_note?.trim() || null, createdBy: p.userId, createdAt: t });
  w.actionPolicies.set(id, rec);
  appendAudit(w, { action: ACTION_AUDIT.policyCreated, actor_type: "human", actor_id: p.userId, resource_type: "action_policy", resource_id: id, resource_ref: name, reason, detail: { policy_id: id, lineage_policy_id: rec.policy_id, version_no: versionNo, scope_kind: scope.kind, scope_id: scope.id, document_sha256: rec.document_sha256 } }, t);
  emit(w, "action_policy.changed", { policy_id: rec.policy_id, id, state: rec.state }, t);
  return rec;
}

function policyOr404(w: World, id: string): ActionPolicyRecord {
  const rec = w.actionPolicies.get(id);
  if (!rec) throw notFound("Action policy");
  return rec;
}

function transition(rec: ActionPolicyRecord, action: string, allowed: readonly string[]): void {
  if (!allowed.includes(rec.state)) throw new ProblemError(409, "invalid_transition", "Not allowed in this state", `policy is ${rec.state}; ${action} needs ${allowed.join(" or ")}`, { from_state: rec.state, action });
}

export function approvePolicy(w: World, p: BffPrincipal, id: string, body: PolicyDecisionBody, t: number): ActionPolicyRecord {
  requireScope(p, "action_policies:write");
  const rec = policyOr404(w, id);
  const reason = reasonOf(body?.reason);
  transition(rec, "approve", ["draft"]);
  if (rec.approval_four_eyes && rec.created_by === p.userId) {
    appendAudit(w, { action: "access.denied", actor_type: "human", actor_id: p.userId, resource_type: "action_policy", resource_id: id, resource_ref: rec.name, reason: "self_approval", detail: { version_no: rec.version_no }, severity: "warning" }, t);
    throw new ProblemError(409, "self_approval", "Self-approval refused", "a tier-1 agent is in scope: another person must approve");
  }
  let supersedes: string | null = null;
  for (const other of w.actionPolicies.values()) {
    if (other.id !== id && other.state === "approved" && sameScope(other, rec.scope)) {
      supersedes = other.id;
      w.actionPolicies.set(other.id, { ...other, state: "superseded", superseded_by: id, superseded_at: iso(t), updated_at: iso(t) });
    }
  }
  const next: ActionPolicyRecord = { ...rec, state: "approved", approved_by: p.userId, approved_at: iso(t), updated_at: iso(t), approvals: [...rec.approvals, { user_id: p.userId, at: iso(t), reason }] };
  w.actionPolicies.set(id, next);
  appendAudit(w, { action: ACTION_AUDIT.policyApproved, actor_type: "human", actor_id: p.userId, resource_type: "action_policy", resource_id: id, resource_ref: rec.name, reason, detail: { policy_id: id, version_no: rec.version_no, approved_by: p.userId, four_eyes: rec.approval_four_eyes, supersedes, document_sha256: rec.document_sha256 } }, t);
  emit(w, "action_policy.changed", { policy_id: rec.policy_id, id, state: next.state }, t);
  return next;
}

export function retirePolicy(w: World, p: BffPrincipal, id: string, body: PolicyDecisionBody, t: number): ActionPolicyRecord {
  requireScope(p, "action_policies:write");
  const rec = policyOr404(w, id);
  const reason = reasonOf(body?.reason);
  transition(rec, "retire", ["draft", "approved"]);
  const next: ActionPolicyRecord = { ...rec, state: "retired", retired_by: p.userId, retired_at: iso(t), updated_at: iso(t) };
  w.actionPolicies.set(id, next);
  appendAudit(w, { action: ACTION_AUDIT.policyRetired, actor_type: "human", actor_id: p.userId, resource_type: "action_policy", resource_id: id, resource_ref: rec.name, reason, detail: { policy_id: id, version_no: rec.version_no } }, t);
  emit(w, "action_policy.changed", { policy_id: rec.policy_id, id, state: next.state }, t);
  return next;
}

function simulateInput(body: { tool?: unknown; args?: unknown; counters?: unknown }): { tool: string; args: Record<string, unknown>; counters: Counters | null } {
  if (typeof body?.tool !== "string" || body.tool.trim() === "") throw new ProblemError(422, "validation_failed", "Tool required", "Name the tool the agent would call.", { errors: [{ pointer: "/tool", code: "required", message: "Required" }] });
  if (!body.args || typeof body.args !== "object" || Array.isArray(body.args)) throw new ProblemError(422, "validation_failed", "Arguments required", "The arguments are a JSON object.", { errors: [{ pointer: "/args", code: "type", message: "An object" }] });
  const counters = body.counters && typeof body.counters === "object" ? Object.fromEntries(Object.entries(body.counters as Record<string, unknown>).map(([k, v]) => [k, Number(v)])) : null;
  return { tool: body.tool, args: body.args as Record<string, unknown>, counters };
}

/** With `agent_id`, the document takes its scope's place beside the agent's other approved policies. */
function othersFor(w: World, agentId: string | null | undefined, scope: Pick<PolicyScope, "kind" | "id"> | null): ActionPolicyDocument[] {
  if (!agentId) return [];
  const rt = w.agents.get(agentId);
  if (!rt) throw notFound("Agent");
  return approvedPoliciesFor(w, rt).filter((r) => !scope || !sameScope(r, scope)).map((r) => r.document);
}

export function simulatePolicy(w: World, p: BffPrincipal, id: string, body: ActionSimulate, t: number): SimulateResult {
  requireScope(p, "actions:read");
  const rec = policyOr404(w, id);
  const { tool, args, counters } = simulateInput(body);
  const d = evaluateAll([rec.document, ...othersFor(w, body.agent_id, rec.scope)], tool, args, counters);
  return simulateAnswer(d, counters, rec.state, iso(t));
}

export function simulateDraft(w: World, p: BffPrincipal, body: ActionPolicyDraftSimulate, t: number): SimulateResult {
  requireScope(p, "actions:read");
  const { tool, args, counters } = simulateInput(body);
  const kind = body.scope_kind ?? (body.agent_id ? "agent" : null);
  if (kind !== null && !SCOPE_KINDS.has(kind)) throw new ProblemError(422, "validation_failed", "Unknown scope", "scope_kind is tenant, agent_group or agent.");
  const scope = kind ? scopeOf(w, kind, kind === "tenant" ? null : (body.scope_id ?? (kind === "agent" ? body.agent_id : null))).scope : null;
  const document = draftDocument(body.document ?? {});
  const d = evaluateAll([document, ...othersFor(w, body.agent_id, scope)], tool, args, counters);
  return simulateAnswer(d, counters, null, iso(t));
}

// ── fleet counts ───────────────────────────────────────────────────────────

/** `GET /action-summary`: distinct calls per agent from the audit chain, `[from, to)` (default 24 h). */
export function actionSummary(w: World, q: URLSearchParams, t: number): ActionSummary {
  const to = q.get("to") ? Date.parse(q.get("to") ?? "") : t;
  const from = q.get("from") ? Date.parse(q.get("from") ?? "") : to - DAY_MS;
  if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to) throw new ProblemError(422, "validation_failed", "Bad window", "from must be before to");
  const only = q.get("agent_id");
  type Key = "blocked" | "escalated" | "approved" | "denied" | "expired";
  const sets = new Map<string, Record<Key, Set<string>>>();
  for (const e of w.audit) {
    const at = Date.parse(e.recorded_at);
    if (at < from || at >= to || !e.action.startsWith("action.")) continue;
    const d = (e.detail ?? {}) as Record<string, unknown>;
    const agent = typeof d.agent_id === "string" ? d.agent_id : null;
    if (!agent || (only && agent !== only)) continue;
    const key: Key | null =
      e.action === ACTION_AUDIT.blocked ? "blocked" : e.action === ACTION_AUDIT.escalated ? "escalated" : e.action === ACTION_AUDIT.denied ? "denied" : e.action === ACTION_AUDIT.expired ? "expired" : e.action === ACTION_AUDIT.approved && Number(d.approvals) >= Number(d.approvals_required) ? "approved" : null;
    if (!key) continue;
    const ref = String((key === "blocked" || key === "escalated" ? d.call_id : d.held_action_id) ?? e.seq);
    const row = sets.get(agent) ?? { blocked: new Set(), escalated: new Set(), approved: new Set(), denied: new Set(), expired: new Set() };
    row[key].add(ref);
    sets.set(agent, row);
  }
  const data = [...sets.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([agent_id, s]) => ({ agent_id, blocked: s.blocked.size, escalated: s.escalated.size, approved: s.approved.size, denied: s.denied.size, expired: s.expired.size }));
  const total = data.reduce((acc, r) => ({ blocked: acc.blocked + r.blocked, escalated: acc.escalated + r.escalated, approved: acc.approved + r.approved, denied: acc.denied + r.denied, expired: acc.expired + r.expired }), { blocked: 0, escalated: 0, approved: 0, denied: 0, expired: 0 });
  return { from: iso(from), to: iso(to), data, total };
}

// ── routes ─────────────────────────────────────────────────────────────────

type Handler = (r: DemoRequest) => DemoResult | unknown;
const created = (body: unknown): DemoResult => ({ status: 201, body });

function listPolicies(r: DemoRequest) {
  requireScope(r.principal, "actions:read");
  const state = r.query.get("state");
  const kind = r.query.get("scope_kind");
  const agent = r.query.get("agent_id");
  const lineage = r.query.get("policy_id");
  const history = r.query.get("include_history") === "true" || state !== null;
  const items = [...r.w.actionPolicies.values()]
    .filter((x) => (!state || x.state === state) && (!kind || x.scope_kind === kind) && (!lineage || x.policy_id === lineage) && (history || x.state !== "superseded") && (!agent || (x.scope_kind === "agent" && x.scope_id === agent)))
    .sort((a, b) => SCOPE_ORDER[a.scope_kind] - SCOPE_ORDER[b.scope_kind] || a.name.localeCompare(b.name) || POLICY_STATE_ORDER[a.state] - POLICY_STATE_ORDER[b.state] || b.version_no - a.version_no);
  return page(items, r.query);
}

/** As the API: newest first, one `state`, no arguments and no trail in a list. */
function listHeld(r: DemoRequest) {
  requireScope(r.principal, "actions:read");
  // `state` repeats for any of several states (state=approved&state=denied).
  const states = r.query.getAll("state");
  const unknown = states.find((s) => !HELD_STATES.has(s));
  if (unknown !== undefined) throw new ProblemError(422, "validation_failed", "Unknown state", `state is one of ${[...HELD_STATES].join(", ")}.`, { errors: [{ pointer: "/state", code: "enum", message: [...HELD_STATES].join(" | ") }] });
  const include = r.query.get("include");
  if (include !== null && include !== "args") throw new ProblemError(422, "validation_failed", "Unknown include", "include accepts args only.", { errors: [{ pointer: "/include", code: "enum", message: "args" }] });
  const agent = r.query.get("agent_id");
  const tool = r.query.get("tool");
  // include=args: scrubbed arguments for human callers who can decide (demo personas are people; no group scoping).
  const withArgs = include === "args" && r.principal.scopes.includes("actions:decide");
  const items = [...r.w.heldActions.values()]
    .filter((h) => (states.length === 0 || states.includes(h.state)) && (!agent || h.agent_id === agent) && (!tool || h.tool === tool))
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id.localeCompare(a.id))
    .map((h) => ({ ...heldListRow(h), args: withArgs ? h.args : null }));
  return page(items, r.query);
}

export const ACTION_GATE_ROUTES: Record<string, Partial<Record<string, Handler>>> = {
  "/action-policies": {
    GET: listPolicies,
    POST: (r) => created(createPolicy(r.w, r.principal, (r.body ?? {}) as ActionPolicyCreate, r.t)),
  },
  // Before "/action-policies/{policy_id}" so the literal segment wins.
  "/action-policies/simulate": { POST: (r) => simulateDraft(r.w, r.principal, (r.body ?? {}) as ActionPolicyDraftSimulate, r.t) },
  "/action-policies/{policy_id}": {
    GET: (r) => {
      requireScope(r.principal, "actions:read");
      return policyOr404(r.w, r.params.policy_id ?? "");
    },
  },
  "/action-policies/{policy_id}/approve": { POST: (r) => approvePolicy(r.w, r.principal, r.params.policy_id ?? "", (r.body ?? {}) as PolicyDecisionBody, r.t) },
  "/action-policies/{policy_id}/retire": { POST: (r) => retirePolicy(r.w, r.principal, r.params.policy_id ?? "", (r.body ?? {}) as PolicyDecisionBody, r.t) },
  "/action-policies/{policy_id}/simulate": { POST: (r) => simulatePolicy(r.w, r.principal, r.params.policy_id ?? "", (r.body ?? {}) as ActionSimulate, r.t) },
  "/action-summary": {
    GET: (r) => {
      requireScope(r.principal, "actions:read");
      return actionSummary(r.w, r.query, r.t);
    },
  },
  "/held-actions": { GET: listHeld },
  "/held-actions/{held_action_id}": {
    GET: (r) => {
      requireScope(r.principal, "actions:read");
      const held = r.w.heldActions.get(r.params.held_action_id ?? "");
      if (!held) throw notFound("Held action");
      return held;
    },
  },
  "/held-actions/{held_action_id}/actions": { POST: (r) => decideHeld(r.w, r.principal, r.params.held_action_id ?? "", (r.body ?? {}) as HeldActionDecisionBody, r.t) },
};
