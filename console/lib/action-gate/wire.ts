/**
 * The boundary between the Action Gate API objects and the console (pure; unit-tested).
 *
 *  - `toPolicy` / `toHeld` make a contract object definite: optional members get their
 *    documented defaults, the opaque policy document is narrowed to `sibyl-action-policy/1`,
 *    and `on_behalf_of` is read in its wire form. Unknown extra members are kept.
 *  - `heldListRow` is what the API returns for a list row (no `args`, no `history`); the demo
 *    engine lists through it so demo and live have the same shape.
 *  - `createBody` and `draftSimulateBody` build the request bodies; `simulateAnswer` turns an
 *    evaluator decision into the `ActionDecision` both simulate routes return (demo and the
 *    editor's offline preview use it, mirroring `simulate.py::_answer`).
 */
import type {
  ActionPolicyCreate,
  ActionPolicyDocument,
  ActionPolicyDraftSimulate,
  ActionPolicyRecord,
  ActionRule,
  ActionRuleView,
  ActionSummary,
  ApiActionPolicy,
  ApiHeldAction,
  HeldAction,
  HeldHistoryEntry,
  OnBehalfOf,
  PolicyDocumentBody,
  PolicyScopeKind,
  PolicyState,
  SimulateResult,
} from "@/lib/api/action-gate";
import { DRAFT_POLICY_ID, POLICY_SCHEMA_ID } from "@/lib/api/action-gate";
import type { Counters, Decision } from "./evaluate";

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/** The members `POST /action-policies` fills in when a document leaves them out (`service.DOCUMENT_DEFAULTS`). */
export const DOCUMENT_DEFAULTS: PolicyDocumentBody = {
  schema: POLICY_SCHEMA_ID,
  default_effect: "escalate",
  tool_allowlist_enforced: false,
  tool_allowlist: null,
  sensitive_tools: [],
  external_tools: [],
  hold_timeout_s: 900,
  rules: [],
};

// ── on behalf of ───────────────────────────────────────────────────────────

/**
 * The wire form is `{kind: "user", id}` or `{kind: "external", ref}`. The generated type names
 * the kinds after the schemas (`OnBehalfOfUser`); both spellings are accepted.
 */
export function onBehalfOf(raw: unknown): OnBehalfOf | null {
  if (!isObject(raw)) return null;
  const kind = str(raw.kind);
  if ((kind === "user" || kind === "OnBehalfOfUser") && str(raw.id)) return { kind: "user", id: raw.id as string };
  if ((kind === "external" || kind === "OnBehalfOfExternal") && str(raw.ref)) return { kind: "external", ref: raw.ref as string };
  return null;
}

/** The app user the agent acted for (never an approver of this hold), or null. */
export function onBehalfUser(h: Pick<HeldAction, "on_behalf_of">): string | null {
  return h.on_behalf_of?.kind === "user" ? h.on_behalf_of.id : null;
}

/** "acting for you" / "acting for On-call Operator" / "acting for crm:4411". */
export function actingFor(obo: OnBehalfOf | null, me: string, nameOf: (userId: string) => string): string | null {
  if (!obo) return null;
  if (obo.kind === "external") return `acting for ${obo.ref}`;
  return `acting for ${obo.id === me ? "you" : nameOf(obo.id)}`;
}

// ── policies ───────────────────────────────────────────────────────────────

function ruleFromView(v: ActionRuleView): ActionRule {
  return {
    rule_id: v.rule_id,
    tool: v.tool,
    ...(isObject(v.when) ? { when: v.when as unknown as ActionRule["when"] } : {}),
    ...(isObject(v.cumulative) ? { cumulative: v.cumulative as unknown as ActionRule["cumulative"] } : {}),
    ...(isObject(v.data_class) ? { data_class: v.data_class as unknown as ActionRule["data_class"] } : {}),
    effect: v.effect,
    reason: v.reason,
  };
}

/** The rule rows of a document, as `GET /action-policies` lists them. */
export function ruleViews(doc: Pick<ActionPolicyDocument, "rules">): ActionRuleView[] {
  return doc.rules.map((r, position) => ({ position, rule_id: r.rule_id, tool: r.tool, effect: r.effect, reason: r.reason, when: r.when ?? null, cumulative: r.cumulative ?? null, data_class: r.data_class ?? null }));
}

/**
 * Narrow the opaque `document` of an API policy. The stored document is normalised by the
 * control plane; missing members fall back to the row's own columns, then to the defaults.
 */
export function policyDocument(raw: Pick<ApiActionPolicy, "id" | "version_no" | "document" | "rules"> & Partial<ApiActionPolicy>): ActionPolicyDocument {
  const d = isObject(raw.document) ? raw.document : {};
  const rules = Array.isArray(d.rules) ? (d.rules as ActionRule[]) : (raw.rules ?? []).slice().sort((a, b) => a.position - b.position).map(ruleFromView);
  const allowlist = d.tool_allowlist === null || d.tool_allowlist === undefined ? null : strList(d.tool_allowlist);
  return {
    schema: POLICY_SCHEMA_ID,
    policy_id: str(d.policy_id) ?? raw.id,
    version: typeof d.version === "number" ? d.version : raw.version_no,
    default_effect: d.default_effect === "allow" || d.default_effect === "escalate" ? d.default_effect : raw.default_effect === "allow" ? "allow" : DOCUMENT_DEFAULTS.default_effect,
    tool_allowlist_enforced: d.tool_allowlist_enforced === true,
    tool_allowlist: allowlist,
    sensitive_tools: strList(d.sensitive_tools),
    external_tools: strList(d.external_tools),
    hold_timeout_s: typeof d.hold_timeout_s === "number" ? d.hold_timeout_s : (raw.hold_timeout_s ?? DOCUMENT_DEFAULTS.hold_timeout_s),
    rules,
  };
}

/** An API policy version as the console reads it. */
export function toPolicy(raw: ApiActionPolicy | ActionPolicyRecord): ActionPolicyRecord {
  const document = policyDocument(raw);
  return {
    ...raw,
    scope_id: raw.scope_id ?? raw.scope.id ?? null,
    document_sha256: raw.document_sha256 ?? "",
    default_effect: raw.default_effect ?? document.default_effect,
    hold_timeout_s: raw.hold_timeout_s ?? document.hold_timeout_s,
    four_eyes: raw.four_eyes ?? false,
    approval_four_eyes: raw.approval_four_eyes ?? false,
    change_note: raw.change_note ?? null,
    approvals: raw.approvals ?? [],
    created_by: raw.created_by ?? "",
    approved_by: raw.approved_by ?? null,
    approved_at: raw.approved_at ?? null,
    retired_by: raw.retired_by ?? null,
    retired_at: raw.retired_at ?? null,
    superseded_by: raw.superseded_by ?? null,
    superseded_at: raw.superseded_at ?? null,
    created_at: raw.created_at ?? "",
    updated_at: raw.updated_at ?? raw.created_at ?? "",
    document,
  };
}

/** Policies that are in force or on their way (draft, approved) before the rest. */
export const POLICY_STATE_ORDER: Readonly<Record<PolicyState, number>> = { draft: 0, approved: 1, retired: 2, superseded: 3 };

/** `POST /action-policies` body: flat scope, the document without its assigned id and version. */
export function createBody(input: { name: string; scopeKind: PolicyScopeKind; scopeId: string | null; document: PolicyDocumentBody; changeNote: string; fourEyes: boolean; basedOnId: string | null }): ActionPolicyCreate {
  const note = input.changeNote.trim();
  return {
    name: input.name.trim(),
    scope_kind: input.scopeKind,
    scope_id: input.scopeKind === "tenant" ? null : input.scopeId,
    document: input.document,
    four_eyes: input.fourEyes,
    change_note: note,
    // The audit reason: the API takes `reason`, else a change note of 10 characters or more.
    ...(note.length >= 10 ? { reason: note } : {}),
    ...(input.basedOnId ? { based_on_id: input.basedOnId } : {}),
  };
}

// ── simulate ───────────────────────────────────────────────────────────────

/** `POST /action-policies/simulate` body for an unsaved draft. */
export function draftSimulateBody(input: { document: PolicyDocumentBody; scopeKind: PolicyScopeKind; scopeId: string | null; tool: string; args: Record<string, unknown>; agentId?: string | null; counters?: Counters | null }): ActionPolicyDraftSimulate {
  return {
    document: input.document,
    scope_kind: input.scopeKind,
    ...(input.scopeKind !== "tenant" && input.scopeId ? { scope_id: input.scopeId } : {}),
    tool: input.tool,
    args: input.args,
    ...(input.agentId ? { agent_id: input.agentId } : {}),
    ...(input.counters && Object.keys(input.counters).length ? { counters: { ...input.counters } } : {}),
  };
}

/** The draft as the control plane simulates it: defaults filled, the placeholder id, version 1. */
export function draftDocument(body: Partial<PolicyDocumentBody>): ActionPolicyDocument {
  return { ...DOCUMENT_DEFAULTS, ...body, schema: POLICY_SCHEMA_ID, policy_id: DRAFT_POLICY_ID, version: 1 };
}

/** An evaluator decision as the simulate routes answer it (`simulate.py::_answer`). */
export function simulateAnswer(d: Decision, counters: Counters | null | undefined, policyState: PolicyState | null, evaluatedAt: string): SimulateResult {
  const draft = d.policy_id === DRAFT_POLICY_ID;
  const need = d.needs_counter;
  const current = need && counters && Object.hasOwn(counters, need.counter_key) ? counters[need.counter_key] : undefined;
  return {
    effect: d.effect,
    rule_id: d.rule_id,
    reason: d.reason,
    matched_paths: [...d.matched_paths],
    policy_id: draft ? null : d.policy_id,
    policy_version: draft ? null : d.policy_version,
    counter: need ? { key: need.counter_key, amount: need.increment, max: need.max, window_s: need.window_s, value: current === undefined ? null : String(current), window_start: null } : null,
    sensitive: d.sensitive,
    hold_timeout_s: d.hold_timeout_s,
    policy_state: policyState,
    evaluated_at: evaluatedAt,
  };
}

// ── held actions ───────────────────────────────────────────────────────────

const HISTORY_KINDS = new Set<HeldHistoryEntry["kind"]>(["requested", "blocked", "approval", "refused", "approved", "denied", "expired", "cancelled"]);

function historyEntry(raw: unknown): HeldHistoryEntry | null {
  if (!isObject(raw) || !HISTORY_KINDS.has(raw.kind as HeldHistoryEntry["kind"]) || !str(raw.at)) return null;
  return {
    at: raw.at as string,
    kind: raw.kind as HeldHistoryEntry["kind"],
    user_id: str(raw.user_id),
    key_id: str(raw.key_id),
    reason: str(raw.reason),
    step_up: raw.step_up === true,
    code: str(raw.code),
    approvals: typeof raw.approvals === "number" ? raw.approvals : null,
  };
}

/** An API held action as the console reads it. */
export function toHeld(raw: ApiHeldAction | HeldAction): HeldAction {
  const required = raw.approvals_required ?? (raw.four_eyes ? 2 : 1);
  const args = isObject(raw.args) ? raw.args : null;
  return {
    ...raw,
    id: raw.id ?? raw.held_action_id,
    policy_id: raw.policy_id ?? null,
    policy_version: raw.policy_version ?? null,
    rule_id: raw.rule_id ?? null,
    source: raw.source ?? "gateway",
    args_sha256: raw.args_sha256 ?? "",
    args_payload_ref: raw.args_payload_ref ?? null,
    args,
    server_effect: raw.server_effect ?? "escalate",
    reason: raw.reason ?? "",
    sensitive: raw.sensitive ?? false,
    approvals_required: required,
    approvals: raw.approvals ?? [],
    decided_by: raw.decided_by ?? null,
    decided_at: raw.decided_at ?? null,
    decision_reason: raw.decision_reason ?? null,
    resolved_by_timeout: raw.resolved_by_timeout ?? false,
    hold_timeout_s: raw.hold_timeout_s ?? 0,
    created_at: raw.created_at ?? raw.expires_at,
    matched_paths: raw.matched_paths ?? [],
    four_eyes: raw.four_eyes ?? required >= 2,
    counter: raw.counter ?? null,
    on_behalf_of: onBehalfOf(raw.on_behalf_of),
    history: (raw.history ?? []).map(historyEntry).filter((e): e is HeldHistoryEntry => e !== null),
  };
}

/** A list row: no arguments (`null`; `include=args` adds them back for deciders) and no trail. */
export function heldListRow(h: HeldAction): Omit<HeldAction, "history"> {
  const row: Partial<HeldAction> = { ...h, args: null };
  delete row.history;
  return row as Omit<HeldAction, "history">;
}

/** Approvals still needed before the action runs. */
export function approvalsLeft(h: Pick<HeldAction, "approvals" | "approvals_required" | "state">): number {
  return h.state === "pending" ? Math.max(0, h.approvals_required - h.approvals.length) : 0;
}

// ── fleet counts ───────────────────────────────────────────────────────────

export interface ActionCounts {
  blocked: number;
  escalated: number;
  approved: number;
  denied: number;
  expired: number;
}

/** `GET /action-summary` as a per-agent map plus the total. */
export function summaryCounts(summary: ActionSummary): { byAgent: Map<string, ActionCounts>; total: ActionCounts } {
  const byAgent = new Map<string, ActionCounts>();
  for (const r of summary.data) byAgent.set(r.agent_id, { blocked: r.blocked, escalated: r.escalated, approved: r.approved, denied: r.denied, expired: r.expired });
  const t = summary.total;
  return { byAgent, total: { blocked: t.blocked, escalated: t.escalated, approved: t.approved, denied: t.denied, expired: t.expired } };
}

/** Waiting first (soonest deadline first), then the most recently decided. */
export function heldOrder(a: HeldAction, b: HeldAction): number {
  const pa = a.state === "pending" ? 0 : 1;
  const pb = b.state === "pending" ? 0 : 1;
  if (pa !== pb) return pa - pb;
  if (pa === 0) return Date.parse(a.expires_at) - Date.parse(b.expires_at);
  return Date.parse(b.decided_at ?? b.created_at) - Date.parse(a.decided_at ?? a.created_at);
}
