/**
 * Action Gate wire types, derived from the generated contract (`schema.gen.ts`; regenerate with
 * `npm run gen:api`). Two things stay hand-typed, both for a stated reason:
 *
 *  - The `sibyl-action-policy/1` document (predicate AST, caps, data-class rules). The OpenAPI
 *    document leaves it opaque (`{[key: string]: unknown}`); the shape is the pydantic model in
 *    `packages/sibyl-schemas` (`models/action_policy.py`). `lib/action-gate/wire.ts` narrows
 *    the opaque value at the boundary.
 *  - `OnBehalfOf`. openapi-typescript invents a discriminator value from the schema names
 *    (`kind: "OnBehalfOfUser"`); the API sends `kind: "user" | "external"`.
 *
 * The console views (`ActionPolicyRecord`, `HeldAction`) are the API objects with the optional
 * members made definite by `toPolicy` / `toHeld`. Demo data is built in exactly these shapes, so
 * demo and live render through the same code.
 *
 * Pure types and constants only: safe for client and server.
 */
import type { components } from "./schema.gen";

type S = components["schemas"];

/** Make the listed optional members required (and drop `undefined`). */
type Definite<T, K extends keyof T> = Omit<T, K> & { [P in K]-?: Exclude<T[P], undefined> };

// ── the policy document (opaque in the contract) ─────────────────────────────

export type ActionEffect = S["ActionDecision"]["effect"];
export type Pointer = string;
export type Scalar = string | number | boolean | null;

/** `sibyl-action-policy/1` predicate AST: exactly one operator per node, never evaluated as code. */
export type Predicate =
  | { eq: [Pointer, Scalar] }
  | { ne: [Pointer, Scalar] }
  | { lt: [Pointer, number] }
  | { le: [Pointer, number] }
  | { gt: [Pointer, number] }
  | { ge: [Pointer, number] }
  | { in: [Pointer, Scalar[]] }
  | { not_in: [Pointer, Scalar[]] }
  | { matches: [Pointer, string] }
  | { exists: Pointer }
  | { all: Predicate[] }
  | { any: Predicate[] }
  | { not: Predicate };

/** Exactly one of `sum` or `count: true`. */
export type CumulativeCap = {
  sum?: Pointer;
  count?: true;
  max: number;
  window_s: number;
  per?: Pointer;
  on_exceed?: "escalate" | "block";
};

/** `pii_standard` detector ids (sibyl_schemas.pii.PII_DETECTOR_IDS). */
export const PII_DETECTOR_IDS = ["email", "phone", "credit_card", "iban", "ip_address", "national_id", "postal_address"] as const;
export type PiiId = (typeof PII_DETECTOR_IDS)[number];

export type DataClassRule = {
  secrets: boolean;
  pii: PiiId[];
};

export type ActionRule = {
  rule_id: string;
  tool: string;
  when?: Predicate;
  cumulative?: CumulativeCap;
  data_class?: DataClassRule;
  effect: ActionEffect;
  reason: string;
};

export const POLICY_SCHEMA_ID = "sibyl-action-policy/1" as const;

/**
 * The signed policy document. On a stored version `policy_id` is that VERSION's id (the
 * snapshot key and the counter-key prefix) and `version` its `version_no`; the stable id that
 * every version of one scope shares is `ActionPolicyRecord.policy_id`.
 */
export type ActionPolicyDocument = {
  schema: typeof POLICY_SCHEMA_ID;
  policy_id: string;
  version: number;
  default_effect: "allow" | "escalate";
  tool_allowlist_enforced: boolean;
  tool_allowlist: string[] | null;
  sensitive_tools: string[];
  external_tools: string[];
  hold_timeout_s: number;
  rules: ActionRule[];
};

/** A document as it is written: `policy_id` and `version` are assigned by the control plane. */
export type PolicyDocumentBody = Omit<ActionPolicyDocument, "policy_id" | "version">;

/** The placeholder `policy_id` the control plane gives an unsaved draft it simulates. */
export const DRAFT_POLICY_ID = "00000000-0000-0000-0000-000000000000";

// ── policies ───────────────────────────────────────────────────────────────

export type ApiActionPolicy = S["ActionPolicy"];
export type PolicyState = ApiActionPolicy["state"];
export type PolicyScopeKind = ApiActionPolicy["scope_kind"];
export type PolicyScope = S["ActionPolicyScope"];
export type PolicyApprovalEntry = S["ActionPolicyApproval"];
export type ActionRuleView = S["ActionRuleView"];

/** One policy version, as the console reads it (`toPolicy`). */
export type ActionPolicyRecord = Omit<
  Definite<
    ApiActionPolicy,
    | "scope_id"
    | "document_sha256"
    | "default_effect"
    | "hold_timeout_s"
    | "four_eyes"
    | "approval_four_eyes"
    | "change_note"
    | "approvals"
    | "created_by"
    | "approved_by"
    | "approved_at"
    | "retired_by"
    | "retired_at"
    | "superseded_by"
    | "superseded_at"
    | "created_at"
    | "updated_at"
  >,
  "document"
> & { document: ActionPolicyDocument };

/** `POST /action-policies` (flat `scope_kind` / `scope_id`). */
export type ActionPolicyCreate = Omit<S["ActionPolicyCreate"], "document"> & { document: PolicyDocumentBody };
export type PolicyDecisionBody = S["ReasonBody"];

/** `POST /action-policies/{policy_id}/simulate`. Counters: `<policy version id>/<rule_id>[/hash]` → window total. */
export type ActionSimulate = Omit<S["ActionSimulate"], "counters"> & { counters?: Record<string, number> };
/** `POST /action-policies/simulate`: an unsaved document. */
export type ActionPolicyDraftSimulate = Omit<S["ActionPolicyDraftSimulate"], "document" | "counters"> & { document: PolicyDocumentBody; counters?: Record<string, number> };
/** The answer of both simulate routes. */
export type SimulateResult = S["ActionDecision"];
export type ActionCounter = S["ActionCounter"];

// ── held actions ───────────────────────────────────────────────────────────

export type ApiHeldAction = S["HeldAction"];
export type HeldState = ApiHeldAction["state"];
export type HeldHistoryEntry = S["HeldActionHistoryEntry"];
export type HeldHistoryKind = HeldHistoryEntry["kind"];
export type HeldApproval = S["HeldActionApproval"];
export type HeldCounter = S["HeldActionCounter"];
export type HeldActionDecisionBody = S["HeldActionAction"];

/** Who the agent acted for (the API's wire form; see the note at the top). That user never approves the hold. */
export type OnBehalfOf = { kind: "user"; id: string } | { kind: "external"; ref: string };

/** One held action, as the console reads it (`toHeld`). `args` and `history` are on single reads only. */
export type HeldAction = Omit<
  Definite<
    ApiHeldAction,
    | "id"
    | "rule_id"
    | "source"
    | "args_sha256"
    | "args_payload_ref"
    | "server_effect"
    | "reason"
    | "sensitive"
    | "approvals_required"
    | "approvals"
    | "decided_by"
    | "decided_at"
    | "decision_reason"
    | "resolved_by_timeout"
    | "hold_timeout_s"
    | "created_at"
    | "matched_paths"
    | "four_eyes"
    | "counter"
    | "history"
  >,
  "on_behalf_of" | "args" | "policy_id" | "policy_version"
> & {
  /** The version id of the policy that held it (links to `/action-policies/{policy_id}`). */
  policy_id: string | null;
  policy_version: number | null;
  on_behalf_of: OnBehalfOf | null;
  args: Record<string, unknown> | null;
};

// ── fleet counts ───────────────────────────────────────────────────────────

/** `GET /action-summary`: distinct calls per agent, last 24 h by default. */
export type ActionSummary = S["ActionSummary"];
export type ActionSummaryRow = S["ActionSummaryRow"];

/** Audit actions the Action Gate writes (ACTION-GATE.md §3). */
export const ACTION_AUDIT = {
  allowed: "action.allowed",
  blocked: "action.blocked",
  escalated: "action.escalated",
  approved: "action.approved",
  denied: "action.denied",
  expired: "action.expired",
  policyCreated: "action_policy.created",
  policyApproved: "action_policy.approved",
  policyRetired: "action_policy.retired",
} as const;
