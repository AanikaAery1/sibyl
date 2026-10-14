/**
 * Seeded Action Gate policies (real `sibyl-action-policy/1` documents) for the demo tenants, in
 * the API's `ActionPolicy` shape. As on the control plane, versions are numbered per scope, the
 * stable `policy_id` is the scope's first version id, and the document's `policy_id` is the
 * version id (the counter-key prefix).
 *   meridian  · Claims payouts (claims-triage, tier 1: approval needs a second person) v2 superseded → v3 approved
 *             · Refund guardrails (returns-agent; held refunds need two approvers) v1 superseded → v2 approved
 *             · Personal data egress (tenant-wide) v1 approved
 *             · Finance close tools (agent group) v1 draft
 *             · Legacy refund rule (customer-chat) v1 retired
 *   northstar · Personal data egress (tenant-wide) v1 approved
 */
import "server-only";
import type { ActionPolicyDocument, ActionPolicyRecord, ActionRule, PolicyDocumentBody, PolicyScope, PolicyState } from "@/lib/api/action-gate";
import { POLICY_SCHEMA_ID } from "@/lib/api/action-gate";
import { PERSONAS } from "@/lib/auth/personas";
import { ruleViews } from "@/lib/action-gate/wire";
import { MINUTE, idFor, iso } from "./core";
import { agentId } from "./fixtures";
import { appendAudit, canonical, sha256, type World } from "./world";

const HOUR = 60 * MINUTE;
const ADMIN = PERSONAS[0]?.userId ?? "";
const OPERATOR = PERSONAS[1]?.userId ?? "";
const REVIEWED = "Reviewed the rules and a simulate run";

/** Demo agent groups are the business process (the contract's `agent_group_id` stays null). */
export const groupIdFor = (tenant: string, process: string): string => idFor(`group:${tenant}:${process}`);
export const groupId = (w: World, process: string): string => groupIdFor(w.slug, process);

const doc = (over: Partial<PolicyDocumentBody> & Pick<PolicyDocumentBody, "rules">): PolicyDocumentBody => ({
  schema: POLICY_SCHEMA_ID,
  default_effect: "allow",
  tool_allowlist_enforced: false,
  tool_allowlist: null,
  sensitive_tools: [],
  external_tools: [],
  hold_timeout_s: 900,
  ...over,
});

const PAYOUT_RULES = (reviewAbove: number): ActionRule[] => [
  { rule_id: "transfer-limit", tool: "payments.transfer", when: { gt: ["/amount", 100000] }, effect: "block", reason: "Above the ₹1,00,000 single-transfer limit for claim payouts" },
  { rule_id: "transfer-review", tool: "payments.transfer", when: { all: [{ gt: ["/amount", reviewAbove] }, { in: ["/currency", ["INR"]] }] }, effect: "escalate", reason: `Payouts above ₹${reviewAbove.toLocaleString("en-IN")} need a second person` },
  { rule_id: "transfer-routine", tool: "payments.transfer", when: { all: [{ le: ["/amount", reviewAbove] }, { matches: ["/reference", "CLM-[0-9]{6}"] }] }, cumulative: { sum: "/amount", max: 500000, window_s: 86400, on_exceed: "escalate" }, effect: "allow", reason: "Routine claim payouts, up to ₹5,00,000 a day" },
];

export const CLAIMS_PAYOUTS = (reviewAbove: number): PolicyDocumentBody =>
  doc({
    tool_allowlist_enforced: true,
    tool_allowlist: ["payments.transfer", "claims.*", "kb.search", "email.send_internal"],
    sensitive_tools: ["payments.transfer"],
    rules: PAYOUT_RULES(reviewAbove),
  });

const REFUNDS = (perMinute: number): PolicyDocumentBody =>
  doc({
    hold_timeout_s: 600,
    rules: [
      { rule_id: "refund-large", tool: "refunds.issue", when: { gt: ["/amount", 5000] }, effect: "escalate", reason: "Refunds above ₹5,000 need a person" },
      { rule_id: "refund-burst", tool: "refunds.issue", cumulative: { count: true, max: perMinute, window_s: 60 }, effect: "allow", reason: `At most ${perMinute} refunds a minute` },
    ],
  });

const EGRESS = doc({
  external_tools: ["email.send_external", "webhook.*", "slack.post_external"],
  rules: [
    { rule_id: "pii-external", tool: "*", data_class: { secrets: true, pii: ["phone", "national_id", "credit_card", "iban", "postal_address"] }, effect: "block", reason: "Personal data and secrets may not leave through an external tool" },
  ],
});

const FINANCE_CLOSE = doc({
  default_effect: "escalate",
  tool_allowlist_enforced: true,
  tool_allowlist: ["ledger.*", "payments.transfer", "email.send_internal"],
  sensitive_tools: ["ledger.post_journal", "payments.transfer"],
  rules: [
    { rule_id: "journal-small", tool: "ledger.post_journal", when: { le: ["/amount", 250000] }, effect: "allow", reason: "Journals up to ₹2,50,000 post directly" },
    { rule_id: "vendor-allowlist", tool: "payments.transfer", when: { not: { in: ["/vendor_id", ["V-1021", "V-1088", "V-2210"]] } }, effect: "block", reason: "Vendor is not on the approved list" },
  ],
});

/** Build one version row in the API shape (also used by the demo's `POST /action-policies`). */
export function policyRecord(input: {
  id: string;
  lineage: string;
  versionNo: number;
  name: string;
  scope: PolicyScope;
  state: PolicyState;
  body: PolicyDocumentBody;
  fourEyes: boolean;
  approvalFourEyes: boolean;
  changeNote: string | null;
  createdBy: string;
  createdAt: number;
}): ActionPolicyRecord {
  const document: ActionPolicyDocument = { ...input.body, policy_id: input.id, version: input.versionNo };
  return {
    id: input.id,
    policy_id: input.lineage,
    name: input.name,
    scope: input.scope,
    scope_kind: input.scope.kind,
    scope_id: input.scope.id,
    version_no: input.versionNo,
    state: input.state,
    document,
    document_sha256: sha256(canonical(document)),
    default_effect: document.default_effect,
    hold_timeout_s: document.hold_timeout_s,
    four_eyes: input.fourEyes,
    approval_four_eyes: input.approvalFourEyes,
    rules: ruleViews(document),
    change_note: input.changeNote,
    approvals: [],
    created_by: input.createdBy,
    approved_by: null,
    approved_at: null,
    retired_by: null,
    retired_at: null,
    superseded_by: null,
    superseded_at: null,
    created_at: iso(input.createdAt),
    updated_at: iso(input.createdAt),
  };
}

interface SeedVersion {
  version: number;
  state: PolicyState;
  body: PolicyDocumentBody;
  note: string;
  ageHours: number;
  createdBy: string;
  approvedBy?: string;
}

interface SeedPolicy {
  key: string;
  name: string;
  scope: (w: World) => PolicyScope;
  /** Held actions under this policy need two distinct approvers. */
  fourEyes: boolean;
  /** A tier-1 agent is in scope: the author cannot approve a version. */
  approvalFourEyes: boolean;
  versions: SeedVersion[];
}

const MERIDIAN: SeedPolicy[] = [
  {
    key: "claims-payouts",
    name: "Claims payouts",
    scope: (w) => ({ kind: "agent", id: agentId(w.slug, "claims-triage"), label: "Claims triage" }),
    fourEyes: false,
    approvalFourEyes: true,
    versions: [
      { version: 2, state: "superseded", body: CLAIMS_PAYOUTS(75000), note: "Add the ₹1,00,000 single-transfer limit", ageHours: 52, createdBy: ADMIN, approvedBy: OPERATOR },
      { version: 3, state: "approved", body: CLAIMS_PAYOUTS(50000), note: "Lower the review threshold to ₹50,000 after the Q3 audit", ageHours: 26, createdBy: ADMIN, approvedBy: OPERATOR },
    ],
  },
  {
    key: "refund-guardrails",
    name: "Refund guardrails",
    scope: (w) => ({ kind: "agent", id: agentId(w.slug, "returns-agent"), label: "Returns agent" }),
    fourEyes: true,
    approvalFourEyes: false,
    versions: [
      { version: 1, state: "superseded", body: REFUNDS(10), note: "First refund caps", ageHours: 60, createdBy: ADMIN, approvedBy: ADMIN },
      { version: 2, state: "approved", body: REFUNDS(5), note: "Halve the burst cap after the duplicate-refund incident", ageHours: 30, createdBy: OPERATOR, approvedBy: OPERATOR },
    ],
  },
  {
    key: "data-egress",
    name: "Personal data egress",
    scope: () => ({ kind: "tenant", id: null, label: "All agents" }),
    fourEyes: false,
    approvalFourEyes: true,
    versions: [{ version: 1, state: "approved", body: EGRESS, note: "DPDP: no personal data to external tools", ageHours: 64, createdBy: OPERATOR, approvedBy: ADMIN }],
  },
  {
    key: "finance-close",
    name: "Finance close tools",
    scope: (w) => ({ kind: "agent_group", id: groupId(w, "Finance close"), label: "Finance close" }),
    fourEyes: false,
    approvalFourEyes: false,
    versions: [{ version: 1, state: "draft", body: FINANCE_CLOSE, note: "Lock finance-close agents to ledger and approved vendors", ageHours: 3, createdBy: ADMIN }],
  },
  {
    key: "legacy-refunds",
    name: "Legacy refund rule",
    scope: (w) => ({ kind: "agent", id: agentId(w.slug, "customer-chat"), label: "Customer chat" }),
    fourEyes: false,
    approvalFourEyes: false,
    versions: [{ version: 1, state: "retired", body: REFUNDS(20), note: "Pilot cap from the beta", ageHours: 70, createdBy: ADMIN, approvedBy: ADMIN }],
  },
];

const NORTHSTAR: SeedPolicy[] = [
  {
    key: "data-egress",
    name: "Personal data egress",
    scope: () => ({ kind: "tenant", id: null, label: "All agents" }),
    fourEyes: false,
    approvalFourEyes: true,
    versions: [{ version: 1, state: "approved", body: EGRESS, note: "Patient data never leaves through external tools", ageHours: 40, createdBy: OPERATOR, approvedBy: ADMIN }],
  },
];

const versionId = (w: World, key: string, v: number): string => idFor(`${w.slug}:action-policy:${key}:v${v}`);

function seedOne(w: World, spec: SeedPolicy, at: number): void {
  const first = spec.versions[0];
  if (!first) return;
  const lineage = versionId(w, spec.key, first.version);
  spec.versions.forEach((v, i) => {
    const created = Math.max(at, w.anchorAt - v.ageHours * HOUR);
    const approved = created + 40 * MINUTE;
    const id = versionId(w, spec.key, v.version);
    const decided = v.state !== "draft";
    const next = spec.versions[i + 1];
    const base = policyRecord({ id, lineage, versionNo: v.version, name: spec.name, scope: spec.scope(w), state: v.state, body: v.body, fourEyes: spec.fourEyes, approvalFourEyes: spec.approvalFourEyes, changeNote: v.note, createdBy: v.createdBy, createdAt: created });
    const supersededAt = next ? Math.max(at, w.anchorAt - next.ageHours * HOUR) + 40 * MINUTE : null;
    const retiredAt = v.state === "retired" ? approved + 6 * HOUR : null;
    const rec: ActionPolicyRecord = {
      ...base,
      approvals: decided && v.approvedBy ? [{ user_id: v.approvedBy, at: iso(approved), reason: REVIEWED }] : [],
      approved_by: decided ? (v.approvedBy ?? null) : null,
      approved_at: decided ? iso(approved) : null,
      retired_by: retiredAt ? ADMIN : null,
      retired_at: retiredAt ? iso(retiredAt) : null,
      superseded_by: v.state === "superseded" && next ? versionId(w, spec.key, next.version) : null,
      superseded_at: v.state === "superseded" && supersededAt ? iso(supersededAt) : null,
      updated_at: iso(retiredAt ?? supersededAt ?? (decided ? approved : created)),
    };
    w.actionPolicies.set(id, rec);
    appendAudit(w, { action: "action_policy.created", actor_type: "human", actor_id: v.createdBy, resource_type: "action_policy", resource_id: id, resource_ref: spec.name, reason: v.note, detail: { policy_id: id, lineage_policy_id: lineage, version_no: v.version, scope_kind: rec.scope_kind, scope_id: rec.scope_id, document_sha256: rec.document_sha256 } }, created);
    if (decided) appendAudit(w, { action: "action_policy.approved", actor_type: "human", actor_id: v.approvedBy ?? null, resource_type: "action_policy", resource_id: id, resource_ref: spec.name, reason: REVIEWED, detail: { policy_id: id, version_no: v.version, approved_by: v.approvedBy ?? null, four_eyes: spec.approvalFourEyes, document_sha256: rec.document_sha256 } }, approved);
    if (retiredAt) appendAudit(w, { action: "action_policy.retired", actor_type: "human", actor_id: ADMIN, resource_type: "action_policy", resource_id: id, resource_ref: spec.name, reason: "Replaced by Refund guardrails", detail: { policy_id: id, version_no: v.version } }, retiredAt);
  });
}

export function seedActionPolicies(w: World, at: number): void {
  const specs = w.slug === "meridian" ? MERIDIAN : w.slug === "northstar" ? NORTHSTAR : [];
  for (const spec of specs) seedOne(w, spec, at);
}
