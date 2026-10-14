/**
 * Settings, onboarding and audit operations in demo mode: capture policy (D12), API keys
 * (secret shown once), tenant-key rotation behind step-up, chain verification and exports.
 */
import "server-only";
import { ProblemError, notFound } from "@/lib/api/problem";
import type { ApiKey, ApiKeyCreate, ApiKeyCreated, ApiKeyScope, AuditExport, CapturePolicy, CapturePolicyCreate, TenantKeyPurpose, VerificationResult } from "@/lib/api/types";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { SECOND, idFor, iso, tokenFor } from "./core";
import { requireScope, requireStepUp } from "./actions";
import { appendAudit, makeAnchor, nextId, sha256, verifyChain, type World } from "./world";

const KEY_SCOPES: ReadonlySet<ApiKeyScope> = new Set<ApiKeyScope>(["agents:read", "agents:write", "routing:read", "killswitch:pull", "gateway:proxy", "ingest:write", "handoff:write"]);
const DAY = 86_400_000;

export function createCapturePolicy(w: World, p: BffPrincipal, body: CapturePolicyCreate, t: number): CapturePolicy {
  requireScope(p, "capture:write");
  if (!body.capture_mode) throw new ProblemError(422, "capture_mode_required", "Choose a capture mode", "There is no default capture mode (D12); pick full, redacted or metadata.");
  if (body.acknowledged !== true) throw new ProblemError(422, "validation_failed", "Acknowledge the consequences", "Confirm you have read what each capture mode stores.", { errors: [{ pointer: "/acknowledged", code: "required", message: "Required" }] });
  const days = body.payload_retention_days;
  if (!Number.isInteger(days) || days < 1 || days > 365) throw new ProblemError(422, "validation_failed", "Retention out of range", "Payload retention is 1–365 days.", { errors: [{ pointer: "/payload_retention_days", code: "range", message: "1–365" }] });
  const prev = w.capturePolicies.find((c) => c.scope_kind === "tenant" && !c.superseded_by);
  const id = nextId(w, "capture");
  const policy: CapturePolicy = { id, scope_kind: body.scope_kind, agent_id: body.agent_id ?? null, capture_mode: body.capture_mode, redaction_profile_id: body.redaction_profile_id, payload_retention_days: days, max_payload_bytes: body.max_payload_bytes ?? 262144, header_allowlist: body.header_allowlist ?? [], consequences_version: body.consequences_version, version_no: (prev?.version_no ?? 0) + 1, superseded_by: null, created_at: iso(t) };
  w.capturePolicies = [...w.capturePolicies.map((c) => (c.id === prev?.id ? { ...c, superseded_by: id } : c)), policy];
  appendAudit(w, { action: "capture.policy_set", actor_type: "human", actor_id: p.userId, resource_type: "capture_policy", resource_id: id, detail: { capture_mode: body.capture_mode, payload_retention_days: days, scrub: "secrets_only (always on)", version_no: policy.version_no } }, t);
  return policy;
}

function validateScopes(scopes: readonly ApiKeyScope[], agentIdIn: string | undefined): void {
  if (scopes.length === 0 || scopes.some((s) => !KEY_SCOPES.has(s))) throw new ProblemError(400, "invalid_scope", "Invalid scope", "Keys can only carry machine scopes (agents:*, routing:read, gateway:proxy, ingest:write, handoff:write, killswitch:pull).");
  if (scopes.includes("killswitch:pull") && (scopes.length !== 1 || agentIdIn)) {
    throw new ProblemError(422, "break_glass_scope_exclusive", "Break-glass keys carry one scope", "A key with killswitch:pull must have exactly that scope and no agent binding (D20).");
  }
}

export function createApiKey(w: World, p: BffPrincipal, body: ApiKeyCreate, t: number): ApiKeyCreated {
  requireScope(p, body.agent_id ? "apikeys:manage_agent" : "apikeys:manage");
  if (body.scopes?.includes("killswitch:pull")) requireStepUp(p, t);
  if (!w.capturePolicies.some((c) => c.scope_kind === "tenant" && !c.superseded_by)) {
    throw new ProblemError(409, "capture_policy_missing", "Set a capture policy first", "Sibyl will not mint keys until the tenant has a capture policy (D12). Choose one in onboarding step 1.");
  }
  const name = (body.name ?? "").trim();
  if (!name || name.length > 80) throw new ProblemError(422, "validation_failed", "Name required", "Give the key a name of 1–80 characters.", { errors: [{ pointer: "/name", code: "length", message: "1–80 characters" }] });
  validateScopes(body.scopes ?? [], body.agent_id);
  const id = nextId(w, "apikey");
  const prefix = tokenFor(`prefix:${id}`, 12);
  const secret = `sbl_live_${prefix}_${tokenFor(`secret:${id}`, 43)}`;
  const key: ApiKey = { id, name, env: "live", prefix, scopes: body.scopes, agent_id: body.agent_id ?? null, status: "active", expires_at: body.expires_at ?? iso(t + 365 * DAY), last_used_at: null, last_used_ip_hash: null, rotated_from_id: null, rotation_grace_until: null, created_by: p.userId, created_at: iso(t) };
  w.apiKeys = [...w.apiKeys, key];
  appendAudit(w, { action: "api_key.created", actor_type: "human", actor_id: p.userId, resource_type: "api_key", resource_id: id, resource_ref: name, detail: { scopes: body.scopes, agent_id: body.agent_id ?? null, prefix }, severity: body.scopes.includes("killswitch:pull") ? "warning" : "info" }, t);
  if (w.slug === "sandbox" && body.scopes.includes("gateway:proxy") && !w.pending.some((x) => x.slug === "quote-worker")) {
    w.pending = [...w.pending, { at: t + 5 * SECOND, kind: "discover", slug: "quote-worker" }];
  }
  return { ...key, secret };
}

export function revokeApiKey(w: World, p: BffPrincipal, id: string, reason: string | undefined, t: number): ApiKey {
  const key = w.apiKeys.find((k) => k.id === id);
  if (!key) throw notFound("API key");
  requireScope(p, key.agent_id ? "apikeys:manage_agent" : "apikeys:manage");
  if (key.status === "revoked") throw new ProblemError(409, "already_revoked", "Already revoked", "This key is already revoked.");
  const next: ApiKey = { ...key, status: "revoked" };
  w.apiKeys = w.apiKeys.map((k) => (k.id === id ? next : k));
  appendAudit(w, { action: "api_key.revoked", actor_type: "human", actor_id: p.userId, resource_type: "api_key", resource_id: id, resource_ref: key.name, reason: reason ?? null, detail: { prefix: key.prefix } }, t);
  return next;
}

export function rotateApiKey(w: World, p: BffPrincipal, id: string, t: number): ApiKeyCreated {
  const key = w.apiKeys.find((k) => k.id === id);
  if (!key) throw notFound("API key");
  requireScope(p, key.agent_id ? "apikeys:manage_agent" : "apikeys:manage");
  if (key.status !== "active") throw new ProblemError(409, "key_not_active", "Key is not active", `This key is ${key.status}.`);
  const created = createApiKey(w, p, { name: key.name, env: "live", scopes: key.scopes, ...(key.agent_id ? { agent_id: key.agent_id } : {}) }, t);
  w.apiKeys = w.apiKeys.map((k) => (k.id === id ? { ...k, status: "rotating", rotation_grace_until: iso(t + 3600 * SECOND) } : k.id === created.id ? { ...k, rotated_from_id: id } : k));
  appendAudit(w, { action: "api_key.rotated", actor_type: "human", actor_id: p.userId, resource_type: "api_key", resource_id: id, resource_ref: key.name, detail: { new_key_id: created.id, grace_s: 3600 } }, t);
  return { ...created, rotated_from_id: id };
}

export function rotateTenantKey(w: World, p: BffPrincipal, purpose: TenantKeyPurpose, reason: string | undefined, t: number) {
  requireScope(p, "keys:rotate");
  requireStepUp(p, t);
  if (!reason || reason.trim().length < 10) throw new ProblemError(422, "validation_failed", "Reason too short", "Give a reason of at least 10 characters.");
  const active = w.tenantKeys.find((k) => k.purpose === purpose && k.state === "active");
  if (!active) throw notFound("Tenant key");
  const next = { ...active, id: idFor(`tkey:${w.slug}:${purpose}:${active.version + 1}`), version: active.version + 1, activated_at: iso(t) };
  w.tenantKeys = [...w.tenantKeys.map((k) => (k.id === active.id ? { ...k, state: "retired" as const, retired_at: iso(t) } : k)), next];
  appendAudit(w, { action: "tenant_key.rotated", actor_type: "human", actor_id: p.userId, resource_type: "tenant_key", resource_id: next.id, resource_ref: purpose, reason, detail: { purpose, from_version: active.version, to_version: next.version, rewrap: "background job queued" }, severity: "warning" }, t);
  return { purpose, previous_version: active.version, active: next, rewrap_job_id: nextId(w, "job") };
}

export function verifyAudit(w: World, p: BffPrincipal, body: { from_seq?: number; to_seq?: number }, t: number): VerificationResult {
  requireScope(p, "audit:verify");
  const rows = w.audit.filter((r) => (body.from_seq ? r.seq >= body.from_seq : true) && (body.to_seq ? r.seq <= body.to_seq : true));
  const fullCheck = verifyChain(w.audit, w.anchors);
  const res: VerificationResult = { ok: fullCheck.ok, rows: rows.length, anchors_checked: fullCheck.anchors_checked, first_break_seq: fullCheck.first_break_seq, kind: fullCheck.ok ? null : "hash_mismatch" };
  appendAudit(w, { action: fullCheck.ok ? "audit.verified" : "audit.verify_failed", actor_type: "human", actor_id: p.userId, resource_type: "audit_chain", resource_ref: w.slug, detail: { rows: res.rows, anchors_checked: res.anchors_checked } }, t);
  return res;
}

/** Demo-only: verify a copy of the chain with one byte changed, to show what a break looks like. */
export function tamperedCheck(w: World): VerificationResult & { tampered_seq: number } {
  const victim = w.audit[Math.floor(w.audit.length * 0.6)];
  const seq = victim?.seq ?? 1;
  const copy = w.audit.map((r) => (r.seq === seq ? { ...r, reason: `${r.reason ?? ""}x` } : r));
  const res = verifyChain(copy, w.anchors);
  return { ok: res.ok, rows: res.rows, anchors_checked: res.anchors_checked, first_break_seq: res.first_break_seq, kind: "hash_mismatch", tampered_seq: seq };
}

export function createExport(w: World, p: BffPrincipal, body: { from_seq?: number; to_seq?: number; format?: "jsonl" | "csv" }, t: number): AuditExport {
  requireScope(p, "audit:export");
  const running = [...w.exports.values()].find((e) => e.state === "queued" || e.state === "running");
  if (running) throw new ProblemError(409, "export_in_progress", "An export is already running", "One export runs at a time per tenant.");
  const id = nextId(w, "export");
  const fromSeq = body.from_seq ?? 1;
  const toSeq = body.to_seq ?? w.seq;
  appendAudit(w, { action: "audit.exported", actor_type: "human", actor_id: p.userId, resource_type: "audit_export", resource_id: id, detail: { from_seq: fromSeq, to_seq: toSeq, format: body.format ?? "jsonl" }, severity: "info" }, t);
  const exp = { id, requested_real: Date.now(), state: "queued" as const, from_seq: fromSeq, to_seq: toSeq, format: body.format ?? "jsonl", anchor_id: null, export_sha256: null, download_url: null, download_expires_at: null, requested_at: t, body: null, anchor: null };
  w.exports.set(id, exp);
  return stripExport(exp);
}

/**
 * Exports progress queued → running → done over ~3 s of real time (worker work does not stop
 * when the scenario clock is paused); the worker writes an export anchor first.
 */
export function exportView(w: World, id: string, t: number): AuditExport {
  const exp = w.exports.get(id);
  if (!exp) throw notFound("Export");
  const age = Date.now() - exp.requested_real;
  if (exp.state !== "done" && age >= 3 * SECOND) {
    const anchor = makeAnchor(w, "export", exp.requested_at + 1500) ?? w.anchors.at(-1) ?? null;
    const rows = w.audit.filter((r) => r.seq >= exp.from_seq && r.seq <= exp.to_seq);
    const body = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
    w.exports.set(id, { ...exp, state: "done", anchor_id: anchor?.id ?? null, export_sha256: sha256(body), download_url: `/api/bff/audit/exports/${id}/download`, download_expires_at: iso(t + 15 * 60 * SECOND), body, anchor });
  } else if (exp.state === "queued" && age >= SECOND) {
    w.exports.set(id, { ...exp, state: "running" });
  }
  const cur = w.exports.get(id);
  if (!cur) throw notFound("Export");
  return stripExport(cur);
}

function stripExport(e: AuditExport & { requested_at: number; body: string | null }): AuditExport {
  return { id: e.id, state: e.state, from_seq: e.from_seq, to_seq: e.to_seq, format: e.format, anchor_id: e.anchor_id ?? null, export_sha256: e.export_sha256 ?? null, download_url: e.download_url ?? null, download_expires_at: e.download_expires_at ?? null };
}
