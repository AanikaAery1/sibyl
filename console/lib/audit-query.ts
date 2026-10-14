/**
 * Audit list query rules (pure; unit-tested). The API filters `action` by exact match,
 * `actor_type` by enum, `resource_id` and `agent_id` by UUID, `occurred_after` /
 * `occurred_before` by instant, and lists by seq in the requested `order`. The console asks for
 * `order=desc` so the first page is the newest events. The action menu offers families
 * ("failover", "access"), so a family is filtered on the client and only exact actions go to the
 * API; rows are shown newest first.
 */
const ACTOR_TYPES = new Set(["human", "rule", "policy", "system", "agent", "api_key"]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTION_RE = /^[a-z_]+(\.[a-z_]+)+$/;
const FAMILY_RE = /^[a-z_]{1,40}$/;
/** RFC 3339 with an explicit offset (the API refuses a naive time). */
const INSTANT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

export interface AuditQuery {
  /** Query string for the API (without the leading "?"); never empty-valued params. */
  api: string;
  /** Action family to filter on the client, e.g. "failover" matches "failover.started". */
  family: string | null;
}

export interface AuditQueryInput {
  action?: string | null;
  actor_type?: string | null;
  resource_id?: string | null;
  agent_id?: string | null;
  occurred_after?: string | null;
  occurred_before?: string | null;
}

const instant = (v: string | null | undefined): string | null => (v && INSTANT_RE.test(v) && Number.isFinite(Date.parse(v)) ? v : null);

export function auditQuery(input: AuditQueryInput): AuditQuery {
  const q = new URLSearchParams();
  let family: string | null = null;
  const action = input.action?.trim() ?? "";
  if (ACTION_RE.test(action)) q.set("action", action);
  else if (FAMILY_RE.test(action)) family = action;
  if (input.actor_type && ACTOR_TYPES.has(input.actor_type)) q.set("actor_type", input.actor_type);
  if (input.resource_id && UUID_RE.test(input.resource_id)) q.set("resource_id", input.resource_id);
  if (input.agent_id && UUID_RE.test(input.agent_id)) q.set("agent_id", input.agent_id);
  const after = instant(input.occurred_after);
  const before = instant(input.occurred_before);
  if (after) q.set("occurred_after", after);
  if (before && (!after || Date.parse(before) > Date.parse(after))) q.set("occurred_before", before);
  q.set("order", "desc");
  return { api: q.toString(), family };
}

/** The `occurred_after` instant for "the last `hours` hours" before `now` (ms). */
export function sinceHours(now: number, hours: number): string {
  return new Date(now - hours * 3_600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function matchesFamily(action: string, family: string | null): boolean {
  return !family || action === family || action.startsWith(`${family}.`) || action.startsWith(`${family}_`);
}

/** Newest first, whatever order the server used. */
export function newestFirst<T extends { seq: number }>(rows: readonly T[]): T[] {
  return [...rows].sort((a, b) => b.seq - a.seq);
}

/** The most recent anchor, whatever order the server used. */
export function latestAnchor<T extends { seq_to: number }>(anchors: readonly T[]): T | null {
  return anchors.reduce<T | null>((best, a) => (!best || a.seq_to > best.seq_to ? a : best), null);
}
