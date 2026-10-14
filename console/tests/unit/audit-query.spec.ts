/** Audit filters against the API's rules (lib/audit-query.ts). */
import { expect, test } from "@playwright/test";
import { auditQuery, latestAnchor, matchesFamily, newestFirst, sinceHours } from "@/lib/audit-query";

const AGENT = "0192a000-0000-7000-8000-00000000a001";

test("exact actions go to the API; families are filtered on the client; newest first always", () => {
  expect(auditQuery({ action: "route.changed" })).toEqual({ api: "action=route.changed&order=desc", family: null });
  expect(auditQuery({ action: "failover" })).toEqual({ api: "order=desc", family: "failover" });
  expect(auditQuery({ action: "" })).toEqual({ api: "order=desc", family: null });
});

test("actor_type must be a known actor and resource_id a UUID, else they are dropped", () => {
  expect(auditQuery({ actor_type: "human" }).api).toBe("actor_type=human&order=desc");
  expect(auditQuery({ actor_type: "robot" }).api).toBe("order=desc");
  expect(auditQuery({ resource_id: "0192a000-0000-7000-8000-00000000d001" }).api).toBe("resource_id=0192a000-0000-7000-8000-00000000d001&order=desc");
  expect(auditQuery({ resource_id: "inc-42" }).api).toBe("order=desc");
});

test("agent_id must be a UUID; occurred_after / occurred_before need an RFC 3339 instant with an offset", () => {
  expect(auditQuery({ agent_id: AGENT }).api).toBe(`agent_id=${AGENT}&order=desc`);
  expect(auditQuery({ agent_id: "claims-triage" }).api).toBe("order=desc");
  const q = new URLSearchParams(auditQuery({ occurred_after: "2026-10-09T03:30:00Z", occurred_before: "2026-10-10T03:30:00+05:30" }).api);
  expect(q.get("occurred_after")).toBe("2026-10-09T03:30:00Z");
  expect(q.get("occurred_before")).toBe("2026-10-10T03:30:00+05:30");
  expect(auditQuery({ occurred_after: "2026-10-09 03:30" }).api).toBe("order=desc");
  expect(auditQuery({ occurred_after: "2026-10-09T03:30:00" }).api).toBe("order=desc");
  // An empty window is dropped on the "before" side rather than sent for a 422.
  expect(new URLSearchParams(auditQuery({ occurred_after: "2026-10-10T00:00:00Z", occurred_before: "2026-10-09T00:00:00Z" }).api).has("occurred_before")).toBe(false);
});

test("sinceHours gives the occurred_after instant for a relative window", () => {
  expect(sinceHours(Date.parse("2026-10-10T03:30:00.250Z"), 24)).toBe("2026-10-09T03:30:00Z");
});

test("families match dotted and snake-case actions", () => {
  expect(matchesFamily("failover.started", "failover")).toBe(true);
  expect(matchesFamily("api_key.created", "api_key")).toBe(true);
  expect(matchesFamily("access.login", "api_key")).toBe(false);
  expect(matchesFamily("anything", null)).toBe(true);
});

test("rows are shown newest first and the latest anchor is the highest seq_to", () => {
  expect(newestFirst([{ seq: 1 }, { seq: 3 }, { seq: 2 }]).map((r) => r.seq)).toEqual([3, 2, 1]);
  expect(latestAnchor([{ seq_to: 10 }, { seq_to: 40 }, { seq_to: 20 }])).toEqual({ seq_to: 40 });
  expect(latestAnchor([])).toBeNull();
});
