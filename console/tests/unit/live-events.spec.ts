/**
 * Every SSE event the API streams (sibyl_schemas `SseEventType`, minus the `reset` control frame)
 * revalidates something in the console. Copied from packages/sibyl-schemas/src/sibyl_schemas/_bus.py.
 */
import { expect, test } from "@playwright/test";
import { EVENT_PREFIXES } from "@/components/live/LiveProvider";

const SERVER_EVENTS = [
  "policy_changed",
  "snapshot.issued",
  "graph.changed",
  "health.transition",
  "alert.fired",
  "alert.resolved",
  "alert.updated",
  "provider_incident.opened",
  "provider_incident.resolved",
  "incident.updated",
  "approval.requested",
  "approval.decided",
  "approval.expired",
  "handoff.queued",
  "handoff.claimed",
  "handoff.completed",
  "handoff.returned",
  "handoff.expired",
  "killswitch.pulled",
  "killswitch.released",
  "killswitch.applied",
  "erasure.step",
];

test("the console listens for every streamed event type", () => {
  expect(Object.keys(EVENT_PREFIXES).sort()).toEqual([...SERVER_EVENTS].sort());
});

test("every event revalidates at least one contract path", () => {
  for (const prefixes of Object.values(EVENT_PREFIXES)) {
    expect(prefixes.length).toBeGreaterThan(0);
    for (const p of prefixes) expect(p.startsWith("/")).toBe(true);
  }
});
