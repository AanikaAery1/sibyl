/** SSE relay (lib/bff/sse.ts): Last-Event-ID resume and upstream headers. */
import { expect, test } from "@playwright/test";
import { resumeId, upstreamStreamHeaders } from "@/lib/bff/sse";

const CURSOR = "9001|0192a000-0000-7000-8000-000000000001";

test("prefers the Last-Event-ID header, then the last_event_id query (manual reconnects)", () => {
  expect(resumeId(CURSOR, "x")).toBe(CURSOR);
  expect(resumeId(null, CURSOR)).toBe(CURSOR);
  expect(resumeId("", CURSOR)).toBe(CURSOR);
  expect(resumeId(null, null)).toBeNull();
});

test("drops ids that are too long or carry control characters", () => {
  expect(resumeId("a".repeat(129), null)).toBeNull();
  expect(resumeId("1|x\r\nevil: 1", null)).toBeNull();
});

test("upstream headers carry the bearer and the resume point, nothing else", () => {
  const token = "t".repeat(43);
  expect(upstreamStreamHeaders(token, "5|abc")).toEqual({ accept: "text/event-stream", authorization: `Bearer sibyl_sess_${token}`, "last-event-id": "5|abc" });
  expect(upstreamStreamHeaders(token, null)).not.toHaveProperty("last-event-id");
});
