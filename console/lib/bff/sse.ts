/**
 * SSE relay helpers (pure; unit-tested). The browser's EventSource sends Last-Event-ID on its
 * own reconnects; the console's manual reconnect (after a non-200, which EventSource never
 * retries) passes the last seen id as `?last_event_id=` instead. Either way the BFF forwards it
 * upstream as the Last-Event-ID header (API §7).
 */
const MAX_ID = 128;
const SAFE_ID = /^[\x21-\x7e]+$/;

function clean(v: string | null | undefined): string | null {
  if (!v) return null;
  const t = v.trim();
  return t.length > 0 && t.length <= MAX_ID && SAFE_ID.test(t) ? t : null;
}

export function resumeId(header: string | null | undefined, query: string | null | undefined): string | null {
  return clean(header) ?? clean(query);
}

export function upstreamStreamHeaders(token: string, lastEventId: string | null): Record<string, string> {
  return {
    accept: "text/event-stream",
    authorization: `Bearer sibyl_sess_${token}`,
    ...(lastEventId ? { "last-event-id": lastEventId } : {}),
  };
}
