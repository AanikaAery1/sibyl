/**
 * SSE (API §7). Live mode relays the API's outbox stream unchanged: ids are outbox cursors,
 * payloads are refs and versions only, `: ping` heartbeats, resume via Last-Event-ID (the
 * EventSource header, or `?last_event_id=` from the console's manual reconnect). An upstream
 * refusal keeps its status (401/403/429) so the client can react; it never turns into demo
 * events. Demo mode simulates the same projection over the demo world's outbox.
 */
import type { NextRequest } from "next/server";
import { consoleMode, apiBaseUrl } from "@/lib/bff/mode";
import { currentPrincipal, demoTenantOf, liveSessionToken } from "@/lib/bff/principal";
import { resumeId, upstreamStreamHeaders } from "@/lib/bff/sse";
import { getWorld } from "@/lib/demo/store";

export const dynamic = "force-dynamic";

const POLL_MS = 1000;
const PING_MS = 15_000;
const STREAM_HEADERS = { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store, no-transform", connection: "keep-alive", "x-accel-buffering": "no" };
const PASS_QUERY = ["topics", "agent_id", "since"] as const;

async function liveStream(req: NextRequest): Promise<Response> {
  const token = await liveSessionToken();
  if (!token) return new Response(null, { status: 401 });
  const qs = new URLSearchParams();
  for (const k of PASS_QUERY) {
    const v = req.nextUrl.searchParams.get(k);
    if (v) qs.set(k, v);
  }
  const lastId = resumeId(req.headers.get("last-event-id"), req.nextUrl.searchParams.get("last_event_id"));
  const upstream = await fetch(`${apiBaseUrl()}/api/v1/events/stream${qs.size ? `?${qs.toString()}` : ""}`, {
    headers: upstreamStreamHeaders(token, lastId),
    cache: "no-store",
    signal: req.signal,
  }).catch(() => null);
  if (!upstream) return new Response(null, { status: 502 });
  if (!upstream.ok || !upstream.body) {
    return new Response(null, { status: upstream.status === 200 ? 502 : upstream.status, headers: upstream.headers.get("retry-after") ? { "retry-after": upstream.headers.get("retry-after") ?? "" } : {} });
  }
  return new Response(upstream.body, { headers: STREAM_HEADERS });
}

export async function GET(req: NextRequest): Promise<Response> {
  if (consoleMode() === "live") return liveStream(req);

  const principal = await currentPrincipal();
  if (!principal.scopes.includes("agents:read")) return new Response(null, { status: 403 });
  const tenant = demoTenantOf(principal.tenant);
  const encoder = new TextEncoder();
  const lastId = resumeId(req.headers.get("last-event-id"), req.nextUrl.searchParams.get("last_event_id") ?? req.nextUrl.searchParams.get("since_id"));
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let cursor = lastId ?? null;
      let lastPing = Date.now();
      let closed = false;
      const send = (s: string): void => {
        if (!closed) controller.enqueue(encoder.encode(s));
      };
      send("retry: 3000\n\n");
      if (!cursor) {
        const w = getWorld(tenant);
        cursor = w.outbox.at(-1)?.id ?? "";
      }
      const tick = (): void => {
        if (closed) return;
        const w = getWorld(tenant);
        const idx = cursor ? w.outbox.findIndex((e) => e.id === cursor) : -1;
        const fresh = idx >= 0 ? w.outbox.slice(idx + 1) : cursor ? [] : w.outbox.slice(-50);
        if (idx < 0 && cursor && w.outbox.length > 0 && !w.outbox.some((e) => e.id === cursor)) {
          send(`event: reset\ndata: ${JSON.stringify({ reason: "cursor_expired", oldest: w.outbox[0]?.id ?? null })}\n\n`);
          cursor = w.outbox.at(-1)?.id ?? null;
        }
        for (const e of fresh) {
          send(`id: ${e.id}\nevent: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`);
          cursor = e.id;
        }
        if (Date.now() - lastPing > PING_MS) {
          send(": ping\n\n");
          lastPing = Date.now();
        }
      };
      const timer = setInterval(tick, POLL_MS);
      const stop = (): void => {
        if (closed) return;
        closed = true;
        clearInterval(timer);
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };
      req.signal.addEventListener("abort", stop);
    },
  });
  return new Response(stream, { headers: STREAM_HEADERS });
}
