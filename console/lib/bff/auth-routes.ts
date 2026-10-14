/**
 * Server side of the live sign-in relays used by app/api/bff/auth/**: call the API's auth
 * endpoint with `redirect: "manual"`, then hand its 302 and Set-Cookie headers to the browser.
 */
import "server-only";
import type { NextRequest } from "next/server";
import { relayRedirect, type RelayResult } from "./auth-relay";

const AUTH_TIMEOUT_MS = 10_000;

/**
 * The client address Caddy saw, forwarded so the API's per-IP auth limits and ip_hash see the
 * user. Caddy overwrites X-Forwarded-For with the peer address, so the last hop is the one it
 * added (a client-supplied value can never be chosen). The API honours it only once the console
 * is in SIBYL_TRUSTED_PROXIES (lane C2 change request); until then it sees the console's IP.
 */
function forwardedFor(req: NextRequest): Record<string, string> {
  const xff = req.headers.get("x-forwarded-for")?.split(",").at(-1)?.trim();
  return xff ? { "x-forwarded-for": xff } : {};
}

export async function callAuth(req: NextRequest, url: string, init: { method: "GET" | "POST"; token?: string | null; body?: unknown }): Promise<RelayResult> {
  let res: Response;
  try {
    res = await fetch(url, {
      method: init.method,
      redirect: "manual",
      cache: "no-store",
      signal: AbortSignal.timeout(AUTH_TIMEOUT_MS),
      headers: {
        accept: "application/json",
        "user-agent": req.headers.get("user-agent") ?? "sibyl-console",
        ...forwardedFor(req),
        ...(init.token ? { authorization: `Bearer sibyl_sess_${init.token}` } : {}),
        ...(init.body !== undefined ? { "content-type": "application/json" } : {}),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
  } catch {
    return { ok: false, code: "upstream_unavailable", status: 502 };
  }
  let body: { type?: unknown } | null = null;
  if (res.status !== 302 && res.status !== 303) {
    try {
      body = (await res.json()) as { type?: unknown };
    } catch {
      body = null;
    }
  }
  return relayRedirect(res, body);
}

/** A 302 to `location` carrying the relayed cookies (plus any the console adds). */
export function redirectWith(location: string, cookies: readonly string[] = []): Response {
  const headers = new Headers({ location, "cache-control": "no-store" });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 302, headers });
}
