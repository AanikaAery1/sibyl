/**
 * POST /api/bff/auth/logout (live mode): revokes the session at the API (`access.logout` is
 * audited there), relays the API's cookie-clearing header and clears the cookie itself too, so
 * the browser is signed out even when the API is unreachable. CSRF-checked like every mutation.
 */
import type { NextRequest } from "next/server";
import { ProblemError } from "@/lib/api/problem";
import { assertCsrf, json, problem } from "@/lib/bff/http";
import { apiBaseUrl, consoleMode } from "@/lib/bff/mode";
import { SESSION_COOKIE, liveSessionToken } from "@/lib/bff/principal";

export const dynamic = "force-dynamic";

const CLEAR = `${SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;

export async function POST(req: NextRequest): Promise<Response> {
  try {
    assertCsrf(req);
  } catch (err) {
    if (err instanceof ProblemError) return problem(err);
    throw err;
  }
  if (consoleMode() !== "live") return json({ redirect: "/fleet" });
  const token = await liveSessionToken();
  let revoked = false;
  if (token) {
    try {
      const res = await fetch(`${apiBaseUrl()}/api/v1/auth/logout`, {
        method: "POST",
        headers: { accept: "application/json", authorization: `Bearer sibyl_sess_${token}` },
        cache: "no-store",
        signal: AbortSignal.timeout(10_000),
      });
      revoked = res.status === 204 || res.status === 401;
    } catch {
      revoked = false;
    }
  }
  const res = json({ redirect: "/login?error=signed_out", revoked });
  res.headers.append("set-cookie", CLEAR);
  return res;
}
