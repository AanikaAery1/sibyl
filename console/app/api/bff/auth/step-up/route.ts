/**
 * GET /api/bff/auth/step-up?for_action=<op>&mode=popup|page&return_to=<path>
 * (live mode). Opened by the step-up dialog, normally in a small popup window: calls the API's
 * `POST /api/v1/auth/step-up` with the session bearer and relays its 302 to the identity
 * provider (`prompt=login max_age=0`) plus the state cookie. The IdP returns to the API's
 * callback, which stamps `session.step_up_at`, audits `access.step_up` and redirects to
 * `/auth/done` (popup: tells the opener and closes) or back to the page.
 *
 * It is a navigation, so it is guarded by fetch metadata rather than a token in the URL (which
 * would land in access logs): the browser must say Sec-Fetch-Site: same-origin (a missing header
 * is refused), and the SameSite=Strict CSRF cookie must be present.
 */
import type { NextRequest } from "next/server";
import { CSRF_COOKIE } from "@/lib/auth/personas";
import { safeReturnTo } from "@/lib/bff/auth-relay";
import { callAuth, redirectWith } from "@/lib/bff/auth-routes";
import { apiBaseUrl, consoleMode } from "@/lib/bff/mode";
import { liveSessionToken } from "@/lib/bff/principal";

export const dynamic = "force-dynamic";

const ACTION_RE = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/;

function done(params: Record<string, string>): Response {
  return redirectWith(`/auth/done?${new URLSearchParams(params).toString()}`);
}

export async function GET(req: NextRequest): Promise<Response> {
  const q = req.nextUrl.searchParams;
  const popup = q.get("mode") !== "page";
  const site = req.headers.get("sec-fetch-site");
  const csrfCookie = req.cookies.get(CSRF_COOKIE)?.value;
  if (site !== "same-origin" || !csrfCookie) return done({ status: "refused" });
  if (consoleMode() !== "live") return done({ status: "demo" });
  const token = await liveSessionToken();
  if (!token) return redirectWith("/login?error=unauthenticated");

  const forAction = q.get("for_action");
  const returnTo = popup ? "/auth/done?status=ok" : safeReturnTo(q.get("return_to"));
  const url = `${apiBaseUrl()}/api/v1/auth/step-up${forAction && ACTION_RE.test(forAction) ? `?for_action=${encodeURIComponent(forAction)}` : ""}`;
  const out = await callAuth(req, url, { method: "POST", token, body: { return_to: returnTo } });
  if (!out.ok) return out.code === "unauthenticated" ? redirectWith("/login?error=unauthenticated") : done({ status: "failed", code: out.code });
  return redirectWith(out.location, out.cookies);
}
