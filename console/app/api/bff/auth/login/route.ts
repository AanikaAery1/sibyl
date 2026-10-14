/**
 * GET /api/bff/auth/login?tenant=<slug>&return_to=<path> — tenant-first sign-in (live mode).
 * Starts the API's OIDC code flow (`/api/v1/auth/login`) server-side and relays its 302 to the
 * identity provider together with the sealed `__Host-sibyl_oidc_state` cookie. A refusal
 * (unknown workspace, IdP down) comes back to the glass login screen as a sentence, not JSON.
 * A plain GET form posts here, so sign-in works before any JavaScript loads.
 */
import type { NextRequest } from "next/server";
import { loginUpstreamUrl, safeReturnTo, tenantSlugOk } from "@/lib/bff/auth-relay";
import { callAuth, redirectWith } from "@/lib/bff/auth-routes";
import { apiBaseUrl, consoleMode } from "@/lib/bff/mode";
import { isHttps } from "@/lib/bff/origin";

export const dynamic = "force-dynamic";

const LAST_TENANT_COOKIE = "sibyl_last_tenant";
const YEAR_S = 365 * 24 * 3600;

function back(params: Record<string, string>): Response {
  return redirectWith(`/login?${new URLSearchParams(params).toString()}`);
}

export async function GET(req: NextRequest): Promise<Response> {
  const returnTo = safeReturnTo(req.nextUrl.searchParams.get("return_to"));
  if (consoleMode() !== "live") return redirectWith(returnTo === "/" ? "/fleet" : returnTo);
  const tenant = (req.nextUrl.searchParams.get("tenant") ?? "").trim().toLowerCase();
  if (!tenantSlugOk(tenant)) return back({ error: "bad_tenant", tenant: tenant.slice(0, 63), return_to: returnTo });
  const out = await callAuth(req, loginUpstreamUrl(apiBaseUrl(), tenant, returnTo), { method: "GET" });
  if (!out.ok) return back({ error: out.code, tenant, return_to: returnTo });
  const secure = isHttps(req.nextUrl.protocol, req.headers.get("x-forwarded-proto"));
  const remember = `${LAST_TENANT_COOKIE}=${tenant}; Path=/; Max-Age=${YEAR_S}; SameSite=Lax${secure ? "; Secure" : ""}`;
  return redirectWith(out.location, [...out.cookies, remember]);
}
