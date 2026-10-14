/**
 * Helpers for relaying the API's OIDC redirects through the console (pure; unit-tested).
 *
 * The API owns the code flow (`/auth/login`, `/auth/callback`, `/auth/step-up`, `/auth/logout`)
 * and sets its cookies (`__Host-sibyl_oidc_state`, `__Host-sibyl_session`). The console starts
 * each flow server-side so it can validate input and turn a refusal into a designed message,
 * then relays the API's 302 and Set-Cookie headers unchanged. Console and API share one origin
 * behind Caddy, so the cookies are first-party for both.
 */
import { problemCode } from "@/lib/api/problem";

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;
const MAX_RETURN_TO = 2048;

export function tenantSlugOk(slug: string | null | undefined): boolean {
  return typeof slug === "string" && SLUG_RE.test(slug);
}

/** Same rule as the API's `safe_return_to`, plus: never return to the login screen itself. */
export function safeReturnTo(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/";
  if (value.includes("\\") || value.length > MAX_RETURN_TO) return "/";
  for (const ch of value) if (ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f) return "/";
  if (value === "/login" || value.startsWith("/login?") || value.startsWith("/login/")) return "/";
  return value;
}

export function loginUpstreamUrl(apiBase: string, tenant: string, returnTo: string): string {
  const qs = new URLSearchParams({ tenant, return_to: returnTo });
  return `${apiBase}/api/v1/auth/login?${qs.toString()}`;
}

export type RelayResult = { ok: true; location: string; cookies: string[] } | { ok: false; code: string; status: number };

/** The only cookies the API may set through the console, and only as `__Host-` cookies. */
const RELAYED_COOKIES = new Set(["__Host-sibyl_session", "__Host-sibyl_oidc_state"]);

export function relayableCookie(header: string): boolean {
  const [pair = "", ...attrs] = header.split(";").map((p) => p.trim());
  const name = pair.split("=", 1)[0] ?? "";
  const lower = attrs.map((a) => a.toLowerCase());
  return RELAYED_COOKIES.has(name) && lower.includes("secure") && lower.includes("path=/") && !lower.some((a) => a.startsWith("domain="));
}

/** An IdP URL (http/https) or a same-origin absolute path; never `//host`, `javascript:` and the like. */
export function relayableLocation(location: string): boolean {
  if (location.startsWith("/")) return !location.startsWith("//") && !location.includes("\\");
  try {
    const u = new URL(location);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

/** A 302/303 with a safe Location is relayed; anything else is a failure carrying the problem code. */
export function relayRedirect(res: Response, body: { type?: unknown } | null): RelayResult {
  const location = res.headers.get("location");
  if ((res.status === 302 || res.status === 303) && location && relayableLocation(location)) {
    return { ok: true, location, cookies: res.headers.getSetCookie().filter(relayableCookie) };
  }
  const type = body && typeof body.type === "string" ? body.type : null;
  return { ok: false, code: type ? problemCode({ type }) : "unexpected_response", status: res.status };
}

const LOGIN_ERRORS: Record<string, string> = {
  tenant_unknown: "We could not find that workspace. Check the name with your administrator.",
  bad_tenant: "Workspace names use lowercase letters, numbers and hyphens.",
  oidc_failed: "The sign-in did not complete. Start again; if it keeps failing, your identity provider may have refused the account.",
  unauthenticated: "Your session ended. Sign in again to continue.",
  service_unavailable: "Sign-in is unavailable right now: the identity provider could not be reached.",
  upstream_unavailable: "The console could not reach the Sibyl API.",
  rate_limited: "Too many sign-in attempts. Wait a minute and try again.",
  signed_out: "You are signed out.",
};

export function loginErrorMessage(code: string | null | undefined): string | null {
  if (!code) return null;
  return LOGIN_ERRORS[code] ?? "Something went wrong signing you in. Please try again.";
}
