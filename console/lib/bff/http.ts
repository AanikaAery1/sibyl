/**
 * Helpers shared by the BFF route handlers: JSON/problem responses and the CSRF check
 * (API §2.1: Origin / Sec-Fetch-Site plus a double-submit X-Sibyl-CSRF header).
 */
import "server-only";
import { NextResponse, type NextRequest } from "next/server";
import { ProblemError } from "@/lib/api/problem";
import { CSRF_COOKIE, CSRF_HEADER } from "@/lib/auth/personas";
import { SOURCE_HEADER, type DataSource } from "./mode";
import { consoleOrigins } from "./origin";

export function json(body: unknown, status = 200, headers: Record<string, string> = {}, source?: DataSource): NextResponse {
  const isProblem = status >= 400 && body && typeof body === "object" && "type" in body;
  return NextResponse.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      ...(isProblem ? { "content-type": "application/problem+json" } : {}),
      ...(source ? { [SOURCE_HEADER]: source } : {}),
      ...headers,
    },
  });
}

export function problem(err: ProblemError): NextResponse {
  return json(err.problem, err.status);
}

/** Throws a 403 problem unless the request is same-origin and carries the CSRF token. */
export function assertCsrf(req: NextRequest): void {
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") {
    throw new ProblemError(403, "csrf_failed", "Cross-site request refused", "State-changing requests must come from the console itself.");
  }
  const origin = req.headers.get("origin");
  const own = consoleOrigins(req.nextUrl.origin, { proto: req.headers.get("x-forwarded-proto"), host: req.headers.get("host"), forwardedHost: req.headers.get("x-forwarded-host") });
  if (origin && !own.includes(origin)) {
    throw new ProblemError(403, "csrf_failed", "Cross-origin request refused", "Origin does not match the console.");
  }
  const cookie = req.cookies.get(CSRF_COOKIE)?.value;
  const header = req.headers.get(CSRF_HEADER);
  if (!cookie || !header || cookie !== header) {
    throw new ProblemError(403, "csrf_failed", "Missing CSRF token", "Reload the console and try again.");
  }
}

export async function readJson(req: NextRequest): Promise<unknown> {
  const text = await req.text();
  if (!text) return undefined;
  if (text.length > 64 * 1024) throw new ProblemError(413, "payload_too_large", "Request too large", "The console sends at most 64 KB.");
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ProblemError(400, "malformed_json", "Malformed JSON", "The request body is not valid JSON.");
  }
}
