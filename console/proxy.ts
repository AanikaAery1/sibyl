/**
 * Per-request nonce CSP (user web rules: nonce-based script-src, no 'unsafe-inline' scripts)
 * and the double-submit CSRF cookie the BFF checks on every mutation.
 */
import { NextResponse, type NextRequest } from "next/server";
import { isHttps } from "@/lib/bff/origin";

const CSRF_COOKIE = "sibyl_csrf";

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    // Inline style attributes carry dynamic geometry (rings, bars); no external styles.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  // Where the user was going, so a live sign-in can bring them back (never trusted from the client).
  requestHeaders.set("x-sibyl-path", `${request.nextUrl.pathname}${request.nextUrl.search}`);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  if (!request.cookies.get(CSRF_COOKIE)) {
    response.cookies.set(CSRF_COOKIE, crypto.randomUUID().replaceAll("-", ""), {
      path: "/",
      sameSite: "strict",
      // Behind Caddy the server sees http; X-Forwarded-Proto says what the browser used.
      secure: isHttps(request.nextUrl.protocol, request.headers.get("x-forwarded-proto")),
      httpOnly: false,
    });
  }
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico|healthz).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
