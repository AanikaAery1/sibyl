/**
 * BFF passthrough: /api/bff/<contract path> → demo handlers or the live API (/api/v1/<path>).
 * CSRF (Origin / Sec-Fetch-Site + double-submit token) is checked here for every mutation in
 * both modes, before anything is forwarded. Note for compose: Caddy routes /api/* to the API,
 * so it needs `handle /api/bff/*` → console ahead of that rule (lane C2 change request).
 */
import type { NextRequest } from "next/server";
import { ProblemError } from "@/lib/api/problem";
import { safeSegment } from "@/lib/bff/contract";
import { dispatch } from "@/lib/bff/dispatch";
import { assertCsrf, json, problem, readJson } from "@/lib/bff/http";
import { currentPrincipal } from "@/lib/bff/principal";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ path: string[] }> };


async function handle(req: NextRequest, ctx: Ctx): Promise<Response> {
  try {
    const { path: segments } = await ctx.params;
    if (!segments.every(safeSegment)) throw new ProblemError(400, "bad_path", "Bad path", "Path segments must be plain identifiers (no . or ..).");
    if (req.method !== "GET") assertCsrf(req);
    const principal = currentPrincipal;
    const body = req.method === "GET" ? undefined : await readJson(req);
    const res = await dispatch({
      method: req.method,
      path: `/${segments.join("/")}`,
      search: req.nextUrl.search,
      body,
      idempotencyKey: req.headers.get("idempotency-key"),
      ifMatch: req.headers.get("if-match"),
      principal,
    });
    return json(res.body, res.status, res.headers, res.source);
  } catch (err) {
    if (err instanceof ProblemError) return problem(err);
    console.error("[bff] unhandled", err);
    return problem(new ProblemError(500, "internal", "Something went wrong", "The console hit an unexpected error; the action was not applied."));
  }
}

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
