"use client";
/**
 * Browser client for the BFF. Paths are the contract's path templates (typed against the
 * generated `paths`), so a typo or a removed route fails `npm run typecheck`.
 */
import { ProblemError } from "@/lib/api/problem";
import type { paths } from "@/lib/api/types";
import { CSRF_COOKIE, CSRF_HEADER } from "@/lib/auth/personas";
import { noteServerNow, noteSource } from "./sources";

export type ContractPath = keyof paths;

/** Fill `{param}` segments; the template keeps the call site checked against the contract. */
export function route<P extends ContractPath>(template: P, params: Record<string, string> = {}, query?: Record<string, string | number | boolean | null | undefined>): string {
  const path = (template as string).replace(/\{(\w+)\}/g, (_m, k: string) => encodeURIComponent(params[k] ?? ""));
  const qs = query
    ? Object.entries(query)
        .filter(([, v]) => v !== undefined && v !== null && v !== "")
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
        .join("&")
    : "";
  return qs ? `${path}?${qs}` : path;
}

export function csrfToken(): string {
  const m = document.cookie.match(new RegExp(`(?:^|; )${CSRF_COOKIE}=([^;]+)`));
  return m?.[1] ?? "";
}

async function parse<T>(res: Response, path: string): Promise<T> {
  noteSource(path, res.headers.get("x-sibyl-console-source"));
  noteServerNow(res.headers.get("x-sibyl-now"));
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!res.ok) {
    const err = ProblemError.from(res.status, body);
    if (res.status === 401 && err.code === "unauthenticated") toSignIn();
    throw err;
  }
  return body as T;
}

/** The last ETag each GET path answered with (optimistic concurrency: sent back as If-Match). */
const ETAGS = new Map<string, string>();

export function lastEtag(path: string): string | null {
  return ETAGS.get(path) ?? null;
}

function noteEtag(path: string, res: Response): void {
  const tag = res.headers.get("etag");
  if (res.ok && tag) ETAGS.set(path, tag);
}

export async function bffGet<T>(path: string): Promise<T> {
  const res = await fetch(`/api/bff${path}`, { headers: { accept: "application/json" }, cache: "no-store" });
  noteEtag(path, res);
  return parse<T>(res, path);
}

/** A GET whose ETag the caller needs now (e.g. before a conditional write). */
export async function bffGetWithEtag<T>(path: string): Promise<{ data: T; etag: string | null }> {
  const data = await bffGet<T>(path);
  return { data, etag: lastEtag(path) };
}

export interface MutateOptions {
  method?: "POST" | "PUT" | "PATCH" | "DELETE";
  idempotencyKey?: string;
  ifMatch?: string;
  /** Called with the response headers (e.g. to show the `x-sibyl-audit-receipt`). */
  onHeaders?: (headers: Headers) => void;
}

export async function bffSend<T>(path: string, body: unknown, opts: MutateOptions = {}): Promise<T> {
  const res = await fetch(`/api/bff${path}`, {
    method: opts.method ?? "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      [CSRF_HEADER]: csrfToken(),
      "idempotency-key": opts.idempotencyKey ?? crypto.randomUUID(),
      ...(opts.ifMatch ? { "if-match": opts.ifMatch } : {}),
    },
    body: JSON.stringify(body ?? {}),
  });
  opts.onHeaders?.(res.headers);
  return parse<T>(res, path);
}

/** A live session expired or was revoked: go to the glass sign-in, then come back here. */
let leaving = false;
function toSignIn(): void {
  if (leaving || window.location.pathname.startsWith("/login")) return;
  leaving = true;
  const back = `${window.location.pathname}${window.location.search}`;
  window.location.replace(`/login?${new URLSearchParams({ error: "unauthenticated", return_to: back }).toString()}`);
}

/** Console-only routes (session, sign-out, demo controls) — not part of the contract. */
export async function consolePost<T>(path: "/session" | "/demo" | "/auth/logout", body: unknown): Promise<T> {
  const res = await fetch(`/api/bff${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", [CSRF_HEADER]: csrfToken() },
    body: JSON.stringify(body),
  });
  return parse<T>(res, path);
}

export const swrFetcher = <T,>(path: string): Promise<T> => bffGet<T>(path);
