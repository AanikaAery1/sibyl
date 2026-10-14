/**
 * RFC 9457 problem details (API §2.3). `ProblemError` is thrown by BFF handlers and by the
 * browser client when a response carries `application/problem+json`.
 */
import type { Problem } from "./types";

export const PROBLEM_BASE = "https://sibyl.dev/problems/";

export class ProblemError extends Error {
  readonly status: number;
  readonly problem: Problem & Record<string, unknown>;

  constructor(status: number, code: string, title: string, detail?: string, extra: Record<string, unknown> = {}) {
    super(detail ?? title);
    this.status = status;
    this.problem = { type: `${PROBLEM_BASE}${code}`, title, status, ...(detail ? { detail } : {}), ...extra };
  }

  get code(): string {
    return problemCode(this.problem);
  }

  static from(status: number, body: unknown): ProblemError {
    if (body && typeof body === "object" && "type" in body && "title" in body) {
      const p = body as Problem & Record<string, unknown>;
      const err = new ProblemError(status, problemCode(p), p.title, p.detail);
      Object.assign(err.problem, p);
      return err;
    }
    return new ProblemError(status, "unexpected_response", `Request failed with status ${status}`);
  }
}

export function problemCode(p: Pick<Problem, "type">): string {
  return p.type.startsWith(PROBLEM_BASE) ? p.type.slice(PROBLEM_BASE.length) : p.type;
}

export const notFound = (what: string): ProblemError => new ProblemError(404, "not_found", "Not found", `${what} does not exist in this tenant.`);
export const forbidden = (scope: string): ProblemError =>
  new ProblemError(403, "forbidden", "Not permitted", `Your role does not include the '${scope}' scope.`, { required_scope: scope });
