/**
 * Server-component data access: calls the BFF in-process with the current principal.
 * Returns `null` data for 4xx/5xx so pages can render a designed empty or restricted state.
 */
import "server-only";
import type { DataSource } from "./mode";
import { dispatch } from "./dispatch";
import { currentPrincipal } from "./principal";

export interface ServerResult<T> {
  data: T | null;
  status: number;
  source: DataSource;
  problem: { title?: string; detail?: string; type?: string } | null;
}

export async function serverGet<T>(pathWithQuery: string): Promise<ServerResult<T>> {
  const [path, search] = pathWithQuery.split("?", 2) as [string, string | undefined];
  const res = await dispatch({ method: "GET", path, search: search ? `?${search}` : "", principal: currentPrincipal });
  if (res.status >= 400) {
    return { data: null, status: res.status, source: res.source, problem: (res.body ?? null) as ServerResult<T>["problem"] };
  }
  return { data: res.body as T, status: res.status, source: res.source, problem: null };
}
