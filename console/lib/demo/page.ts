/** Cursor paging for demo routes (API §2.4): base64url offsets, limit 1..200 (default 50). */
import "server-only";
import type { Page } from "@/lib/api/types";

export function page<T>(items: readonly T[], q: URLSearchParams): Page<T> {
  const limit = Math.min(200, Math.max(1, Number(q.get("limit") ?? 50) || 50));
  const offset = q.get("cursor") ? Number(Buffer.from(q.get("cursor") ?? "", "base64url").toString()) || 0 : 0;
  const slice = items.slice(offset, offset + limit);
  const more = offset + limit < items.length;
  return { data: slice, next_cursor: more ? Buffer.from(String(offset + limit)).toString("base64url") : null, has_more: more };
}
