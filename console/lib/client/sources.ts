"use client";
/**
 * Tiny external stores: where each route's data came from (demo / live / demo-fallback) and
 * the server's clock (the demo runs on a virtual clock), read with useSyncExternalStore.
 */
import { useSyncExternalStore } from "react";
import type { DataSource } from "@/lib/bff/mode";

type Listener = () => void;

function createStore<T>(initial: T) {
  let value = initial;
  const listeners = new Set<Listener>();
  return {
    get: (): T => value,
    set: (next: T): void => {
      if (Object.is(next, value)) return;
      value = next;
      for (const l of listeners) l();
    },
    subscribe: (l: Listener): (() => void) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
  };
}

const fallbackRoutes = createStore<readonly string[]>([]);

export function noteSource(path: string, source: string | null): void {
  const template = path.split("?")[0] ?? path;
  const cur = fallbackRoutes.get();
  const isFallback = (source as DataSource | null) === "demo-fallback";
  if (isFallback && !cur.includes(template)) fallbackRoutes.set([...cur, template]);
  if (!isFallback && cur.includes(template)) fallbackRoutes.set(cur.filter((x) => x !== template));
}

const EMPTY: readonly string[] = [];

export function useFallbackRoutes(): readonly string[] {
  return useSyncExternalStore(fallbackRoutes.subscribe, fallbackRoutes.get, () => EMPTY);
}

/** True when any of these BFF paths (query ignored) was last served from the demo fallback. */
export function useDemoFallback(paths: readonly (string | null | undefined)[]): boolean {
  const routes = useFallbackRoutes();
  return paths.some((p) => typeof p === "string" && routes.includes(p.split("?")[0] ?? p));
}

/** Offset between the server's (virtual) clock and Date.now(). */
const clockOffset = createStore<number>(0);
const clockPaused = createStore<number | null>(null);

export function seedServerNow(serverNowMs: number, paused: boolean): void {
  clockOffset.set(serverNowMs - Date.now());
  clockPaused.set(paused ? serverNowMs : null);
}

export function noteServerNow(header: string | null): void {
  if (!header) return;
  const v = Number(header);
  if (!Number.isFinite(v)) return;
  if (clockPaused.get() !== null) {
    clockPaused.set(v);
    return;
  }
  clockOffset.set(v - Date.now());
}

export function setClockPaused(pausedAt: number | null): void {
  clockPaused.set(pausedAt);
}

export function serverNow(): number {
  return clockPaused.get() ?? Date.now() + clockOffset.get();
}

export const clockStores = { clockOffset, clockPaused };
