"use client";
/** Time rendering in the viewer's timezone (cookie-backed), with live relative text. */
import { createContext, useContext, type ReactNode } from "react";
import { useNow } from "@/hooks/useNow";
import { DEFAULT_TZ, formatClock, formatDateTime, formatStopwatch, relative } from "@/lib/format";

const TzCtx = createContext<string>(DEFAULT_TZ);

export function TzProvider({ tz, children }: { tz: string; children: ReactNode }) {
  return <TzCtx.Provider value={tz}>{children}</TzCtx.Provider>;
}

export function useTz(): string {
  return useContext(TzCtx);
}

export function Clock({ at, seconds = true }: { at: string | number | null | undefined; seconds?: boolean }) {
  const tz = useTz();
  if (at === null || at === undefined) return <span>—</span>;
  return <time dateTime={new Date(at).toISOString()}>{formatClock(at, tz, seconds)}</time>;
}

export function DateTime({ at }: { at: string | number | null | undefined }) {
  const tz = useTz();
  if (at === null || at === undefined) return <span>—</span>;
  return <time dateTime={new Date(at).toISOString()}>{formatDateTime(at, tz)}</time>;
}

export function Ago({ at }: { at: string | number | null | undefined }) {
  const now = useNow(5000);
  if (at === null || at === undefined) return <span>—</span>;
  return (
    <time dateTime={new Date(at).toISOString()} suppressHydrationWarning>
      {relative(at, now)}
    </time>
  );
}

/** Seconds remaining until `at` as a ticking MM:SS (approval countdowns). */
export function Countdown({ to }: { to: string }) {
  const now = useNow(1000);
  const left = Math.max(0, (Date.parse(to) - now) / 1000);
  return (
    <span className="num" suppressHydrationWarning role="timer" aria-live="off">
      {formatStopwatch(left)}
    </span>
  );
}
