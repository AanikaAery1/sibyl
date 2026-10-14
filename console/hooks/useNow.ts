"use client";
import { useEffect, useState } from "react";
import { serverNow } from "@/lib/client/sources";

/**
 * The server's (virtual, in demo) "now", ticking every `intervalMs`. The first render uses
 * the value seeded by the shell so server and client agree closely; relative-time text is
 * rendered with suppressHydrationWarning for the remaining seconds of drift.
 */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState<number>(() => serverNow());
  useEffect(() => {
    const id = window.setInterval(() => setNow(serverNow()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}
