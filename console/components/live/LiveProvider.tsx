"use client";
/**
 * One EventSource per tab (API §7). Events carry ids and versions only, so each one revalidates
 * the SWR keys whose data it can change; bursts are coalesced. `reset` reloads everything.
 *
 * Reconnects: EventSource retries by itself (sending Last-Event-ID) while the server keeps
 * answering 200. When a connection is refused outright (401, 429, the API restarting), the
 * browser gives up, so this provider reconnects with backoff and passes the last id it saw as
 * `?last_event_id=` (the BFF forwards it as Last-Event-ID), so nothing is missed. A refused
 * reconnect whose session is gone sends the user to sign in.
 */
import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useSWRConfig } from "swr";

type LiveState = "connecting" | "live" | "reconnecting";

interface LiveCtx {
  state: LiveState;
  lastEventAt: number | null;
  recent: { event: string; data: Record<string, unknown> }[];
}

const Ctx = createContext<LiveCtx>({ state: "connecting", lastEventAt: null, recent: [] });

export const EVENT_PREFIXES: Readonly<Record<string, readonly string[]>> = {
  policy_changed: ["/agents", "/fleet", "/incidents", "/capture-policies"],
  "snapshot.issued": ["/agents", "/fleet"],
  "health.transition": ["/agents", "/fleet"],
  "incident.updated": ["/incidents", "/agents", "/fleet", "/queue"],
  "approval.requested": ["/incidents", "/approvals", "/fleet", "/agents"],
  "approval.decided": ["/incidents", "/approvals", "/fleet", "/agents"],
  "approval.expired": ["/incidents", "/approvals", "/fleet", "/agents"],
  "handoff.queued": ["/queue", "/fleet", "/incidents"],
  "handoff.claimed": ["/queue", "/handoff-tasks"],
  "handoff.completed": ["/queue", "/handoff-tasks", "/fleet"],
  "handoff.returned": ["/queue", "/handoff-tasks"],
  "handoff.expired": ["/queue", "/handoff-tasks", "/fleet"],
  "alert.fired": ["/alerts", "/fleet", "/agents"],
  "alert.resolved": ["/alerts", "/fleet", "/agents"],
  "alert.updated": ["/alerts"],
  "provider_incident.opened": ["/fleet", "/provider-incidents", "/alerts", "/providers"],
  "provider_incident.resolved": ["/fleet", "/provider-incidents", "/alerts", "/providers"],
  "killswitch.pulled": ["/kill-switches", "/agents", "/fleet", "/incidents"],
  "killswitch.applied": ["/kill-switches"],
  "killswitch.released": ["/kill-switches", "/agents", "/fleet"],
  "graph.changed": ["/agents", "/fleet", "/models", "/providers"],
  "erasure.step": ["/erasure-requests", "/legal-holds"],
};
const ALWAYS = ["/audit/events", "/audit/anchors"];
const FLUSH_MS = 350;
const BACKOFF_MS = [1_000, 3_000, 10_000, 30_000] as const;

export function LiveProvider({ children, tenant }: { children: ReactNode; tenant: string }) {
  const { mutate } = useSWRConfig();
  const [state, setState] = useState<LiveState>("connecting");
  const [lastEventAt, setLastEventAt] = useState<number | null>(null);
  const [recent, setRecent] = useState<LiveCtx["recent"]>([]);
  const pending = useRef<Set<string>>(new Set());
  const timer = useRef<number | null>(null);

  useEffect(() => {
    let es: EventSource | null = null;
    let lastId: string | null = null;
    let failures = 0;
    let retry: number | null = null;
    let stopped = false;

    const flush = (): void => {
      timer.current = null;
      const prefixes = [...pending.current];
      pending.current.clear();
      void mutate((key) => typeof key === "string" && prefixes.some((p) => key.startsWith(p)));
    };
    const schedule = (prefixes: readonly string[]): void => {
      for (const p of prefixes) pending.current.add(p);
      if (timer.current === null) timer.current = window.setTimeout(flush, FLUSH_MS);
    };
    const onEvent = (ev: MessageEvent<string>): void => {
      if (ev.lastEventId) lastId = ev.lastEventId;
      failures = 0;
      setState("live");
      setLastEventAt(Date.now());
      let data: Record<string, unknown> = {};
      try {
        data = JSON.parse(ev.data) as Record<string, unknown>;
      } catch {
        /* ids only; ignore malformed */
      }
      setRecent((r) => [{ event: ev.type, data }, ...r].slice(0, 20));
      schedule([...(EVENT_PREFIXES[ev.type] ?? ["/"]), ...ALWAYS]);
    };

    const sessionGone = async (): Promise<boolean> => {
      try {
        return (await fetch("/api/bff/session", { cache: "no-store" })).status === 401;
      } catch {
        return false;
      }
    };

    const connect = (): void => {
      if (stopped) return;
      es = new EventSource(`/api/bff/events/stream${lastId ? `?last_event_id=${encodeURIComponent(lastId)}` : ""}`);
      for (const name of Object.keys(EVENT_PREFIXES)) es.addEventListener(name, onEvent as EventListener);
      es.addEventListener("reset", () => {
        lastId = null;
        void mutate(() => true);
      });
      es.onopen = () => {
        failures = 0;
        setState("live");
      };
      es.onerror = () => {
        setState("reconnecting");
        if (!es || es.readyState !== EventSource.CLOSED) return; // the browser is retrying itself
        es.close();
        const delay = BACKOFF_MS[Math.min(failures, BACKOFF_MS.length - 1)] ?? 30_000;
        failures += 1;
        retry = window.setTimeout(() => {
          void sessionGone().then((gone) => {
            if (gone) window.location.replace(`/login?error=unauthenticated&return_to=${encodeURIComponent(window.location.pathname + window.location.search)}`);
            else connect();
          });
        }, delay);
      };
    };

    connect();
    return () => {
      stopped = true;
      es?.close();
      if (retry !== null) window.clearTimeout(retry);
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, [mutate, tenant]);

  const value = useMemo(() => ({ state, lastEventAt, recent }), [state, lastEventAt, recent]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLive(): LiveCtx {
  return useContext(Ctx);
}
