"use client";
/**
 * Session context: who is acting (roles/scopes), in which tenant, which data mode.
 * Also owns the step-up flow: an action that returns 403 step_up_required opens the re-auth
 * dialog, then retries with the same Idempotency-Key (API §2.1).
 *
 * Demo mode simulates the re-auth. Live mode runs the real one: the dialog opens a small window
 * on /api/bff/auth/step-up, which sends the user through the identity provider with
 * `prompt=login max_age=0`; the API's callback stamps the session and lands on /auth/done,
 * which tells this tab and closes. If the browser blocks the window, the whole page goes
 * through the same flow and comes back here (the action then has to be run again).
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useSWRConfig } from "swr";
import { ProblemError } from "@/lib/api/problem";
import type { RoleName, Scope } from "@/lib/api/types";
import type { PersonaId, TenantSlug } from "@/lib/auth/personas";
import { consolePost } from "@/lib/client/bff";
import { STEP_UP_MESSAGE } from "@/lib/client/step-up";
import { Layer } from "@/components/ui/Layer";
import { Icon } from "@/components/ui/Icon";

export interface SessionInfo {
  mode: "demo" | "live";
  /** `env` for new API keys; must equal the control plane's SIBYL_ENV. */
  keyEnv: "live" | "test";
  personaId: PersonaId | null;
  userId: string;
  name: string;
  fullName: string;
  email: string | null;
  initials: string;
  title: string;
  tenant: string;
  tenantName: string;
  roles: readonly RoleName[];
  roleLabels: readonly string[];
  scopes: readonly Scope[];
  tenants: readonly { slug: string; name: string; blurb: string }[];
  personas: readonly { id: PersonaId; name: string; fullName: string; initials: string; title: string; tenants: readonly TenantSlug[] }[];
}

interface SessionApi extends SessionInfo {
  can: (scope: Scope) => boolean;
  switchTo: (change: { persona?: PersonaId; tenant?: string }) => Promise<void>;
  signOut: () => Promise<void>;
  withStepUp: <T>(fn: () => Promise<T>) => Promise<T>;
  switching: boolean;
}

const POPUP_FEATURES = "popup,width=500,height=700";
const POPUP_POLL_MS = 500;

const Ctx = createContext<SessionApi | null>(null);

interface Pending {
  resolve: () => void;
  reject: (e: unknown) => void;
  forAction: string | null;
}

function stepUpUrl(mode: "popup" | "page", forAction: string | null): string {
  const qs = new URLSearchParams({ mode });
  if (forAction) qs.set("for_action", forAction);
  if (mode === "page") qs.set("return_to", `${window.location.pathname}${window.location.search}`);
  return `/api/bff/auth/step-up?${qs.toString()}`;
}

const cancelled = (): ProblemError => new ProblemError(403, "step_up_cancelled", "Re-authentication cancelled", "The action was not applied.");

export function SessionProvider({ info, children }: { info: SessionInfo; children: ReactNode }) {
  const router = useRouter();
  const { mutate } = useSWRConfig();
  const [switching, setSwitching] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const pending = useRef<Pending | null>(null);
  const popup = useRef<{ win: Window; timer: number } | null>(null);

  const finish = useCallback((outcome: { ok: true } | { ok: false; error: unknown }) => {
    if (popup.current) {
      window.clearInterval(popup.current.timer);
      popup.current = null;
    }
    const p = pending.current;
    pending.current = null;
    setVerifying(false);
    setStepUpOpen(false);
    if (!p) return;
    if (outcome.ok) p.resolve();
    else p.reject(outcome.error);
  }, []);

  // The popup's /auth/done page reports back on this tab's origin only.
  useEffect(() => {
    const onMessage = (ev: MessageEvent<unknown>): void => {
      // Same origin, and from the window this tab opened (not any same-origin frame or tab).
      if (ev.origin !== window.location.origin || !popup.current || ev.source !== popup.current.win) return;
      const data = ev.data as { type?: string; status?: string; code?: string } | null;
      if (!data || data.type !== STEP_UP_MESSAGE) return;
      if (data.status === "ok") finish({ ok: true });
      else finish({ ok: false, error: new ProblemError(403, data.code ?? "step_up_failed", "Re-authentication did not complete", "The identity provider did not confirm it was you; the action was not applied.") });
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [finish]);

  const switchTo = useCallback(
    async (change: { persona?: PersonaId; tenant?: string }) => {
      setSwitching(true);
      try {
        const res = await consolePost<{ redirect?: string }>("/session", change);
        if (res.redirect) {
          // Live: another workspace is a fresh sign-in; end this session first so it is not left open.
          if (info.mode === "live") await consolePost("/auth/logout", {}).catch(() => undefined);
          window.location.assign(res.redirect);
          return;
        }
        await mutate(() => true, undefined, { revalidate: false });
        router.refresh();
      } finally {
        setSwitching(false);
      }
    },
    [info.mode, mutate, router],
  );

  const signOut = useCallback(async () => {
    const res = await consolePost<{ redirect: string }>("/auth/logout", {});
    window.location.assign(res.redirect);
  }, []);

  const askStepUp = useCallback(
    (forAction: string | null) =>
      new Promise<void>((resolve, reject) => {
        pending.current = { resolve, reject, forAction };
        setStepUpOpen(true);
      }),
    [],
  );

  const withStepUp = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn();
      } catch (err) {
        if (err instanceof ProblemError && err.code === "step_up_required") {
          const op = err.problem.operation_id;
          await askStepUp(typeof op === "string" ? op : null);
          return fn();
        }
        throw err;
      }
    },
    [askStepUp],
  );

  const confirmDemo = async (): Promise<void> => {
    setVerifying(true);
    try {
      await new Promise((r) => window.setTimeout(r, 900));
      await consolePost("/session", { step_up: true });
      finish({ ok: true });
    } catch (err) {
      finish({ ok: false, error: err });
    }
  };

  /** Must run synchronously inside the click so the browser allows the window. */
  const confirmLive = (): void => {
    const forAction = pending.current?.forAction ?? null;
    const win = window.open(stepUpUrl("popup", forAction), "sibyl-step-up", POPUP_FEATURES);
    if (!win) {
      window.location.assign(stepUpUrl("page", forAction));
      return;
    }
    setVerifying(true);
    const timer = window.setInterval(() => {
      if (win.closed && pending.current) finish({ ok: false, error: cancelled() });
    }, POPUP_POLL_MS);
    popup.current = { win, timer };
  };

  const cancelStepUp = (): void => {
    popup.current?.win.close();
    finish({ ok: false, error: cancelled() });
  };

  const api = useMemo<SessionApi>(() => ({ ...info, can: (s) => info.scopes.includes(s), switchTo, signOut, withStepUp, switching }), [info, switchTo, signOut, withStepUp, switching]);
  const live = info.mode === "live";

  return (
    <Ctx.Provider value={api}>
      {children}
      <Layer
        open={stepUpOpen}
        onClose={cancelStepUp}
        title="Confirm it's you"
        description="This action needs a sign-in from the last 5 minutes (step-up)."
        testId="step-up"
        footer={
          <>
            <button type="button" className="btn" onClick={cancelStepUp}>
              Cancel
            </button>
            <button type="button" className="btn btn-primary" onClick={live ? confirmLive : () => void confirmDemo()} disabled={verifying} data-testid="step-up-confirm">
              {verifying ? <span className="spinner" aria-hidden /> : <Icon name="lock" size={15} />}
              {verifying ? (live ? "Waiting for sign-in…" : "Verifying…") : `Continue as ${info.name}`}
            </button>
          </>
        }
      >
        <div className="inset panel-pad stack" style={{ gap: 10 }}>
          <div className="row" style={{ padding: 0, minHeight: 0 }}>
            <span className="avatar" data-persona={info.personaId ?? undefined}>
              {info.initials}
            </span>
            <div className="grow">
              <div className="title-sm">{info.fullName}</div>
              <div className="muted">Identity provider: dex{live ? "" : " (simulated in demo mode)"}</div>
            </div>
          </div>
          {live ? (
            <p className="muted" aria-live="polite">
              {verifying ? "Finish signing in in the window that opened. This dialog continues on its own when you are done." : "A small window opens your identity provider's sign-in. The action runs as soon as you finish."} It is audited as <span className="mono">access.step_up</span>.
            </p>
          ) : (
            <p className="muted">
              In production this re-runs your identity provider&apos;s login with <span className="mono">prompt=login max_age=0</span>. The approval is audited as <span className="mono">access.step_up</span>.
            </p>
          )}
        </div>
      </Layer>
    </Ctx.Provider>
  );
}

export function useSession(): SessionApi {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useSession outside SessionProvider");
  return ctx;
}
