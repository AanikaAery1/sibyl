"use client";
/** Toasts: completion and error feedback in a polite live region; auto-dismiss, hover to keep. */
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { ProblemError } from "@/lib/api/problem";
import { Icon } from "./Icon";

type ToastTone = "healthy" | "failed" | "info";
interface ToastItem {
  id: number;
  tone: ToastTone;
  title: string;
  body?: string;
}

interface ToastApi {
  show: (t: Omit<ToastItem, "id">) => void;
  success: (title: string, body?: string) => void;
  error: (err: unknown, fallbackTitle?: string) => void;
}

const Ctx = createContext<ToastApi | null>(null);
const LIFETIME_MS = 5200;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), []);
  const show = useCallback(
    (t: Omit<ToastItem, "id">) => {
      seq.current += 1;
      const id = seq.current;
      setItems((xs) => [...xs.slice(-3), { ...t, id }]);
      window.setTimeout(() => dismiss(id), LIFETIME_MS);
    },
    [dismiss],
  );
  const api = useMemo<ToastApi>(
    () => ({
      show,
      success: (title, body) => show({ tone: "healthy", title, body }),
      error: (err, fallbackTitle = "That didn't work") => {
        if (err instanceof ProblemError) show({ tone: "failed", title: err.problem.title, body: err.problem.detail });
        else show({ tone: "failed", title: fallbackTitle, body: err instanceof Error ? err.message : undefined });
      },
    }),
    [show],
  );
  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className="toast" data-tone={t.tone}>
            <Icon name={t.tone === "failed" ? "incident" : t.tone === "healthy" ? "check" : "info"} size={18} />
            <div className="grow">
              <div className="t-title">{t.title}</div>
              {t.body ? <div className="t-body">{t.body}</div> : null}
            </div>
            <button type="button" className="btn btn-icon btn-sm" style={{ boxShadow: "none", background: "transparent" }} onClick={() => dismiss(t.id)} aria-label="Dismiss">
              <Icon name="x" size={14} />
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useToast outside ToastProvider");
  return ctx;
}
