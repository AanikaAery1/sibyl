"use client";
/**
 * Sheet and Dialog on native <dialog>: top layer, inert background, Esc to close, focus
 * returned to the trigger. Motion lives in CSS (transitions + @starting-style), so closing
 * mid-enter reverses from the current value instead of finishing first.
 */
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Icon } from "./Icon";

interface LayerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  variant?: "dialog" | "sheet" | "sheet-left" | "palette";
  /** Hide the visual header (palette); the title is still the accessible name. */
  bare?: boolean;
  testId?: string;
}

const EXIT_MS = 320;

export function Layer({ open, onClose, title, description, children, footer, variant = "dialog", bare = false, testId }: LayerProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descId = useId();
  const opener = useRef<Element | null>(null);
  // Keep content mounted through the exit transition so the layer leaves as it arrived.
  const [mounted, setMounted] = useState(open);
  if (open && !mounted) setMounted(true);
  useEffect(() => {
    if (open) return;
    const id = window.setTimeout(() => setMounted(false), EXIT_MS);
    return () => window.clearTimeout(id);
  }, [open]);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) {
      opener.current = document.activeElement;
      el.showModal();
    } else if (!open && el.open) {
      el.close();
      if (opener.current instanceof HTMLElement) opener.current.focus();
    }
  }, [open]);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const onCancel = (e: Event): void => {
      e.preventDefault();
      onClose();
    };
    el.addEventListener("cancel", onCancel);
    return () => el.removeEventListener("cancel", onCancel);
  }, [onClose]);

  const cls = variant === "sheet" ? "layer sheet" : variant === "sheet-left" ? "layer sheet left" : variant === "palette" ? "layer palette" : "layer dialog";

  return (
    <dialog
      ref={ref}
      className={cls}
      aria-labelledby={titleId}
      aria-describedby={description ? descId : undefined}
      data-testid={testId}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
    >
      {mounted ? (
        <div className="layer-body">
          {bare ? (
            <h2 id={titleId} className="sr-only">
              {title}
            </h2>
          ) : (
            <div className="layer-head">
              <div>
                <h2 id={titleId}>{title}</h2>
                {description ? (
                  <div id={descId} className="muted" style={{ marginTop: 4 }}>
                    {description}
                  </div>
                ) : null}
              </div>
              <button type="button" className="btn btn-icon btn-sm" onClick={onClose} aria-label="Close">
                <Icon name="x" size={16} />
              </button>
            </div>
          )}
          <div className={bare ? "" : "layer-scroll"} style={bare ? { display: "contents" } : undefined} tabIndex={bare ? undefined : 0}>
            {children}
          </div>
          {footer ? <div className="layer-foot">{footer}</div> : null}
        </div>
      ) : null}
    </dialog>
  );
}
