"use client";
import { useCallback, useEffect, useRef, useState, type RefObject } from "react";

export interface Popover<T extends HTMLElement> {
  open: boolean;
  toggle: () => void;
  close: (refocus?: boolean) => void;
  rootRef: RefObject<T | null>;
  triggerRef: RefObject<HTMLButtonElement | null>;
}

/** Disclosure for an anchored popover: click outside or Esc closes, focus returns to trigger. */
export function usePopover<T extends HTMLElement = HTMLDivElement>(): Popover<T> {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<T>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const close = useCallback((refocus = true) => {
    setOpen(false);
    if (refocus) triggerRef.current?.focus();
  }, []);
  const toggle = useCallback(() => setOpen((v) => !v), []);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent): void => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);

  return { open, toggle, close, rootRef, triggerRef };
}
