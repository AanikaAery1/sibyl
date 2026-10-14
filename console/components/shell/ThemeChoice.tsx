"use client";
/** Light / Dark / Auto. Stored per viewer; the inline theme script applies it before paint. */
import { useSyncExternalStore } from "react";

export type ThemePref = "light" | "dark" | "system";
const KEY = "sibyl-theme";
const EVENT = "sibyl-theme-change";

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

function subscribe(cb: () => void): () => void {
  window.addEventListener(EVENT, cb);
  window.addEventListener("storage", cb);
  return () => {
    window.removeEventListener(EVENT, cb);
    window.removeEventListener("storage", cb);
  };
}

export function applyTheme(pref: ThemePref): void {
  const dark = pref === "dark" || (pref === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export function setThemePref(pref: ThemePref): void {
  try {
    if (pref === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, pref);
  } catch {
    /* storage unavailable: the theme still applies to this page */
  }
  applyTheme(pref);
  window.dispatchEvent(new Event(EVENT));
}

export function ThemeChoice() {
  const pref = useSyncExternalStore(subscribe, readPref, () => "system" as ThemePref);
  return (
    <div className="seg" role="group" aria-label="Appearance" style={{ width: "100%" }}>
      {(["light", "dark", "system"] as const).map((p) => (
        <button key={p} type="button" aria-pressed={pref === p} onClick={() => setThemePref(p)} style={{ flex: 1, justifyContent: "center" }}>
          {p === "system" ? "Auto" : p[0]?.toUpperCase() + p.slice(1)}
        </button>
      ))}
    </div>
  );
}
