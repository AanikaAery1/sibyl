import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Sibyl", template: "%s · Sibyl" },
  description: "Air traffic control, SRE and compliance office for your AI workforce.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f5f5f7" },
    { media: "(prefers-color-scheme: dark)", color: "#0e0e10" },
  ],
};

/**
 * Runs before first paint: applies the stored theme (or the system one) and records the
 * viewer's timezone in a cookie so server-rendered times match on the next request.
 */
const THEME_SCRIPT = `(function(){try{var k='sibyl-theme',p=null;try{p=localStorage.getItem(k)}catch(e){}var m=window.matchMedia('(prefers-color-scheme: dark)');var apply=function(){var d=p==='dark'||(p!=='light'&&m.matches);document.documentElement.dataset.theme=d?'dark':'light'};apply();m.addEventListener&&m.addEventListener('change',function(){try{p=localStorage.getItem(k)}catch(e){}apply()});var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;if(tz&&document.cookie.indexOf('sibyl_tz='+encodeURIComponent(tz))<0){document.cookie='sibyl_tz='+encodeURIComponent(tz)+';path=/;max-age=31536000;samesite=lax'}}catch(e){}})();`;

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" data-theme="light" suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
