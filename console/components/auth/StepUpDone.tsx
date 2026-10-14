"use client";
import Link from "next/link";
import { useEffect } from "react";
import { STEP_UP_MESSAGE } from "@/lib/client/step-up";

/** Tells the opener (same origin only) how the step-up ended, then closes this window. */
export function StepUpDone({ status, code }: { status: string; code: string | null }) {
  const ok = status === "ok";
  useEffect(() => {
    const opener = window.opener as Window | null;
    if (!opener) return;
    opener.postMessage({ type: STEP_UP_MESSAGE, status, code }, window.location.origin);
    window.close();
  }, [status, code]);
  return (
    <div>
      <h1 id="done-title" className="large-title">
        {ok ? "Confirmed" : "Not confirmed"}
      </h1>
      <p className="lede" style={{ fontSize: "var(--fs-body)" }} role="status">
        {ok ? "You can close this window and carry on in the console." : "The identity provider did not confirm it was you. Close this window and try again."}
      </p>
      <p style={{ marginTop: 16 }}>
        <Link className="btn" href="/">
          Back to the console
        </Link>
      </p>
    </div>
  );
}
