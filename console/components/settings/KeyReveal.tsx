"use client";
/** Shows a freshly minted API key secret exactly once, with copy and a clear warning. */
import { useState } from "react";
import type { ApiKeyCreated } from "@/lib/api/types";
import { Layer } from "@/components/ui/Layer";
import { Icon } from "@/components/ui/Icon";

export function KeyReveal({ created, onClose }: { created: ApiKeyCreated | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async (): Promise<void> => {
    if (!created?.secret) return;
    try {
      await navigator.clipboard.writeText(created.secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <Layer
      open={Boolean(created)}
      onClose={onClose}
      title="Copy your key now"
      description="This is the only time Sibyl shows the secret. It stores a keyed hash, never the key."
      testId="key-reveal"
      footer={
        <button type="button" className="btn btn-primary" onClick={onClose} data-testid="key-done">
          I&apos;ve stored it
        </button>
      }
    >
      {created ? (
        <div className="stack">
          <div className="inset panel-pad stack" style={{ gap: 10 }}>
            <div className="caption">
              {created.name} · {created.scopes.join(" ")}
            </div>
            {created.secret ? (
              <>
                <code className="mono" style={{ wordBreak: "break-all", fontSize: 13, lineHeight: 1.6 }} data-testid="key-secret">
                  {created.secret}
                </code>
                <button type="button" className="btn btn-sm" onClick={() => void copy()} style={{ alignSelf: "flex-start" }}>
                  <Icon name={copied ? "check" : "copy"} size={14} /> {copied ? "Copied" : "Copy"}
                </button>
              </>
            ) : (
              <p className="muted" data-testid="key-secret-gone">
                This request was already answered once, so the secret is not shown again. If you did not store it, rotate the key.
              </p>
            )}
          </div>
          <p className="muted">
            Use it as the Authorization bearer for the gateway. Keys with <span className="mono">gateway:proxy</span> are refused by the SDK; mint an agent-bound key for <span className="mono">sibyl.init()</span>.
          </p>
        </div>
      ) : null}
    </Layer>
  );
}
