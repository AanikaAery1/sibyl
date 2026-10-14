/** Small presentational pieces: Panel, EmptyState, Skeleton, SectionTitle, Timeline. */
import type { ReactNode } from "react";
import { Icon, type IconName } from "./Icon";

export function Panel({ title, action, children, className, id, label }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; id?: string; label?: string }) {
  return (
    <section className={`panel ${className ?? ""}`} id={id} aria-label={label}>
      {title ? (
        <div className="panel-head">
          <h3>{title}</h3>
          {action}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export function SectionTitle({ title, meta, id }: { title: string; meta?: ReactNode; id?: string }) {
  return (
    <div className="section-title">
      <h2 id={id}>{title}</h2>
      {meta ? <div className="meta">{meta}</div> : null}
    </div>
  );
}

export function EmptyState({ icon = "info", title, children, action }: { icon?: IconName; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <span className="glyph">
        <Icon name={icon} size={22} />
      </span>
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

export function Skeleton({ width = "100%", height = 14, radius }: { width?: number | string; height?: number; radius?: number }) {
  return <span className="skeleton" aria-hidden style={{ width, height, borderRadius: radius }} />;
}

export function SkeletonRows({ rows = 4 }: { rows?: number }) {
  return (
    <div aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div className="row" key={i}>
          <Skeleton width={32} height={32} radius={16} />
          <div className="grow" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <Skeleton width="40%" />
            <Skeleton width="65%" height={11} />
          </div>
        </div>
      ))}
    </div>
  );
}

export interface TimelineEntry {
  key: string;
  title: ReactNode;
  note?: ReactNode;
  time?: ReactNode;
  state?: "done" | "active" | "pending" | "warn" | "moved";
  icon?: IconName;
}

export function Timeline({ items, label }: { items: readonly TimelineEntry[]; label: string }) {
  return (
    <ol className="timeline" aria-label={label}>
      {items.map((it) => (
        <li key={it.key} className="tl-item" data-state={it.state ?? "pending"}>
          <span className="tl-dot" aria-hidden>
            <Icon name={it.icon ?? (it.state === "done" ? "check" : it.state === "active" ? "clock" : it.state === "warn" ? "incident" : it.state === "moved" ? "route" : "chevronRight")} size={12} strokeWidth={2.4} />
          </span>
          <div>
            <div className="tl-title">{it.title}</div>
            {it.note ? <div className="tl-note">{it.note}</div> : null}
          </div>
          {it.time ? <div className="tl-time">{it.time}</div> : null}
        </li>
      ))}
    </ol>
  );
}
