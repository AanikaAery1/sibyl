/** The Sibyl mark, for screens outside the console shell (sign-in, step-up return). */
export function BrandMark({ caption }: { caption?: string }) {
  return (
    <div className="brand" aria-label="Sibyl">
      <span className="brand-mark" aria-hidden>
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <circle cx="12" cy="12" r="3.2" />
          <path d="M12 3.5v2.2M12 18.3v2.2M3.5 12h2.2M18.3 12h2.2" />
          <path d="M6.2 6.2a8.2 8.2 0 0 1 11.6 0" opacity="0.6" />
        </svg>
      </span>
      <span style={{ display: "flex", flexDirection: "column", lineHeight: 1.15, minWidth: 0 }}>
        <span className="brand-name">Sibyl</span>
        {caption ? <span className="caption truncate">{caption}</span> : null}
      </span>
    </div>
  );
}
