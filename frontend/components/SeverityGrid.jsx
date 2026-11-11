const LEVELS = [
  { key: "critical", label: "CRITICAL", color: "var(--red)",    bg: "rgba(255,61,61,0.07)"   },
  { key: "high",     label: "HIGH",     color: "var(--orange)", bg: "rgba(255,124,42,0.06)"  },
  { key: "medium",   label: "MEDIUM",   color: "var(--yellow)", bg: "rgba(255,201,60,0.05)"  },
  { key: "low",      label: "LOW",      color: "var(--green)",  bg: "rgba(0,229,160,0.04)"   },
];

export function SeverityGrid({ breakdown }) {
  return (
    <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 18px" }}>
      <div style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.22em", marginBottom: 12 }}>SEVERITY MATRIX</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {LEVELS.map(({ key, label, color, bg }) => (
          <div key={key} style={{
            background: bg,
            border: `1px solid ${color}28`,
            borderRadius: "var(--radius)",
            padding: "11px 13px",
          }}>
            <div style={{ fontSize: 7, color, letterSpacing: "0.22em", marginBottom: 5 }}>{label}</div>
            <div style={{ fontSize: 24, fontWeight: 300, color, lineHeight: 1, letterSpacing: "-0.02em" }}>
              {breakdown?.[key] ?? 0}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}