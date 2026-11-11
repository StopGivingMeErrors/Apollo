const STATS = [
  { key: "total_events",    label: "TOTAL EVENTS",    color: "var(--accent)",  fmt: v => v?.toLocaleString() ?? "—", sub: "all time" },
  { key: "blocked",         label: "THREATS BLOCKED", color: "var(--red)",     fmt: v => v?.toLocaleString() ?? "—", sub: "high + critical" },
  { key: "active_scanners", label: "UNIQUE SOURCES",  color: "var(--yellow)",  fmt: v => v ?? "—",                  sub: "distinct IPs seen" },
  { key: "critical",        label: "CRITICAL ALERTS", color: "var(--purple)",  fmt: v => v ?? "—",                  sub: "requires review" },
];

export function StatStrip({ stats }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 }}>
      {STATS.map(({ key, label, color, fmt, sub }) => (
        <div key={key} style={{
          background: "var(--bg1)",
          border: "1px solid var(--border)",
          borderTop: `2px solid ${color}`,
          borderRadius: "var(--radius)",
          padding: "16px 20px",
          position: "relative",
          overflow: "hidden",
          transition: "border-color var(--transition)",
        }}
          onMouseEnter={e => e.currentTarget.style.borderColor = color}
          onMouseLeave={e => e.currentTarget.style.borderTopColor = color}
        >
          {/* Background glow */}
          <div style={{
            position: "absolute", inset: 0,
            background: `radial-gradient(ellipse at 90% 0%, ${color}0a 0%, transparent 65%)`,
            pointerEvents: "none",
          }} />
          <div style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.22em", marginBottom: 10 }}>{label}</div>
          <div style={{ fontSize: 30, fontWeight: 300, color, lineHeight: 1, letterSpacing: "-0.01em" }}>
            {stats ? fmt(stats[key]) : <span style={{ opacity: 0.15 }}>—</span>}
          </div>
          <div style={{ fontSize: 9, color: "var(--text3)", marginTop: 6 }}>{sub}</div>
        </div>
      ))}
    </div>
  );
}