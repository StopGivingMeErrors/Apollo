export function AlertBanner({ alerts, onDismiss }) {
  if (!alerts.length) return null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {alerts.map(a => (
        <div key={a.id} style={{
          display: "flex", alignItems: "center", gap: 14,
          padding: "9px 16px",
          background: "rgba(255,61,61,0.07)",
          border: "1px solid rgba(255,61,61,0.22)",
          borderLeft: "2px solid var(--red)",
          borderRadius: "var(--radius)",
          animation: "slidein 0.22s ease",
        }}>
          <span style={{ fontSize: 8, color: "var(--red)", letterSpacing: "0.22em", fontWeight: 600, whiteSpace: "nowrap" }}>
            ▲ CRITICAL
          </span>
          <div style={{ width: 1, height: 14, background: "rgba(255,61,61,0.25)", flexShrink: 0 }} />
          <span style={{ fontSize: 10, color: "rgba(255,180,180,0.9)", flex: 1, minWidth: 0 }}>
            <span style={{ color: "var(--red)", fontWeight: 500 }}>{a.threat_type}</span>
            {" "}·{" "}
            <span style={{ color: "var(--text)" }}>{a.ip}</span>
            {a.country && !["Unknown","Private"].includes(a.country) && (
              <span style={{ color: "var(--text2)" }}> ({a.country})</span>
            )}
            {a.repeat_offender && (
              <span style={{ color: "var(--orange)", marginLeft: 10, letterSpacing: "0.08em" }}>
                REPEAT OFFENDER
              </span>
            )}
          </span>
          <span style={{ fontSize: 9, color: "var(--text3)", whiteSpace: "nowrap" }}>
            {new Date(a.timestamp).toLocaleTimeString()}
          </span>
          <button onClick={() => onDismiss(a.id)} style={{
            background: "none", border: "none", color: "var(--text3)",
            cursor: "pointer", fontSize: 13, lineHeight: 1, padding: "0 2px",
            fontFamily: "var(--mono)", flexShrink: 0,
            transition: "color var(--transition)",
          }}
            onMouseEnter={e => e.currentTarget.style.color = "var(--text)"}
            onMouseLeave={e => e.currentTarget.style.color = "var(--text3)"}
          >✕</button>
        </div>
      ))}
    </div>
  );
}