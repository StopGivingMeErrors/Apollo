const COLORS = ["var(--red)","var(--orange)","var(--yellow)","var(--accent)","var(--purple)","var(--green)"];

export function ThreatChart({ topThreats }) {
  const data = topThreats ?? [];
  const max  = data[0]?.[1] || 1;

  return (
    <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 18px" }}>
      <div style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.22em", marginBottom: 14 }}>ATTACK VECTORS</div>

      {data.length === 0 && (
        <div style={{ color: "var(--text3)", fontSize: 10, textAlign: "center", padding: "14px 0" }}>Awaiting data…</div>
      )}

      {data.map(([name, count], i) => (
        <div key={name} style={{ marginBottom: 11 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <span style={{ fontSize: 10, color: "var(--text2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "78%" }}>
              {name}
            </span>
            <span style={{ fontSize: 10, color: COLORS[i % COLORS.length], fontWeight: 500, marginLeft: 8 }}>
              {count.toLocaleString()}
            </span>
          </div>
          <div style={{ height: 2, background: "var(--bg4)", borderRadius: 1 }}>
            <div style={{
              height: 2,
              borderRadius: 1,
              width: `${(count / max) * 100}%`,
              background: COLORS[i % COLORS.length],
              boxShadow: `0 0 6px ${COLORS[i % COLORS.length]}88`,
              transition: "width 0.55s cubic-bezier(0.4,0,0.2,1)",
            }} />
          </div>
        </div>
      ))}
    </div>
  );
}