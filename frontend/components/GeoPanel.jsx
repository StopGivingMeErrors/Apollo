export function GeoPanel({ geoBreakdown, topIps }) {
  const geo = geoBreakdown ?? [];
  const ips = topIps        ?? [];
  const maxGeo = geo[0]?.[1] || 1;

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>

      {/* Attack Origins */}
      <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 18px" }}>
        <div style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.22em", marginBottom: 14 }}>ATTACK ORIGINS</div>

        {geo.length === 0 && (
          <div style={{ color: "var(--text3)", fontSize: 10, textAlign: "center", padding: "14px 0" }}>Awaiting geo data…</div>
        )}

        {geo.map(([country, count], i) => (
          <div key={country} style={{ marginBottom: 9 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                <span style={{ fontSize: 8, color: "var(--text3)", width: 12, textAlign: "right", flexShrink: 0 }}>{i + 1}</span>
                <span style={{ fontSize: 11, color: "var(--text2)" }}>{country}</span>
              </div>
              <span style={{ fontSize: 11, color: "var(--text)", fontWeight: 400 }}>{count.toLocaleString()}</span>
            </div>
            <div style={{ height: 2, background: "var(--bg4)", borderRadius: 1, marginLeft: 21 }}>
              <div style={{
                height: 2, borderRadius: 1,
                width: `${(count / maxGeo) * 100}%`,
                background: "linear-gradient(90deg, var(--accent), var(--accent2))",
                transition: "width 0.55s cubic-bezier(0.4,0,0.2,1)",
              }} />
            </div>
          </div>
        ))}
      </div>

      {/* Repeat Offenders */}
      <div style={{ background: "var(--bg1)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 18px" }}>
        <div style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.22em", marginBottom: 14 }}>REPEAT OFFENDERS</div>

        {ips.length === 0 && (
          <div style={{ color: "var(--text3)", fontSize: 10, textAlign: "center", padding: "14px 0" }}>No repeat activity yet…</div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "14px 1fr auto auto", rowGap: 9, columnGap: 10, alignItems: "center" }}>
          {ips.map((entry, i) => {
            const hot = entry.hits >= 10;
            return [
              <span key={`n${i}`} style={{ fontSize: 8, color: "var(--text3)", textAlign: "right" }}>{i + 1}</span>,

              <span key={`ip${i}`} style={{ fontSize: 10, color: hot ? "rgba(255,180,180,0.9)" : "var(--text2)", fontFamily: "var(--mono)" }}>
                {entry.ip}
              </span>,

              <span key={`h${i}`} style={{
                fontSize: 8, fontWeight: 500, letterSpacing: "0.08em",
                background: hot ? "rgba(255,61,61,0.12)" : "var(--bg3)",
                color: hot ? "var(--red)" : "var(--text3)",
                border: `1px solid ${hot ? "rgba(255,61,61,0.28)" : "var(--border)"}`,
                padding: "2px 7px", borderRadius: "var(--radius)",
                boxShadow: hot ? "0 0 6px rgba(255,61,61,0.2)" : "none",
                whiteSpace: "nowrap",
              }}>
                {entry.hits.toLocaleString()} hits
              </span>,

              <span key={`t${i}`} style={{ fontSize: 9, color: "var(--text3)" }}>
                {new Date(entry.last_seen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
              </span>,
            ];
          })}
        </div>
      </div>
    </div>
  );
}