export function GeoFeed({ geoBreakdown, topIps }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>

      {/* Top countries */}
      <div style={{ background: "#0f172a", border: "0.5px solid #1e293b", borderRadius: 8, padding: "14px 18px" }}>
        <div style={{ fontSize: 10, color: "#64748b", letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>
          Top Origins
        </div>
        {!geoBreakdown?.length && <div style={{ color: "#334155", fontSize: 11, textAlign: "center", marginTop: 12 }}>Awaiting GeoIP data...</div>}
        {geoBreakdown?.map(([country, count], i) => (
          <div key={country} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0", borderBottom: "0.5px solid #0f1829", fontSize: 11 }}>
            <span style={{ color: "#94a3b8" }}>{country}</span>
            <span style={{ color: "#f87171", fontFamily: "monospace" }}>{count}</span>
          </div>
        ))}
      </div>

      {/* Top IPs */}
      <div style={{ background: "#0f172a", border: "0.5px solid #1e293b", borderRadius: 8, padding: "14px 18px" }}>
        <div style={{ fontSize: 10, color: "#64748b", letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>
          Repeat Offenders
        </div>
        {!topIps?.length && <div style={{ color: "#334155", fontSize: 11, textAlign: "center", marginTop: 12 }}>No repeat hits yet...</div>}
        {topIps?.map((entry) => (
          <div key={entry.ip} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0", borderBottom: "0.5px solid #0f1829", fontSize: 11 }}>
            <span style={{ color: "#94a3b8", fontFamily: "monospace" }}>{entry.ip}</span>
            <span style={{
              background: entry.hits >= 10 ? "#450a0a" : "#1e293b",
              color: entry.hits >= 10 ? "#f87171" : "#64748b",
              padding: "1px 6px", borderRadius: 4, fontSize: 10
            }}>{entry.hits} hits</span>
          </div>
        ))}
      </div>

    </div>
  );
}