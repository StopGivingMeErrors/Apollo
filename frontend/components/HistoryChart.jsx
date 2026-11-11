export function HistoryChart({ hourlyHistory }) {
  const data = hourlyHistory ?? [];
  const max  = Math.max(...data.map(h => h[1]), 1);
  const total = data.reduce((s, h) => s + h[1], 0);

  return (
    <div style={{
      background: "var(--bg1)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius)",
      padding: "14px 20px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <span style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.22em" }}>
          ATTACK TIMELINE — LAST 24 HOURS
        </span>
        <div style={{ display: "flex", gap: 20 }}>
          {data.length > 0 && <>
            <span style={{ fontSize: 8, color: "var(--text3)" }}>
              PEAK <span style={{ color: "var(--orange)" }}>{max}</span>/HR
            </span>
            <span style={{ fontSize: 8, color: "var(--text3)" }}>
              TOTAL <span style={{ color: "var(--accent)" }}>{total}</span>
            </span>
          </>}
        </div>
      </div>

      {data.length === 0 ? (
        <div style={{ height: 52, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text3)", fontSize: 10 }}>
          Awaiting timeline data...
        </div>
      ) : (
        <div style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 52 }}>
          {Array.from({ length: 24 }, (_, i) => {
            const entry = data.find(h => h[0] === `${String(i).padStart(2,"0")}:00`);
            const count = entry ? entry[1] : 0;
            const pct   = count / max;
            const color = pct > 0.75 ? "var(--red)"
                        : pct > 0.45 ? "var(--orange)"
                        : pct > 0    ? "var(--accent)"
                        : undefined;

            return (
              <div key={i} title={`${String(i).padStart(2,"0")}:00 — ${count} events`}
                style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 3, cursor: "default" }}>
                <div style={{
                  width: "100%",
                  height: count > 0 ? `${Math.max(pct * 40, 2)}px` : "1px",
                  background: color ?? "var(--bg4)",
                  borderRadius: "1px 1px 0 0",
                  transition: "height 0.4s ease",
                  boxShadow: color && count > 0 ? `0 0 4px ${color}88` : "none",
                }} />
                {i % 4 === 0 && (
                  <span style={{ fontSize: 7, color: "var(--text3)", lineHeight: 1 }}>
                    {String(i).padStart(2,"0")}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}