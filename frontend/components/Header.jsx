import { useState, useEffect } from "react";
import { API, API_KEY } from "../hooks/useSentinel";

export function Header({ connected, stats }) {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const handleExport = () =>
    fetch(`${API}/api/export`, { headers: { "X-API-Key": API_KEY } })
      .then(r => r.json())
      .then(data => {
        const a   = document.createElement("a");
        const ts  = new Date().toISOString().slice(0, 19).replace(/:/g, "-");
        a.href    = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
        a.download = `sentinel-export-${ts}.json`;
        a.click();
      });

  const SERVICES = [
    { label: "SSH",    port: 2222 },
    { label: "HTTP",   port: 8080 },
    { label: "FTP",    port: 2121 },
    { label: "TELNET", port: 2323 },
  ];

  return (
    <header style={{
      height: 58,
      borderBottom: "1px solid var(--border2)",
      padding: "0 24px",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      background: "linear-gradient(180deg, rgba(0,212,255,0.04) 0%, transparent 100%)",
      backdropFilter: "blur(16px)",
      position: "sticky",
      top: 0,
      zIndex: 200,
      flexShrink: 0,
    }}>

      {/* ── Left: logo + services ── */}
      <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
        {/* Logo mark */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
            <polygon points="14,1 27,8 27,20 14,27 1,20 1,8"
              stroke="var(--accent)" strokeWidth="1.2"
              fill="rgba(0,212,255,0.05)" />
            <polygon points="14,6 22,11 22,17 14,22 6,17 6,11"
              stroke="var(--accent)" strokeWidth="0.4"
              fill="rgba(0,212,255,0.03)" />
            <circle cx="14" cy="14" r="2.5" fill="var(--accent)"
              style={{ filter: "drop-shadow(0 0 4px var(--accent))" }} />
          </svg>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", letterSpacing: "0.18em" }}>SENTINEL</div>
            <div style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.22em", marginTop: 1 }}>SECURITY OPERATIONS CENTER</div>
          </div>
        </div>

        {/* Divider */}
        <div style={{ width: 1, height: 28, background: "var(--border2)" }} />

        {/* Service indicators */}
        <div style={{ display: "flex", gap: 16 }}>
          {SERVICES.map(({ label, port }) => (
            <div key={port} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <div style={{
                width: 5, height: 5, borderRadius: "50%",
                background: connected ? "var(--green)" : "var(--red)",
                boxShadow: connected ? "0 0 5px var(--green)" : "none",
                animation: connected ? "pulse 2.5s ease-in-out infinite" : "none",
              }} />
              <span style={{ fontSize: 9, color: "var(--text3)", letterSpacing: "0.12em" }}>
                {label}:{port}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Right: clock + status + export ── */}
      <div style={{ display: "flex", alignItems: "center", gap: 20 }}>

        {/* Event rate */}
        {stats && (
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.18em" }}>TOTAL EVENTS</div>
            <div style={{ fontSize: 14, color: "var(--accent)", fontWeight: 400, lineHeight: 1, marginTop: 2 }}>
              {stats.total_events?.toLocaleString()}
            </div>
          </div>
        )}

        <div style={{ width: 1, height: 28, background: "var(--border2)" }} />

        {/* Clock */}
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.18em" }}>
            {time.toLocaleDateString("en-GB", { weekday: "short", day: "2-digit", month: "short" }).toUpperCase()}
          </div>
          <div style={{ fontSize: 16, fontWeight: 300, color: "var(--text)", lineHeight: 1, marginTop: 2, letterSpacing: "0.04em" }}>
            {time.toLocaleTimeString("en-GB")}
            <span style={{ animation: "blink 1s step-start infinite", color: "var(--accent)" }}>_</span>
          </div>
        </div>

        <div style={{ width: 1, height: 28, background: "var(--border2)" }} />

        {/* Live indicator */}
        <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
          <div style={{
            width: 7, height: 7, borderRadius: "50%",
            background: connected ? "var(--green)" : "var(--red)",
            boxShadow: connected ? "0 0 8px var(--green)" : "0 0 8px var(--red)",
          }} />
          <span style={{ fontSize: 9, letterSpacing: "0.2em", color: connected ? "var(--green)" : "var(--red)" }}>
            {connected ? "LIVE" : "OFFLINE"}
          </span>
        </div>

        {/* Export */}
        <button onClick={handleExport} style={{
          background: "transparent",
          border: "1px solid var(--border2)",
          color: "var(--text2)",
          borderRadius: "var(--radius)",
          padding: "5px 14px",
          fontSize: 9,
          letterSpacing: "0.16em",
          cursor: "pointer",
          fontFamily: "var(--mono)",
          transition: "all var(--transition)",
        }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--accent)"; e.currentTarget.style.color = "var(--accent)"; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = "var(--border2)"; e.currentTarget.style.color = "var(--text2)"; }}
        >
          EXPORT LOGS ↓
        </button>
      </div>
    </header>
  );
}