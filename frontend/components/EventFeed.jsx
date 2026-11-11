import { useState, useMemo } from "react";

const BADGE = {
  critical: { bg: "rgba(255,61,61,0.12)",   color: "var(--red)",    border: "rgba(255,61,61,0.28)"   },
  high:     { bg: "rgba(255,124,42,0.12)",  color: "var(--orange)", border: "rgba(255,124,42,0.28)"  },
  medium:   { bg: "rgba(255,201,60,0.09)",  color: "var(--yellow)", border: "rgba(255,201,60,0.25)"  },
  low:      { bg: "rgba(0,229,160,0.07)",   color: "var(--green)",  border: "rgba(0,229,160,0.2)"    },
};

const COL = "8px 140px 115px 50px 95px 1fr 76px";

function ColHeaders() {
  return (
    <div style={{
      display: "grid", gridTemplateColumns: COL,
      gap: 8, padding: "7px 16px",
      borderBottom: "1px solid var(--border)",
    }}>
      {["","THREAT","IP ADDRESS","PORT","COUNTRY","PAYLOAD PREVIEW","TIME"].map(h => (
        <span key={h} style={{ fontSize: 7, color: "var(--text3)", letterSpacing: "0.18em" }}>{h}</span>
      ))}
    </div>
  );
}

export function EventFeed({ events }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");

  const filtered = useMemo(() =>
    events.filter(e => {
      if (filter !== "all" && e.severity !== filter) return false;
      if (!search) return true;
      const q = search.toLowerCase();
      return e.ip.includes(q)
        || e.threat_type.toLowerCase().includes(q)
        || (e.country ?? "").toLowerCase().includes(q)
        || (e.payload ?? "").toLowerCase().includes(q);
    }),
  [events, filter, search]);

  return (
    <div style={{
      background: "var(--bg1)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius)",
      display: "flex",
      flexDirection: "column",
      minHeight: 0,
      height: 520,
    }}>
      {/* Toolbar */}
      <div style={{
        display: "flex", alignItems: "center", gap: 10,
        padding: "10px 14px",
        borderBottom: "1px solid var(--border)",
        background: "var(--bg2)",
        borderRadius: "var(--radius) var(--radius) 0 0",
        flexShrink: 0,
      }}>
        <span style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.22em", flex: 1 }}>LIVE EVENT FEED</span>
        <input
          placeholder="Search IP, threat, country…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ width: 195 }}
        />
        <select value={filter} onChange={e => setFilter(e.target.value)}>
          {["all","critical","high","medium","low"].map(v => (
            <option key={v} value={v}>{v.toUpperCase()}</option>
          ))}
        </select>
        <span style={{
          padding: "3px 9px",
          background: "rgba(0,229,160,0.06)",
          border: "1px solid rgba(0,229,160,0.18)",
          borderRadius: "var(--radius)",
          fontSize: 8, color: "var(--green)", letterSpacing: "0.1em",
        }}>
          {filtered.length} EVENTS
        </span>
      </div>

      <ColHeaders />

      {/* Rows */}
      <div style={{ overflowY: "auto", flex: 1 }}>
        {filtered.length === 0 && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text3)", fontSize: 11 }}>
            No events match filter
          </div>
        )}
        {filtered.map((e, idx) => {
          const b = BADGE[e.severity] ?? BADGE.low;
          const even = idx % 2 === 0;
          const baseBg = e.repeat_offender ? "rgba(255,61,61,0.04)" : even ? "transparent" : "rgba(255,255,255,0.012)";

          return (
            <div
              key={`${e.id}-${e.timestamp}`}
              style={{
                display: "grid",
                gridTemplateColumns: COL,
                gap: 8,
                alignItems: "center",
                padding: "6px 16px",
                borderBottom: "1px solid var(--border)",
                background: baseBg,
                transition: "background var(--transition)",
                cursor: "default",
              }}
              onMouseEnter={ev => ev.currentTarget.style.background = "rgba(0,212,255,0.04)"}
              onMouseLeave={ev => ev.currentTarget.style.background = baseBg}
            >
              {/* Severity dot */}
              <div style={{
                width: 4, height: 4, borderRadius: "50%",
                background: b.color,
                boxShadow: `0 0 4px ${b.color}`,
                justifySelf: "center",
              }} />

              {/* Threat badge */}
              <span style={{
                background: b.bg, color: b.color,
                border: `1px solid ${b.border}`,
                padding: "2px 6px", borderRadius: "var(--radius)",
                fontSize: 9, fontWeight: 500,
                whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
                letterSpacing: "0.03em",
              }}>{e.threat_type}</span>

              {/* IP */}
              <span style={{ color: "var(--text)", fontSize: 10, fontFamily: "var(--mono)", letterSpacing: "0.02em" }}>
                {e.ip}
                {e.repeat_offender && <span style={{ color: "var(--red)", marginLeft: 4, fontSize: 7 }}>●</span>}
              </span>

              {/* Port */}
              <span style={{ color: "var(--text3)", fontSize: 9 }}>:{e.port}</span>

              {/* Country */}
              <span style={{
                color: ["Unknown","Private",""].includes(e.country) ? "var(--text3)" : "var(--text2)",
                fontSize: 10,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              }}>
                {e.country || "—"}
              </span>

              {/* Payload */}
              <span style={{ color: "var(--text3)", fontSize: 9, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {e.payload ? e.payload.replace(/\r?\n/g, " ").trim().slice(0, 72) : "—"}
              </span>

              {/* Time */}
              <span style={{ color: "var(--text3)", fontSize: 9, textAlign: "right" }}>
                {new Date(e.timestamp).toLocaleTimeString()}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}