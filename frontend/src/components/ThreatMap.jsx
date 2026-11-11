import { memo, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { sevColor } from "../api";
import { WORLD_PATHS, MAP_W, MAP_H } from "../assets/worldPaths";

function project(lat, lon) {
  const x = ((Number(lon) + 180) / 360) * MAP_W;
  const y = ((90 - Number(lat)) / 180) * MAP_H;
  return [x, y];
}

function arcPath(x1, y1, x2, y2) {
  const mx = (x1 + x2) / 2;
  const my = Math.min(y1, y2) - Math.abs(x2 - x1) * 0.16 - 24;
  return `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`;
}

const SOC = { lat: 37.7749, lon: -122.4194 };

// Static geometry — kept out of the live re-render path so incoming events
// only repaint markers, not 177 country outlines.
const Landmass = memo(function Landmass() {
  return (
    <g fill="#1f2937" stroke="rgba(148,163,184,0.18)" strokeWidth="0.4">
      {WORLD_PATHS.map((p) => (
        <path key={p.id} d={p.d} />
      ))}
    </g>
  );
});

export function ThreatMap({ points = [], liveEvents = [], height = 340, compact = false }) {
  const [pulses, setPulses] = useState([]);
  const seen = useRef(new Set());

  useEffect(() => {
    if (compact) return undefined;
    for (const e of liveEvents.slice(0, 12)) {
      if (!e?.latitude || !e?.longitude || seen.current.has(e.id)) continue;
      seen.current.add(e.id);
      const [x, y] = project(e.latitude, e.longitude);
      setPulses((prev) => [...prev.slice(-16), {
        id: `p-${e.id}`, x, y, sev: e.severity, ts: Date.now(),
      }]);
    }
    return undefined;
  }, [liveEvents, compact]);

  useEffect(() => {
    if (compact) return undefined;
    const t = setInterval(() => {
      const cut = Date.now() - 4000;
      setPulses((prev) => prev.filter((p) => p.ts > cut));
    }, 800);
    return () => clearInterval(t);
  }, [compact]);

  const [socX, socY] = project(SOC.lat, SOC.lon);

  const markers = useMemo(() => {
    const rows = (points || [])
      .filter((p) => p.latitude != null && p.longitude != null)
      .map((p) => {
        const [x, y] = project(p.latitude, p.longitude);
        return { ...p, x, y };
      });
    if (!compact) return rows;
    // Keep loud offenders AND recent probes (e.g. a real hit with few hits).
    const byHits = [...rows].sort((a, b) => (b.hits || 0) - (a.hits || 0));
    const byRecent = [...rows].sort((a, b) =>
      String(b.last_seen || "").localeCompare(String(a.last_seen || "")),
    );
    const picked = new Map();
    for (const p of byHits.slice(0, 16)) picked.set(p.ip, p);
    for (const p of byRecent.slice(0, 16)) picked.set(p.ip, p);
    return [...picked.values()];
  }, [points, compact]);

  const maxHits = Math.max(1, ...markers.map((m) => m.hits || 1));
  const arcLimit = compact ? 8 : 22;

  return (
    <div className={`threat-map ${compact ? "threat-map-compact" : ""}`}>
      <div className="threat-map-frame">
        <svg
          viewBox={`0 0 ${MAP_W} ${MAP_H}`}
          className="threat-map-svg"
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-label="World threat map"
          style={{ maxHeight: height }}
        >
          <defs>
            <radialGradient id="mapGlow" cx="50%" cy="50%" r="55%">
              <stop offset="0%" stopColor="#152033" />
              <stop offset="100%" stopColor="#0d0d0f" />
            </radialGradient>
            {!compact && (
              <filter id="dotGlow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="1.6" result="b" />
                <feMerge>
                  <feMergeNode in="b" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            )}
          </defs>

          <rect width={MAP_W} height={MAP_H} fill="url(#mapGlow)" />

          {!compact && Array.from({ length: 11 }, (_, i) => (
            <line
              key={`v${i}`}
              x1={(i + 1) * (MAP_W / 12)}
              y1={0}
              x2={(i + 1) * (MAP_W / 12)}
              y2={MAP_H}
              stroke="rgba(255,255,255,0.035)"
            />
          ))}
          {!compact && Array.from({ length: 5 }, (_, i) => (
            <line
              key={`h${i}`}
              x1={0}
              y1={(i + 1) * (MAP_H / 6)}
              x2={MAP_W}
              y2={(i + 1) * (MAP_H / 6)}
              stroke="rgba(255,255,255,0.035)"
            />
          ))}

          <Landmass />

          {markers.slice(0, arcLimit).map((m) => (
            <path
              key={`arc-${m.ip}`}
              d={arcPath(m.x, m.y, socX, socY)}
              fill="none"
              stroke={sevColor[m.severity] || "#0a84ff"}
              strokeOpacity={0.22 + (m.hits / maxHits) * 0.35}
              strokeWidth={0.9 + (m.hits / maxHits) * 1.4}
              className={compact ? undefined : "threat-arc"}
            />
          ))}

          {markers.map((m) => {
            const r = (compact ? 3.2 : 2.8) + (m.hits / maxHits) * (compact ? 5 : 7);
            const color = sevColor[m.severity] || "#0a84ff";
            return (
              <g key={m.ip}>
                <circle cx={m.x} cy={m.y} r={r + 4} fill={color} opacity="0.12" />
                <circle
                  cx={m.x}
                  cy={m.y}
                  r={r}
                  fill={color}
                  filter={compact ? undefined : "url(#dotGlow)"}
                  opacity="0.95"
                >
                  <title>{`${m.ip} · ${m.city || m.country} · ${m.hits} hits`}</title>
                </circle>
                <Link to={`/investigate?ip=${m.ip}`}>
                  <circle cx={m.x} cy={m.y} r={r + 7} fill="transparent" />
                </Link>
              </g>
            );
          })}

          {!compact && pulses.map((p) => (
            <circle
              key={p.id}
              cx={p.x}
              cy={p.y}
              r="3"
              fill="none"
              stroke={sevColor[p.sev] || "#0a84ff"}
              strokeWidth="1.5"
              className="threat-pulse"
            />
          ))}

          <g>
            <circle cx={socX} cy={socY} r="9" fill="rgba(10,132,255,0.18)" stroke="#0a84ff" strokeWidth="1.25" />
            <circle cx={socX} cy={socY} r="2.8" fill="#64d2ff" />
            <text
              x={socX + 12}
              y={socY + 4}
              fill="#f5f5f7"
              fontSize="11"
              fontFamily="Public Sans, sans-serif"
              fontWeight="600"
            >
              SOC
            </text>
          </g>
        </svg>
      </div>

      <div className="threat-map-legend">
        <span><i style={{ background: sevColor.critical }} /> critical</span>
        <span><i style={{ background: sevColor.high }} /> high</span>
        <span><i style={{ background: sevColor.medium }} /> medium</span>
        <span><i style={{ background: sevColor.low }} /> low</span>
        <span>{markers.length} origins</span>
      </div>
    </div>
  );
}

export function GeoIntel({ geoBreakdown = [], topIps = [], points = [], compact = false }) {
  const geo = geoBreakdown ?? [];
  const ips = topIps ?? [];
  const maxGeo = geo[0]?.[1] || 1;

  if (compact) {
    if (geo.length) {
      return (
        <div>
          {geo.map(([country, count], i) => (
            <div key={country} className="origin-row">
              <span className="muted">{i + 1}</span>
              <span>{country}</span>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${(count / maxGeo) * 100}%` }} />
              </div>
              <span className="mono muted">{count}</span>
            </div>
          ))}
        </div>
      );
    }
    if (ips.length) {
      return (
        <div className="offender-list">
          {ips.map((entry, i) => {
            const hot = entry.hits >= 10;
            const pt = points.find((p) => p.ip === entry.ip);
            return (
              <div key={entry.ip} className={`offender-row ${hot ? "hot" : ""}`}>
                <span className="muted">{i + 1}</span>
                <Link to={`/investigate?ip=${entry.ip}`} className="link mono">{entry.ip}</Link>
                <span className="muted">{pt?.country || "—"}</span>
                <span className={`hit-badge ${hot ? "hot" : ""}`}>{entry.hits}</span>
              </div>
            );
          })}
        </div>
      );
    }
    return <div className="empty">No data yet</div>;
  }

  return null;
}
