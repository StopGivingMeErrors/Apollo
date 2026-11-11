import { lazy, Suspense, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useSoc } from "../../hooks/useSoc.jsx";
import { sevColor, sourceTag } from "../api";

const ThreatMap = lazy(() =>
  import("../components/ThreatMap").then((m) => ({ default: m.ThreatMap })),
);
const VolumeChart = lazy(() => import("../components/VolumeChart"));

function useIsMobile() {
  const [mobile, setMobile] = useState(
    () => typeof window !== "undefined" && window.matchMedia("(max-width: 860px)").matches,
  );
  useEffect(() => {
    const mq = window.matchMedia("(max-width: 860px)");
    const onChange = () => setMobile(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return mobile;
}

export default function Overview() {
  const mobile = useIsMobile();
  const { stats, metrics, alerts, events, geoPoints, flashIds, liveTick, connected } = useSoc();
  const hourly = (stats?.hourly_history || []).map(([hour, cnt]) => ({ hour, cnt }));
  const mitre = (stats?.mitre_heatmap || []).slice(0, 5);
  const geo = (stats?.geo_breakdown || []).slice(0, 5);
  const maxGeo = geo[0]?.[1] || 1;
  const offenders = (stats?.top_ips || []).slice(0, 5);

  const openAlerts = [...alerts]
    .filter((a) => !["resolved", "false_positive"].includes(a.status))
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 6);

  const mtta = metrics?.mtta_seconds != null
    ? `${Math.round(metrics.mtta_seconds / 60)}m`
    : "—";

  const enforced = stats?.blocks_enforced ?? 0;
  const unenforced = Math.max(0, (stats?.blocked ?? 0) - enforced);
  const simEvents = stats?.simulated_events ?? 0;
  const sensorEvents = stats?.sensor_events ?? 0;

  return (
    <div className="view fade overview-view">
      <div className="view-head row-between">
        <div>
          <h1>Operations</h1>
          <p className="view-lede">Live attack surface, queue health, and containment — one screen.</p>
        </div>
        <div className="live-counter">
          <span className="dot" />
          <span className="mono">{liveTick}</span>
          <span className="live-counter-label">{connected ? "session events" : "reconnecting"}</span>
        </div>
      </div>

      <div className="bento">
        <article className="tile span-3 tile-pad kpi-tile">
          <div className="tile-kicker">Open queue</div>
          <div className="tile-metric">{stats?.open_alerts ?? "—"}</div>
          <p className="tile-sub">Alerts still open</p>
          <div className="tile-foot"><Link to="/queue">Open queue</Link></div>
        </article>

        <article className="tile span-3 tile-pad kpi-tile">
          <div className="tile-kicker">Breached SLAs</div>
          <div className="tile-metric" style={{ color: "var(--red)" }}>{stats?.breached_slas ?? "—"}</div>
          <p className="tile-sub">Cases past due</p>
          <div className="tile-foot"><Link to="/cases">View cases</Link></div>
        </article>

        <article className="tile span-3 tile-pad kpi-tile">
          <div className="tile-kicker">Active blocks</div>
          <div className="tile-metric" style={{ color: "var(--orange)" }}>{stats?.blocked ?? "—"}</div>
          <p className="tile-sub">
            {enforced} enforced
            {unenforced > 0 && <span className="warn-text"> · {unenforced} recorded</span>}
          </p>
          <div className="tile-foot"><Link to="/response">Response</Link></div>
        </article>

        <article className="tile span-3 tile-pad kpi-tile">
          <div className="tile-kicker">MTTA</div>
          <div className="tile-metric" style={{ color: "var(--green)" }}>{mtta}</div>
          <p className="tile-sub">
            {sensorEvents.toLocaleString()} real · {simEvents.toLocaleString()} sim
          </p>
          <div className="tile-foot"><Link to="/metrics">Metrics</Link></div>
        </article>

        <article className={`tile map-tile h-map ${mobile ? "span-12" : "span-8"}`}>
          <Suspense fallback={<div className="empty" style={{ padding: 24 }}>Loading map…</div>}>
            <ThreatMap
              points={geoPoints}
              liveEvents={mobile ? [] : events}
              height={mobile ? 210 : 340}
              compact={mobile}
            />
          </Suspense>
        </article>

        <article className="tile span-4 tile-pad-sm h-feed">
          <div className="tile-kicker" style={{ display: "flex", justifyContent: "space-between" }}>
            <span>Inbound</span>
            <span className="muted">{connected ? "stream" : "offline"}</span>
          </div>
          <div className="feed-mini tall feed-stream">
            {events.slice(0, mobile ? 6 : 11).map((e) => (
              <div key={e.id} className={`feed-row ${flashIds.has(e.id) ? "row-flash" : ""}`}>
                <span style={{ color: sevColor[e.severity], marginTop: 5 }}>●</span>
                <div className="feed-meta">
                  <div className="feed-top">
                    <span
                      className={`src-tag ${sourceTag(e.source).cls}`}
                      title={sourceTag(e.source).title}
                    >
                      {sourceTag(e.source).label}
                    </span>
                    <span className="feed-threat">{e.threat_type}</span>
                    <span className="mono muted">{e.mitre_technique}</span>
                  </div>
                  <div className="feed-loc">
                    <Link to={`/investigate?ip=${e.ip}`} className="link mono">{e.ip}</Link>
                    {" · "}
                    {e.city || e.country || "Unknown"}
                  </div>
                </div>
              </div>
            ))}
            {events.length === 0 && (
              <div className="empty">No events yet. Keep the API running with live sim on.</div>
            )}
          </div>
        </article>

        <article className="tile span-4 tile-pad h-md secondary-tile">
          <div className="tile-kicker">Origins</div>
          <div className="tile-title">By country</div>
          <div style={{ marginTop: 14 }}>
            {geo.length === 0 && <div className="empty">Waiting for geo</div>}
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
        </article>

        <article className="tile span-4 tile-pad h-md secondary-tile">
          <div className="tile-kicker">Offenders</div>
          <div className="tile-title">Top IPs</div>
          <div className="offender-list" style={{ marginTop: 12 }}>
            {offenders.length === 0 && <div className="empty">No repeats yet</div>}
            {offenders.map((entry, i) => {
              const hot = entry.hits >= 10;
              const pt = geoPoints.find((p) => p.ip === entry.ip);
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
        </article>

        <article className="tile span-4 tile-pad h-md secondary-tile">
          <div className="tile-kicker">ATT&CK</div>
          <div className="tile-title">Techniques</div>
          <div className="mitre-list" style={{ marginTop: 14 }}>
            {mitre.length === 0 && <div className="empty">No techniques yet</div>}
            {mitre.map(([tech, cnt]) => (
              <div key={tech} className="mitre-row" style={{ marginBottom: 10 }}>
                <span className="mono accent" style={{ minWidth: 72 }}>{tech}</span>
                <div className="bar-track">
                  <div
                    className="bar-fill"
                    style={{ width: `${Math.min(100, (cnt / (mitre[0]?.[1] || 1)) * 100)}%` }}
                  />
                </div>
                <span className="muted">{cnt}</span>
              </div>
            ))}
          </div>
        </article>

        {!mobile && (
          <article className="tile span-7 tile-pad">
            <div className="tile-kicker">Volume</div>
            <div className="tile-title">Last 24 hours</div>
            <Suspense fallback={<div className="empty">Loading chart…</div>}>
              <VolumeChart data={hourly} />
            </Suspense>
          </article>
        )}

        <article className="tile span-5 tile-pad">
          <div className="tile-kicker" style={{ display: "flex", justifyContent: "space-between" }}>
            <span>Priority</span>
            <Link to="/queue" className="link">Triage</Link>
          </div>
          <div className="tile-title">Needs attention</div>
          <div className="priority-list" style={{ marginTop: 8 }}>
            {openAlerts.slice(0, 5).map((a) => (
              <Link
                key={a.id}
                to={`/investigate?ip=${a.ip}`}
                className={`priority-card ${flashIds.has(`a-${a.id}`) ? "row-flash" : ""}`}
              >
                <span className={`sev-chip ${a.severity}`}>{a.severity}</span>
                <div className="priority-meta">
                  <strong>{a.title}</strong>
                  <span className="muted">{a.country || "—"} · {a.status}</span>
                </div>
                <span className="mono priority-risk">{a.risk_score}</span>
              </Link>
            ))}
            {openAlerts.length === 0 && <div className="empty">Queue clear</div>}
          </div>
        </article>
      </div>
    </div>
  );
}
