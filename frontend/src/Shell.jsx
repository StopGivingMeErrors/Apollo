import { useLayoutEffect, useRef, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { API, API_KEY, sevColor, sourceTag } from "./api";
import { useSoc } from "../hooks/useSoc.jsx";

const NAV = [
  { to: "/", label: "Overview", short: "Home", end: true },
  { to: "/queue", label: "Queue", short: "Queue" },
  { to: "/investigate", label: "Investigate", short: "Hunt" },
  { to: "/cases", label: "Cases", short: "Cases" },
  { to: "/response", label: "Response", short: "Respond" },
  { to: "/metrics", label: "Metrics", short: "Stats" },
];

const TICKER_IDLE = [{
  id: "idle", severity: "low", threat_type: "Sensors quiet", ip: "—", country: "", ts: null,
}];

const TICKER_MAX = 8;

function useFittingCount(ref, signature) {
  const [fit, setFit] = useState(TICKER_MAX);

  useLayoutEffect(() => {
    const track = ref.current;
    if (!track) return undefined;

    const measure = () => {
      const items = track.children;
      if (!items.length) return;
      const padRight = parseFloat(getComputedStyle(track).paddingRight) || 0;
      const limit = track.getBoundingClientRect().right - padRight;
      let n = 0;
      for (const item of items) {
        if (item.getBoundingClientRect().right > limit + 0.5) break;
        n += 1;
      }
      setFit(Math.max(1, n));
    };

    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(track);
    return () => observer.disconnect();
  }, [ref, signature]);

  return fit;
}

function ago(ts) {
  if (ts == null) return "";
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 2) return "now";
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m`;
}

export function Shell() {
  const {
    connected, stats, analyst, setAnalyst, analysts, health, setSimulator,
    toastAlerts, dismissToast, ticker, liveTick,
  } = useSoc();
  const [simBusy, setSimBusy] = useState(false);

  const trackRef = useRef(null);
  const tickerItems = (ticker.length ? ticker : TICKER_IDLE).slice(0, TICKER_MAX);
  const tickerFit = useFittingCount(
    trackRef,
    `${liveTick}:${tickerItems.map((t) => t.id).join(",")}`,
  );

  const simAvailable = health?.simulator_available;
  const simRunning = health?.simulator_running;
  const fw = health?.firewall_enforcement;
  const fwDegraded = fw && fw.available === false && (stats?.blocked ?? 0) > 0;

  const toggleSim = async () => {
    setSimBusy(true);
    try {
      await setSimulator(!simRunning);
    } catch {
      /* banner keeps showing the last known state */
    } finally {
      setSimBusy(false);
    }
  };

  const exportJson = () => {
    fetch(`${API}/api/export`, { headers: { "X-API-Key": API_KEY } })
      .then((r) => r.json())
      .then((data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `apollo-export-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      });
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbar-row">
          <div className="brand">
            <span className="brand-mark">A</span>
            <div>
              <div className="brand-name">Apollo</div>
              <div className="brand-sub">SOC</div>
            </div>
          </div>

          <div className="topbar-right">
            <select
              className="analyst-select"
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              aria-label="Acting analyst"
            >
              {(analysts.length ? analysts : [{ id: "alice", name: "Alice" }]).map((a) => (
                <option key={a.id} value={a.id}>{a.name || a.id}</option>
              ))}
            </select>
            <div className={`live-pill ${connected ? "on" : "off"}`}>
              <span className="dot" />
              <span className="live-pill-text">{connected ? "Live" : "Off"}</span>
              <span className="live-pill-tick mono">{connected ? liveTick : ""}</span>
            </div>
            <button type="button" className="btn ghost export-btn" onClick={exportJson}>Export</button>
          </div>
        </div>

        <nav className="nav nav-desktop" aria-label="Primary">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
      </header>

      {(simAvailable || fwDegraded) && (
        <div className="disclosure-bar">
          {simAvailable && (
            <span className={`disclosure ${simRunning ? "" : "paused"}`}>
              <span className="disclosure-text">
                {simRunning ? (
                  <>
                    <b>Demo mode</b>
                    <span className="disclosure-long">
                      {" "}— ambient traffic is generated by the built-in
                      simulator and tagged <code>SIM</code>. Honeypot-observed traffic
                      is tagged <code>REAL</code>.
                    </span>
                  </>
                ) : (
                  <>
                    <b>Sensors only</b>
                    <span className="disclosure-long">
                      {" "}— showing honeypot-observed traffic.
                    </span>
                  </>
                )}
              </span>
              <button
                type="button"
                className={`sim-btn ${simRunning ? "stop" : "start"}`}
                onClick={toggleSim}
                disabled={simBusy}
              >
                {simBusy ? "…" : simRunning ? "Stop" : "Start sim"}
              </button>
            </span>
          )}
          {fwDegraded && (
            <span className="disclosure warn">
              <b>Containment not enforced</b>
              <span className="disclosure-long">
                {" "}— {stats.blocked} IPs recorded,{" "}
                {stats.blocks_enforced ?? 0} applied at the firewall.
              </span>
            </span>
          )}
        </div>
      )}

      <div className={`attack-ticker ${ticker.length ? "active" : ""}`}>
        <span className="ticker-label">LIVE</span>
        <div className="ticker-track" ref={trackRef}>
          {tickerItems.map((t, i) => (
            <span
              key={t.id}
              className={`ticker-item ${i >= tickerFit ? "clipped" : ""}`}
              aria-hidden={i >= tickerFit}
            >
              <span style={{ color: sevColor[t.severity] || "var(--blue)" }}>●</span>
              <span
                className={`src-tag ${sourceTag(t.source).cls}`}
                title={sourceTag(t.source).title}
              >
                {sourceTag(t.source).label}
              </span>
              <strong>{t.threat_type}</strong>
              <span className="mono ticker-ip">{t.ip}</span>
              <span className="ticker-loc">{t.city || t.country || ""}</span>
              <span className="ticker-ago">{ago(t.ts)}</span>
            </span>
          ))}
        </div>
      </div>

      {toastAlerts.length > 0 && (
        <div className="toast-row">
          {toastAlerts.slice(0, 2).map((t) => (
            <div
              key={t.id}
              className={`toast sev-${t.severity || "high"}`}
              onClick={() => dismissToast(t.id)}
              role="status"
            >
              <strong>{(t.severity || "").toUpperCase()}</strong>
              {" "}{t.threat_type} · {t.ip}
            </div>
          ))}
        </div>
      )}

      <main className="main">
        <Outlet context={{ stats }} />
      </main>

      <footer className="foot">
        <span>2222 · 8080 · 2121 · 2323</span>
        <span>Queue {stats?.open_alerts ?? "—"} · Blocks {stats?.blocked ?? "—"}</span>
      </footer>

      <nav className="bottom-nav" aria-label="Mobile">
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) => (isActive ? "bottom-link active" : "bottom-link")}
          >
            <span className="bottom-link-label">{n.short}</span>
          </NavLink>
        ))}
      </nav>
    </div>
  );
}
