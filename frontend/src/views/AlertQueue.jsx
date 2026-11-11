import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useSoc } from "../../hooks/useSoc.jsx";
import { statusColor, fmtTime } from "../api";

const STATUSES = ["", "new", "acked", "investigating", "escalated", "resolved", "false_positive"];
const SEVS = ["", "critical", "high", "medium", "low"];
const PAGE_SIZE = 25;

export default function AlertQueue() {
  const { alerts, triage, refreshAlerts, flashIds } = useSoc();
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState(null);
  const [q, setQ] = useState("");
  const [visible, setVisible] = useState(PAGE_SIZE);

  useEffect(() => {
    refreshAlerts();
  }, [refreshAlerts]);

  useEffect(() => {
    setVisible(PAGE_SIZE);
  }, [status, severity, q]);

  const filtered = useMemo(() => {
    return alerts.filter((a) => {
      if (status === "open") {
        if (["resolved", "false_positive"].includes(a.status)) return false;
      } else if (status && a.status !== status) {
        return false;
      }
      if (severity && a.severity !== severity) return false;
      if (q) {
        const hay = `${a.title} ${a.ip} ${a.threat_type}`.toLowerCase();
        if (!hay.includes(q.toLowerCase())) return false;
      }
      return true;
    });
  }, [alerts, status, severity, q]);

  const shown = filtered.slice(0, visible);
  const selectedAlert = alerts.find((a) => a.id === selected) || null;

  return (
    <div className="view fade compact-view">
      <div className="view-head">
        <h1>Alert queue</h1>
        <p className="view-lede">
          Fast triage. Shortcuts on desktop: <kbd>a</kbd> ack · <kbd>i</kbd> investigate ·{" "}
          <kbd>e</kbd> escalate · <kbd>r</kbd> resolve · <kbd>f</kbd> FP
        </p>
      </div>

      <div className="toolbar">
        <input placeholder="Search IP / threat…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="open">Open queue</option>
          <option value="">All statuses</option>
          {STATUSES.filter(Boolean).map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {SEVS.filter(Boolean).map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="muted">{filtered.length} alerts</span>
      </div>

      <div className="mobile-stack">
        {shown.map((a) => (
          <button
            type="button"
            key={a.id}
            className={`mobile-card ${selected === a.id ? "selected" : ""} ${flashIds?.has(`a-${a.id}`) ? "row-flash" : ""}`}
            onClick={() => setSelected(a.id)}
          >
            <div className="mobile-card-top">
              <span className={`sev-chip ${a.severity}`}>{a.severity}</span>
              <span className="mono muted">{a.risk_score}</span>
            </div>
            <strong className="mobile-card-title">{a.title}</strong>
            <div className="mobile-card-meta">
              <Link to={`/investigate?ip=${a.ip}`} className="link mono" onClick={(e) => e.stopPropagation()}>
                {a.ip}
              </Link>
              <span style={{ color: statusColor[a.status] }}>{a.status}</span>
              <span className="muted">{fmtTime(a.last_seen)}</span>
            </div>
          </button>
        ))}
        {shown.length === 0 && <div className="empty panel">No alerts match filters</div>}
        {visible < filtered.length && (
          <button type="button" className="btn ghost load-more" onClick={() => setVisible((n) => n + PAGE_SIZE)}>
            Show more ({filtered.length - visible} left)
          </button>
        )}
      </div>

      {selectedAlert && (
        <div className="mobile-action-sheet">
          <div className="mobile-action-head">
            <div>
              <strong>{selectedAlert.title}</strong>
              <div className="muted mono">{selectedAlert.ip}</div>
            </div>
            <button type="button" className="btn ghost" onClick={() => setSelected(null)}>Close</button>
          </div>
          <div className="action-stack horizontal-actions">
            <button type="button" className="btn" onClick={() => triage(selectedAlert.id, "ack")}>Ack</button>
            <button type="button" className="btn" onClick={() => triage(selectedAlert.id, "investigate")}>Investigate</button>
            <button type="button" className="btn warn" onClick={() => triage(selectedAlert.id, "escalate")}>Escalate</button>
            <button type="button" className="btn ok" onClick={() => triage(selectedAlert.id, "resolve", { reason: "mobile resolve" })}>Resolve</button>
            <button type="button" className="btn ghost" onClick={() => triage(selectedAlert.id, "false-positive")}>FP</button>
          </div>
        </div>
      )}

      <div className="grid-queue desktop-only-block">
        <section className="panel grow">
          <div className="table-wrap">
            <table className="table clickable">
              <thead>
                <tr>
                  <th>Sev</th>
                  <th>Title</th>
                  <th>IP</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Risk</th>
                  <th>Assignee</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((a) => (
                  <tr
                    key={a.id}
                    className={`${selected === a.id ? "selected" : ""} ${flashIds?.has(`a-${a.id}`) ? "row-flash" : ""}`}
                    onClick={() => setSelected(a.id)}
                  >
                    <td><span className={`sev-chip ${a.severity}`}>{a.severity}</span></td>
                    <td>{a.title}</td>
                    <td className="mono">
                      <Link to={`/investigate?ip=${a.ip}`} className="link" onClick={(e) => e.stopPropagation()}>
                        {a.ip}
                      </Link>
                    </td>
                    <td style={{ color: statusColor[a.status] }}>{a.status}</td>
                    <td>{a.event_count}</td>
                    <td>{a.risk_score}</td>
                    <td>{a.assignee || "—"}</td>
                    <td className="muted">{fmtTime(a.last_seen)}</td>
                  </tr>
                ))}
                {shown.length === 0 && (
                  <tr><td colSpan={8} className="empty">No alerts match filters</td></tr>
                )}
              </tbody>
            </table>
          </div>
          {visible < filtered.length && (
            <button type="button" className="btn ghost load-more" onClick={() => setVisible((n) => n + PAGE_SIZE)}>
              Show more
            </button>
          )}
        </section>

        <aside className="panel side">
          <div className="panel-head">Triage Actions</div>
          {!selectedAlert && <div className="empty">Select an alert</div>}
          {selectedAlert && (
            <div className="action-stack">
              <button type="button" className="btn" onClick={() => triage(selectedAlert.id, "ack")}>Acknowledge</button>
              <button type="button" className="btn" onClick={() => triage(selectedAlert.id, "investigate")}>Investigate</button>
              <button type="button" className="btn warn" onClick={() => triage(selectedAlert.id, "escalate")}>Escalate</button>
              <button type="button" className="btn ok" onClick={() => triage(selectedAlert.id, "resolve", { reason: "desktop resolve" })}>Resolve</button>
              <button type="button" className="btn ghost" onClick={() => triage(selectedAlert.id, "false-positive")}>False positive</button>
              <Link className="btn ghost" to={`/investigate?ip=${selectedAlert.ip}`}>Open investigate</Link>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
