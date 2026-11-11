import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, sevColor, statusColor, fmtTime } from "../api";

export default function Investigate() {
  const [params, setParams] = useSearchParams();
  const [ip, setIp] = useState(params.get("ip") || "");
  const [data, setData] = useState(null);
  const [playbooks, setPlaybooks] = useState([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const load = async (target) => {
    if (!target) return;
    setMsg("");
    try {
      const d = await api(`/api/investigate/${encodeURIComponent(target)}`);
      setData(d);
    } catch (e) {
      setMsg(String(e.message || e));
      setData(null);
    }
  };

  useEffect(() => {
    api("/api/playbooks").then(setPlaybooks).catch(() => {});
  }, []);

  useEffect(() => {
    const q = params.get("ip");
    if (q) {
      setIp(q);
      load(q);
    }
  }, [params]);

  const run = async (playbookId, extra = {}) => {
    if (!data?.ip) return;
    setBusy(true);
    try {
      await api(`/api/playbooks/${playbookId}/run`, {
        method: "POST",
        body: JSON.stringify({ params: { ip: data.ip, ...extra } }),
      });
      setMsg(`Playbook ${playbookId} executed`);
      await load(data.ip);
    } catch (e) {
      setMsg(String(e.message || e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="view fade">
      <div className="view-head">
        <h1>Investigate</h1>
        <p>IP-centric workspace — timeline, risk, related alerts, one-click playbooks.</p>
      </div>

      <form
        className="toolbar"
        onSubmit={(e) => {
          e.preventDefault();
          setParams(ip ? { ip } : {});
          load(ip);
        }}
      >
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="Enter attacker IP…"
          style={{ minWidth: 220 }}
        />
        <button type="submit" className="btn">Pivot</button>
        {msg && <span className="muted">{msg}</span>}
      </form>

      {!data && <div className="empty panel">Search an IP to open the investigation workspace.</div>}

      {data && (
        <>
          <div className="kpi-grid">
            <div className="kpi">
              <div className="kpi-label">Risk Score</div>
              <div className="kpi-value" style={{ color: data.risk_score > 70 ? "var(--red)" : "var(--accent)" }}>
                {data.risk_score}
              </div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Hits</div>
              <div className="kpi-value">{data.hits}</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Ports</div>
              <div className="kpi-value mono">{(data.ports || []).join(", ") || "—"}</div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Geo</div>
              <div className="kpi-value" style={{ fontSize: 16 }}>
                {data.geo?.country || "Unknown"}{data.geo?.city ? ` / ${data.geo.city}` : ""}
              </div>
            </div>
            <div className="kpi">
              <div className="kpi-label">Block Status</div>
              <div className="kpi-value" style={{ color: data.block?.active ? "var(--red)" : "var(--green)", fontSize: 16 }}>
                {data.block?.active ? "BLOCKED" : "CLEAR"}
              </div>
            </div>
          </div>

          <div className="grid-2">
            <section className="panel">
              <div className="panel-head">Event Timeline</div>
              <div className="feed-mini tall investigate-feed">
                {(data.events || []).slice(0, 40).map((e) => (
                  <div key={e.id} className="feed-row col">
                    <div>
                      <span style={{ color: sevColor[e.severity] }}>●</span>{" "}
                      <span className="mono">{fmtTime(e.timestamp)}</span>{" "}
                      <span>{e.threat_type}</span>{" "}
                      <span className="accent mono">:{e.port}</span>{" "}
                      <span className="mono muted">{e.mitre_technique}</span>
                    </div>
                    {e.payload && <pre className="payload">{e.payload}</pre>}
                  </div>
                ))}
                {(data.events || []).length === 0 && <div className="empty">No events</div>}
              </div>
            </section>

            <div className="stack">
              <section className="panel">
                <div className="panel-head">Related Alerts</div>
                {(data.alerts || []).map((a) => (
                  <div key={a.id} className="list-item">
                    <span style={{ color: sevColor[a.severity] }}>{a.severity}</span>
                    <span>{a.title}</span>
                    <span style={{ color: statusColor[a.status] }}>{a.status}</span>
                  </div>
                ))}
                {(data.alerts || []).length === 0 && <div className="empty">No alerts</div>}
              </section>

              <section className="panel">
                <div className="panel-head">Campaign</div>
                {data.campaign ? (
                  <div>
                    <div className="accent">{data.campaign.title}</div>
                    <p className="muted">{data.campaign.summary}</p>
                    <div className="muted">Risk {data.campaign.risk_score} · Alerts {data.campaign.alert_count}</div>
                  </div>
                ) : (
                  <div className="empty">No active campaign</div>
                )}
              </section>

              <section className="panel">
                <div className="panel-head">Run Playbook</div>
                <div className="action-stack">
                  {playbooks.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      className="btn"
                      disabled={busy}
                      onClick={() =>
                        run(
                          p.id,
                          p.id === "recon_burst_response"
                            ? { campaign_id: data.campaign?.id }
                            : p.id === "escalate_critical" && data.alerts?.[0]
                              ? { alert_id: data.alerts[0].id }
                              : p.id === "false_positive_cleanup" && data.alerts?.[0]
                                ? { alert_id: data.alerts[0].id }
                                : { reason: `investigate ${data.ip}` },
                        )
                      }
                    >
                      {p.name}
                    </button>
                  ))}
                </div>
              </section>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
