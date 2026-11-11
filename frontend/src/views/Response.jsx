import { useEffect, useState } from "react";
import { api, fmtTime } from "../api";

const AUDIT_PAGE = 15;

export default function Response() {
  const [blocks, setBlocks] = useState([]);
  const [audit, setAudit] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("manual containment");
  const [pbId, setPbId] = useState("contain_ip");
  const [pbParams, setPbParams] = useState('{"ip":"","reason":"manual"}');
  const [msg, setMsg] = useState("");
  const [auditVisible, setAuditVisible] = useState(AUDIT_PAGE);

  const load = async () => {
    const [b, a, p] = await Promise.all([
      api("/api/blocklist"),
      api("/api/audit?limit=40"),
      api("/api/playbooks"),
    ]);
    setBlocks(Array.isArray(b) ? b : []);
    setAudit(Array.isArray(a) ? a : []);
    setPlaybooks(Array.isArray(p) ? p : []);
  };

  useEffect(() => {
    load().catch(() => {});
  }, []);

  const block = async (e) => {
    e.preventDefault();
    setMsg("");
    try {
      await api("/api/blocklist", {
        method: "POST",
        body: JSON.stringify({ ip, reason, hours: 24 }),
      });
      setIp("");
      await load();
      setMsg(`Contained ${ip}`);
    } catch (err) {
      setMsg(String(err.message || err));
    }
  };

  const unblock = async (target) => {
    await api(`/api/blocklist/${encodeURIComponent(target)}`, { method: "DELETE" });
    await load();
  };

  const runPb = async (e) => {
    e.preventDefault();
    setMsg("");
    try {
      const params = JSON.parse(pbParams);
      await api(`/api/playbooks/${pbId}/run`, {
        method: "POST",
        body: JSON.stringify({ params }),
      });
      await load();
      setMsg(`Playbook ${pbId} ok`);
    } catch (err) {
      setMsg(String(err.message || err));
    }
  };

  const shownAudit = audit.slice(0, auditVisible);

  return (
    <div className="view fade compact-view">
      <div className="view-head">
        <h1>Response</h1>
        <p className="view-lede">Containment, playbooks, and audit trail.</p>
      </div>

      {msg && <div className="toast" style={{ marginBottom: 12 }}>{msg}</div>}

      <section className="panel">
        <div className="panel-head">Contain IP</div>
        <form className="toolbar" onSubmit={block}>
          <input required value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP to contain" />
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason" />
          <button type="submit" className="btn warn">Block</button>
        </form>
      </section>

      <div className="mobile-stack" style={{ marginTop: 10 }}>
        <div className="panel-head" style={{ padding: "0 2px" }}>Active blocks ({blocks.length})</div>
        {blocks.slice(0, 30).map((b) => (
          <div key={b.ip} className="mobile-card static-card">
            <div className="mobile-card-top">
              <span className="mono">{b.ip}</span>
              <span className={`enf-chip ${b.enforced ? "on" : "off"}`}>
                {b.enforced ? "firewall" : "recorded"}
              </span>
            </div>
            <div className="mobile-card-meta">
              <span>{b.source}</span>
              <span className="muted">{b.reason}</span>
              <span className="muted">{fmtTime(b.expires_at)}</span>
            </div>
            <button type="button" className="btn ghost" style={{ marginTop: 8 }} onClick={() => unblock(b.ip)}>
              Unblock
            </button>
          </div>
        ))}
        {blocks.length === 0 && <div className="empty panel">No active blocks</div>}
      </div>

      <section className="panel" style={{ marginTop: 12 }}>
        <div className="panel-head">Playbook</div>
        <form className="action-stack" onSubmit={runPb}>
          <select value={pbId} onChange={(e) => setPbId(e.target.value)}>
            {playbooks.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <div className="muted">
            {playbooks.find((p) => p.id === pbId)?.description}
          </div>
          <textarea
            rows={4}
            value={pbParams}
            onChange={(e) => setPbParams(e.target.value)}
            className="code-area"
          />
          <button type="submit" className="btn">Execute</button>
        </form>
      </section>

      <section className="panel" style={{ marginTop: 12 }}>
        <div className="panel-head">Audit</div>
        <div className="mobile-stack tight-stack">
          {shownAudit.map((a) => (
            <div key={a.id} className="mobile-card static-card compact-card">
              <div className="mobile-card-top">
                <span className="accent">{a.action}</span>
                <span className="mono muted">{fmtTime(a.timestamp)}</span>
              </div>
              <div className="mobile-card-meta">
                <span>{a.actor}</span>
                <span className="mono">{a.target}</span>
              </div>
              {a.detail && <div className="muted" style={{ marginTop: 4, fontSize: 12 }}>{a.detail}</div>}
            </div>
          ))}
          {shownAudit.length === 0 && <div className="empty">No audit entries</div>}
          {auditVisible < audit.length && (
            <button type="button" className="btn ghost load-more" onClick={() => setAuditVisible((n) => n + AUDIT_PAGE)}>
              Show more
            </button>
          )}
        </div>
      </section>
    </div>
  );
}
