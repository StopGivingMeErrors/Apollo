import { useEffect, useState } from "react";
import { api, sevColor, statusColor, fmtTime } from "../api";
import { useSoc } from "../../hooks/useSoc.jsx";

const PAGE_SIZE = 20;

export default function Cases() {
  const { analysts } = useSoc();
  const [cases, setCases] = useState([]);
  const [selected, setSelected] = useState(null);
  const [note, setNote] = useState("");
  const [creating, setCreating] = useState(false);
  const [visible, setVisible] = useState(PAGE_SIZE);
  const [form, setForm] = useState({ title: "", severity: "high", assignee: "alice", sla_minutes: 60 });

  const load = async () => {
    const data = await api("/api/cases?limit=40");
    setCases(Array.isArray(data) ? data : []);
    if (selected) {
      const fresh = data.find((c) => c.id === selected.id);
      if (fresh) setSelected(fresh);
    }
  };

  useEffect(() => {
    load().catch(() => {});
  }, []);

  const openDetail = async (id) => {
    const c = await api(`/api/cases/${id}`);
    setSelected(c);
  };

  const create = async (e) => {
    e.preventDefault();
    const c = await api("/api/cases", { method: "POST", body: JSON.stringify(form) });
    setCreating(false);
    setForm({ title: "", severity: "high", assignee: "alice", sla_minutes: 60 });
    await load();
    setSelected(c);
  };

  const closeCase = async () => {
    if (!selected) return;
    await api(`/api/cases/${selected.id}`, {
      method: "PATCH",
      body: JSON.stringify({ status: "closed", close_reason: "Resolved by analyst" }),
    });
    await load();
    openDetail(selected.id);
  };

  const addNote = async (e) => {
    e.preventDefault();
    if (!note.trim() || !selected) return;
    const c = await api(`/api/cases/${selected.id}/notes`, {
      method: "POST",
      body: JSON.stringify({ text: note }),
    });
    setSelected(c);
    setNote("");
    await load();
  };

  const slaBreached = (c) =>
    c.status === "open" && c.sla_due_at && new Date(c.sla_due_at + "Z") < new Date();

  let notes = [];
  try {
    notes = selected ? JSON.parse(selected.notes || "[]") : [];
  } catch {
    notes = [];
  }
  let alertIds = [];
  try {
    alertIds = selected ? JSON.parse(selected.alert_ids || "[]") : [];
  } catch {
    alertIds = [];
  }

  const shown = cases.slice(0, visible);

  return (
    <div className="view fade compact-view">
      <div className="view-head row-between">
        <div>
          <h1>Cases</h1>
          <p className="view-lede">Incident cases with SLA clocks, linked alerts, and notes.</p>
        </div>
        <button type="button" className="btn" onClick={() => setCreating((v) => !v)}>
          {creating ? "Cancel" : "New Case"}
        </button>
      </div>

      {creating && (
        <form className="panel toolbar" onSubmit={create}>
          <input
            required
            placeholder="Case title"
            value={form.title}
            onChange={(e) => setForm({ ...form, title: e.target.value })}
            style={{ flex: 1 }}
          />
          <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select value={form.assignee} onChange={(e) => setForm({ ...form, assignee: e.target.value })}>
            {analysts.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
          <input
            type="number"
            min={15}
            value={form.sla_minutes}
            onChange={(e) => setForm({ ...form, sla_minutes: Number(e.target.value) })}
            title="SLA minutes"
            style={{ width: 80 }}
          />
          <button type="submit" className="btn">Create</button>
        </form>
      )}

      <div className="mobile-stack">
        {shown.map((c) => (
          <button
            type="button"
            key={c.id}
            className={`mobile-card ${selected?.id === c.id ? "selected" : ""}`}
            onClick={() => openDetail(c.id)}
          >
            <div className="mobile-card-top">
              <span className="mono muted">#{c.id}</span>
              <span style={{ color: sevColor[c.severity] }}>{c.severity}</span>
            </div>
            <strong className="mobile-card-title">{c.title}</strong>
            <div className="mobile-card-meta">
              <span style={{ color: statusColor[c.status] }}>{c.status}</span>
              <span className="muted">{c.assignee || "—"}</span>
              <span style={{ color: slaBreached(c) ? "var(--red)" : "var(--text2)" }}>
                {slaBreached(c) ? "BREACHED" : fmtTime(c.sla_due_at)}
              </span>
            </div>
          </button>
        ))}
        {shown.length === 0 && <div className="empty panel">No cases yet</div>}
        {visible < cases.length && (
          <button type="button" className="btn ghost load-more" onClick={() => setVisible((n) => n + PAGE_SIZE)}>
            Show more
          </button>
        )}
      </div>

      {selected && (
        <div className="mobile-action-sheet">
          <div className="mobile-action-head">
            <div>
              <strong>{selected.title}</strong>
              <div className="muted">#{selected.id} · {selected.status} · {selected.assignee}</div>
            </div>
            <button type="button" className="btn ghost" onClick={() => setSelected(null)}>Close</button>
          </div>
          <div className="muted" style={{ marginBottom: 8 }}>
            SLA: <span style={{ color: slaBreached(selected) ? "var(--red)" : "var(--green)" }}>
              {fmtTime(selected.sla_due_at)}
            </span>
          </div>
          <div className="muted">Linked alerts: {alertIds.length ? alertIds.map((id) => `#${id}`).join(", ") : "none"}</div>
          <div className="feed-mini" style={{ maxHeight: 120, marginTop: 8 }}>
            {notes.slice(0, 8).map((n, i) => (
              <div key={i} className="feed-row col">
                <span className="mono muted">{n.author}</span>
                <span>{n.text}</span>
              </div>
            ))}
          </div>
          <form onSubmit={addNote} className="toolbar" style={{ marginTop: 8 }}>
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add note…" />
            <button type="submit" className="btn ghost">Add</button>
          </form>
          {selected.status === "open" && (
            <button type="button" className="btn ok" style={{ marginTop: 10 }} onClick={closeCase}>
              Close Case
            </button>
          )}
        </div>
      )}

      <div className="grid-queue desktop-only-block">
        <section className="panel grow">
          <div className="table-wrap">
            <table className="table clickable">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Sev</th>
                  <th>Status</th>
                  <th>Assignee</th>
                  <th>SLA</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((c) => (
                  <tr key={c.id} className={selected?.id === c.id ? "selected" : ""} onClick={() => openDetail(c.id)}>
                    <td className="mono">#{c.id}</td>
                    <td>{c.title}</td>
                    <td style={{ color: sevColor[c.severity] }}>{c.severity}</td>
                    <td style={{ color: statusColor[c.status] }}>{c.status}</td>
                    <td>{c.assignee || "—"}</td>
                    <td style={{ color: slaBreached(c) ? "var(--red)" : "var(--text2)" }}>
                      {slaBreached(c) ? "BREACHED" : fmtTime(c.sla_due_at)}
                    </td>
                    <td className="muted">{fmtTime(c.created_at)}</td>
                  </tr>
                ))}
                {shown.length === 0 && (
                  <tr><td colSpan={7} className="empty">No cases yet</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="panel side">
          {!selected && <div className="empty">Select a case</div>}
          {selected && (
            <>
              <div className="panel-head">{selected.title}</div>
              <div className="muted">#{selected.id} · {selected.status} · {selected.assignee}</div>
              <div className="muted" style={{ marginTop: 8 }}>
                SLA: <span style={{ color: slaBreached(selected) ? "var(--red)" : "var(--green)" }}>
                  {fmtTime(selected.sla_due_at)}
                </span>
              </div>
              <div style={{ marginTop: 12 }}>
                <div className="muted">Linked alerts</div>
                {alertIds.length === 0 && <div className="empty">None</div>}
                {alertIds.map((id) => (
                  <div key={id} className="mono">alert:{id}</div>
                ))}
              </div>
              <div style={{ marginTop: 12 }}>
                <div className="muted">Notes</div>
                <div className="feed-mini" style={{ maxHeight: 160 }}>
                  {notes.map((n, i) => (
                    <div key={i} className="feed-row col">
                      <span className="mono muted">{n.author} · {fmtTime(n.at)}</span>
                      <span>{n.text}</span>
                    </div>
                  ))}
                </div>
                <form onSubmit={addNote} className="toolbar" style={{ marginTop: 8 }}>
                  <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add note…" />
                  <button type="submit" className="btn ghost">Add</button>
                </form>
              </div>
              {selected.status === "open" && (
                <button type="button" className="btn ok" style={{ marginTop: 12 }} onClick={closeCase}>
                  Close Case
                </button>
              )}
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
