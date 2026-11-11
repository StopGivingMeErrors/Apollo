export function StatCard({ label, value, color, sub }) {
  return (
    <div style={{
      background: "#0f172a",
      border: "0.5px solid #1e3a5f",
      borderRadius: 8,
      padding: "14px 18px",
    }}>
      <div style={{ fontSize: 10, color: "#64748b", letterSpacing: 2, textTransform: "uppercase", marginBottom: 8 }}>
        {label}
      </div>
      <div style={{ fontSize: 28, fontWeight: 500, color: color || "#e2e8f0", fontFamily: "monospace" }}>
        {value ?? "—"}
      </div>
      {sub && <div style={{ fontSize: 10, color: "#475569", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}