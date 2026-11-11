export function Footer() {
  return (
    <footer style={{
      borderTop: "1px solid var(--border)",
      padding: "8px 24px",
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      flexShrink: 0,
    }}>
      <span style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.18em" }}>
        SENTINEL SOC v3.0 · FOR AUTHORISED USE ONLY · {new Date().getFullYear()}
      </span>
      <span style={{ fontSize: 8, color: "var(--text3)", letterSpacing: "0.12em" }}>
        HONEYPOTS ACTIVE · SSH 2222 · HTTP 8080 · FTP 2121 · TELNET 2323
      </span>
    </footer>
  );
}