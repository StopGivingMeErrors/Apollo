import { useState, useEffect, useCallback } from "react";

export const API     = "http://localhost:8000";
export const API_KEY = import.meta.env.VITE_SENTINEL_KEY ?? "sentinel-dev-key";

const headers = { "X-API-Key": API_KEY };

export function useSentinel() {
  const [events,    setEvents]    = useState([]);
  const [stats,     setStats]     = useState(null);
  const [connected, setConnected] = useState(false);
  const [alerts,    setAlerts]    = useState([]);

  // ── Stats polling ──────────────────────────────────────────────────────
  useEffect(() => {
    let active = true;
    const poll = async () => {
      try {
        const r = await fetch(`${API}/api/stats`, { headers });
        if (!r.ok) return;
        const data = await r.json();
        if (active) setStats(data);
      } catch { /* server offline — silently retry */ }
    };
    poll();
    const t = setInterval(poll, 4000);
    return () => { active = false; clearInterval(t); };
  }, []);

  // ── SSE stream ─────────────────────────────────────────────────────────
  useEffect(() => {
    let es      = null;
    let timeout = null;
    let active  = true;

    const merge = (incoming) =>
      setEvents(prev => {
        const ids  = new Set(prev.map(x => x.id));
        const fresh = incoming.filter(x => !ids.has(x.id));
        return fresh.length
          ? [...fresh, ...prev].sort((a, b) => b.id - a.id).slice(0, 500)
          : prev;
      });

    const connect = () => {
      if (!active) return;
      es = new EventSource(`${API}/api/stream?key=${API_KEY}`);

      es.onopen = () => {
        if (active) setConnected(true);
      };

      es.onerror = () => {
        setConnected(false);
        es.close();
        if (active) timeout = setTimeout(connect, 5000);
      };

      es.onmessage = (msg) => {
        try {
          const ev = JSON.parse(msg.data);
          setEvents(prev => {
            if (prev.some(x => x.id === ev.id)) return prev;
            return [ev, ...prev].slice(0, 500);
          });
          if (ev.severity === "critical" || ev.repeat_offender) {
            setAlerts(prev => [ev, ...prev].slice(0, 5));
          }
        } catch { /* malformed frame */ }
      };
    };

    // Seed initial events
    fetch(`${API}/api/events?limit=100`, { headers })
      .then(r => r.json())
      .then(merge)
      .catch(() => {});

    connect();
    return () => { active = false; es?.close(); clearTimeout(timeout); };
  }, []);

  const dismissAlert = useCallback(
    (id) => setAlerts(prev => prev.filter(a => a.id !== id)),
    [],
  );

  return { events, stats, connected, alerts, dismissAlert };
}