import {
  createContext, useCallback, useContext, useEffect, useMemo, useRef, useState,
} from "react";
import { API, API_KEY, api, getAnalyst, setAnalyst as persistAnalyst } from "../src/api";

const SocContext = createContext(null);

const EVENT_CAP = 60;
const ALERT_CAP = 80;
const TICKER_CAP = 12;
const GEO_CAP = 60;
const TOAST_CAP = 2;

function isMobileViewport() {
  return typeof window !== "undefined" && window.matchMedia("(max-width: 860px)").matches;
}

export function SocProvider({ children }) {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [geoPoints, setGeoPoints] = useState([]);
  const [connected, setConnected] = useState(false);
  const [toastAlerts, setToastAlerts] = useState([]);
  const [ticker, setTicker] = useState([]);
  const [flashIds, setFlashIds] = useState(() => new Set());
  const [analyst, setAnalystState] = useState(getAnalyst());
  const [analysts, setAnalysts] = useState([]);
  const [health, setHealth] = useState(null);
  const [liveTick, setLiveTick] = useState(0);

  const statsTimer = useRef(null);
  const pendingEvents = useRef([]);
  const pendingAlerts = useRef([]);
  const flushRaf = useRef(0);
  const lastTickAt = useRef(0);
  const flashTimers = useRef(new Map());

  const setAnalyst = useCallback((id) => {
    persistAnalyst(id);
    setAnalystState(id);
  }, []);

  const refreshStats = useCallback(async () => {
    try {
      const geoLimit = isMobileViewport() ? 50 : 80;
      const [s, m, g] = await Promise.all([
        api("/api/stats"),
        api("/api/metrics"),
        api(`/api/geo/points?limit=${geoLimit}`),
      ]);
      setStats(s);
      setMetrics(m);
      setGeoPoints(Array.isArray(g) ? g.slice(0, GEO_CAP) : []);
    } catch { /* offline */ }
  }, []);

  const refreshAlerts = useCallback(async (params = "") => {
    try {
      const data = await api(`/api/alerts?limit=${ALERT_CAP}${params}`);
      setAlerts(Array.isArray(data) ? data.slice(0, ALERT_CAP) : []);
      return data;
    } catch {
      return [];
    }
  }, []);

  const scheduleStatsRefresh = useCallback(() => {
    if (statsTimer.current) clearTimeout(statsTimer.current);
    statsTimer.current = setTimeout(() => refreshStats(), 1200);
  }, [refreshStats]);

  const flash = useCallback((id) => {
    if (isMobileViewport()) return;
    setFlashIds((prev) => {
      if (prev.has(id)) return prev;
      const next = new Set(prev);
      next.add(id);
      return next;
    });
    const prevTimer = flashTimers.current.get(id);
    if (prevTimer) clearTimeout(prevTimer);
    const t = setTimeout(() => {
      flashTimers.current.delete(id);
      setFlashIds((prev) => {
        if (!prev.has(id)) return prev;
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }, 900);
    flashTimers.current.set(id, t);
  }, []);

  const bumpLiveTick = useCallback(() => {
    const now = Date.now();
    if (now - lastTickAt.current < 1000) return;
    lastTickAt.current = now;
    setLiveTick((n) => n + 1);
  }, []);

  const flushSseBatch = useCallback(() => {
    flushRaf.current = 0;
    const evBatch = pendingEvents.current;
    const alBatch = pendingAlerts.current;
    pendingEvents.current = [];
    pendingAlerts.current = [];

    if (evBatch.length) {
      setEvents((prev) => {
        const seen = new Set(prev.map((x) => x.id));
        const merged = [];
        for (const e of evBatch) {
          if (seen.has(e.id)) continue;
          seen.add(e.id);
          merged.push(e);
        }
        if (!merged.length) return prev;
        return [...merged, ...prev].slice(0, EVENT_CAP);
      });

      const latest = evBatch[evBatch.length - 1];
      bumpLiveTick();
      setTicker((prev) => {
        const rows = evBatch.slice(-4).reverse().map((data) => ({
          id: data.id,
          severity: data.severity,
          threat_type: data.threat_type,
          ip: data.ip,
          country: data.country,
          city: data.city,
          mitre: data.mitre_technique,
          source: data.source || "sensor",
          ts: Date.now(),
        }));
        return [...rows, ...prev].slice(0, TICKER_CAP);
      });

      const hot = evBatch.filter(
        (d) => d.severity === "critical" || d.severity === "high" || d.repeat_offender,
      );
      if (hot.length && !isMobileViewport()) {
        setToastAlerts((prev) => [...hot.slice(-2).reverse(), ...prev].slice(0, TOAST_CAP));
      }

      setGeoPoints((prev) => {
        let next = prev;
        let changed = false;
        for (const data of evBatch) {
          if (data.latitude == null || data.longitude == null) continue;
          if (!changed) {
            next = [...prev];
            changed = true;
          }
          const i = next.findIndex((p) => p.ip === data.ip);
          if (i >= 0) {
            next[i] = {
              ...next[i],
              hits: (next[i].hits || 0) + 1,
              last_seen: data.timestamp,
              severity: data.severity,
              threat_type: data.threat_type,
              risk_score: data.risk_score,
              country: data.country,
              city: data.city,
              latitude: data.latitude,
              longitude: data.longitude,
            };
          } else {
            next.unshift({
              ip: data.ip,
              country: data.country,
              city: data.city,
              latitude: data.latitude,
              longitude: data.longitude,
              hits: 1,
              severity: data.severity,
              last_seen: data.timestamp,
              threat_type: data.threat_type,
              risk_score: data.risk_score,
            });
          }
        }
        return changed ? next.slice(0, GEO_CAP) : prev;
      });

      if (latest) flash(latest.id);
      scheduleStatsRefresh();
    }

    if (alBatch.length) {
      setAlerts((prev) => {
        let next = prev;
        let changed = false;
        for (const data of alBatch) {
          if (!changed) {
            next = [...prev];
            changed = true;
          }
          const i = next.findIndex((a) => a.id === data.id);
          if (i >= 0) {
            next[i] = { ...data };
            const [row] = next.splice(i, 1);
            next.unshift(row);
          } else {
            next.unshift(data);
          }
        }
        return changed ? next.slice(0, ALERT_CAP) : prev;
      });
      const last = alBatch[alBatch.length - 1];
      if (last) flash(`a-${last.id}`);
      scheduleStatsRefresh();
    }
  }, [bumpLiveTick, flash, scheduleStatsRefresh]);

  const queueSse = useCallback((kind, data) => {
    if (kind === "event") pendingEvents.current.push(data);
    else pendingAlerts.current.push(data);
    if (!flushRaf.current) {
      flushRaf.current = requestAnimationFrame(flushSseBatch);
    }
  }, [flushSseBatch]);

  useEffect(() => {
    api("/api/analysts").then(setAnalysts).catch(() => {});
    api("/api/health").then(setHealth).catch(() => {});
    api(`/api/events?limit=${EVENT_CAP}`).then((rows) => {
      setEvents(Array.isArray(rows) ? rows.slice(0, EVENT_CAP) : []);
    }).catch(() => {});
    refreshAlerts();
    refreshStats();
    const t = setInterval(refreshStats, isMobileViewport() ? 20000 : 10000);
    return () => {
      clearInterval(t);
      if (statsTimer.current) clearTimeout(statsTimer.current);
      if (flushRaf.current) cancelAnimationFrame(flushRaf.current);
      for (const timer of flashTimers.current.values()) clearTimeout(timer);
    };
  }, [refreshAlerts, refreshStats]);

  useEffect(() => {
    let es = null;
    let timeout = null;
    let active = true;

    const connect = () => {
      if (!active) return;
      es = new EventSource(`${API}/api/stream?key=${API_KEY}`);
      es.onopen = () => active && setConnected(true);
      es.onerror = () => {
        setConnected(false);
        es.close();
        if (active) timeout = setTimeout(connect, 3000);
      };
      es.onmessage = (msg) => {
        try {
          const env = JSON.parse(msg.data);
          const { type, data } = env;

          if (type === "hello" || type === "ping") {
            setConnected(true);
            return;
          }

          if (type === "event") {
            queueSse("event", data);
          } else if (type === "alert") {
            queueSse("alert", data);
          } else if (type === "simulator") {
            setHealth((prev) => ({ ...(prev || {}), ...data }));
            if (!data.simulator_running) {
              setTicker([]);
              setToastAlerts([]);
            }
          } else if (type === "stats_hint" || type === "action" || type === "campaign") {
            scheduleStatsRefresh();
          }
        } catch { /* ignore */ }
      };
    };
    connect();
    return () => {
      active = false;
      es?.close();
      clearTimeout(timeout);
    };
  }, [queueSse, scheduleStatsRefresh]);

  const dismissToast = useCallback((id) => {
    setToastAlerts((prev) => prev.filter((a) => a.id !== id));
  }, []);

  const setSimulator = useCallback(async (enabled) => {
    const state = await api("/api/simulator", {
      method: "POST",
      body: JSON.stringify({ enabled }),
    });
    setHealth((prev) => ({ ...(prev || {}), ...state }));
    if (!enabled) {
      setTicker([]);
      setToastAlerts([]);
    }
    return state;
  }, []);

  const triage = useCallback(async (alertId, action, body) => {
    const path =
      action === "false-positive"
        ? `/api/alerts/${alertId}/false-positive`
        : `/api/alerts/${alertId}/${action}`;
    const updated = await api(path, {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    });
    setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
    refreshStats();
    return updated;
  }, [refreshStats]);

  const value = useMemo(
    () => ({
      events,
      alerts,
      stats,
      metrics,
      geoPoints,
      connected,
      toastAlerts,
      dismissToast,
      ticker,
      analyst,
      setAnalyst,
      analysts,
      health,
      setSimulator,
      refreshAlerts,
      refreshStats,
      triage,
      setAlerts,
      flashIds,
      liveTick,
    }),
    [
      events, alerts, stats, metrics, geoPoints, connected, toastAlerts, dismissToast, ticker,
      analyst, setAnalyst, analysts, health, setSimulator, refreshAlerts, refreshStats,
      triage, flashIds, liveTick,
    ],
  );

  return <SocContext.Provider value={value}>{children}</SocContext.Provider>;
}

export function useSoc() {
  const ctx = useContext(SocContext);
  if (!ctx) throw new Error("useSoc requires SocProvider");
  return ctx;
}
