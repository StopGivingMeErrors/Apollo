import { useEffect, useState } from "react";
import {
  Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { api, fmtDuration } from "../api";
import { useSoc } from "../../hooks/useSoc.jsx";

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

export default function Metrics() {
  const { metrics: live } = useSoc();
  const [metrics, setMetrics] = useState(live);
  const mobile = useIsMobile();

  useEffect(() => {
    setMetrics(live);
  }, [live]);

  useEffect(() => {
    api("/api/metrics").then(setMetrics).catch(() => {});
    const t = setInterval(() => {
      api("/api/metrics").then(setMetrics).catch(() => {});
    }, mobile ? 20000 : 12000);
    return () => clearInterval(t);
  }, [mobile]);

  const volume = metrics?.volume_by_day || [];

  const cards = [
    { label: "Mean time to ack", value: fmtDuration(metrics?.mtta_seconds) },
    { label: "Mean time to resolve", value: fmtDuration(metrics?.mttr_seconds) },
    { label: "Open queue", value: metrics?.open_queue ?? "—" },
    { label: "False positive rate", value: metrics ? `${Math.round((metrics.fp_rate || 0) * 100)}%` : "—" },
    { label: "Auto containment", value: metrics?.auto_containments ?? "—" },
    { label: "Manual containment", value: metrics?.manual_containments ?? "—" },
  ];

  const tip = {
    background: "#1c1c1e",
    border: "1px solid rgba(255,255,255,0.1)",
    borderRadius: 12,
    fontSize: 12,
  };

  return (
    <div className="view fade compact-view">
      <div className="view-head">
        <h1>Metrics</h1>
        <p className="view-lede">Ack speed, resolution time, noise rate, containment mix.</p>
      </div>

      <div className="bento metrics-bento">
        {cards.map((c) => (
          <article key={c.label} className="tile span-4 tile-pad kpi-tile">
            <div className="tile-kicker">{c.label}</div>
            <div className="tile-metric metrics-value">{c.value}</div>
          </article>
        ))}
      </div>

      <div className="muted" style={{ margin: "10px 2px 0" }}>
        Alerts {metrics?.total_alerts ?? 0} · Resolved {metrics?.resolved ?? 0} · FP {metrics?.fp_count ?? 0}
        {" · "}Active blocks {metrics?.active_blocks ?? 0}
      </div>

      {!mobile && (
        <div className="bento" style={{ marginTop: 12 }}>
          <article className="tile span-12 tile-pad">
            <div className="tile-kicker">Seven days</div>
            <div className="tile-title">Opened vs closed</div>
            <div style={{ height: 220, marginTop: 10 }}>
              <ResponsiveContainer width="100%" height={220} minWidth={0}>
                <BarChart data={volume}>
                  <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="d" tick={{ fill: "#98989d", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#98989d", fontSize: 11 }} width={28} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tip} />
                  <Legend />
                  <Bar dataKey="opened" fill="#0a84ff" name="Opened" radius={[5, 5, 0, 0]} />
                  <Bar dataKey="closed" fill="#30d158" name="Closed" radius={[5, 5, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </article>
        </div>
      )}
    </div>
  );
}
