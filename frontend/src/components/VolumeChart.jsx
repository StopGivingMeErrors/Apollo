import {
  Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";

export default function VolumeChart({ data }) {
  return (
    <div style={{ height: 168, marginTop: 10 }}>
      <ResponsiveContainer width="100%" height={168} minWidth={0}>
        <BarChart data={data}>
          <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
          <XAxis dataKey="hour" tick={{ fill: "#98989d", fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: "#98989d", fontSize: 11 }} width={28} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{
              background: "#1c1c1e",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 12,
              fontSize: 12,
            }}
          />
          <Bar dataKey="cnt" fill="#0a84ff" radius={[5, 5, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
