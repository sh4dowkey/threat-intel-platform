import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell,
} from "recharts";
import { AlertTriangle, Shield, Activity, Eye } from "lucide-react";
import { listAlerts } from "../lib/api";
import { StatCard, SectionHeader, VerdictBadge, SeverityBadge, RiskBar, Empty, Spinner } from "../components/ui";
import { format } from "date-fns";

// Aggregate alerts into hourly buckets for the timeline chart
function buildTimeline(alerts) {
  const buckets = {};
  alerts.forEach((a) => {
    const hour = format(new Date(a.created_at), "HH:mm");
    if (!buckets[hour]) buckets[hour] = { time: hour, malicious: 0, suspicious: 0, clean: 0 };
    buckets[hour][a.verdict] = (buckets[hour][a.verdict] || 0) + 1;
  });
  return Object.values(buckets).slice(-12);
}

// Count by attack class for the bar chart
function buildClassDist(alerts) {
  const counts = {};
  alerts.forEach((a) => {
    if (a.attack_class && a.attack_class !== "BENIGN") {
      counts[a.attack_class] = (counts[a.attack_class] || 0) + 1;
    }
  });
  return Object.entries(counts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
}

const tooltipStyle = {
  background: "var(--bg-raised)",
  border: "1px solid var(--border-lit)",
  borderRadius: 4,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  color: "var(--text-primary)",
};

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchAlerts = useCallback(async () => {
    try {
      const data = await listAlerts({ limit: 100 });
      setAlerts(data);
    } catch (_) {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const iv = setInterval(fetchAlerts, 15000); // auto-refresh every 15s
    return () => clearInterval(iv);
  }, [fetchAlerts]);

  const malicious  = alerts.filter((a) => a.verdict === "malicious").length;
  const suspicious = alerts.filter((a) => a.verdict === "suspicious").length;
  const open       = alerts.filter((a) => a.status === "open").length;
  const timeline   = buildTimeline(alerts);
  const classDist  = buildClassDist(alerts);

  return (
    <div style={{ padding: "28px 32px", overflowY: "auto", height: "100%" }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 style={{
          fontFamily: "var(--font-mono)",
          fontSize: 18,
          fontWeight: 600,
          color: "var(--text-primary)",
          letterSpacing: "0.04em",
          marginBottom: 4,
        }}>
          SECURITY OVERVIEW
        </h1>
        <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
          {format(new Date(), "yyyy-MM-dd HH:mm:ss")} UTC
          <span className="animate-blink" style={{ marginLeft: 4, color: "var(--green)" }}>█</span>
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 24 }}>
        <StatCard label="Total Alerts"  value={loading ? "…" : alerts.length} icon={Activity} />
        <StatCard label="Malicious"     value={loading ? "…" : malicious}  accent="var(--red)"   icon={AlertTriangle} />
        <StatCard label="Suspicious"    value={loading ? "…" : suspicious} accent="var(--amber)" icon={Eye} />
        <StatCard label="Open / Unread" value={loading ? "…" : open}       accent="var(--blue)"  icon={Shield} />
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 16, marginBottom: 24 }}>
        {/* Timeline */}
        <div className="card" style={{ padding: "20px 20px 12px" }}>
          <SectionHeader title="Alert Timeline (last 12 windows)" />
          {timeline.length === 0 ? <Empty message="No timeline data yet" /> : (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={timeline} margin={{ top: 4, right: 4, bottom: 0, left: -28 }}>
                <defs>
                  <linearGradient id="gRed"   x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="var(--red)"   stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--red)"   stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gAmber" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="var(--amber)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--amber)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="malicious"  stroke="var(--red)"   fill="url(#gRed)"   strokeWidth={1.5} dot={false} />
                <Area type="monotone" dataKey="suspicious" stroke="var(--amber)" fill="url(#gAmber)" strokeWidth={1.5} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Attack class distribution */}
        <div className="card" style={{ padding: "20px 20px 12px" }}>
          <SectionHeader title="Attack Classes" />
          {classDist.length === 0 ? <Empty message="No attack data yet" /> : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={classDist} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 4 }}>
                <XAxis type="number" tick={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={100}
                  tick={{ fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-secondary)" }}
                  axisLine={false} tickLine={false}
                />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                  {classDist.map((_, i) => (
                    <Cell key={i} fill={i === 0 ? "var(--red)" : i === 1 ? "var(--amber)" : "var(--blue)"} fillOpacity={0.7} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent alerts table */}
      <div className="card">
        <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)" }}>
          <SectionHeader title="Recent Alerts">
            <button className="btn btn-ghost" onClick={() => navigate("/alerts")}
              style={{ fontSize: 11 }}>
              View all →
            </button>
          </SectionHeader>
        </div>
        {loading ? (
          <div style={{ padding: 32, display: "flex", justifyContent: "center" }}>
            <Spinner size={20} />
          </div>
        ) : alerts.length === 0 ? (
          <Empty message="No alerts yet — submit a flow on the Analyze page" />
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)" }}>
                {["ID", "Source IP", "Attack Class", "Risk", "Verdict", "Severity", "Status", "Time"].map((h) => (
                  <th key={h} style={{
                    padding: "8px 16px",
                    textAlign: "left",
                    fontFamily: "var(--font-mono)",
                    fontSize: 10,
                    letterSpacing: "0.08em",
                    color: "var(--text-muted)",
                    fontWeight: 600,
                    textTransform: "uppercase",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 10).map((a) => (
                <tr
                  key={a.id}
                  onClick={() => navigate(`/alerts/${a.id}`)}
                  className="animate-fade-in"
                  style={{
                    borderBottom: "1px solid var(--border)",
                    cursor: "pointer",
                    transition: "background 0.1s",
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-hover)"}
                  onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
                >
                  <td style={{ padding: "10px 16px", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)" }}>#{a.id}</td>
                  <td style={{ padding: "10px 16px", fontFamily: "var(--font-mono)", fontSize: 12 }}>{a.source_ip || "—"}</td>
                  <td style={{ padding: "10px 16px", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--amber)" }}>{a.attack_class}</td>
                  <td style={{ padding: "10px 16px", minWidth: 120 }}><RiskBar score={a.risk_score} /></td>
                  <td style={{ padding: "10px 16px" }}><VerdictBadge verdict={a.verdict} /></td>
                  <td style={{ padding: "10px 16px" }}><SeverityBadge severity={a.severity} /></td>
                  <td style={{ padding: "10px 16px" }}>
                    <span className={`badge badge-${a.status}`}>{a.status?.toUpperCase()}</span>
                  </td>
                  <td style={{ padding: "10px 16px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                    {format(new Date(a.created_at), "HH:mm:ss")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
