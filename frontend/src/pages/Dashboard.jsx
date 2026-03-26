import { useEffect, useState, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, LineChart, Line, PieChart, Pie, Legend,
} from "recharts";
import {
  AlertTriangle, Shield, Activity, Eye, RefreshCw, Zap,
  TrendingUp, Clock, CheckCircle, XCircle, Layers, ChevronRight,
  ExternalLink, Cpu, Target,
} from "lucide-react";
import { listAlerts } from "../lib/api";
import {
  StatCard, SectionHeader, VerdictBadge, SeverityBadge,
  RiskBar, Empty, Spinner, SkeletonRow
} from "../components/ui";
import { format, formatDistanceToNow } from "date-fns";

/* ── Helpers ─────────────────────────────────────────────────────────────────── */
function buildTimeline(alerts) {
  const buckets = {};
  alerts.forEach((a) => {
    const key = format(new Date(a.created_at), "MM/dd HH:mm");
    if (!buckets[key]) buckets[key] = { time: key, malicious: 0, suspicious: 0, clean: 0 };
    buckets[key][a.verdict] = (buckets[key][a.verdict] || 0) + 1;
  });
  return Object.values(buckets).slice(-16);
}

function buildClassDist(alerts) {
  const counts = {};
  alerts.forEach((a) => {
    if (a.attack_class && a.attack_class.toUpperCase() !== "BENIGN") {
      counts[a.attack_class] = (counts[a.attack_class] || 0) + 1;
    }
  });
  return Object.entries(counts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
}

function buildSeverityDist(alerts) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  alerts.forEach((a) => { if (counts[a.severity] !== undefined) counts[a.severity]++; });
  return Object.entries(counts).map(([name, value]) => ({ name: name.toUpperCase(), value }));
}

function buildStatusDist(alerts) {
  const counts = { open: 0, acknowledged: 0, escalated: 0, dismissed: 0 };
  alerts.forEach((a) => { if (counts[a.status] !== undefined) counts[a.status]++; });
  return counts;
}

const COLORS = ["var(--red)", "var(--amber)", "var(--blue)", "var(--green)"];
const PIE_COLORS = { CRITICAL: "var(--red)", HIGH: "var(--amber)", MEDIUM: "var(--blue)", LOW: "var(--green)" };

const TOOLTIP_STYLE = {
  background: "var(--bg-raised)",
  border: "1px solid var(--border-lit)",
  borderRadius: 6,
  fontFamily: "var(--font-mono)",
  fontSize: 11,
  color: "var(--text-primary)",
  boxShadow: "0 4px 20px rgba(0,0,0,0.4)",
};

const AXIS_TICK = { fontFamily: "var(--font-mono)", fontSize: 10, fill: "var(--text-muted)" };

/* ── Ticker ──────────────────────────────────────────────────────────────────── */
function AlertTicker({ alerts }) {
  const critical = alerts.filter(a => a.verdict === "malicious").slice(0, 20);
  if (critical.length === 0) return null;

  return (
    <div style={{
      background: "rgba(239,68,68,0.05)",
      borderTop: "1px solid rgba(239,68,68,0.15)",
      borderBottom: "1px solid rgba(239,68,68,0.15)",
      padding: "7px 0",
      overflow: "hidden",
      position: "relative",
    }}>
      <div style={{
        position: "absolute",
        left: 0, top: 0, bottom: 0,
        width: 100,
        background: "linear-gradient(90deg, var(--bg-base), transparent)",
        zIndex: 2,
      }} />
      <div style={{
        position: "absolute",
        right: 0, top: 0, bottom: 0,
        width: 100,
        background: "linear-gradient(270deg, var(--bg-base), transparent)",
        zIndex: 2,
      }} />

      <div style={{ display: "flex", alignItems: "center", gap: 0, overflow: "hidden" }}>
        <div style={{
          flexShrink: 0,
          display: "flex", alignItems: "center", gap: 8,
          padding: "0 20px",
          zIndex: 3,
          background: "var(--bg-base)",
        }}>
          <span className="pulse-amber" style={{ color: "var(--red)", fontSize: 10 }}>●</span>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            fontWeight: 700,
            color: "var(--red)",
            letterSpacing: "0.12em",
          }}>
            LIVE
          </span>
        </div>
        <div className="ticker-wrap" style={{ flex: 1 }}>
          <div className="ticker-inner">
            {[...critical, ...critical].map((a, i) => (
              <span key={i} style={{
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                color: "var(--text-secondary)",
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}>
                <span style={{ color: "var(--red)" }}>▲</span>
                <span style={{ color: "var(--amber)" }}>{a.attack_class}</span>
                {a.source_ip && <span>from {a.source_ip}</span>}
                <span style={{ color: "var(--text-muted)" }}>·</span>
                <span>risk {a.risk_score}</span>
                <span style={{ color: "var(--text-dim)", marginLeft: 24 }}>///</span>
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Metric mini spark ───────────────────────────────────────────────────────── */
function MiniSparkline({ data, color = "var(--amber)" }) {
  if (!data || data.length === 0) return null;
  return (
    <ResponsiveContainer width="100%" height={36}>
      <LineChart data={data} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
        <Line type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

/* ── Attack class row ────────────────────────────────────────────────────────── */
function AttackClassRow({ name, count, max, index }) {
  const colors = ["var(--red)", "var(--amber)", "var(--blue)", "var(--purple)", "var(--cyan)", "var(--green-bright)", "var(--red)", "var(--amber)"];
  const color = colors[index % colors.length];

  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          color: "var(--text-secondary)",
          maxWidth: 160,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}>
          {name}
        </span>
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          fontWeight: 700,
          color,
        }}>
          {count}
        </span>
      </div>
      <div className="progress-wrap">
        <div
          className="progress-bar"
          style={{
            width: `${(count / max) * 100}%`,
            background: `linear-gradient(90deg, ${color}60, ${color})`,
          }}
        />
      </div>
    </div>
  );
}

/* ── Main Dashboard ──────────────────────────────────────────────────────────── */
export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [refreshing, setRefreshing] = useState(false);
  const navigate = useNavigate();
  const intervalRef = useRef(null);

  const fetchAlerts = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    try {
      const data = await listAlerts({ limit: 200 });
      setAlerts(data);
      setLastRefresh(new Date());
    } catch (_) {}
    finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts(false);
    intervalRef.current = setInterval(() => fetchAlerts(true), 15000);
    return () => clearInterval(intervalRef.current);
  }, [fetchAlerts]);

  /* Computed metrics */
  const malicious    = alerts.filter(a => a.verdict === "malicious").length;
  const suspicious   = alerts.filter(a => a.verdict === "suspicious").length;
  const open         = alerts.filter(a => a.status === "open").length;
  const escalated    = alerts.filter(a => a.status === "escalated").length;
  const criticalOpen = alerts.filter(a => a.severity === "critical" && a.status === "open").length;

  const timeline    = buildTimeline(alerts);
  const classDist   = buildClassDist(alerts);
  const severityDist = buildSeverityDist(alerts);
  const statusDist  = buildStatusDist(alerts);
  const maxClassCount = classDist[0]?.count || 1;

  const recentAlerts = [...alerts].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 12);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Ticker */}
      <AlertTicker alerts={alerts} />

      {/* Main scrollable area */}
      <div style={{ flex: 1, overflowY: "auto", padding: "24px 28px" }}>
        {/* Header */}
        <div style={{ marginBottom: 24, display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h1 style={{
              fontFamily: "var(--font-display)",
              fontSize: 22,
              fontWeight: 800,
              color: "var(--text-primary)",
              letterSpacing: "-0.02em",
              lineHeight: 1.1,
              marginBottom: 6,
            }}>
              Security Overview
            </h1>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <span style={{
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                color: "var(--text-muted)",
              }}>
                {format(new Date(), "EEEE, MMMM d yyyy")}
              </span>
              {criticalOpen > 0 && (
                <span style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 5,
                  fontFamily: "var(--font-mono)",
                  fontSize: 10,
                  fontWeight: 700,
                  color: "var(--red)",
                  background: "var(--red-glow)",
                  border: "1px solid rgba(239,68,68,0.25)",
                  padding: "3px 8px",
                  borderRadius: 4,
                  animation: "pulse-red 2s infinite",
                }}>
                  <AlertTriangle size={10} />
                  {criticalOpen} CRITICAL OPEN
                </span>
              )}
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              fontFamily: "var(--font-mono)",
              fontSize: 10,
              color: "var(--text-muted)",
            }}>
              Updated {formatDistanceToNow(lastRefresh, { addSuffix: true })}
            </div>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => fetchAlerts(true)}
              disabled={refreshing}
            >
              <RefreshCw size={11} style={{ animation: refreshing ? "spin 1s linear infinite" : "none" }} />
              Refresh
            </button>
            <button className="btn btn-primary btn-sm" onClick={() => navigate("/analyze")}>
              <Zap size={11} /> Analyze Flow
            </button>
          </div>
        </div>

        {/* Stat cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 20 }}>
          <div className="animate-fade-in stagger-1">
            <StatCard
              label="Total Alerts"
              value={loading ? "—" : alerts.length}
              sub="all time"
              icon={Layers}
              loading={loading}
            />
          </div>
          <div className="animate-fade-in stagger-2">
            <StatCard
              label="Malicious"
              value={loading ? "—" : malicious}
              sub="confirmed threats"
              accent="var(--red)"
              icon={AlertTriangle}
              loading={loading}
            />
          </div>
          <div className="animate-fade-in stagger-3">
            <StatCard
              label="Suspicious"
              value={loading ? "—" : suspicious}
              sub="need review"
              accent="var(--amber)"
              icon={Eye}
              loading={loading}
            />
          </div>
          <div className="animate-fade-in stagger-4">
            <StatCard
              label="Open Queue"
              value={loading ? "—" : open}
              sub="awaiting action"
              accent="var(--blue)"
              icon={Clock}
              loading={loading}
            />
          </div>
          <div className="animate-fade-in stagger-5">
            <StatCard
              label="Escalated"
              value={loading ? "—" : escalated}
              sub="high priority"
              accent="var(--red)"
              icon={TrendingUp}
              loading={loading}
            />
          </div>
        </div>

        {/* Charts row 1 */}
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 16 }}>
          {/* Timeline */}
          <div className="card animate-fade-in stagger-2" style={{ padding: "20px 20px 12px" }}>
            <SectionHeader title="Alert Timeline" subtitle="Threat activity over time">
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
                last {timeline.length} windows
              </span>
            </SectionHeader>

            {loading ? (
              <div style={{ height: 200, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Spinner />
              </div>
            ) : timeline.length === 0 ? (
              <Empty message="No timeline data — submit flows to generate alerts" />
            ) : (
              <>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={timeline} margin={{ top: 4, right: 4, bottom: 0, left: -28 }}>
                    <defs>
                      <linearGradient id="gMalicious" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="var(--red)"   stopOpacity={0.4} />
                        <stop offset="95%" stopColor="var(--red)"   stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gSuspicious" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="var(--amber)" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="var(--amber)" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gClean" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="var(--green)" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="var(--green)" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" tick={AXIS_TICK} axisLine={false} tickLine={false} />
                    <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: "var(--border-lit)", strokeWidth: 1 }} />
                    <Area type="monotone" dataKey="malicious"  name="Malicious"  stroke="var(--red)"   fill="url(#gMalicious)"  strokeWidth={2} dot={false} />
                    <Area type="monotone" dataKey="suspicious" name="Suspicious" stroke="var(--amber)" fill="url(#gSuspicious)" strokeWidth={1.5} dot={false} />
                    <Area type="monotone" dataKey="clean"      name="Clean"      stroke="var(--green)" fill="url(#gClean)"      strokeWidth={1} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>

                {/* Legend */}
                <div style={{ display: "flex", gap: 16, marginTop: 8, paddingLeft: 4 }}>
                  {[["Malicious", "var(--red)"], ["Suspicious", "var(--amber)"], ["Clean", "var(--green)"]].map(([label, color]) => (
                    <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                      <div style={{ width: 8, height: 2, background: color, borderRadius: 1 }} />
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>{label}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>

          {/* Severity donut */}
          <div className="card animate-fade-in stagger-3" style={{ padding: "20px" }}>
            <SectionHeader title="Severity Distribution" />
            {loading ? (
              <div style={{ height: 200, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Spinner />
              </div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie
                      data={severityDist}
                      cx="50%" cy="50%"
                      innerRadius={45}
                      outerRadius={70}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {severityDist.map((entry, index) => (
                        <Cell key={entry.name} fill={PIE_COLORS[entry.name] || COLORS[index]} fillOpacity={0.8} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                  </PieChart>
                </ResponsiveContainer>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, marginTop: 4 }}>
                  {severityDist.map((item) => (
                    <div key={item.name} style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "6px 10px",
                      background: "var(--bg-raised)",
                      borderRadius: 4,
                      border: "1px solid var(--border)",
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <div style={{ width: 6, height: 6, borderRadius: "50%", background: PIE_COLORS[item.name] }} />
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.08em" }}>
                          {item.name}
                        </span>
                      </div>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, color: PIE_COLORS[item.name] }}>
                        {item.value}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

        {/* Charts row 2 */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
          {/* Attack classes */}
          <div className="card" style={{ padding: "20px" }}>
            <SectionHeader title="Top Attack Classes" subtitle="By detection count" />
            {loading ? (
              <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center" }}><Spinner /></div>
            ) : classDist.length === 0 ? (
              <Empty message="No attack data yet" />
            ) : (
              <div>
                {classDist.map((item, i) => (
                  <AttackClassRow key={item.name} {...item} max={maxClassCount} index={i} />
                ))}
              </div>
            )}
          </div>

          {/* Status breakdown + recent action */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="card" style={{ padding: "18px 20px" }}>
              <SectionHeader title="Alert Status" />
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {Object.entries(statusDist).map(([status, count]) => {
                  const conf = {
                    open:         { label: "OPEN",         icon: Clock,        color: "var(--blue)" },
                    acknowledged: { label: "ACKNOWLEDGED",  icon: CheckCircle,  color: "var(--amber)" },
                    escalated:    { label: "ESCALATED",     icon: AlertTriangle,color: "var(--red)" },
                    dismissed:    { label: "DISMISSED",     icon: XCircle,      color: "var(--gray-lit)" },
                  }[status] || { label: status.toUpperCase(), icon: Activity, color: "var(--gray-lit)" };

                  const Icon = conf.icon;

                  return (
                    <div key={status} style={{
                      padding: "12px 14px",
                      background: "var(--bg-raised)",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      cursor: "pointer",
                      transition: "all 0.15s",
                    }}
                    onClick={() => navigate(`/alerts?status=${status}`)}
                    onMouseEnter={e => e.currentTarget.style.borderColor = "var(--border-lit)"}
                    onMouseLeave={e => e.currentTarget.style.borderColor = "var(--border)"}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                        <Icon size={11} color={conf.color} />
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em" }}>
                          {conf.label}
                        </span>
                      </div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 700, color: conf.color }}>
                        {loading ? "—" : count}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Quick actions */}
            <div className="card" style={{ padding: "16px 18px" }}>
              <div className="section-label" style={{ marginBottom: 12 }}>Quick Actions</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {[
                  { label: "View all open alerts", to: "/alerts?status=open", accent: "var(--blue)" },
                  { label: "Analyze new flow", to: "/analyze", accent: "var(--amber)" },
                  { label: "IOC enrichment lookup", to: "/ioc", accent: "var(--purple)" },
                  { label: "Browse data explorer", to: "/explorer", accent: "var(--green)" },
                ].map(({ label, to, accent }) => (
                  <button
                    key={to}
                    onClick={() => navigate(to)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "9px 12px",
                      background: "var(--bg-raised)",
                      border: "1px solid var(--border)",
                      borderRadius: 5,
                      cursor: "pointer",
                      color: "var(--text-secondary)",
                      fontSize: 12,
                      fontFamily: "var(--font-sans)",
                      transition: "all 0.15s",
                      textAlign: "left",
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.borderColor = accent;
                      e.currentTarget.style.color = "var(--text-primary)";
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.borderColor = "var(--border)";
                      e.currentTarget.style.color = "var(--text-secondary)";
                    }}
                  >
                    {label}
                    <ChevronRight size={12} style={{ color: accent }} />
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Recent alerts table */}
        <div className="card">
          <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)" }}>
            <SectionHeader title="Recent Alerts" subtitle={`${recentAlerts.length} most recent`}>
              <button className="btn btn-ghost btn-sm" onClick={() => navigate("/alerts")}>
                View all <ChevronRight size={10} />
              </button>
            </SectionHeader>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  {["ID", "Time", "Source IP", "Attack Class", "Risk Score", "Verdict", "Severity", "Status"].map(h => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={8} />)
                ) : recentAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={8}>
                      <Empty
                        message="No alerts yet — submit flows on the Analyze page"
                        action={
                          <button className="btn btn-primary btn-sm" onClick={() => navigate("/analyze")}>
                            <Cpu size={11} /> Analyze Flow
                          </button>
                        }
                      />
                    </td>
                  </tr>
                ) : recentAlerts.map((a, idx) => (
                  <tr
                    key={a.id}
                    className="animate-fade-in"
                    style={{
                      cursor: "pointer",
                      borderLeft: a.verdict === "malicious"
                        ? "2px solid var(--red)"
                        : a.verdict === "suspicious"
                        ? "2px solid var(--amber)"
                        : "2px solid transparent",
                      animationDelay: `${idx * 0.03}s`,
                    }}
                    onClick={() => navigate(`/alerts/${a.id}`)}
                  >
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                        #{a.id}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
                        {format(new Date(a.created_at), "MM-dd HH:mm")}
                      </div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
                        {formatDistanceToNow(new Date(a.created_at), { addSuffix: true })}
                      </div>
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                        {a.source_ip || <span style={{ color: "var(--text-muted)" }}>—</span>}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--amber)" }}>
                        {a.attack_class}
                      </span>
                    </td>
                    <td style={{ minWidth: 140 }}>
                      <RiskBar score={a.risk_score} />
                    </td>
                    <td><VerdictBadge verdict={a.verdict} /></td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td>
                      <span className={`badge badge-${a.status}`}>{a.status?.toUpperCase()}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
