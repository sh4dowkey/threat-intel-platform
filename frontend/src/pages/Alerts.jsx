import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listAlerts, updateAlert } from "../lib/api";
import { format } from "date-fns";
import { Filter, RefreshCw, ExternalLink } from "lucide-react";
import {
  VerdictBadge, SeverityBadge, RiskBar, Spinner, Empty, SectionHeader,
} from "../components/ui";

const VERDICTS  = ["", "malicious", "suspicious", "clean"];
const SEVERITIES = ["", "critical", "high", "medium", "low"];
const STATUSES  = ["", "open", "acknowledged", "escalated", "dismissed"];

export default function Alerts() {
  const [alerts, setAlerts]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [verdict, setVerdict]   = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus]     = useState("");
  const navigate = useNavigate();

  const fetch = async () => {
    setLoading(true);
    try {
      const params = {};
      if (verdict)  params.verdict  = verdict;
      if (severity) params.severity = severity;
      if (status)   params.status   = status;
      setAlerts(await listAlerts({ limit: 200, ...params }));
    } catch (_) {}
    finally { setLoading(false); }
  };

  useEffect(() => { fetch(); }, [verdict, severity, status]);

  const handleStatus = async (e, id, newStatus) => {
    e.stopPropagation();
    try {
      await updateAlert(id, newStatus);
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, status: newStatus } : a))
      );
    } catch (_) {}
  };

  return (
    <div style={{ padding: "28px 32px", overflowY: "auto", height: "100%" }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{
          fontFamily: "var(--font-mono)", fontSize: 18, fontWeight: 600,
          letterSpacing: "0.04em", marginBottom: 4,
        }}>
          ALERT QUEUE
        </h1>
        <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
          {alerts.length} alerts
        </div>
      </div>

      {/* Filters */}
      <div style={{
        display: "flex", gap: 10, marginBottom: 20, alignItems: "center",
        padding: "12px 16px",
        background: "var(--bg-surface)",
        border: "1px solid var(--border)",
        borderRadius: 6,
      }}>
        <Filter size={13} color="var(--text-muted)" />
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", marginRight: 4 }}>
          FILTER
        </span>
        {[
          { label: "Verdict",  value: verdict,  set: setVerdict,  opts: VERDICTS },
          { label: "Severity", value: severity, set: setSeverity, opts: SEVERITIES },
          { label: "Status",   value: status,   set: setStatus,   opts: STATUSES },
        ].map(({ label, value, set, opts }) => (
          <select
            key={label}
            value={value}
            onChange={(e) => set(e.target.value)}
            style={{
              background: "var(--bg-base)",
              border: "1px solid var(--border-lit)",
              borderRadius: 4,
              color: value ? "var(--text-primary)" : "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              padding: "5px 10px",
              cursor: "pointer",
              outline: "none",
            }}
          >
            <option value="">{label}: All</option>
            {opts.filter(Boolean).map((o) => (
              <option key={o} value={o}>{o.toUpperCase()}</option>
            ))}
          </select>
        ))}
        <button className="btn btn-ghost" onClick={fetch} style={{ marginLeft: "auto", padding: "5px 12px" }}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Table */}
      <div className="card">
        {loading ? (
          <div style={{ padding: 48, display: "flex", justifyContent: "center" }}>
            <Spinner size={22} />
          </div>
        ) : alerts.length === 0 ? (
          <Empty message="No alerts match your filters" />
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)" }}>
                {["#", "Time", "Source IP", "Attack Class", "MITRE", "Risk", "Severity", "Status", "Actions"].map((h) => (
                  <th key={h} style={{
                    padding: "9px 14px", textAlign: "left",
                    fontFamily: "var(--font-mono)", fontSize: 10,
                    letterSpacing: "0.08em", color: "var(--text-muted)",
                    fontWeight: 600, textTransform: "uppercase",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr
                  key={a.id}
                  className="animate-fade-in"
                  style={{
                    borderBottom: "1px solid var(--border)",
                    cursor: "pointer",
                    borderLeft: a.verdict === "malicious"
                      ? "2px solid var(--red)"
                      : a.verdict === "suspicious"
                      ? "2px solid var(--amber)"
                      : "2px solid transparent",
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-hover)"}
                  onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
                  onClick={() => navigate(`/alerts/${a.id}`)}
                >
                  <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                    {a.id}
                  </td>
                  <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                    {format(new Date(a.created_at), "MM-dd HH:mm:ss")}
                  </td>
                  <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 12 }}>
                    {a.source_ip || <span style={{ color: "var(--text-muted)" }}>—</span>}
                  </td>
                  <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--amber)" }}>
                    {a.attack_class}
                  </td>
                  <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
                    {a.mitre?.technique_id || "—"}
                  </td>
                  <td style={{ padding: "10px 14px", minWidth: 130 }}>
                    <RiskBar score={a.risk_score} />
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className={`badge badge-${a.status}`}>{a.status?.toUpperCase()}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }} onClick={(e) => e.stopPropagation()}>
                    <div style={{ display: "flex", gap: 4 }}>
                      {a.status === "open" && (
                        <>
                          <button
                            className="btn btn-ghost"
                            style={{ padding: "3px 8px", fontSize: 10 }}
                            onClick={(e) => handleStatus(e, a.id, "acknowledged")}
                          >ACK</button>
                          <button
                            className="btn btn-danger"
                            style={{ padding: "3px 8px", fontSize: 10 }}
                            onClick={(e) => handleStatus(e, a.id, "escalated")}
                          >ESC</button>
                        </>
                      )}
                      {a.status !== "dismissed" && a.status !== "open" && (
                        <button
                          className="btn btn-ghost"
                          style={{ padding: "3px 8px", fontSize: 10 }}
                          onClick={(e) => handleStatus(e, a.id, "dismissed")}
                        >DIS</button>
                      )}
                    </div>
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
