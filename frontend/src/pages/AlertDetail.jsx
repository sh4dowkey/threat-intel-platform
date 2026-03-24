import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getAlert, updateAlert } from "../lib/api";
import { format } from "date-fns";
import { ArrowLeft, ExternalLink, Zap, Shield, AlertTriangle } from "lucide-react";
import { VerdictBadge, SeverityBadge, RiskBar, Spinner } from "../components/ui";

function InfoRow({ label, value, mono, color }) {
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "flex-start",
      padding: "9px 0", borderBottom: "1px solid var(--border)",
    }}>
      <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", flexShrink: 0, marginRight: 24 }}>
        {label}
      </span>
      <span style={{
        fontSize: 12,
        color: color || "var(--text-primary)",
        fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
        textAlign: "right",
      }}>
        {value ?? "—"}
      </span>
    </div>
  );
}

function ExplainBlock({ title, children, accent }) {
  return (
    <div style={{
      padding: "14px 16px",
      background: "var(--bg-raised)",
      border: `1px solid ${accent || "var(--border-lit)"}`,
      borderRadius: 6,
      marginBottom: 10,
    }}>
      <div style={{
        fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
        letterSpacing: "0.1em", color: accent || "var(--text-muted)",
        textTransform: "uppercase", marginBottom: 8,
      }}>
        {title}
      </div>
      <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7 }}>
        {children}
      </div>
    </div>
  );
}

export default function AlertDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    getAlert(id)
      .then(setAlert)
      .catch(() => navigate("/alerts"))
      .finally(() => setLoading(false));
  }, [id]);

  const handleStatus = async (status) => {
    setUpdating(true);
    try {
      await updateAlert(id, status);
      setAlert((prev) => ({ ...prev, status }));
    } catch (_) {}
    finally { setUpdating(false); }
  };

  if (loading) return (
    <div style={{ display: "flex", justifyContent: "center", padding: 64 }}>
      <Spinner size={24} />
    </div>
  );
  if (!alert) return null;

  const ismalicious = alert.verdict === "malicious";
  const accentColor = ismalicious ? "var(--red)" : alert.verdict === "suspicious" ? "var(--amber)" : "var(--green)";

  return (
    <div style={{ padding: "28px 32px", overflowY: "auto", height: "100%" }}>
      {/* Back + header */}
      <div style={{ marginBottom: 24 }}>
        <button
          className="btn btn-ghost"
          style={{ padding: "5px 10px", fontSize: 11, marginBottom: 16 }}
          onClick={() => navigate("/alerts")}
        >
          <ArrowLeft size={12} /> Back to alerts
        </button>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h1 style={{
              fontFamily: "var(--font-mono)", fontSize: 16, fontWeight: 600,
              color: "var(--text-primary)", letterSpacing: "0.04em", marginBottom: 6,
            }}>
              ALERT <span style={{ color: accentColor }}>#{alert.id}</span>
              {ismalicious && (
                <span style={{ marginLeft: 10 }}
                  className="pulse-red"
                  title="Critical — active threat">
                  <AlertTriangle size={16} color="var(--red)" style={{ display: "inline" }} />
                </span>
              )}
            </h1>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)" }}>
              {format(new Date(alert.created_at), "yyyy-MM-dd HH:mm:ss")} ·{" "}
              <span style={{ color: "var(--amber)" }}>{alert.attack_class}</span>
            </div>
          </div>
          {/* Status actions */}
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className={`badge badge-${alert.status}`}>{alert.status?.toUpperCase()}</span>
            {alert.status === "open" && (
              <>
                <button className="btn btn-ghost" disabled={updating} onClick={() => handleStatus("acknowledged")}>
                  Acknowledge
                </button>
                <button className="btn btn-danger" disabled={updating} onClick={() => handleStatus("escalated")}>
                  Escalate
                </button>
              </>
            )}
            {alert.status !== "dismissed" && (
              <button className="btn btn-ghost" disabled={updating} onClick={() => handleStatus("dismissed")} style={{ fontSize: 11 }}>
                Dismiss
              </button>
            )}
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 20 }}>
        {/* Left col — LLM explanation */}
        <div>
          {/* Summary card */}
          <div className="card" style={{
            padding: "18px 20px", marginBottom: 16,
            borderLeft: `3px solid ${accentColor}`,
          }}>
            <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginBottom: 8, letterSpacing: "0.08em" }}>
              SUMMARY {alert.explanation_cached && (
                <span style={{ color: "var(--green)", marginLeft: 8 }}>● CACHED</span>
              )}
            </div>
            <p style={{ fontSize: 14, color: "var(--text-primary)", lineHeight: 1.7 }}>
              {alert.summary}
            </p>
          </div>

          {/* Explanation blocks */}
          <ExplainBlock title="What is happening" accent={accentColor}>
            {alert.what_is_happening}
          </ExplainBlock>
          <ExplainBlock title="Why it was flagged" accent="var(--amber)">
            {alert.why_flagged}
          </ExplainBlock>
          <ExplainBlock title="Potential impact" accent="var(--red)">
            {alert.potential_impact}
          </ExplainBlock>

          {/* Recommended action */}
          <div style={{
            padding: "14px 16px",
            background: "rgba(39,200,122,0.06)",
            border: "1px solid var(--green-dim)",
            borderRadius: 6,
            marginBottom: 16,
          }}>
            <div style={{
              fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
              letterSpacing: "0.1em", color: "var(--green)",
              textTransform: "uppercase", marginBottom: 8,
            }}>
              ⚡ Recommended Action
            </div>
            <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.8, whiteSpace: "pre-line" }}>
              {alert.recommended_action}
            </div>
          </div>

          {/* False positive assessment */}
          <div style={{
            padding: "10px 16px",
            background: "var(--bg-raised)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            color: "var(--text-muted)",
          }}>
            <span style={{ color: "var(--text-primary)", marginRight: 8 }}>FP LIKELIHOOD:</span>
            {alert.false_positive_likelihood}
          </div>
        </div>

        {/* Right col — scores, MITRE, features */}
        <div>
          {/* Score card */}
          <div className="card" style={{ padding: "18px 20px", marginBottom: 14 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 14, letterSpacing: "0.1em" }}>
              DETECTION SCORES
            </div>
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 6 }}>
                RISK SCORE
              </div>
              <RiskBar score={alert.risk_score} />
            </div>
            <InfoRow label="Verdict"     value={<VerdictBadge verdict={alert.verdict} />} />
            <InfoRow label="Severity"    value={<SeverityBadge severity={alert.severity} />} />
            <InfoRow label="Attack Class" value={alert.attack_class}  mono color="var(--amber)" />
            <InfoRow label="Confidence"  value={`${(alert.attack_confidence * 100).toFixed(1)}%`} mono />
            <InfoRow label="Anomaly Score" value={alert.anomaly_score?.toFixed(4)} mono />
            <InfoRow label="Is Anomaly"  value={alert.is_anomaly ? "YES" : "NO"} mono
              color={alert.is_anomaly ? "var(--red)" : "var(--green)"} />
          </div>

          {/* Network context */}
          <div className="card" style={{ padding: "18px 20px", marginBottom: 14 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 14, letterSpacing: "0.1em" }}>
              NETWORK CONTEXT
            </div>
            <InfoRow label="Source IP"  value={alert.source_ip}      mono />
            <InfoRow label="Dest IP"    value={alert.destination_ip} mono />
            <InfoRow label="Dest Port"  value={alert.destination_port} mono />
          </div>

          {/* MITRE ATT&CK */}
          {alert.mitre && (
            <div style={{
              padding: "16px",
              background: "rgba(74,158,255,0.05)",
              border: "1px solid var(--blue-dim)",
              borderRadius: 6,
              marginBottom: 14,
            }}>
              <div style={{
                fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
                letterSpacing: "0.1em", color: "var(--blue)",
                textTransform: "uppercase", marginBottom: 12,
                display: "flex", alignItems: "center", gap: 6,
              }}>
                <Shield size={12} /> MITRE ATT&CK
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>
                <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 10 }}>TACTIC</span>
                <br />
                <span style={{ fontFamily: "var(--font-mono)", color: "var(--blue)" }}>
                  {alert.mitre.tactic_id}
                </span>{" "}
                {alert.mitre.tactic_name}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 12 }}>
                <span style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 10 }}>TECHNIQUE</span>
                <br />
                <span style={{ fontFamily: "var(--font-mono)", color: "var(--blue)" }}>
                  {alert.mitre.technique_id}
                </span>{" "}
                {alert.mitre.technique_name}
              </div>
              <a
                href={alert.mitre.technique_url}
                target="_blank"
                rel="noreferrer"
                style={{
                  display: "inline-flex", alignItems: "center", gap: 5,
                  fontFamily: "var(--font-mono)", fontSize: 11,
                  color: "var(--blue)", textDecoration: "none",
                }}
              >
                <ExternalLink size={11} /> View on MITRE ATT&CK
              </a>
            </div>
          )}

          {/* SHAP feature importance */}
          {alert.top_features?.length > 0 && (
            <div className="card" style={{ padding: "16px 18px" }}>
              <div style={{
                fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)",
                marginBottom: 12, letterSpacing: "0.1em",
              }}>
                TOP CONTRIBUTING FEATURES
              </div>
              {alert.top_features.map((f, i) => (
                <div key={i} style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
                      {f.feature?.replace(/_/g, " ")}
                    </span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--amber)" }}>
                      {f.importance?.toFixed(4)}
                    </span>
                  </div>
                  <div className="risk-bar-wrap">
                    <div
                      className="risk-bar"
                      style={{
                        width: `${Math.min(100, (f.importance / (alert.top_features[0]?.importance || 1)) * 100)}%`,
                        background: i === 0 ? "var(--amber)" : "var(--blue)",
                        opacity: 1 - i * 0.1,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
