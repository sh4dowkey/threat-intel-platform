import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getAlert, updateAlert } from "../lib/api";
import { format, formatDistanceToNow } from "date-fns";
import {
  ArrowLeft, ExternalLink, Shield, AlertTriangle, CheckCircle,
  XCircle, Activity, Target, Brain, Zap, ChevronDown, ChevronUp,
  Copy, Clock, Server, Globe, Info, BookOpen, TrendingUp,
} from "lucide-react";
import {
  VerdictBadge, SeverityBadge, RiskBar, Spinner,
  InfoRow, CopyButton, Collapsible, Tag, toast, ToastContainer,
} from "../components/ui";

/* ── Explanation section card ────────────────────────────────────────────────── */
function ExplainCard({ icon: Icon, title, children, accentColor = "var(--border-lit)", badge }) {
  return (
    <div style={{
      background: "var(--bg-card)",
      border: `1px solid var(--border)`,
      borderLeft: `3px solid ${accentColor}`,
      borderRadius: 8,
      overflow: "hidden",
      marginBottom: 10,
    }}>
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "12px 16px",
        background: `linear-gradient(90deg, ${accentColor}08, transparent)`,
        borderBottom: "1px solid var(--border)",
      }}>
        {Icon && <Icon size={13} color={accentColor} />}
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: "0.1em",
          color: accentColor,
          textTransform: "uppercase",
          flex: 1,
        }}>
          {title}
        </span>
        {badge && badge}
      </div>
      <div style={{ padding: "14px 16px" }}>
        {children}
      </div>
    </div>
  );
}

/* ── SHAP waterfall bar ──────────────────────────────────────────────────────── */
function ShapBar({ feature, importance, value, max, index }) {
  const pct = Math.min(100, (importance / max) * 100);
  const colors = [
    "var(--red)", "var(--amber)", "var(--blue)",
    "var(--purple)", "var(--cyan)", "var(--green)",
  ];
  const color = colors[index % colors.length];

  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 5 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            fontWeight: 700,
            color: "var(--text-muted)",
            minWidth: 14,
          }}>
            {index + 1}
          </span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-primary)" }}>
            {feature?.replace(/_/g, " ")}
          </span>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
            val: {typeof value === "number" ? value.toFixed(3) : value}
          </span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, color }}>
            {importance?.toFixed(4)}
          </span>
        </div>
      </div>
      <div style={{ position: "relative" }}>
        <div className="progress-wrap" style={{ height: 8 }}>
          <div
            className="progress-bar"
            style={{
              width: `${pct}%`,
              background: `linear-gradient(90deg, ${color}40, ${color})`,
              boxShadow: `0 0 8px ${color}40`,
            }}
          />
        </div>
        <div style={{
          position: "absolute",
          left: `${pct}%`,
          top: -2,
          width: 2,
          height: 12,
          background: color,
          borderRadius: 1,
        }} />
      </div>
    </div>
  );
}

/* ── MITRE card ──────────────────────────────────────────────────────────────── */
function MITRECard({ mitre }) {
  if (!mitre) return null;
  return (
    <div style={{
      background: "rgba(59,130,246,0.05)",
      border: "1px solid rgba(59,130,246,0.2)",
      borderRadius: 8,
      padding: "16px",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
        <div style={{
          width: 28, height: 28,
          background: "rgba(59,130,246,0.1)",
          border: "1px solid rgba(59,130,246,0.2)",
          borderRadius: 6,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <Shield size={14} color="var(--blue-bright)" />
        </div>
        <div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--blue)", fontWeight: 700, letterSpacing: "0.1em" }}>
            MITRE ATT&CK
          </div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)" }}>
            Enterprise Framework
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", marginBottom: 4, letterSpacing: "0.1em" }}>
          TACTIC
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            fontWeight: 700,
            color: "var(--blue-bright)",
            background: "rgba(59,130,246,0.1)",
            padding: "2px 7px",
            borderRadius: 3,
          }}>
            {mitre.tactic_id}
          </span>
          <span style={{ fontSize: 13, color: "var(--text-primary)" }}>
            {mitre.tactic_name}
          </span>
        </div>
      </div>

      <div style={{ marginBottom: 14 }}>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", marginBottom: 4, letterSpacing: "0.1em" }}>
          TECHNIQUE
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            fontWeight: 700,
            color: "var(--blue-bright)",
            background: "rgba(59,130,246,0.1)",
            padding: "2px 7px",
            borderRadius: 3,
          }}>
            {mitre.technique_id}
          </span>
          <span style={{ fontSize: 13, color: "var(--text-primary)" }}>
            {mitre.technique_name}
          </span>
        </div>
      </div>

      <a
        href={mitre.technique_url}
        target="_blank"
        rel="noreferrer"
        style={{ textDecoration: "none" }}
      >
        <button className="btn btn-ghost" style={{ width: "100%", fontSize: 11 }}>
          <ExternalLink size={11} />
          View on attack.mitre.org
        </button>
      </a>
    </div>
  );
}

/* ── Recommended actions parser ──────────────────────────────────────────────── */
function ActionSteps({ text }) {
  if (!text) return null;

  const lines = text.split(/\n/).map(l => l.trim()).filter(Boolean);
  const steps = lines.filter(l => /^\d+\./.test(l)).map(l => l.replace(/^\d+\.\s*/, ""));
  const rest = lines.filter(l => !/^\d+\./.test(l));

  if (steps.length === 0) {
    return (
      <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.8, whiteSpace: "pre-wrap" }}>
        {text}
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {steps.map((step, i) => (
          <div key={i} style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 12,
            padding: "10px 14px",
            background: "var(--bg-raised)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            transition: "border-color 0.15s",
          }}>
            <div style={{
              width: 22, height: 22,
              borderRadius: "50%",
              background: "rgba(16,185,129,0.1)",
              border: "1px solid rgba(16,185,129,0.2)",
              color: "var(--green-bright)",
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              fontWeight: 700,
              display: "flex", alignItems: "center", justifyContent: "center",
              flexShrink: 0,
              marginTop: 1,
            }}>
              {i + 1}
            </div>
            <span style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>
              {step}
            </span>
          </div>
        ))}
      </div>
      {rest.length > 0 && (
        <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-muted)", lineHeight: 1.7 }}>
          {rest.join(" ")}
        </div>
      )}
    </div>
  );
}

/* ── Main AlertDetail ────────────────────────────────────────────────────────── */
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
      setAlert(prev => ({ ...prev, status }));
      toast.success(`Alert ${status} successfully`);
    } catch (_) {
      toast.error("Failed to update status");
    }
    finally { setUpdating(false); }
  };

  if (loading) return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100%" }}>
      <Spinner size={28} />
    </div>
  );
  if (!alert) return null;

  const accentColor =
    alert.verdict === "malicious"  ? "var(--red)" :
    alert.verdict === "suspicious" ? "var(--amber)" :
    "var(--green)";

  const maxShap = alert.top_features?.[0]?.importance || 1;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      <ToastContainer />

      {/* Header bar */}
      <div style={{
        padding: "14px 24px",
        borderBottom: "1px solid var(--border)",
        background: "var(--bg-surface)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <button className="btn btn-ghost btn-sm" onClick={() => navigate("/alerts")}>
            <ArrowLeft size={12} /> Back
          </button>

          <div style={{ width: 1, height: 20, background: "var(--border)" }} />

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 8, height: 8, borderRadius: "50%",
              background: accentColor,
              boxShadow: `0 0 8px ${accentColor}`,
              animation: alert.verdict === "malicious" ? "pulse-red 2s infinite" : "none",
            }} />
            <span style={{ fontFamily: "var(--font-display)", fontSize: 16, fontWeight: 700, letterSpacing: "-0.01em" }}>
              Alert <span style={{ color: accentColor }}>#{alert.id}</span>
            </span>
            <VerdictBadge verdict={alert.verdict} size="lg" />
            <SeverityBadge severity={alert.severity} />
          </div>

          <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
            {format(new Date(alert.created_at), "yyyy-MM-dd HH:mm:ss")} ·{" "}
            {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
          </div>
        </div>

        {/* Actions */}
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span className={`badge badge-${alert.status}`}>{alert.status?.toUpperCase()}</span>

          {alert.status === "open" && (
            <>
              <button className="btn btn-ghost btn-sm" disabled={updating} onClick={() => handleStatus("acknowledged")}>
                <CheckCircle size={11} /> Acknowledge
              </button>
              <button className="btn btn-danger btn-sm" disabled={updating} onClick={() => handleStatus("escalated")}>
                <AlertTriangle size={11} /> Escalate
              </button>
            </>
          )}
          {alert.status === "escalated" && (
            <button className="btn btn-ghost btn-sm" disabled={updating} onClick={() => handleStatus("acknowledged")}>
              <CheckCircle size={11} /> De-escalate
            </button>
          )}
          {alert.status !== "dismissed" && (
            <button className="btn btn-ghost btn-sm" disabled={updating} onClick={() => handleStatus("dismissed")}>
              <XCircle size={11} /> Dismiss
            </button>
          )}
        </div>
      </div>

      {/* Main content */}
      <div style={{ flex: 1, overflowY: "auto", padding: "24px" }}>
        {/* Summary banner */}
        <div style={{
          padding: "18px 20px",
          background: `linear-gradient(135deg, ${accentColor}08, var(--bg-card))`,
          border: `1px solid ${accentColor}25`,
          borderRadius: 10,
          marginBottom: 20,
          position: "relative",
          overflow: "hidden",
        }}>
          <div style={{
            position: "absolute",
            top: 0, right: 0,
            width: 200, height: "100%",
            background: `radial-gradient(ellipse at 100% 50%, ${accentColor}08, transparent 70%)`,
            pointerEvents: "none",
          }} />

          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
            <Brain size={14} color={accentColor} />
            <span className="section-label" style={{ color: accentColor }}>
              AI ANALYSIS SUMMARY
            </span>
            {alert.explanation_cached && (
              <span style={{
                fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700,
                color: "var(--green)", background: "var(--green-glow)",
                border: "1px solid rgba(16,185,129,0.2)",
                padding: "2px 7px", borderRadius: 3,
              }}>
                ● CACHED
              </span>
            )}
          </div>

          <p style={{
            fontSize: 15,
            color: "var(--text-primary)",
            lineHeight: 1.7,
            fontWeight: 400,
          }}>
            {alert.summary}
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 20 }}>
          {/* Left: LLM explanation */}
          <div>
            {/* What is happening */}
            <ExplainCard
              icon={Activity}
              title="What is Happening"
              accentColor="var(--blue-bright)"
            >
              <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.8 }}>
                {alert.what_is_happening}
              </p>
            </ExplainCard>

            {/* Why flagged */}
            <ExplainCard
              icon={Target}
              title="Why It Was Flagged"
              accentColor="var(--amber)"
            >
              <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.8 }}>
                {alert.why_flagged}
              </p>

              {/* Feature highlights */}
              {alert.top_features?.length > 0 && (
                <div style={{
                  marginTop: 12,
                  padding: "12px 14px",
                  background: "var(--bg-raised)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                }}>
                  <div className="section-label" style={{ marginBottom: 10 }}>
                    Key Triggering Features
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {alert.top_features.slice(0, 3).map((f, i) => (
                      <div key={i} style={{
                        padding: "5px 10px",
                        background: "var(--bg-base)",
                        border: "1px solid var(--border-lit)",
                        borderRadius: 4,
                        fontFamily: "var(--font-mono)",
                        fontSize: 11,
                      }}>
                        <span style={{ color: "var(--amber)" }}>{f.feature?.replace(/_/g, "_")}</span>
                        <span style={{ color: "var(--text-muted)", margin: "0 4px" }}>=</span>
                        <span style={{ color: "var(--text-primary)" }}>{typeof f.value === "number" ? f.value.toFixed(2) : f.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </ExplainCard>

            {/* Potential impact */}
            <ExplainCard
              icon={AlertTriangle}
              title="Potential Impact"
              accentColor="var(--red)"
            >
              <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.8 }}>
                {alert.potential_impact}
              </p>
            </ExplainCard>

            {/* Recommended action */}
            <ExplainCard
              icon={CheckCircle}
              title="Recommended Action"
              accentColor="var(--green)"
              badge={
                <span style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: 9,
                  color: "var(--green)",
                  background: "var(--green-glow)",
                  border: "1px solid rgba(16,185,129,0.2)",
                  padding: "2px 7px",
                  borderRadius: 3,
                }}>
                  ANALYST RUNBOOK
                </span>
              }
            >
              <ActionSteps text={alert.recommended_action} />
            </ExplainCard>

            {/* False positive assessment */}
            <div style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 12,
              padding: "12px 14px",
              background: "var(--bg-raised)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              marginBottom: 10,
            }}>
              <Info size={14} color="var(--text-muted)" style={{ marginTop: 2, flexShrink: 0 }} />
              <div>
                <div className="section-label" style={{ marginBottom: 4 }}>
                  False Positive Assessment
                </div>
                <p style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.7 }}>
                  {alert.false_positive_likelihood}
                </p>
              </div>
            </div>

            {/* SHAP explanation */}
            {alert.top_features?.length > 0 && (
              <Collapsible
                title="SHAP Feature Contributions"
                defaultOpen={true}
                badge={
                  <span style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: 9,
                    color: "var(--purple)",
                    background: "rgba(139,92,246,0.1)",
                    padding: "2px 6px",
                    borderRadius: 3,
                  }}>
                    EXPLAINABILITY
                  </span>
                }
              >
                <div style={{ marginTop: 4 }}>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 14, lineHeight: 1.6 }}>
                    Higher importance → stronger contribution to this detection. Values show the scaled feature score after preprocessing.
                  </div>
                  {alert.top_features.map((f, i) => (
                    <ShapBar
                      key={i}
                      feature={f.feature}
                      importance={f.importance}
                      value={f.value}
                      max={maxShap}
                      index={i}
                    />
                  ))}
                </div>
              </Collapsible>
            )}
          </div>

          {/* Right: metadata */}
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {/* Detection scores */}
            <div className="card" style={{ padding: "18px 20px" }}>
              <div className="section-label" style={{ marginBottom: 14 }}>Detection Scores</div>

              <div style={{ marginBottom: 16 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>COMPOSITE RISK</span>
                  <span style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: 22,
                    fontWeight: 700,
                    color: accentColor,
                  }}>
                    {alert.risk_score}
                    <span style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 400 }}>/100</span>
                  </span>
                </div>
                <RiskBar score={alert.risk_score} height={6} />
              </div>

              <InfoRow label="Attack Class" value={alert.attack_class} mono color="var(--amber)" />
              <InfoRow label="Confidence" value={`${(alert.attack_confidence * 100).toFixed(1)}%`} mono />
              <InfoRow label="Anomaly Score" value={alert.anomaly_score?.toFixed(4)} mono />
              <InfoRow label="Is Anomaly" value={alert.is_anomaly ? "YES" : "NO"} mono
                color={alert.is_anomaly ? "var(--red)" : "var(--green)"} last
              />
            </div>

            {/* Network context */}
            <div className="card" style={{ padding: "18px 20px" }}>
              <div className="section-label" style={{ marginBottom: 14 }}>Network Context</div>
              <InfoRow
                label="Source IP"
                value={alert.source_ip}
                mono
                copyable
              />
              <InfoRow
                label="Dest IP"
                value={alert.destination_ip}
                mono
                copyable
              />
              <InfoRow
                label="Dest Port"
                value={alert.destination_port ? (
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span>{alert.destination_port}</span>
                    <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      ({alert.destination_port === 80 ? "HTTP" :
                        alert.destination_port === 443 ? "HTTPS" :
                        alert.destination_port === 22 ? "SSH" :
                        alert.destination_port === 21 ? "FTP" :
                        alert.destination_port === 3389 ? "RDP" : "TCP"})
                    </span>
                  </div>
                ) : null}
                mono
                last
              />

              {/* Quick link to IOC lookup */}
              {alert.source_ip && (
                <div style={{ marginTop: 14 }}>
                  <a href={`/ioc?q=${alert.source_ip}`} style={{ textDecoration: "none" }}>
                    <button className="btn btn-ghost" style={{ width: "100%", fontSize: 11 }}>
                      <Globe size={11} /> Enrich Source IP
                    </button>
                  </a>
                </div>
              )}
            </div>

            {/* MITRE */}
            {alert.mitre && <MITRECard mitre={alert.mitre} />}

            {/* Alert metadata */}
            <div className="card" style={{ padding: "18px 20px" }}>
              <div className="section-label" style={{ marginBottom: 14 }}>Alert Metadata</div>
              <InfoRow label="Alert ID" value={`#${alert.id}`} mono />
              <InfoRow label="Created" value={format(new Date(alert.created_at), "yyyy-MM-dd HH:mm:ss")} mono />
              <InfoRow label="Status" value={<span className={`badge badge-${alert.status}`}>{alert.status?.toUpperCase()}</span>} />
              <InfoRow label="Cached" value={alert.explanation_cached ? "Yes (Redis)" : "No (fresh)"} mono
                color={alert.explanation_cached ? "var(--green)" : "var(--text-muted)"} last />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
