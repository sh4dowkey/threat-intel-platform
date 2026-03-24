// ── Risk score bar ────────────────────────────────────────────────────────────
export function RiskBar({ score }) {
  const color =
    score >= 70 ? "var(--red)" :
    score >= 30 ? "var(--amber)" :
    "var(--green)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div className="risk-bar-wrap" style={{ flex: 1 }}>
        <div
          className="risk-bar"
          style={{ width: `${score}%`, background: color }}
        />
      </div>
      <span style={{
        fontFamily: "var(--font-mono)",
        fontSize: 12,
        color,
        minWidth: 28,
        textAlign: "right",
      }}>
        {score}
      </span>
    </div>
  );
}

// ── Verdict badge ─────────────────────────────────────────────────────────────
export function VerdictBadge({ verdict }) {
  const map = {
    malicious:  { label: "MALICIOUS",  cls: "badge-critical" },
    suspicious: { label: "SUSPICIOUS", cls: "badge-high" },
    clean:      { label: "CLEAN",      cls: "badge-low" },
    unknown:    { label: "UNKNOWN",    cls: "badge-low" },
  };
  const { label, cls } = map[verdict] || map.unknown;
  return <span className={`badge ${cls}`}>{label}</span>;
}

// ── Severity badge ────────────────────────────────────────────────────────────
export function SeverityBadge({ severity }) {
  return (
    <span className={`badge badge-${severity || "low"}`}>
      {(severity || "low").toUpperCase()}
    </span>
  );
}

// ── Status badge ──────────────────────────────────────────────────────────────
export function StatusBadge({ status }) {
  return (
    <span className={`badge badge-${status || "open"}`}>
      {(status || "open").toUpperCase()}
    </span>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────
export function StatCard({ label, value, sub, accent, icon: Icon }) {
  return (
    <div className="card" style={{ padding: "18px 20px" }}>
      <div style={{
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "space-between",
        marginBottom: 8,
      }}>
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: 10,
          letterSpacing: "0.1em",
          color: "var(--text-muted)",
          textTransform: "uppercase",
        }}>
          {label}
        </span>
        {Icon && <Icon size={14} color="var(--text-muted)" />}
      </div>
      <div style={{
        fontFamily: "var(--font-mono)",
        fontSize: 28,
        fontWeight: 600,
        color: accent || "var(--text-primary)",
        lineHeight: 1,
        marginBottom: 4,
      }}>
        {value}
      </div>
      {sub && (
        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{sub}</div>
      )}
    </div>
  );
}

// ── Section header ────────────────────────────────────────────────────────────
export function SectionHeader({ title, children }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: 14,
    }}>
      <h2 style={{
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: "0.12em",
        color: "var(--text-muted)",
        textTransform: "uppercase",
      }}>
        {title}
      </h2>
      {children}
    </div>
  );
}

// ── Loading spinner ───────────────────────────────────────────────────────────
export function Spinner({ size = 16 }) {
  return (
    <svg
      width={size} height={size}
      viewBox="0 0 24 24"
      style={{ animation: "spin 0.8s linear infinite" }}
    >
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <circle
        cx="12" cy="12" r="10"
        stroke="var(--amber)" strokeWidth="2"
        fill="none" strokeDasharray="40" strokeDashoffset="15"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ── Empty state ────────────────────────────────────────────────────────────────
export function Empty({ message = "No data" }) {
  return (
    <div style={{
      padding: "48px 24px",
      textAlign: "center",
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: "var(--text-muted)",
    }}>
      <div style={{ marginBottom: 8, fontSize: 24 }}>◌</div>
      {message}
    </div>
  );
}

// ── Mono label ────────────────────────────────────────────────────────────────
export function MonoLabel({ children, color }) {
  return (
    <span style={{
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: color || "var(--text-secondary)",
    }}>
      {children}
    </span>
  );
}
