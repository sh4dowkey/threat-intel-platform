import { useState } from "react";
import { Copy, Check, TrendingUp, TrendingDown, Minus } from "lucide-react";

// ── Risk score bar ────────────────────────────────────────────────────────────
export function RiskBar({ score, showLabel = true, height = 4 }) {
  const color =
    score >= 70 ? "var(--red)" :
    score >= 30 ? "var(--amber)" :
    "var(--green)";

  const label =
    score >= 70 ? "CRITICAL" :
    score >= 50 ? "HIGH" :
    score >= 30 ? "MEDIUM" : "LOW";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div className="risk-bar-wrap" style={{ flex: 1, height }}>
        <div
          className="risk-bar"
          style={{
            width: `${score}%`,
            background: score >= 70
              ? "linear-gradient(90deg, var(--red-dim), var(--red))"
              : score >= 30
              ? "linear-gradient(90deg, var(--amber-dim), var(--amber))"
              : "linear-gradient(90deg, var(--green-dim), var(--green))",
          }}
        />
      </div>
      {showLabel && (
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          fontWeight: 700,
          color,
          minWidth: 28,
          textAlign: "right",
        }}>
          {score}
        </span>
      )}
    </div>
  );
}

// ── Verdict badge ─────────────────────────────────────────────────────────────
export function VerdictBadge({ verdict, size = "sm" }) {
  const map = {
    malicious:  { label: "MALICIOUS",  cls: "badge-critical" },
    suspicious: { label: "SUSPICIOUS", cls: "badge-high" },
    clean:      { label: "CLEAN",      cls: "badge-low" },
    unknown:    { label: "UNKNOWN",    cls: "badge-low" },
  };
  const { label, cls } = map[verdict] || map.unknown;
  return (
    <span className={`badge ${cls}`} style={size === "lg" ? { fontSize: 11, padding: "4px 10px" } : {}}>
      {label}
    </span>
  );
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

// ── Enhanced stat card ────────────────────────────────────────────────────────
export function StatCard({ label, value, sub, accent, icon: Icon, trend, loading }) {
  const accentColor = accent || "var(--text-muted)";

  return (
    <div className="stat-card" style={{ "--accent-color": accentColor }}>
      {/* Background glow */}
      <div style={{
        position: "absolute",
        bottom: 0, right: 0,
        width: 80, height: 80,
        borderRadius: "50%",
        background: `radial-gradient(circle, ${accentColor}08 0%, transparent 70%)`,
        pointerEvents: "none",
      }} />

      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 12 }}>
        <span className="section-label">{label}</span>
        {Icon && (
          <div style={{
            width: 28, height: 28,
            borderRadius: 6,
            background: `${accentColor}10`,
            border: `1px solid ${accentColor}20`,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <Icon size={13} color={accentColor} />
          </div>
        )}
      </div>

      <div style={{
        fontFamily: "var(--font-mono)",
        fontSize: loading ? 20 : 32,
        fontWeight: 700,
        color: loading ? "var(--text-muted)" : (accent || "var(--text-primary)"),
        lineHeight: 1,
        marginBottom: 6,
        animation: loading ? "none" : "count-up 0.4s ease",
      }}>
        {loading ? (
          <div className="skeleton" style={{ width: 60, height: 32 }} />
        ) : value}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        {sub && (
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{sub}</span>
        )}
        {trend !== undefined && (
          <div style={{
            display: "flex", alignItems: "center", gap: 2,
            fontSize: 10, fontFamily: "var(--font-mono)",
            color: trend > 0 ? "var(--red)" : trend < 0 ? "var(--green)" : "var(--text-muted)",
          }}>
            {trend > 0 ? <TrendingUp size={10} /> : trend < 0 ? <TrendingDown size={10} /> : <Minus size={10} />}
            {Math.abs(trend)}%
          </div>
        )}
      </div>
    </div>
  );
}

// ── Section header ────────────────────────────────────────────────────────────
export function SectionHeader({ title, subtitle, children }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: 16,
    }}>
      <div>
        <h2 className="section-label">{title}</h2>
        {subtitle && (
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, fontFamily: "var(--font-mono)" }}>
            {subtitle}
          </div>
        )}
      </div>
      {children && (
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {children}
        </div>
      )}
    </div>
  );
}

// ── Loading spinner ───────────────────────────────────────────────────────────
export function Spinner({ size = 16, color = "var(--amber)" }) {
  return (
    <svg
      width={size} height={size}
      viewBox="0 0 24 24"
      style={{ animation: "spin 0.8s linear infinite", flexShrink: 0 }}
    >
      <circle
        cx="12" cy="12" r="10"
        stroke={color} strokeWidth="2"
        fill="none" strokeDasharray="45" strokeDashoffset="15"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ── Skeleton row ──────────────────────────────────────────────────────────────
export function SkeletonRow({ cols = 6 }) {
  return (
    <tr style={{ borderBottom: "1px solid var(--border)" }}>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} style={{ padding: "12px 16px" }}>
          <div className="skeleton" style={{ height: 14, width: `${60 + Math.random() * 40}%` }} />
        </td>
      ))}
    </tr>
  );
}

// ── Empty state ────────────────────────────────────────────────────────────────
export function Empty({ message = "No data", icon, action }) {
  return (
    <div style={{
      padding: "60px 24px",
      textAlign: "center",
    }}>
      <div style={{
        width: 48, height: 48,
        borderRadius: 12,
        border: "1px solid var(--border-lit)",
        background: "var(--bg-raised)",
        display: "flex", alignItems: "center", justifyContent: "center",
        margin: "0 auto 16px",
        fontSize: 24,
      }}>
        {icon || "◌"}
      </div>
      <div style={{
        fontFamily: "var(--font-mono)",
        fontSize: 12,
        color: "var(--text-muted)",
        marginBottom: action ? 16 : 0,
      }}>
        {message}
      </div>
      {action && action}
    </div>
  );
}

// ── Copy button ───────────────────────────────────────────────────────────────
export function CopyButton({ text, style }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      style={{
        background: "none",
        border: "none",
        cursor: "pointer",
        color: copied ? "var(--green)" : "var(--text-muted)",
        padding: "2px 4px",
        borderRadius: 3,
        display: "inline-flex",
        alignItems: "center",
        transition: "color 0.15s",
        ...style,
      }}
      title="Copy to clipboard"
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}

// ── Info row (key-value) ──────────────────────────────────────────────────────
export function InfoRow({ label, value, mono, color, copyable, last }) {
  return (
    <div style={{
      display: "flex",
      justifyContent: "space-between",
      alignItems: "flex-start",
      padding: "10px 0",
      borderBottom: last ? "none" : "1px solid var(--border)",
      gap: 16,
    }}>
      <span style={{
        fontSize: 11,
        color: "var(--text-muted)",
        fontFamily: "var(--font-mono)",
        flexShrink: 0,
        whiteSpace: "nowrap",
      }}>
        {label}
      </span>
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: 4,
        textAlign: "right",
      }}>
        <span style={{
          fontSize: 12,
          color: color || "var(--text-primary)",
          fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
          wordBreak: "break-all",
        }}>
          {value ?? <span style={{ color: "var(--text-muted)" }}>—</span>}
        </span>
        {copyable && value && (
          <CopyButton text={String(value)} />
        )}
      </div>
    </div>
  );
}

// ── Tag ───────────────────────────────────────────────────────────────────────
export function Tag({ children, color }) {
  return (
    <span className="tag" style={color ? { color, borderColor: `${color}30` } : {}}>
      {children}
    </span>
  );
}

// ── Mono label ────────────────────────────────────────────────────────────────
export function MonoLabel({ children, color, size = 12 }) {
  return (
    <span style={{
      fontFamily: "var(--font-mono)",
      fontSize: size,
      color: color || "var(--text-secondary)",
    }}>
      {children}
    </span>
  );
}

// ── Toast system ──────────────────────────────────────────────────────────────
const toastListeners = new Set();
let toastId = 0;

export const toast = {
  _listeners: toastListeners,
  success: (msg) => toastListeners.forEach(fn => fn({ id: ++toastId, type: "success", msg })),
  error:   (msg) => toastListeners.forEach(fn => fn({ id: ++toastId, type: "error",   msg })),
  info:    (msg) => toastListeners.forEach(fn => fn({ id: ++toastId, type: "info",    msg })),
};

export function ToastContainer() {
  const [toasts, setToasts] = useState([]);

  useState(() => {
    const fn = (t) => {
      setToasts(prev => [...prev, t]);
      setTimeout(() => setToasts(prev => prev.filter(x => x.id !== t.id)), 3500);
    };
    toastListeners.add(fn);
    return () => toastListeners.delete(fn);
  });

  const icons = { success: "✓", error: "✕", info: "i" };
  const colors = { success: "var(--green)", error: "var(--red)", info: "var(--blue)" };

  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.type}`}>
          <span style={{
            width: 18, height: 18,
            borderRadius: "50%",
            background: `${colors[t.type]}20`,
            color: colors[t.type],
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 11, fontWeight: 700, flexShrink: 0,
          }}>
            {icons[t.type]}
          </span>
          {t.msg}
        </div>
      ))}
    </div>
  );
}

// ── Collapsible section ───────────────────────────────────────────────────────
export function Collapsible({ title, defaultOpen = false, children, badge }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 16px",
          background: open ? "var(--bg-raised)" : "var(--bg-card)",
          border: "none",
          cursor: "pointer",
          color: "var(--text-primary)",
          transition: "background 0.15s",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className="section-label">{title}</span>
          {badge && badge}
        </div>
        <span style={{
          color: "var(--text-muted)",
          transform: open ? "rotate(90deg)" : "none",
          transition: "transform 0.2s",
          display: "flex",
        }}>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M4 2L8 6L4 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
        </span>
      </button>
      {open && (
        <div style={{ padding: "14px 16px", background: "var(--bg-card)", borderTop: "1px solid var(--border)" }}>
          {children}
        </div>
      )}
    </div>
  );
}
