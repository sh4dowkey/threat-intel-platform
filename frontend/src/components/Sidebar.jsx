import { NavLink } from "react-router-dom";
import {
  Shield, Activity, Search, Cpu, AlertTriangle, Circle,
  Database, BarChart3, Settings, ChevronRight, Zap
} from "lucide-react";
import { useState, useEffect } from "react";

const nav = [
  { to: "/",        icon: Activity,      label: "Dashboard",    sub: "Overview" },
  { to: "/alerts",  icon: AlertTriangle, label: "Alerts",       sub: "Queue" },
  { to: "/ioc",     icon: Search,        label: "IOC Lookup",   sub: "Enrich" },
  { to: "/analyze", icon: Cpu,           label: "Analyze Flow", sub: "ML Score" },
  { to: "/explorer",icon: Database,      label: "Data Explorer",sub: "Records" },
];

export default function Sidebar({ apiOnline, alertCount = 0 }) {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const iv = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(iv);
  }, []);

  const pad = (n) => String(n).padStart(2, "0");
  const timeStr = `${pad(time.getHours())}:${pad(time.getMinutes())}:${pad(time.getSeconds())}`;

  return (
    <aside style={{
      width: 220,
      flexShrink: 0,
      background: "var(--bg-surface)",
      borderRight: "1px solid var(--border)",
      display: "flex",
      flexDirection: "column",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Ambient glow */}
      <div style={{
        position: "absolute",
        top: 0, left: 0, right: 0, height: 200,
        background: "radial-gradient(ellipse at 50% -30%, rgba(245,158,11,0.06) 0%, transparent 70%)",
        pointerEvents: "none",
      }} />

      {/* Logo */}
      <div style={{ padding: "20px 18px 18px", borderBottom: "1px solid var(--border)", position: "relative" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <div style={{
            width: 32, height: 32,
            background: "linear-gradient(135deg, rgba(245,158,11,0.2), rgba(245,158,11,0.05))",
            border: "1px solid rgba(245,158,11,0.3)",
            borderRadius: 8,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <Shield size={16} color="var(--amber)" />
          </div>
          <div>
            <div style={{
              fontFamily: "var(--font-display)",
              fontSize: 13,
              fontWeight: 800,
              color: "var(--text-primary)",
              letterSpacing: "-0.01em",
              lineHeight: 1.1,
            }}>
              THREAT<span style={{ color: "var(--amber)" }}>INTEL</span>
            </div>
            <div style={{
              fontSize: 9,
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.15em",
              marginTop: 2,
            }}>
              SOC PLATFORM
            </div>
          </div>
        </div>

        {/* Live clock */}
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "6px 10px",
          background: "var(--bg-base)",
          border: "1px solid var(--border)",
          borderRadius: 4,
        }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
            UTC
          </span>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            fontWeight: 600,
            color: "var(--text-secondary)",
            letterSpacing: "0.05em",
          }}>
            {timeStr}
          </span>
          <span className="animate-blink" style={{ color: "var(--green)", fontSize: 8 }}>●</span>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "12px 10px", overflowY: "auto" }}>
        <div style={{ marginBottom: 6 }}>
          <div style={{
            fontFamily: "var(--font-mono)",
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: "0.15em",
            color: "var(--text-dim)",
            textTransform: "uppercase",
            padding: "6px 10px 4px",
          }}>
            Navigation
          </div>
        </div>

        {nav.map(({ to, icon: Icon, label, sub }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            style={({ isActive }) => ({
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "9px 10px",
              borderRadius: 6,
              marginBottom: 2,
              textDecoration: "none",
              color: isActive ? "var(--amber-bright)" : "var(--text-secondary)",
              background: isActive ? "rgba(245,158,11,0.08)" : "transparent",
              border: isActive
                ? "1px solid rgba(245,158,11,0.15)"
                : "1px solid transparent",
              transition: "all 0.15s",
              position: "relative",
            })}
          >
            {({ isActive }) => (
              <>
                <div style={{
                  width: 28, height: 28,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  borderRadius: 6,
                  background: isActive ? "rgba(245,158,11,0.12)" : "transparent",
                  flexShrink: 0,
                }}>
                  <Icon size={14} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, lineHeight: 1.2 }}>
                    {label}
                  </div>
                  <div style={{
                    fontSize: 10,
                    color: isActive ? "rgba(251,191,36,0.6)" : "var(--text-muted)",
                    fontFamily: "var(--font-mono)",
                    marginTop: 1,
                  }}>
                    {sub}
                  </div>
                </div>
                {isActive && (
                  <ChevronRight size={12} style={{ opacity: 0.5 }} />
                )}
                {label === "Alerts" && alertCount > 0 && (
                  <span style={{
                    background: "var(--red)",
                    color: "white",
                    fontSize: 9,
                    fontFamily: "var(--font-mono)",
                    fontWeight: 700,
                    padding: "1px 5px",
                    borderRadius: 10,
                    minWidth: 18,
                    textAlign: "center",
                  }}>
                    {alertCount > 99 ? "99+" : alertCount}
                  </span>
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Bottom status */}
      <div style={{
        padding: "14px 16px",
        borderTop: "1px solid var(--border)",
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}>
        {/* API Status */}
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "8px 10px",
          background: apiOnline ? "rgba(16,185,129,0.05)" : "rgba(239,68,68,0.05)",
          border: `1px solid ${apiOnline ? "rgba(16,185,129,0.15)" : "rgba(239,68,68,0.15)"}`,
          borderRadius: 6,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{
              width: 6, height: 6,
              borderRadius: "50%",
              background: apiOnline ? "var(--green)" : "var(--red)",
              boxShadow: apiOnline ? "0 0 6px var(--green)" : "0 0 6px var(--red)",
              animation: apiOnline ? "none" : "pulse-red 2s infinite",
            }} />
            <span style={{
              fontFamily: "var(--font-mono)",
              fontSize: 10,
              fontWeight: 700,
              color: apiOnline ? "var(--green)" : "var(--red)",
              letterSpacing: "0.08em",
            }}>
              {apiOnline ? "CONNECTED" : "OFFLINE"}
            </span>
          </div>
          <Zap size={10} color={apiOnline ? "var(--green)" : "var(--red)"} />
        </div>

        {/* Version */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-dim)" }}>
            v0.3.0-beta
          </span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-dim)" }}>
            FYP 2026
          </span>
        </div>
      </div>
    </aside>
  );
}
