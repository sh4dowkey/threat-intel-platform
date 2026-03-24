import { NavLink } from "react-router-dom";
import {
  Shield, Activity, Search, Cpu, AlertTriangle, Circle
} from "lucide-react";

const nav = [
  { to: "/",        icon: Activity,      label: "Dashboard" },
  { to: "/alerts",  icon: AlertTriangle, label: "Alerts" },
  { to: "/ioc",     icon: Search,        label: "IOC Lookup" },
  { to: "/analyze", icon: Cpu,           label: "Analyze Flow" },
];

export default function Sidebar({ apiOnline }) {
  return (
    <aside style={{
      width: 220,
      flexShrink: 0,
      background: "var(--bg-surface)",
      borderRight: "1px solid var(--border)",
      display: "flex",
      flexDirection: "column",
      padding: "20px 0",
    }}>
      {/* Logo */}
      <div style={{ padding: "0 20px 24px", borderBottom: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Shield size={20} color="var(--amber)" />
          <div>
            <div style={{
              fontFamily: "var(--font-mono)",
              fontSize: 13,
              fontWeight: 600,
              color: "var(--text-primary)",
              letterSpacing: "0.05em",
            }}>
              THREAT<span style={{ color: "var(--amber)" }}>INTEL</span>
            </div>
            <div style={{
              fontSize: 10,
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              letterSpacing: "0.1em",
            }}>
              PLATFORM v0.3
            </div>
          </div>
        </div>
      </div>

      {/* Nav links */}
      <nav style={{ flex: 1, padding: "16px 10px" }}>
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            style={({ isActive }) => ({
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "9px 12px",
              borderRadius: 4,
              marginBottom: 2,
              fontFamily: "var(--font-mono)",
              fontSize: 12,
              fontWeight: 500,
              letterSpacing: "0.04em",
              textDecoration: "none",
              color: isActive ? "var(--amber)" : "var(--text-secondary)",
              background: isActive ? "rgba(245,166,35,0.08)" : "transparent",
              borderLeft: isActive
                ? "2px solid var(--amber)"
                : "2px solid transparent",
              transition: "all 0.15s",
            })}
          >
            <Icon size={15} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* API status indicator */}
      <div style={{
        padding: "16px 20px",
        borderTop: "1px solid var(--border)",
        display: "flex",
        alignItems: "center",
        gap: 8,
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        color: apiOnline ? "var(--green)" : "var(--red)",
      }}>
        <Circle
          size={7}
          fill={apiOnline ? "var(--green)" : "var(--red)"}
          color={apiOnline ? "var(--green)" : "var(--red)"}
          style={apiOnline ? {} : { animation: "blink 1s step-end infinite" }}
        />
        {apiOnline ? "API ONLINE" : "API OFFLINE"}
      </div>
    </aside>
  );
}
