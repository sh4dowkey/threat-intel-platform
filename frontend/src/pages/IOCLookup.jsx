import { useState } from "react";
import { lookupIOC } from "../lib/api";
import { Search, ExternalLink } from "lucide-react";
import { VerdictBadge, RiskBar, Spinner } from "../components/ui";

function ResultCard({ label, value, mono, color, full }) {
  return (
    <div style={{
      padding: "9px 0",
      borderBottom: "1px solid var(--border)",
      display: full ? "block" : "flex",
      justifyContent: "space-between",
      alignItems: "flex-start",
      gap: 16,
    }}>
      <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-muted)", flexShrink: 0 }}>
        {label}
      </span>
      <span style={{
        fontSize: 12,
        fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
        color: color || "var(--text-primary)",
        textAlign: full ? "left" : "right",
        marginTop: full ? 6 : 0,
        wordBreak: "break-all",
      }}>
        {value ?? "—"}
      </span>
    </div>
  );
}

function EngineBar({ malicious, suspicious, harmless, total }) {
  if (!total) return <span style={{ color: "var(--text-muted)", fontSize: 12 }}>No data</span>;
  return (
    <div>
      <div style={{ display: "flex", gap: 3, marginBottom: 6, height: 8, borderRadius: 4, overflow: "hidden" }}>
        {malicious > 0  && <div style={{ flex: malicious,  background: "var(--red)",   opacity: 0.85 }} />}
        {suspicious > 0 && <div style={{ flex: suspicious, background: "var(--amber)", opacity: 0.85 }} />}
        {harmless > 0   && <div style={{ flex: harmless,   background: "var(--green)", opacity: 0.4 }} />}
      </div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
        <span style={{ color: "var(--red)" }}>{malicious} malicious</span> ·{" "}
        <span style={{ color: "var(--amber)" }}>{suspicious} suspicious</span> ·{" "}
        <span style={{ color: "var(--green)" }}>{harmless} harmless</span>{" "}
        / {total} engines
      </div>
    </div>
  );
}

export default function IOCLookup() {
  const [query, setQuery]   = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState("");

  const handleSubmit = async () => {
    const val = query.trim();
    if (!val) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      setResult(await lookupIOC(val));
    } catch (e) {
      setError(e?.response?.data?.detail || "Lookup failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "28px 32px", overflowY: "auto", height: "100%" }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{
          fontFamily: "var(--font-mono)", fontSize: 18, fontWeight: 600,
          letterSpacing: "0.04em", marginBottom: 4,
        }}>
          IOC LOOKUP
        </h1>
        <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
          Enrich any IP address, domain, or file hash against VirusTotal + AbuseIPDB
        </div>
      </div>

      {/* Search bar */}
      <div style={{ display: "flex", gap: 10, marginBottom: 28 }}>
        <input
          className="input"
          placeholder="Enter IP address, domain, or MD5/SHA1/SHA256 hash..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
          style={{ flex: 1 }}
          autoFocus
        />
        <button
          className="btn btn-primary"
          onClick={handleSubmit}
          disabled={loading || !query.trim()}
          style={{ whiteSpace: "nowrap" }}
        >
          {loading ? <Spinner size={14} /> : <Search size={14} />}
          {loading ? "Looking up…" : "Lookup"}
        </button>
      </div>

      {error && (
        <div style={{
          padding: "12px 16px",
          background: "rgba(232,69,60,0.08)",
          border: "1px solid var(--red-dim)",
          borderRadius: 6,
          fontFamily: "var(--font-mono)",
          fontSize: 12,
          color: "var(--red)",
          marginBottom: 20,
        }}>
          {error}
        </div>
      )}

      {result && (
        <div className="animate-fade-in" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {/* Summary */}
          <div className="card" style={{
            padding: "20px",
            gridColumn: "1 / -1",
            borderLeft: `3px solid ${
              result.verdict === "malicious" ? "var(--red)"
              : result.verdict === "suspicious" ? "var(--amber)"
              : "var(--green)"
            }`,
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, color: "var(--text-primary)", marginBottom: 4 }}>
                  {result.ioc}
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                  {result.ioc_type.toUpperCase()} · queried {result.sources_queried?.join(", ")}
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                <div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 6 }}>RISK SCORE</div>
                  <RiskBar score={result.risk_score} />
                </div>
                <VerdictBadge verdict={result.verdict} />
              </div>
            </div>
          </div>

          {/* VirusTotal */}
          <div className="card" style={{ padding: "18px 20px" }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 16, letterSpacing: "0.1em" }}>
              VIRUSTOTAL
            </div>
            <div style={{ marginBottom: 14 }}>
              <EngineBar
                malicious={result.vt_malicious}
                suspicious={result.vt_suspicious}
                harmless={result.vt_harmless}
                total={result.vt_total_engines}
              />
            </div>
            <ResultCard label="Reputation"  value={result.vt_reputation} mono
              color={result.vt_reputation < 0 ? "var(--red)" : "var(--green)"} />
            <ResultCard label="Country"     value={result.vt_country} mono />
            <ResultCard label="AS Owner"    value={result.vt_as_owner} />
            {result.vt_tags?.length > 0 && (
              <ResultCard label="Tags" full
                value={
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {result.vt_tags.map((t) => (
                      <span key={t} className="badge badge-medium">{t}</span>
                    ))}
                  </div>
                }
              />
            )}
            {result.vt_error && (
              <div style={{ marginTop: 8, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--red)" }}>
                Error: {result.vt_error}
              </div>
            )}
          </div>

          {/* AbuseIPDB */}
          {result.ioc_type === "ip" && (
            <div className="card" style={{ padding: "18px 20px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 16, letterSpacing: "0.1em" }}>
                ABUSEIPDB
              </div>
              <ResultCard label="Confidence Score"
                value={`${result.abuse_confidence_score}/100`} mono
                color={result.abuse_confidence_score >= 50 ? "var(--red)" : result.abuse_confidence_score >= 25 ? "var(--amber)" : "var(--green)"}
              />
              <ResultCard label="Total Reports"    value={result.abuse_total_reports} mono />
              <ResultCard label="Distinct Reporters" value={result.abuse_num_reporters} mono />
              <ResultCard label="ISP"              value={result.abuse_isp} />
              <ResultCard label="Usage Type"       value={result.abuse_usage_type} />
              <ResultCard label="Whitelisted"
                value={result.abuse_is_whitelisted ? "YES" : "NO"} mono
                color={result.abuse_is_whitelisted ? "var(--green)" : "var(--text-secondary)"}
              />
              <ResultCard label="Last Reported"    value={result.abuse_last_reported ? result.abuse_last_reported.slice(0, 10) : "Never"} mono />
              {result.abuse_error && (
                <div style={{ marginTop: 8, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--red)" }}>
                  Error: {result.abuse_error}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Quick examples */}
      {!result && !loading && (
        <div style={{ marginTop: 40 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.1em", marginBottom: 12 }}>
            QUICK EXAMPLES
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {["185.220.101.1", "8.8.8.8", "malware.wicar.org", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"].map((ex) => (
              <button
                key={ex}
                className="btn btn-ghost"
                style={{ fontSize: 11, fontFamily: "var(--font-mono)" }}
                onClick={() => { setQuery(ex); }}
              >
                {ex.length > 32 ? ex.slice(0, 16) + "…" : ex}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
