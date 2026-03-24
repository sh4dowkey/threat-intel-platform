import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { analyzeFlow } from "../lib/api";
import { Cpu, Play } from "lucide-react";
import { Spinner, VerdictBadge, SeverityBadge, RiskBar } from "../components/ui";

const PRESETS = {
  "DDoS (SYN Flood)": {
    flow_duration: 1000, total_fwd_packets: 50000, total_backward_packets: 0,
    total_length_of_fwd_packets: 3000000, flow_bytes_per_s: 3000000000,
    flow_packets_per_s: 50000000, flow_iat_mean: 20, flow_iat_std: 5,
    syn_flag_count: 50000, ack_flag_count: 0, fwd_packet_length_mean: 60,
    init_win_bytes_forward: 1024, init_win_bytes_backward: 0,
    bwd_packet_length_mean: 0, destination_port: 80,
  },
  "Port Scan": {
    flow_duration: 500, total_fwd_packets: 1, total_backward_packets: 0,
    flow_bytes_per_s: 100, flow_packets_per_s: 2000,
    syn_flag_count: 1, ack_flag_count: 0, rst_flag_count: 1,
    fwd_packet_length_mean: 40, bwd_packet_length_mean: 0,
    init_win_bytes_forward: 8192, destination_port: 22,
  },
  "Normal HTTP": {
    flow_duration: 1000000, total_fwd_packets: 10, total_backward_packets: 8,
    flow_bytes_per_s: 9000, flow_packets_per_s: 18,
    syn_flag_count: 1, ack_flag_count: 17, fin_flag_count: 1,
    fwd_packet_length_mean: 500, bwd_packet_length_mean: 500,
    init_win_bytes_forward: 65535, init_win_bytes_backward: 65535,
    destination_port: 80,
  },
  "SSH Brute Force": {
    flow_duration: 5000000, total_fwd_packets: 800, total_backward_packets: 800,
    flow_bytes_per_s: 50000, flow_packets_per_s: 320,
    syn_flag_count: 400, ack_flag_count: 800, rst_flag_count: 400,
    fwd_packet_length_mean: 80, bwd_packet_length_mean: 80,
    init_win_bytes_forward: 32768, destination_port: 22,
    bwd_iat_mean: 6250, fwd_iat_mean: 6250,
  },
};

export default function AnalyzeFlow() {
  const navigate = useNavigate();
  const [sourceIP,  setSourceIP]  = useState("");
  const [destIP,    setDestIP]    = useState("");
  const [destPort,  setDestPort]  = useState("");
  const [featText,  setFeatText]  = useState(JSON.stringify(PRESETS["DDoS (SYN Flood)"], null, 2));
  const [loading,   setLoading]   = useState(false);
  const [result,    setResult]    = useState(null);
  const [error,     setError]     = useState("");

  const loadPreset = (name) => {
    setFeatText(JSON.stringify(PRESETS[name], null, 2));
    if (name === "DDoS (SYN Flood)") setSourceIP("185.220.101.1");
    else if (name === "SSH Brute Force") setSourceIP("45.33.32.156");
    else setSourceIP("");
  };

  const handleSubmit = async () => {
    setError("");
    setResult(null);
    let features;
    try {
      features = JSON.parse(featText);
    } catch {
      setError("Invalid JSON in features field");
      return;
    }
    setLoading(true);
    try {
      const data = await analyzeFlow({
        features,
        source_ip:        sourceIP || undefined,
        destination_ip:   destIP || undefined,
        destination_port: destPort ? parseInt(destPort) : undefined,
      });
      setResult(data);
    } catch (e) {
      setError(e?.response?.data?.detail || "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "28px 32px", overflowY: "auto", height: "100%" }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{
          fontFamily: "var(--font-mono)", fontSize: 18, fontWeight: 600,
          letterSpacing: "0.04em", marginBottom: 4,
        }}>
          ANALYZE FLOW
        </h1>
        <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
          Submit network flow features — ML scoring + LLM explanation + MITRE mapping
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 380px", gap: 20 }}>
        {/* Input panel */}
        <div>
          {/* Presets */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 8, letterSpacing: "0.1em" }}>
              LOAD PRESET
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {Object.keys(PRESETS).map((name) => (
                <button
                  key={name}
                  className="btn btn-ghost"
                  style={{ fontSize: 11 }}
                  onClick={() => loadPreset(name)}
                >
                  {name}
                </button>
              ))}
            </div>
          </div>

          {/* Network context */}
          <div className="card" style={{ padding: "16px 18px", marginBottom: 14 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginBottom: 12, letterSpacing: "0.1em" }}>
              NETWORK CONTEXT (optional)
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 120px", gap: 10 }}>
              <div>
                <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginBottom: 5 }}>SOURCE IP</div>
                <input className="input" placeholder="e.g. 185.220.101.1"
                  value={sourceIP} onChange={(e) => setSourceIP(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginBottom: 5 }}>DEST IP</div>
                <input className="input" placeholder="e.g. 10.0.0.1"
                  value={destIP} onChange={(e) => setDestIP(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginBottom: 5 }}>DEST PORT</div>
                <input className="input" placeholder="80" type="number"
                  value={destPort} onChange={(e) => setDestPort(e.target.value)} />
              </div>
            </div>
          </div>

          {/* Feature JSON editor */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginBottom: 8, letterSpacing: "0.1em" }}>
              FLOW FEATURES (JSON)
            </div>
            <textarea
              value={featText}
              onChange={(e) => setFeatText(e.target.value)}
              style={{
                width: "100%", height: 300,
                background: "var(--bg-base)",
                border: "1px solid var(--border-lit)",
                borderRadius: 4,
                color: "var(--text-primary)",
                fontFamily: "var(--font-mono)",
                fontSize: 12,
                padding: "12px",
                outline: "none",
                resize: "vertical",
                lineHeight: 1.6,
              }}
              onFocus={(e) => e.target.style.borderColor = "var(--amber)"}
              onBlur={(e) => e.target.style.borderColor = "var(--border-lit)"}
            />
          </div>

          {error && (
            <div style={{
              padding: "10px 14px", marginBottom: 12,
              background: "rgba(232,69,60,0.08)", border: "1px solid var(--red-dim)",
              borderRadius: 4, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--red)",
            }}>
              {error}
            </div>
          )}

          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={loading}
            style={{ width: "100%", justifyContent: "center", padding: "10px" }}
          >
            {loading ? <Spinner size={14} /> : <Play size={14} />}
            {loading ? "Analyzing — LLM explanation in progress…" : "Run Analysis"}
          </button>
        </div>

        {/* Result panel */}
        <div>
          {!result && !loading && (
            <div style={{
              padding: "40px 20px", textAlign: "center",
              fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)",
              border: "1px dashed var(--border)", borderRadius: 6,
            }}>
              <Cpu size={32} color="var(--border-lit)" style={{ margin: "0 auto 12px" }} />
              <div>Select a preset or enter<br />features and run analysis</div>
            </div>
          )}

          {loading && (
            <div style={{
              display: "flex", flexDirection: "column", alignItems: "center",
              justifyContent: "center", gap: 12, padding: 60,
              border: "1px solid var(--border)", borderRadius: 6,
            }}>
              <Spinner size={24} />
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)" }}>
                Running ML pipeline…
              </div>
            </div>
          )}

          {result && !loading && (
            <div className="animate-fade-in">
              {/* Verdict */}
              <div className="card" style={{
                padding: "16px 18px", marginBottom: 12,
                borderLeft: `3px solid ${
                  result.verdict === "malicious" ? "var(--red)"
                  : result.verdict === "suspicious" ? "var(--amber)"
                  : "var(--green)"
                }`,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
                  <VerdictBadge verdict={result.verdict} />
                  <SeverityBadge severity={result.severity} />
                </div>
                <div style={{ marginBottom: 10 }}>
                  <RiskBar score={result.risk_score} />
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--amber)", marginBottom: 4 }}>
                  {result.attack_class}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  Confidence: {(result.attack_confidence * 100).toFixed(1)}% ·
                  Anomaly: {result.anomaly_score?.toFixed(3)}
                </div>
              </div>

              {/* Summary */}
              <div style={{
                padding: "12px 14px", marginBottom: 10,
                background: "var(--bg-raised)", border: "1px solid var(--border-lit)", borderRadius: 6,
                fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7,
              }}>
                {result.summary}
              </div>

              {/* MITRE */}
              {result.mitre && (
                <div style={{
                  padding: "12px 14px", marginBottom: 10,
                  background: "rgba(74,158,255,0.05)", border: "1px solid var(--blue-dim)", borderRadius: 6,
                }}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--blue)", marginBottom: 6, letterSpacing: "0.1em" }}>
                    MITRE ATT&CK
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-secondary)" }}>
                    <span style={{ color: "var(--blue)" }}>{result.mitre.technique_id}</span>{" "}
                    {result.mitre.technique_name}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{result.mitre.tactic_name}</div>
                </div>
              )}

              {/* View full alert button */}
              <button
                className="btn btn-primary"
                style={{ width: "100%", justifyContent: "center" }}
                onClick={() => navigate(`/alerts/${result.id}`)}
              >
                View Full Alert →
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
