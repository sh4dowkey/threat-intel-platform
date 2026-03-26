import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Database, Search, RefreshCw, Filter, ChevronRight,
  Shield, Globe, Hash, AlertTriangle, Eye, Clock,
  Download, SortAsc, SortDesc, ChevronLeft, ExternalLink,
} from "lucide-react";
import { listAlerts, lookupIOC } from "../lib/api";
import {
  SectionHeader, VerdictBadge, SeverityBadge, RiskBar,
  Empty, Spinner, SkeletonRow, StatusBadge, InfoRow, Tag, CopyButton,
} from "../components/ui";
import { format, formatDistanceToNow } from "date-fns";

/* ── API for IOC records (using listAlerts pattern for alerts, inline for IOC) ── */
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function fetchIOCRecords(params = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await fetch(`${API_BASE}/api/ioc/records?${query}`);
  if (!res.ok) throw new Error("Failed to fetch");
  return res.json();
}

/* ── Tab: Alerts Explorer ────────────────────────────────────────────────────── */
function AlertsExplorer() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [verdict, setVerdict] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [sortBy, setSortBy] = useState("created_at");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = { limit: 200 };
      if (verdict)  params.verdict  = verdict;
      if (severity) params.severity = severity;
      if (status)   params.status   = status;
      setAlerts(await listAlerts(params));
    } catch (_) {}
    finally { setLoading(false); }
  }, [verdict, severity, status]);

  useEffect(() => { fetchData(); }, [fetchData]);
  useEffect(() => { setPage(0); }, [search, verdict, severity, status, sortBy, sortDir]);

  const filtered = alerts
    .filter(a => {
      if (!search) return true;
      const s = search.toLowerCase();
      return (
        String(a.id).includes(s) ||
        (a.source_ip || "").toLowerCase().includes(s) ||
        (a.attack_class || "").toLowerCase().includes(s) ||
        (a.summary || "").toLowerCase().includes(s)
      );
    })
    .sort((a, b) => {
      let va = a[sortBy], vb = b[sortBy];
      if (sortBy === "created_at") { va = new Date(va); vb = new Date(vb); }
      if (sortBy === "risk_score") { va = Number(va); vb = Number(vb); }
      return sortDir === "desc" ? (vb > va ? 1 : -1) : (va > vb ? 1 : -1);
    });

  const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);

  const toggleSort = (col) => {
    if (sortBy === col) setSortDir(d => d === "desc" ? "asc" : "desc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const SortIcon = ({ col }) => sortBy === col
    ? (sortDir === "desc" ? <SortDesc size={10} /> : <SortAsc size={10} />)
    : null;

  const exportCSV = () => {
    const headers = ["id","source_ip","attack_class","risk_score","verdict","severity","status","created_at"];
    const rows = filtered.map(a => headers.map(h => JSON.stringify(a[h] || "")).join(","));
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `alerts_${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      {/* Controls */}
      <div style={{
        display: "flex",
        gap: 10,
        marginBottom: 16,
        flexWrap: "wrap",
        alignItems: "center",
        padding: "14px 16px",
        background: "var(--bg-raised)",
        border: "1px solid var(--border)",
        borderRadius: 8,
      }}>
        {/* Search */}
        <div style={{ position: "relative", flex: 1, minWidth: 200 }}>
          <Search size={13} style={{
            position: "absolute", left: 10, top: "50%",
            transform: "translateY(-50%)", color: "var(--text-muted)",
          }} />
          <input
            className="input input-search"
            placeholder="Search by IP, attack class, ID..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ paddingLeft: 34 }}
          />
        </div>

        {/* Filters */}
        {[
          { label: "Verdict", value: verdict, set: setVerdict, opts: ["malicious","suspicious","clean"] },
          { label: "Severity", value: severity, set: setSeverity, opts: ["critical","high","medium","low"] },
          { label: "Status", value: status, set: setStatus, opts: ["open","acknowledged","escalated","dismissed"] },
        ].map(({ label, value, set, opts }) => (
          <select
            key={label}
            value={value}
            onChange={e => set(e.target.value)}
            style={{
              background: "var(--bg-base)",
              border: "1px solid var(--border-lit)",
              borderRadius: 4,
              color: value ? "var(--text-primary)" : "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              padding: "8px 12px",
              outline: "none",
              cursor: "pointer",
            }}
          >
            <option value="">{label}</option>
            {opts.map(o => <option key={o} value={o}>{o.toUpperCase()}</option>)}
          </select>
        ))}

        <button className="btn btn-ghost btn-sm" onClick={fetchData}>
          <RefreshCw size={11} /> Refresh
        </button>

        <button className="btn btn-ghost btn-sm" onClick={exportCSV}>
          <Download size={11} /> CSV
        </button>

        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" }}>
          {filtered.length} records
        </span>
      </div>

      {/* Table */}
      <div className="card" style={{ overflow: "hidden" }}>
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => toggleSort("id")}>
                  ID <SortIcon col="id" />
                </th>
                <th className="sortable" onClick={() => toggleSort("created_at")}>
                  Timestamp <SortIcon col="created_at" />
                </th>
                <th>Source IP</th>
                <th>Attack Class</th>
                <th className="sortable" onClick={() => toggleSort("risk_score")}>
                  Risk <SortIcon col="risk_score" />
                </th>
                <th>Verdict</th>
                <th>Severity</th>
                <th>Status</th>
                <th>MITRE</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={10} />)
              ) : paginated.length === 0 ? (
                <tr>
                  <td colSpan={10}>
                    <Empty message="No records match your filters" />
                  </td>
                </tr>
              ) : paginated.map((a, idx) => (
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
                    animationDelay: `${idx * 0.02}s`,
                  }}
                  onClick={() => navigate(`/alerts/${a.id}`)}
                >
                  <td>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                      #{a.id}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
                      {format(new Date(a.created_at), "yyyy-MM-dd HH:mm:ss")}
                    </div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>
                      {formatDistanceToNow(new Date(a.created_at), { addSuffix: true })}
                    </div>
                  </td>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                        {a.source_ip || <span style={{ color: "var(--text-muted)" }}>—</span>}
                      </span>
                      {a.source_ip && <CopyButton text={a.source_ip} />}
                    </div>
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--amber)" }}>
                      {a.attack_class}
                    </span>
                  </td>
                  <td style={{ minWidth: 130 }}>
                    <RiskBar score={a.risk_score} />
                  </td>
                  <td><VerdictBadge verdict={a.verdict} /></td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td><StatusBadge status={a.status} /></td>
                  <td>
                    {a.mitre_technique_id ? (
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--blue-bright)" }}>
                        {a.mitre_technique_id}
                      </span>
                    ) : <span style={{ color: "var(--text-muted)" }}>—</span>}
                  </td>
                  <td onClick={e => e.stopPropagation()}>
                    <button
                      className="btn btn-ghost btn-icon"
                      onClick={() => navigate(`/alerts/${a.id}`)}
                    >
                      <ExternalLink size={11} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "12px 16px",
            borderTop: "1px solid var(--border)",
          }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
              Page {page + 1} of {totalPages} · {filtered.length} total
            </span>
            <div style={{ display: "flex", gap: 6 }}>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                <ChevronLeft size={11} />
              </button>
              {Array.from({ length: Math.min(7, totalPages) }).map((_, i) => {
                const pageNum = Math.min(Math.max(page - 3, 0) + i, totalPages - 1);
                return (
                  <button
                    key={pageNum}
                    className={`btn btn-sm ${pageNum === page ? "btn-primary" : "btn-ghost"}`}
                    onClick={() => setPage(pageNum)}
                  >
                    {pageNum + 1}
                  </button>
                );
              })}
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page === totalPages - 1}
              >
                <ChevronRight size={11} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Tab: IOC Records ────────────────────────────────────────────────────────── */
function IOCExplorer() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [type, setType] = useState("");
  const [verdict, setVerdict] = useState("");
  const [selected, setSelected] = useState(null);
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 20;

  const loadRecords = async () => {
    setLoading(true);
    try {
      // We list alerts as a proxy; IOC records come from looking up what's been searched.
      // Since there's no dedicated GET /api/ioc/records endpoint in the current API,
      // we'll show the data from a simulated local cache + what alerts reference.
      // In production, you'd add GET /api/ioc/records to the backend.
      // For now we demonstrate with placeholder.
      const res = await fetch(`${API_BASE}/api/ioc/records`);
      if (res.ok) {
        setRecords(await res.json());
      } else {
        setRecords([]);
      }
    } catch {
      setRecords([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadRecords(); }, []);
  useEffect(() => { setPage(0); }, [search, type, verdict]);

  const filtered = records.filter(r => {
    if (search && !r.ioc?.toLowerCase().includes(search.toLowerCase())) return false;
    if (type && r.ioc_type !== type) return false;
    if (verdict && r.verdict !== verdict) return false;
    return true;
  });

  const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);

  const iocTypeIcon = (t) => t === "ip" ? Globe : t === "hash" ? Hash : Shield;
  const iocTypeColor = (t) => t === "ip" ? "var(--blue)" : t === "hash" ? "var(--purple)" : "var(--cyan)";

  if (!loading && records.length === 0) {
    return (
      <div className="card">
        <Empty
          message="No IOC records in database. Use the IOC Lookup page to enrich indicators — they'll be saved here automatically."
          icon={<Globe size={20} color="var(--text-muted)" />}
          action={
            <a href="/ioc" style={{ textDecoration: "none" }}>
              <button className="btn btn-primary btn-sm">
                <Search size={11} /> Go to IOC Lookup
              </button>
            </a>
          }
        />
        <div style={{ padding: "0 20px 20px" }}>
          <div style={{
            background: "var(--bg-raised)",
            border: "1px solid var(--border-lit)",
            borderRadius: 6,
            padding: "16px",
          }}>
            <div className="section-label" style={{ marginBottom: 10 }}>
              Note: Backend endpoint required
            </div>
            <p style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.7 }}>
              To show all IOC records from Supabase, add this endpoint to{" "}
              <code style={{ fontFamily: "var(--font-mono)", color: "var(--amber)", fontSize: 11 }}>backend/app/api/ioc.py</code>:
            </p>
            <div className="code-block" style={{ marginTop: 10 }}>
              {`@router.get("/records", response_model=list[IOCResponse])
async def list_ioc_records(
    limit: int = Query(200, le=500),
    ioc_type: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(IOCRecord).order_by(
        desc(IOCRecord.looked_up_at)
    ).limit(limit)
    if ioc_type:
        stmt = stmt.where(IOCRecord.ioc_type == ioc_type)
    if verdict:
        stmt = stmt.where(IOCRecord.verdict == verdict)
    result = await db.execute(stmt)
    return result.scalars().all()`}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: selected ? "1fr 360px" : "1fr", gap: 16 }}>
      <div>
        {/* Controls */}
        <div style={{
          display: "flex", gap: 10, marginBottom: 16, alignItems: "center",
          padding: "12px 14px",
          background: "var(--bg-raised)",
          border: "1px solid var(--border)",
          borderRadius: 8,
        }}>
          <div style={{ position: "relative", flex: 1 }}>
            <Search size={13} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
            <input
              className="input input-search"
              placeholder="Search IOC..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ paddingLeft: 34 }}
            />
          </div>
          {[
            { label: "Type", value: type, set: setType, opts: [["ip","IP Address"],["domain","Domain"],["hash","File Hash"]] },
            { label: "Verdict", value: verdict, set: setVerdict, opts: [["malicious","Malicious"],["suspicious","Suspicious"],["clean","Clean"]] },
          ].map(({ label, value, set, opts }) => (
            <select key={label} value={value} onChange={e => set(e.target.value)}
              style={{
                background: "var(--bg-base)", border: "1px solid var(--border-lit)",
                borderRadius: 4, color: value ? "var(--text-primary)" : "var(--text-muted)",
                fontFamily: "var(--font-mono)", fontSize: 11, padding: "8px 12px", outline: "none",
              }}
            >
              <option value="">{label}: All</option>
              {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          ))}
          <button className="btn btn-ghost btn-sm" onClick={loadRecords}><RefreshCw size={11} /></button>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" }}>
            {filtered.length} records
          </span>
        </div>

        <div className="card" style={{ overflow: "hidden" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>IOC</th>
                <th>Type</th>
                <th>Risk</th>
                <th>Verdict</th>
                <th>VT Engines</th>
                <th>AbuseIPDB</th>
                <th>Looked Up</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={8} />)
              ) : paginated.length === 0 ? (
                <tr><td colSpan={8}><Empty message="No IOC records" /></td></tr>
              ) : paginated.map((r, idx) => {
                const TypeIcon = iocTypeIcon(r.ioc_type);
                const typeColor = iocTypeColor(r.ioc_type);
                return (
                  <tr
                    key={r.id}
                    style={{ cursor: "pointer", animationDelay: `${idx * 0.02}s`, background: selected?.id === r.id ? "var(--bg-hover)" : undefined }}
                    className="animate-fade-in"
                    onClick={() => setSelected(selected?.id === r.id ? null : r)}
                  >
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <TypeIcon size={11} color={typeColor} />
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {r.ioc}
                        </span>
                        <CopyButton text={r.ioc} />
                      </div>
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: typeColor, textTransform: "uppercase", letterSpacing: "0.08em" }}>
                        {r.ioc_type}
                      </span>
                    </td>
                    <td style={{ minWidth: 120 }}><RiskBar score={r.risk_score} /></td>
                    <td><VerdictBadge verdict={r.verdict} /></td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                        {r.vt_malicious > 0
                          ? <span style={{ color: "var(--red)" }}>{r.vt_malicious}/<span style={{ color: "var(--text-muted)" }}>{r.vt_total_engines}</span></span>
                          : <span style={{ color: "var(--green)" }}>0/{r.vt_total_engines}</span>
                        }
                      </span>
                    </td>
                    <td>
                      {r.ioc_type === "ip" ? (
                        <span style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: 12,
                          color: r.abuse_confidence_score >= 50 ? "var(--red)" : r.abuse_confidence_score > 0 ? "var(--amber)" : "var(--green)",
                        }}>
                          {r.abuse_confidence_score}%
                        </span>
                      ) : <span style={{ color: "var(--text-muted)" }}>—</span>}
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                        {format(new Date(r.looked_up_at), "MM-dd HH:mm")}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: 11,
                        background: "var(--bg-raised)",
                        border: "1px solid var(--border)",
                        padding: "2px 6px",
                        borderRadius: 3,
                        color: "var(--text-muted)",
                      }}>
                        ×{r.lookup_count}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {totalPages > 1 && (
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "12px 16px", borderTop: "1px solid var(--border)",
            }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                Page {page + 1} of {totalPages}
              </span>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="btn btn-ghost btn-sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                  <ChevronLeft size={11} />
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page === totalPages - 1}>
                  <ChevronRight size={11} />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="card animate-slide-right" style={{ padding: "18px", height: "fit-content", position: "sticky", top: 0 }}>
          <div style={{ display: "flex", justify: "space-between", alignItems: "center", marginBottom: 16 }}>
            <div className="section-label">IOC Detail</div>
            <button className="btn btn-ghost btn-sm btn-icon" onClick={() => setSelected(null)}>×</button>
          </div>

          <div style={{
            padding: "12px",
            background: "var(--bg-raised)",
            borderRadius: 6,
            border: `1px solid ${selected.verdict === "malicious" ? "rgba(239,68,68,0.2)" : selected.verdict === "suspicious" ? "rgba(245,158,11,0.2)" : "rgba(16,185,129,0.2)"}`,
            marginBottom: 14,
          }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all", marginBottom: 8, color: "var(--text-primary)" }}>
              {selected.ioc}
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              <span className={`badge badge-${selected.verdict === "malicious" ? "critical" : selected.verdict === "suspicious" ? "high" : "low"}`}>
                {selected.verdict?.toUpperCase()}
              </span>
              <span className="badge badge-info">{selected.ioc_type?.toUpperCase()}</span>
            </div>
          </div>

          <div style={{ marginBottom: 14 }}>
            <RiskBar score={selected.risk_score} />
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
              Composite Risk Score
            </div>
          </div>

          <div className="section-label" style={{ marginBottom: 8 }}>VirusTotal</div>
          <InfoRow label="Malicious" value={`${selected.vt_malicious} / ${selected.vt_total_engines} engines`} mono color={selected.vt_malicious > 0 ? "var(--red)" : "var(--green)"} />
          <InfoRow label="Suspicious" value={selected.vt_suspicious} mono />
          <InfoRow label="Reputation" value={selected.vt_reputation} mono color={selected.vt_reputation < 0 ? "var(--red)" : "var(--text-primary)"} />
          {selected.vt_country && <InfoRow label="Country" value={selected.vt_country} mono />}
          {selected.vt_as_owner && <InfoRow label="AS Owner" value={selected.vt_as_owner} />}

          {selected.ioc_type === "ip" && (
            <>
              <div className="divider" />
              <div className="section-label" style={{ marginBottom: 8 }}>AbuseIPDB</div>
              <InfoRow label="Confidence" value={`${selected.abuse_confidence_score}/100`} mono color={selected.abuse_confidence_score >= 50 ? "var(--red)" : selected.abuse_confidence_score > 0 ? "var(--amber)" : "var(--green)"} />
              <InfoRow label="Total Reports" value={selected.abuse_total_reports} mono />
              <InfoRow label="ISP" value={selected.abuse_isp} />
              <InfoRow label="Usage" value={selected.abuse_usage_type} />
              {selected.abuse_last_reported && <InfoRow label="Last Reported" value={selected.abuse_last_reported?.slice(0, 10)} mono last />}
            </>
          )}

          <div className="divider" />
          <InfoRow label="Looked Up" value={format(new Date(selected.looked_up_at), "yyyy-MM-dd HH:mm")} mono />
          <InfoRow label="Lookup Count" value={`×${selected.lookup_count}`} mono last />

          <div style={{ marginTop: 14 }}>
            <a
              href={`https://www.virustotal.com/gui/${selected.ioc_type === "ip" ? "ip-address" : selected.ioc_type === "hash" ? "file" : "domain"}/${selected.ioc}`}
              target="_blank"
              rel="noreferrer"
              style={{ textDecoration: "none" }}
            >
              <button className="btn btn-ghost" style={{ width: "100%" }}>
                <ExternalLink size={11} /> View on VirusTotal
              </button>
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Main Explorer Page ───────────────────────────────────────────────────────── */
export default function DataExplorer() {
  const [tab, setTab] = useState("alerts");

  const tabs = [
    { id: "alerts", label: "Alerts", icon: AlertTriangle, desc: "All detection records" },
    { id: "ioc",    label: "IOC Records", icon: Database, desc: "Enriched indicators" },
  ];

  return (
    <div style={{ padding: "24px 28px", overflowY: "auto", height: "100%" }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
          <div style={{
            width: 36, height: 36,
            background: "linear-gradient(135deg, rgba(16,185,129,0.15), rgba(16,185,129,0.05))",
            border: "1px solid rgba(16,185,129,0.2)",
            borderRadius: 8,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <Database size={18} color="var(--green)" />
          </div>
          <div>
            <h1 style={{
              fontFamily: "var(--font-display)",
              fontSize: 22,
              fontWeight: 800,
              letterSpacing: "-0.02em",
              color: "var(--text-primary)",
              lineHeight: 1.1,
            }}>
              Data Explorer
            </h1>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
              Browse all records saved in your Supabase database
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="tab-list" style={{ marginBottom: 20 }}>
        {tabs.map(({ id, label, icon: Icon, desc }) => (
          <div
            key={id}
            className={`tab-item ${tab === id ? "active" : ""}`}
            onClick={() => setTab(id)}
            style={{ display: "flex", alignItems: "center", gap: 7 }}
          >
            <Icon size={12} />
            {label}
            <span style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              — {desc}
            </span>
          </div>
        ))}
      </div>

      {/* Tab content */}
      {tab === "alerts" && <AlertsExplorer />}
      {tab === "ioc" && <IOCExplorer />}
    </div>
  );
}
