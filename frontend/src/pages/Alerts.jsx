import { useEffect, useState, useCallback, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { listAlerts, updateAlert } from "../lib/api";
import { format, formatDistanceToNow } from "date-fns";
import {
  Filter, RefreshCw, Search, X, Download,
  AlertTriangle, ChevronRight, SortAsc, SortDesc, Keyboard,
} from "lucide-react";
import {
  VerdictBadge, SeverityBadge, RiskBar, Spinner, SkeletonRow,
  Empty, SectionHeader, StatusBadge, CopyButton, toast, ToastContainer,
} from "../components/ui";

const VERDICTS   = ["malicious", "suspicious", "clean"];
const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES   = ["open", "acknowledged", "escalated", "dismissed"];
const PAGE_SIZE  = 30;

export default function Alerts() {
  const [alerts, setAlerts]       = useState([]);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState("");
  const [verdict, setVerdict]     = useState("");
  const [severity, setSeverity]   = useState("");
  const [status, setStatus]       = useState("");
  const [sortBy, setSortBy]       = useState("created_at");
  const [sortDir, setSortDir]     = useState("desc");
  const [page, setPage]           = useState(0);
  const [selected, setSelected]   = useState(new Set());
  const [searchParams]            = useSearchParams();
  const navigate = useNavigate();
  const searchRef = useRef(null);

  // Initialize from URL params
  useEffect(() => {
    const s = searchParams.get("status");
    const v = searchParams.get("verdict");
    if (s) setStatus(s);
    if (v) setVerdict(v);
  }, []);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const params = { limit: 500 };
      if (verdict)  params.verdict  = verdict;
      if (severity) params.severity = severity;
      if (status)   params.status   = status;
      setAlerts(await listAlerts(params));
      setPage(0);
      setSelected(new Set());
    } catch (_) {}
    finally { setLoading(false); }
  }, [verdict, severity, status]);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
      if (e.key === "/" || e.key === "f") { e.preventDefault(); searchRef.current?.focus(); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const handleStatus = async (id, newStatus, e) => {
    if (e) e.stopPropagation();
    try {
      await updateAlert(id, newStatus);
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: newStatus } : a));
      toast.success(`Alert #${id} ${newStatus}`);
    } catch (_) {
      toast.error("Failed to update status");
    }
  };

  const handleBulkStatus = async (newStatus) => {
    for (const id of selected) {
      await handleStatus(id, newStatus, null);
    }
    setSelected(new Set());
  };

  const toggleSelect = (id, e) => {
    e.stopPropagation();
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleSort = (col) => {
    if (sortBy === col) setSortDir(d => d === "desc" ? "asc" : "desc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const SortIcon = ({ col }) => sortBy !== col ? null :
    (sortDir === "desc" ? <SortDesc size={10} /> : <SortAsc size={10} />);

  // Filter + sort
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

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated  = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const exportCSV = () => {
    const toExport = selected.size > 0 ? filtered.filter(a => selected.has(a.id)) : filtered;
    const headers = ["id","source_ip","attack_class","risk_score","verdict","severity","status","created_at"];
    const rows = toExport.map(a => headers.map(h => JSON.stringify(a[h] || "")).join(","));
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `alerts_${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
    toast.info(`Exported ${toExport.length} alerts`);
  };

  const clearFilters = () => {
    setSearch(""); setVerdict(""); setSeverity(""); setStatus("");
  };
  const hasFilters = search || verdict || severity || status;

  return (
    <div style={{ padding: "24px 28px", overflowY: "auto", height: "100%" }}>
      <ToastContainer />

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
          <h1 style={{ fontFamily: "var(--font-display)", fontSize: 22, fontWeight: 800, letterSpacing: "-0.02em" }}>
            Alert Queue
          </h1>
          <div style={{ display: "flex", gap: 8 }}>
            {selected.size > 0 && (
              <>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--amber)", alignSelf: "center" }}>
                  {selected.size} selected
                </span>
                <button className="btn btn-ghost btn-sm" onClick={() => handleBulkStatus("acknowledged")}>
                  Bulk ACK
                </button>
                <button className="btn btn-danger btn-sm" onClick={() => handleBulkStatus("escalated")}>
                  Bulk Escalate
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>
                  Clear
                </button>
              </>
            )}
            <button className="btn btn-ghost btn-sm" onClick={exportCSV}>
              <Download size={11} />
              {selected.size > 0 ? `Export (${selected.size})` : "Export CSV"}
            </button>
            <button className="btn btn-ghost btn-sm" onClick={fetchAlerts}>
              <RefreshCw size={11} /> Refresh
            </button>
          </div>
        </div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
          {filtered.length} records · press <kbd style={{ fontFamily: "var(--font-mono)", background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 3, padding: "1px 4px", fontSize: 10 }}>/</kbd> to search
        </div>
      </div>

      {/* Filter bar */}
      <div style={{
        display: "flex",
        gap: 10,
        marginBottom: 16,
        padding: "12px 14px",
        background: "var(--bg-raised)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        flexWrap: "wrap",
        alignItems: "center",
      }}>
        <Filter size={13} color="var(--text-muted)" />

        {/* Search */}
        <div style={{ position: "relative", flex: 1, minWidth: 200 }}>
          <Search size={12} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
          <input
            ref={searchRef}
            className="input"
            placeholder="Search alerts..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0); }}
            style={{ paddingLeft: 32 }}
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
            >
              <X size={12} />
            </button>
          )}
        </div>

        {/* Filter dropdowns */}
        {[
          { label: "Verdict", value: verdict, set: setVerdict, opts: VERDICTS },
          { label: "Severity", value: severity, set: setSeverity, opts: SEVERITIES },
          { label: "Status", value: status, set: setStatus, opts: STATUSES },
        ].map(({ label, value, set, opts }) => (
          <select
            key={label}
            value={value}
            onChange={e => { set(e.target.value); setPage(0); }}
            style={{
              background: value ? "rgba(245,158,11,0.05)" : "var(--bg-base)",
              border: `1px solid ${value ? "rgba(245,158,11,0.3)" : "var(--border-lit)"}`,
              borderRadius: 4,
              color: value ? "var(--amber-bright)" : "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              padding: "7px 10px",
              outline: "none",
              cursor: "pointer",
            }}
          >
            <option value="">{label}</option>
            {opts.map(o => <option key={o} value={o}>{o.toUpperCase()}</option>)}
          </select>
        ))}

        {hasFilters && (
          <button className="btn btn-ghost btn-sm" onClick={clearFilters}>
            <X size={10} /> Clear
          </button>
        )}

        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" }}>
          {filtered.length} / {alerts.length}
        </span>
      </div>

      {/* Quick filter chips */}
      <div style={{ display: "flex", gap: 6, marginBottom: 14, flexWrap: "wrap" }}>
        {[
          { label: "🔴 Critical Open", fn: () => { setSeverity("critical"); setStatus("open"); } },
          { label: "⚠ Escalated", fn: () => setStatus("escalated") },
          { label: "🟠 Malicious", fn: () => setVerdict("malicious") },
          { label: "📋 Open Queue", fn: () => setStatus("open") },
        ].map(({ label, fn }) => (
          <button key={label} className="btn btn-ghost btn-sm" onClick={fn}
            style={{ fontSize: 10 }}>
            {label}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="card" style={{ overflow: "hidden" }}>
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 36 }}>
                  <input
                    type="checkbox"
                    style={{ cursor: "pointer", accentColor: "var(--amber)" }}
                    checked={selected.size === paginated.length && paginated.length > 0}
                    onChange={e => {
                      if (e.target.checked) setSelected(new Set(paginated.map(a => a.id)));
                      else setSelected(new Set());
                    }}
                  />
                </th>
                <th className="sortable" onClick={() => toggleSort("id")}>
                  ID <SortIcon col="id" />
                </th>
                <th className="sortable" onClick={() => toggleSort("created_at")}>
                  Time <SortIcon col="created_at" />
                </th>
                <th>Source IP</th>
                <th>Attack Class</th>
                <th>MITRE</th>
                <th className="sortable" onClick={() => toggleSort("risk_score")}>
                  Risk <SortIcon col="risk_score" />
                </th>
                <th>Verdict</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={11} />)
              ) : paginated.length === 0 ? (
                <tr>
                  <td colSpan={11}>
                    <Empty
                      message={hasFilters ? "No alerts match your filters" : "No alerts yet"}
                      action={hasFilters ? (
                        <button className="btn btn-ghost btn-sm" onClick={clearFilters}>
                          Clear filters
                        </button>
                      ) : null}
                    />
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
                    background: selected.has(a.id) ? "rgba(245,158,11,0.04)" : undefined,
                  }}
                  onClick={() => navigate(`/alerts/${a.id}`)}
                >
                  <td onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      style={{ cursor: "pointer", accentColor: "var(--amber)" }}
                      checked={selected.has(a.id)}
                      onChange={e => toggleSelect(a.id, e)}
                    />
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                      #{a.id}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
                      {format(new Date(a.created_at), "MM-dd HH:mm:ss")}
                    </div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
                      {formatDistanceToNow(new Date(a.created_at), { addSuffix: true })}
                    </div>
                  </td>
                  <td onClick={e => e.stopPropagation()}>
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
                  <td>
                    {a.mitre_technique_id ? (
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--blue-bright)" }}>
                        {a.mitre_technique_id}
                      </span>
                    ) : <span style={{ color: "var(--text-muted)" }}>—</span>}
                  </td>
                  <td style={{ minWidth: 130 }}>
                    <RiskBar score={a.risk_score} />
                  </td>
                  <td><VerdictBadge verdict={a.verdict} /></td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td><StatusBadge status={a.status} /></td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: "flex", gap: 4 }}>
                      {a.status === "open" && (
                        <>
                          <button className="btn btn-ghost btn-sm" onClick={e => handleStatus(a.id, "acknowledged", e)} title="Acknowledge">
                            ACK
                          </button>
                          <button className="btn btn-danger btn-sm" onClick={e => handleStatus(a.id, "escalated", e)} title="Escalate">
                            ESC
                          </button>
                        </>
                      )}
                      {a.status !== "dismissed" && a.status !== "open" && (
                        <button className="btn btn-ghost btn-sm" onClick={e => handleStatus(a.id, "dismissed", e)} title="Dismiss">
                          DIS
                        </button>
                      )}
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={e => { e.stopPropagation(); navigate(`/alerts/${a.id}`); }}
                        title="View detail"
                      >
                        <ChevronRight size={10} />
                      </button>
                    </div>
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
              Page {page + 1} of {totalPages} · {filtered.length} records
            </span>
            <div style={{ display: "flex", gap: 4 }}>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPage(0)}
                disabled={page === 0}
              >
                «
              </button>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                ‹
              </button>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                const p = Math.min(Math.max(page - 2, 0) + i, totalPages - 1);
                return (
                  <button
                    key={p}
                    className={`btn btn-sm ${p === page ? "btn-primary" : "btn-ghost"}`}
                    onClick={() => setPage(p)}
                  >
                    {p + 1}
                  </button>
                );
              })}
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page === totalPages - 1}
              >
                ›
              </button>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setPage(totalPages - 1)}
                disabled={page === totalPages - 1}
              >
                »
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
