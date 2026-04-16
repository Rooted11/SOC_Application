import { useState, useEffect, useCallback } from "react";
import { api } from "../services/api";

const SEV_COLOR = {
  critical: "text-red-400 border-red-700 bg-red-950/50",
  high:     "text-orange-400 border-orange-800 bg-orange-950/40",
  medium:   "text-yellow-400 border-yellow-800 bg-yellow-900/30",
  low:      "text-blue-400 border-blue-800 bg-blue-900/20",
  info:     "text-gray-400 border-gray-700 bg-gray-800/30",
};

const SEV_ROW = {
  critical: "border-l-2 border-l-red-600",
  high:     "border-l-2 border-l-orange-600",
  medium:   "border-l-2 border-l-yellow-600",
  low:      "border-l-2 border-l-blue-600",
  info:     "",
};

const STATUS_COLOR = {
  open:           "text-red-400",
  investigating:  "text-yellow-400",
  contained:      "text-orange-400",
  resolved:       "text-green-400",
  false_positive: "text-gray-500",
};

const STATUS_ICONS = {
  open:           "●",
  investigating:  "◐",
  contained:      "◑",
  resolved:       "✓",
  false_positive: "○",
};

const STATUSES = ["open", "investigating", "contained", "resolved", "false_positive"];

function SeverityBadge({ sev }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${SEV_COLOR[sev] || SEV_COLOR.info}`}>
      {sev === "critical" && (
        <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse inline-block" />
      )}
      {sev}
    </span>
  );
}

function RiskBar({ score }) {
  const color =
    score >= 80 ? "bg-red-500" :
    score >= 60 ? "bg-orange-500" :
    score >= 40 ? "bg-yellow-500" : "bg-blue-500";
  const textColor =
    score >= 80 ? "text-red-400" :
    score >= 60 ? "text-orange-400" :
    score >= 40 ? "text-yellow-400" : "text-gray-500";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1.5 bg-gray-800 rounded overflow-hidden">
        <div className={`h-full rounded ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className={`font-mono text-xs ${textColor}`}>{Math.round(score)}</span>
    </div>
  );
}

export default function IncidentList({ lastUpdated, showAlert }) {
  const [incidents,     setIncidents]     = useState([]);
  const [total,         setTotal]         = useState(0);
  const [selected,      setSelected]      = useState(null);
  const [detail,        setDetail]        = useState(null);
  const [loading,       setLoading]       = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [search,        setSearch]        = useState("");
  const [filterStatus,  setFilterStatus]  = useState("open");
  const [filterSev,     setFilterSev]     = useState("");
  const [page,          setPage]          = useState(0);
  const [maintenanceBusy, setMaintenanceBusy] = useState(false);
  const [confirmAction, setConfirmAction] = useState(null); // "archive" | "clear" | null
  const limit = 20;

  const fetchIncidents = useCallback(() => {
    setLoading(true);
    api.getIncidents({
      status:   filterStatus || undefined,
      severity: filterSev    || undefined,
      skip:     page * limit,
      limit,
    })
      .then((r) => {
        let list = r.incidents || [];
        if (search.trim()) {
          const q = search.toLowerCase();
          list = list.filter(
            (i) => i.title?.toLowerCase().includes(q) || String(i.id).includes(q)
          );
        }
        setIncidents(list);
        setTotal(r.total);
      })
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setLoading(false));
  }, [lastUpdated, filterStatus, filterSev, page, search]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  const openDetail = (id) => {
    setSelected(id);
    api.getIncident(id).then(setDetail).catch((e) => showAlert(e.message, "error"));
  };

  const updateStatus = (id, status) => {
    setActionLoading(true);
    api.updateIncident(id, { status })
      .then(() => {
        showAlert(`Incident #${id} marked as ${status}`, "success");
        fetchIncidents();
        if (selected === id) openDetail(id);
      })
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setActionLoading(false));
  };

  const runPlaybook = (id) => {
    setActionLoading(true);
    api.triggerPlaybook(id)
      .then((r) => showAlert(`Playbook executed — ${r.actions?.length || 0} actions`, "success"))
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setActionLoading(false));
  };

  const critCount = incidents.filter((i) => i.severity === "critical").length;

  const runArchive = async () => {
    setMaintenanceBusy(true);
    try {
      const result = await api.archiveLogs();
      if (result.archived === 0) {
        showAlert(result.message || "No logs eligible for archive", "info");
      } else {
        showAlert(`Archived ${result.archived} logs and purged from DB`, "success");
      }
      setConfirmAction(null);
    } catch (e) {
      showAlert(e.message, "error");
    } finally {
      setMaintenanceBusy(false);
    }
  };

  const runClearAll = async () => {
    setMaintenanceBusy(true);
    try {
      const result = await api.deleteLogsBulk({ all: true });
      showAlert(`Deleted ${result.deleted_logs} logs`, "success");
      setConfirmAction(null);
      fetchIncidents();
    } catch (e) {
      showAlert(e.message, "error");
    } finally {
      setMaintenanceBusy(false);
    }
  };

  return (
    <div className="flex gap-4 h-full">
      {/* ── Left panel ──────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* Toolbar */}
        <div className="flex flex-wrap gap-2 mb-3">
          {/* Search */}
          <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-xl px-3 py-1.5 text-xs flex-1 min-w-48">
            <span className="text-slate-500">⌕</span>
            <input
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(0); }}
              placeholder="Search by title or ID…"
              className="bg-transparent outline-none text-slate-200 placeholder:text-slate-600 w-full"
            />
            {search && (
              <button onClick={() => setSearch("")} className="text-slate-500 hover:text-slate-300">✕</button>
            )}
          </div>

          {/* Status quick-filter buttons */}
          <div className="flex gap-1">
            {["", "open", "investigating", "contained", "resolved"].map((s) => (
              <button
                key={s || "all"}
                onClick={() => { setFilterStatus(s); setPage(0); }}
                className={`text-xs px-3 py-1.5 rounded-xl border transition-colors ${
                  filterStatus === s
                    ? "bg-cyan-500/15 border-cyan-500/50 text-cyan-300"
                    : "bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600"
                }`}
              >
                {s ? `${STATUS_ICONS[s]} ${s}` : "All"}
              </button>
            ))}
          </div>

          {/* Severity filter */}
          <select
            value={filterSev}
            onChange={(e) => { setFilterSev(e.target.value); setPage(0); }}
            className="bg-slate-900 border border-slate-700 text-slate-300 text-xs rounded-xl px-3 py-1.5"
          >
            <option value="">All severities</option>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          <button
            onClick={() => setConfirmAction(confirmAction === "archive" ? null : "archive")}
            disabled={maintenanceBusy}
            className="text-xs px-3 py-1.5 rounded-xl border border-yellow-700/50 bg-yellow-950/25 text-yellow-300 hover:bg-yellow-950/40 disabled:opacity-40"
          >
            Archive & Purge
          </button>

          <button
            onClick={() => setConfirmAction(confirmAction === "clear" ? null : "clear")}
            disabled={maintenanceBusy}
            className="text-xs px-3 py-1.5 rounded-xl border border-red-700/50 bg-red-950/25 text-red-300 hover:bg-red-950/40 disabled:opacity-40"
          >
            Clear All Logs
          </button>

          {/* Counts */}
          <div className="ml-auto flex items-center gap-3 text-xs text-slate-500 self-center">
            {critCount > 0 && (
              <span className="flex items-center gap-1.5 text-red-400 font-medium">
                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                {critCount} critical
              </span>
            )}
            <span>{total} total</span>
          </div>
        </div>

        {confirmAction && (
          <div className={`mb-3 flex items-center gap-3 rounded-xl border px-3 py-2 text-xs ${
            confirmAction === "clear"
              ? "border-red-700/50 bg-red-950/20 text-red-300"
              : "border-yellow-700/50 bg-yellow-950/20 text-yellow-300"
          }`}>
            <span className="font-medium">
              {confirmAction === "clear"
                ? "Delete all logs and linked incidents? This cannot be undone."
                : "Archive old logs and purge them from the database now?"}
            </span>
            <button
              onClick={confirmAction === "clear" ? runClearAll : runArchive}
              disabled={maintenanceBusy}
              className={`px-3 py-1 rounded font-semibold disabled:opacity-50 ${
                confirmAction === "clear"
                  ? "bg-red-700 text-white hover:bg-red-600"
                  : "bg-yellow-700 text-white hover:bg-yellow-600"
              }`}
            >
              {maintenanceBusy ? "Working..." : "Confirm"}
            </button>
            <button
              onClick={() => setConfirmAction(null)}
              className="text-slate-300 hover:text-white"
            >
              Cancel
            </button>
          </div>
        )}

        {/* Table */}
        <div className="flex-1 overflow-auto bg-slate-900/60 border border-slate-800 rounded-2xl">
          {loading ? (
            <div className="flex items-center justify-center h-32 gap-2 text-slate-600">
              <span className="w-2 h-2 rounded-full bg-cyan-500 animate-ping" />
              Loading incidents…
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-slate-900/90 backdrop-blur z-10">
                <tr className="border-b border-slate-800 text-slate-500 uppercase tracking-widest text-[10px]">
                  <th className="text-left p-3">ID</th>
                  <th className="text-left p-3">Title</th>
                  <th className="text-left p-3">Severity</th>
                  <th className="text-left p-3">Risk</th>
                  <th className="text-left p-3">Status</th>
                  <th className="text-left p-3">Asset</th>
                  <th className="text-left p-3">Created</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => openDetail(inc.id)}
                    className={`border-b border-slate-800/50 cursor-pointer transition-colors ${SEV_ROW[inc.severity] || ""} ${
                      selected === inc.id ? "bg-slate-800/70" : "hover:bg-slate-800/30"
                    }`}
                  >
                    <td className="p-3 text-slate-500 font-mono">#{inc.id}</td>
                    <td className="p-3 text-slate-300 max-w-xs">
                      <span className="truncate block">{inc.title}</span>
                      {inc.ioc_matches?.length > 0 && (
                        <span className="text-red-400 text-[10px]">
                          ⚑ {inc.ioc_matches.length} IOC match{inc.ioc_matches.length > 1 ? "es" : ""}
                        </span>
                      )}
                    </td>
                    <td className="p-3"><SeverityBadge sev={inc.severity} /></td>
                    <td className="p-3"><RiskBar score={inc.risk_score} /></td>
                    <td className={`p-3 font-medium ${STATUS_COLOR[inc.status] || "text-slate-400"}`}>
                      {STATUS_ICONS[inc.status]} {inc.status}
                    </td>
                    <td className="p-3 text-slate-500 max-w-[7rem] truncate">
                      {inc.affected_assets?.[0] || "–"}
                    </td>
                    <td className="p-3 text-slate-600 whitespace-nowrap">
                      {inc.created_at
                        ? new Date(inc.created_at).toLocaleString([], {
                            month: "short", day: "numeric",
                            hour: "2-digit", minute: "2-digit",
                          })
                        : "–"}
                    </td>
                  </tr>
                ))}
                {incidents.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-10 text-center">
                      <div className="text-slate-500 text-2xl mb-2">
                        {filterStatus === "open" ? "✓" : "⊘"}
                      </div>
                      <div className="text-slate-500 text-sm">
                        {filterStatus === "open"
                          ? "No open incidents — environment is clean"
                          : "No incidents match the current filters"}
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        <div className="flex justify-between items-center mt-3 text-xs text-slate-500">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1.5 bg-slate-800 rounded-xl disabled:opacity-30 hover:bg-slate-700"
          >← Prev</button>
          <span>Page {page + 1} · showing {Math.min((page + 1) * limit, total)} of {total}</span>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={(page + 1) * limit >= total}
            className="px-3 py-1.5 bg-slate-800 rounded-xl disabled:opacity-30 hover:bg-slate-700"
          >Next →</button>
        </div>
      </div>

      {/* ── Right panel: detail ───────────────────────────────────────────── */}
      {detail && (
        <div className="w-[420px] flex-shrink-0 bg-slate-900/80 border border-slate-800 rounded-2xl p-5 overflow-auto space-y-4 text-sm backdrop-blur">
          <div className="flex items-start justify-between gap-2">
            <div>
              <span className="text-slate-500 text-xs font-mono">Incident #{detail.id}</span>
              <p className="font-semibold text-slate-200 mt-0.5 leading-snug">{detail.title}</p>
            </div>
            <button
              onClick={() => { setSelected(null); setDetail(null); }}
              className="text-slate-600 hover:text-slate-300 text-lg leading-none flex-shrink-0"
            >✕</button>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge sev={detail.severity} />
            <span className={`text-xs font-medium ${STATUS_COLOR[detail.status]}`}>
              {STATUS_ICONS[detail.status]} {detail.status}
            </span>
            <span className="text-xs text-slate-500 ml-auto">Risk {Math.round(detail.risk_score)}/100</span>
          </div>

          {detail.description && (
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
              <div className="text-slate-500 text-[10px] uppercase tracking-widest mb-1.5">Detection Signal</div>
              <p className="text-slate-400 text-xs leading-relaxed">{detail.description}</p>
            </div>
          )}

          {detail.ioc_matches?.length > 0 && (
            <div>
              <div className="text-slate-500 text-[10px] uppercase tracking-widest mb-2">Threat Intel Matches</div>
              <div className="flex flex-wrap gap-1.5">
                {detail.ioc_matches.map((m, i) => (
                  <span key={i} className="text-xs bg-red-950/40 border border-red-800/60 text-red-400 px-2 py-0.5 rounded-lg">
                    ⚑ {m}
                  </span>
                ))}
              </div>
            </div>
          )}

          {detail.affected_assets?.length > 0 && (
            <div>
              <div className="text-slate-500 text-[10px] uppercase tracking-widest mb-2">Affected Assets</div>
              <div className="flex flex-wrap gap-1.5">
                {detail.affected_assets.map((a, i) => (
                  <span key={i} className="text-xs bg-slate-800 border border-slate-700 text-slate-300 px-2 py-0.5 rounded-lg">
                    ⬡ {a}
                  </span>
                ))}
              </div>
            </div>
          )}

          {detail.ai_recommendation && (
            <div>
              <div className="text-slate-500 text-[10px] uppercase tracking-widest mb-2">AI Recommendation</div>
              <pre className="text-xs text-emerald-400 bg-slate-950 border border-slate-800 rounded-xl p-3 whitespace-pre-wrap leading-relaxed overflow-auto max-h-56 font-sans">
                {detail.ai_recommendation}
              </pre>
            </div>
          )}

          {detail.playbook_actions?.length > 0 && (
            <div>
              <div className="text-slate-500 text-[10px] uppercase tracking-widest mb-2">Automated Actions</div>
              <div className="space-y-1.5">
                {detail.playbook_actions.map((a) => (
                  <div key={a.id} className="flex items-center gap-2 text-xs bg-slate-800/60 border border-slate-700/50 rounded-lg px-3 py-2">
                    <span className={a.status === "completed" ? "text-emerald-500" : "text-red-500"}>
                      {a.status === "completed" ? "✓" : "✗"}
                    </span>
                    <span className="text-slate-400">{a.playbook}: {a.action}</span>
                    <span className="text-slate-600 ml-auto font-mono">{a.target}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-col gap-2 pt-2 border-t border-slate-800">
            <button
              onClick={() => runPlaybook(detail.id)}
              disabled={actionLoading}
              className="w-full text-xs bg-red-900/30 border border-red-800/60 text-red-400 rounded-xl px-3 py-2.5 hover:bg-red-900/50 disabled:opacity-40 font-medium"
            >
              ▶ Run Response Playbook
            </button>
            <div className="flex gap-1.5 flex-wrap">
              {STATUSES.map((s) => (
                <button
                  key={s}
                  onClick={() => updateStatus(detail.id, s)}
                  disabled={actionLoading || detail.status === s}
                  className={`flex-1 min-w-fit text-xs px-2 py-1.5 rounded-lg border disabled:opacity-30 transition-colors whitespace-nowrap ${
                    detail.status === s
                      ? "border-cyan-600/50 bg-cyan-900/20 text-cyan-400"
                      : "border-slate-700 bg-slate-800/60 text-slate-400 hover:border-slate-600"
                  }`}
                >
                  {STATUS_ICONS[s]} {s.replace("_", " ")}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
