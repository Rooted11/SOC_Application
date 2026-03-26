import { useState, useEffect } from "react";
import { api } from "../services/api";

const SEV_COLOR = {
  critical: "text-red-400 border-red-800 bg-red-900/30",
  high:     "text-orange-400 border-orange-800 bg-orange-900/30",
  medium:   "text-yellow-400 border-yellow-800 bg-yellow-900/30",
  low:      "text-blue-400 border-blue-800 bg-blue-900/30",
  info:     "text-gray-400 border-gray-700 bg-gray-800/30",
};

const STATUS_COLOR = {
  open:           "text-red-400",
  investigating:  "text-yellow-400",
  contained:      "text-orange-400",
  resolved:       "text-green-400",
  false_positive: "text-gray-500",
};

const STATUSES = ["open", "investigating", "contained", "resolved", "false_positive"];

export default function IncidentList({ lastUpdated, showAlert }) {
  const [incidents,  setIncidents]  = useState([]);
  const [total,      setTotal]      = useState(0);
  const [selected,   setSelected]   = useState(null);
  const [detail,     setDetail]     = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [actionLoading, setActionLoading] = useState(false);

  // Filters
  const [filterStatus,   setFilterStatus]  = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [page, setPage] = useState(0);
  const limit = 20;

  const fetchIncidents = () => {
    setLoading(true);
    api.getIncidents({
      status:   filterStatus   || undefined,
      severity: filterSeverity || undefined,
      skip:     page * limit,
      limit,
    })
      .then((r) => { setIncidents(r.incidents); setTotal(r.total); })
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchIncidents(); }, [lastUpdated, filterStatus, filterSeverity, page]);

  const openDetail = (id) => {
    setSelected(id);
    api.getIncident(id)
      .then(setDetail)
      .catch((e) => showAlert(e.message, "error"));
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
      .then((r) => {
        showAlert(`Playbook '${r.playbook}' executed — ${r.actions?.length} actions`, "success");
        if (selected === id) openDetail(id);
      })
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setActionLoading(false));
  };

  return (
    <div className="flex gap-4 h-full">
      {/* ── Left panel: list ──────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Filters */}
        <div className="flex gap-2 mb-4">
          <select
            value={filterStatus}
            onChange={(e) => { setFilterStatus(e.target.value); setPage(0); }}
            className="bg-gray-900 border border-gray-700 text-gray-300 text-xs rounded px-2 py-1.5"
          >
            <option value="">All Statuses</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            value={filterSeverity}
            onChange={(e) => { setFilterSeverity(e.target.value); setPage(0); }}
            className="bg-gray-900 border border-gray-700 text-gray-300 text-xs rounded px-2 py-1.5"
          >
            <option value="">All Severities</option>
            {["critical","high","medium","low","info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <span className="ml-auto text-gray-600 text-xs self-center">
            {total} incident{total !== 1 ? "s" : ""}
          </span>
        </div>

        {/* Table */}
        <div className="flex-1 overflow-auto bg-gray-900 border border-gray-800 rounded-lg">
          {loading ? (
            <div className="flex items-center justify-center h-32 text-gray-600">Loading…</div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 uppercase tracking-widest">
                  <th className="text-left p-3">ID</th>
                  <th className="text-left p-3">Title</th>
                  <th className="text-left p-3">Sev</th>
                  <th className="text-left p-3">Risk</th>
                  <th className="text-left p-3">Status</th>
                  <th className="text-left p-3">Created</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => openDetail(inc.id)}
                    className={`border-b border-gray-800/50 cursor-pointer transition-colors ${
                      selected === inc.id ? "bg-gray-800" : "hover:bg-gray-800/40"
                    }`}
                  >
                    <td className="p-3 text-gray-500">#{inc.id}</td>
                    <td className="p-3 text-gray-300 max-w-xs truncate">{inc.title}</td>
                    <td className="p-3">
                      <span className={`px-1.5 py-0.5 rounded border text-xs ${SEV_COLOR[inc.severity] || SEV_COLOR.info}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-1">
                        <div className="w-16 h-1.5 bg-gray-800 rounded overflow-hidden">
                          <div
                            className={`h-full rounded ${
                              inc.risk_score >= 80 ? "bg-red-500" :
                              inc.risk_score >= 60 ? "bg-orange-500" :
                              inc.risk_score >= 40 ? "bg-yellow-500" : "bg-blue-500"
                            }`}
                            style={{ width: `${inc.risk_score}%` }}
                          />
                        </div>
                        <span className="text-gray-500">{Math.round(inc.risk_score)}</span>
                      </div>
                    </td>
                    <td className={`p-3 ${STATUS_COLOR[inc.status] || "text-gray-400"}`}>
                      {inc.status}
                    </td>
                    <td className="p-3 text-gray-600">
                      {inc.created_at ? new Date(inc.created_at).toLocaleString() : "–"}
                    </td>
                  </tr>
                ))}
                {incidents.length === 0 && (
                  <tr><td colSpan={6} className="p-6 text-center text-gray-600">No incidents found.</td></tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        <div className="flex justify-between items-center mt-3 text-xs text-gray-500">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1 bg-gray-800 rounded disabled:opacity-30"
          >← Prev</button>
          <span>Page {page + 1}</span>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={(page + 1) * limit >= total}
            className="px-3 py-1 bg-gray-800 rounded disabled:opacity-30"
          >Next →</button>
        </div>
      </div>

      {/* ── Right panel: detail ───────────────────────────────────────── */}
      {detail && (
        <div className="w-96 flex-shrink-0 bg-gray-900 border border-gray-800 rounded-lg p-4 overflow-auto space-y-4 text-sm">
          <div className="flex items-start justify-between gap-2">
            <span className="font-bold text-gray-200 text-base">#{detail.id}</span>
            <button onClick={() => { setSelected(null); setDetail(null); }} className="text-gray-600 hover:text-gray-300">✕</button>
          </div>
          <p className="text-gray-300">{detail.title}</p>
          <div className="flex gap-2">
            <span className={`px-2 py-0.5 rounded border text-xs ${SEV_COLOR[detail.severity] || SEV_COLOR.info}`}>
              {detail.severity}
            </span>
            <span className={`text-xs ${STATUS_COLOR[detail.status]}`}>{detail.status}</span>
            <span className="text-xs text-gray-500 ml-auto">Risk: {Math.round(detail.risk_score)}/100</span>
          </div>

          {detail.description && (
            <div>
              <div className="text-gray-500 text-xs uppercase mb-1">Detection reason</div>
              <p className="text-gray-400 text-xs">{detail.description}</p>
            </div>
          )}

          {detail.ioc_matches?.length > 0 && (
            <div>
              <div className="text-gray-500 text-xs uppercase mb-1">IOC Matches</div>
              <div className="flex flex-wrap gap-1">
                {detail.ioc_matches.map((m, i) => (
                  <span key={i} className="text-xs bg-red-900/30 border border-red-800 text-red-400 px-1.5 py-0.5 rounded">
                    {m}
                  </span>
                ))}
              </div>
            </div>
          )}

          {detail.affected_assets?.length > 0 && (
            <div>
              <div className="text-gray-500 text-xs uppercase mb-1">Affected Assets</div>
              <div className="flex flex-wrap gap-1">
                {detail.affected_assets.map((a, i) => (
                  <span key={i} className="text-xs bg-gray-800 border border-gray-700 text-gray-300 px-1.5 py-0.5 rounded">{a}</span>
                ))}
              </div>
            </div>
          )}

          {detail.ai_recommendation && (
            <div>
              <div className="text-gray-500 text-xs uppercase mb-1">AI Recommendation</div>
              <pre className="text-xs text-green-400 bg-gray-950 border border-gray-800 rounded p-2 whitespace-pre-wrap leading-relaxed overflow-auto max-h-48">
                {detail.ai_recommendation}
              </pre>
            </div>
          )}

          {/* Playbook actions */}
          {detail.playbook_actions?.length > 0 && (
            <div>
              <div className="text-gray-500 text-xs uppercase mb-1">Automated Actions</div>
              <div className="space-y-1">
                {detail.playbook_actions.map((a) => (
                  <div key={a.id} className="flex items-center gap-2 text-xs bg-gray-800 rounded px-2 py-1">
                    <span className={a.status === "completed" ? "text-green-500" : "text-red-500"}>
                      {a.status === "completed" ? "✓" : "✗"}
                    </span>
                    <span className="text-gray-400">{a.playbook}:{a.action}</span>
                    <span className="text-gray-600 ml-auto">{a.target}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-col gap-2 pt-2 border-t border-gray-800">
            <button
              onClick={() => runPlaybook(detail.id)}
              disabled={actionLoading}
              className="w-full text-xs bg-red-900/40 border border-red-800 text-red-400 rounded px-3 py-2 hover:bg-red-900/60 disabled:opacity-40"
            >
              ▶ Run Playbook
            </button>
            <div className="flex gap-2">
              <select
                onChange={(e) => e.target.value && updateStatus(detail.id, e.target.value)}
                defaultValue=""
                disabled={actionLoading}
                className="flex-1 text-xs bg-gray-800 border border-gray-700 text-gray-300 rounded px-2 py-1.5"
              >
                <option value="" disabled>Set status…</option>
                {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
