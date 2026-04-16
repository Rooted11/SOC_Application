import { useState, useEffect } from "react";
import { api } from "../services/api";

const SEV_COLOR = {
  critical: "text-red-400 bg-red-900/30 border-red-800",
  high:     "text-orange-400 bg-orange-900/30 border-orange-800",
  medium:   "text-yellow-400 bg-yellow-900/30 border-yellow-800",
  low:      "text-blue-400 bg-blue-900/30 border-blue-800",
};

const IOC_ICON = {
  ip:     "🌐",
  domain: "🔗",
  hash:   "#",
  url:    "📎",
  email:  "✉",
};

// Simple bar chart rendered with plain divs (no extra library needed)
function BarChart({ data, colorClass = "bg-blue-600" }) {
  const max = Math.max(1, ...Object.values(data));
  return (
    <div className="space-y-1">
      {Object.entries(data)
        .sort(([, a], [, b]) => b - a)
        .map(([label, count]) => (
          <div key={label} className="flex items-center gap-2 text-xs">
            <span className="w-28 truncate text-gray-400 text-right">{label}</span>
            <div className="flex-1 h-3 bg-gray-800 rounded overflow-hidden">
              <div
                className={`h-full rounded ${colorClass}`}
                style={{ width: `${(count / max) * 100}%` }}
              />
            </div>
            <span className="w-6 text-gray-500">{count}</span>
          </div>
        ))}
    </div>
  );
}

export default function ThreatTrends({ lastUpdated, showAlert }) {
  const [data,       setData]       = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filterType, setFilterType] = useState("");
  const [maintenanceBusy, setMaintenanceBusy] = useState(false);
  const [confirmAction, setConfirmAction] = useState(null); // "old" | "recent" | null

  const fetchData = () => {
    setLoading(true);
    Promise.all([
      api.getThreatIntel({ ioc_type: filterType || undefined, limit: 60 }),
    ])
      .then(([ti]) => {
        setData(ti.summary);
        setIndicators(ti.indicators || []);
      })
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, [lastUpdated, filterType]);

  const handleRefresh = () => {
    setRefreshing(true);
    api.refreshThreatFeed()
      .then((r) => {
        showAlert(`Feed refreshed: ${r.total_added} new IOCs`, "success");
        fetchData();
      })
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setRefreshing(false));
  };

  const clearOldIndicators = async () => {
    setMaintenanceBusy(true);
    try {
      const result = await api.purgeThreatIntel({ older_than_days: 30 });
      if (result.deleted === 0) {
        showAlert("No old indicators to clear", "info");
      } else {
        showAlert(`Cleared ${result.deleted} old indicators`, "success");
      }
      setConfirmAction(null);
      fetchData();
    } catch (e) {
      showAlert(e.message, "error");
    } finally {
      setMaintenanceBusy(false);
    }
  };

  const clearRecentIndicators = async () => {
    setMaintenanceBusy(true);
    try {
      const ids = indicators.map((i) => i.id).filter(Boolean);
      if (ids.length === 0) {
        showAlert("No recent indicators to clear", "info");
        setConfirmAction(null);
        return;
      }
      const result = await api.purgeThreatIntel({ indicator_ids: ids });
      showAlert(`Cleared ${result.deleted} recent indicators`, "success");
      setConfirmAction(null);
      fetchData();
    } catch (e) {
      showAlert(e.message, "error");
    } finally {
      setMaintenanceBusy(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-gray-600">Loading threat data…</div>;
  }

  const sev  = data?.by_severity    || {};
  const type = data?.by_threat_type || {};

  return (
    <div className="space-y-5">
      {/* ── Summary ──────────────────────────────────────────────────── */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs uppercase tracking-widest text-gray-500">
            Threat Landscape Summary
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setConfirmAction(confirmAction === "old" ? null : "old")}
              disabled={maintenanceBusy}
              className="text-xs bg-yellow-950/25 border border-yellow-700/50 text-yellow-300 rounded px-3 py-1 hover:bg-yellow-950/40 disabled:opacity-40"
            >
              Clear Old Data
            </button>
            <button
              onClick={() => setConfirmAction(confirmAction === "recent" ? null : "recent")}
              disabled={maintenanceBusy}
              className="text-xs bg-red-950/25 border border-red-700/50 text-red-300 rounded px-3 py-1 hover:bg-red-950/40 disabled:opacity-40"
            >
              Clear Recent Indicators
            </button>
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="text-xs bg-gray-800 border border-gray-700 text-gray-400 rounded px-3 py-1 hover:border-red-700 hover:text-red-400 disabled:opacity-40"
            >
              {refreshing ? "Refreshing…" : "↻ Refresh Feed"}
            </button>
          </div>
        </div>

        {confirmAction && (
          <div className={`mb-3 flex items-center gap-3 rounded-lg border px-3 py-2 text-xs ${
            confirmAction === "recent"
              ? "border-red-700/50 bg-red-950/20 text-red-300"
              : "border-yellow-700/50 bg-yellow-950/20 text-yellow-300"
          }`}>
            <span className="font-medium">
              {confirmAction === "recent"
                ? `Delete ${indicators.length} recent indicators currently shown?`
                : "Delete indicators older than 30 days?"}
            </span>
            <button
              onClick={confirmAction === "recent" ? clearRecentIndicators : clearOldIndicators}
              disabled={maintenanceBusy}
              className={`px-3 py-1 rounded font-semibold disabled:opacity-50 ${
                confirmAction === "recent"
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
        <p className="text-sm text-gray-300 leading-relaxed">{data?.narrative}</p>
        <div className="mt-3 flex gap-4 text-xs text-gray-500">
          <span>Total IOCs: <span className="text-gray-300">{data?.total_iocs ?? 0}</span></span>
          <span>Updated: <span className="text-gray-300">{data?.generated_at?.slice(0, 19).replace("T", " ")}</span></span>
        </div>
      </div>

      {/* ── Charts row ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-4">By Severity</h2>
          <div className="grid grid-cols-2 gap-3 mb-4">
            {Object.entries(sev).map(([s, n]) => (
              <div key={s} className={`rounded border px-3 py-2 ${SEV_COLOR[s] || "border-gray-700 text-gray-400 bg-gray-800/30"}`}>
                <div className="text-lg font-bold">{n}</div>
                <div className="text-xs capitalize">{s}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-4">By Threat Type</h2>
          <BarChart data={type} colorClass="bg-red-700/70" />
        </div>
      </div>

      {/* ── IOC table ────────────────────────────────────────────────── */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
        <div className="flex items-center gap-3 mb-4">
          <h2 className="text-xs uppercase tracking-widest text-gray-500">Recent Indicators</h2>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="ml-auto text-xs bg-gray-800 border border-gray-700 text-gray-300 rounded px-2 py-1"
          >
            <option value="">All Types</option>
            {["ip", "domain", "hash", "url", "email"].map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>

        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 uppercase tracking-widest">
                <th className="text-left p-2">Type</th>
                <th className="text-left p-2">Value</th>
                <th className="text-left p-2">Threat</th>
                <th className="text-left p-2">Severity</th>
                <th className="text-left p-2">Conf.</th>
                <th className="text-left p-2">Feed</th>
                <th className="text-left p-2">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {indicators.map((ti) => (
                <tr key={ti.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="p-2">
                    <span className="text-base" title={ti.ioc_type}>
                      {IOC_ICON[ti.ioc_type] || "?"}
                    </span>
                  </td>
                  <td className="p-2 font-mono text-gray-300 max-w-xs truncate">{ti.value}</td>
                  <td className="p-2 text-gray-400">{ti.threat_type}</td>
                  <td className="p-2">
                    <span className={`px-1.5 py-0.5 rounded border text-xs ${SEV_COLOR[ti.severity] || "border-gray-700 text-gray-400"}`}>
                      {ti.severity}
                    </span>
                  </td>
                  <td className="p-2 text-gray-500">{(ti.confidence * 100).toFixed(0)}%</td>
                  <td className="p-2 text-gray-600">{ti.feed_source}</td>
                  <td className="p-2 text-gray-600">
                    {ti.last_seen ? new Date(ti.last_seen).toLocaleDateString() : "–"}
                  </td>
                </tr>
              ))}
              {indicators.length === 0 && (
                <tr><td colSpan={7} className="p-6 text-center text-gray-600">No indicators found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
