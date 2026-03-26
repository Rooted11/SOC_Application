/**
 * LiveFeed — Real-time log stream
 * Auto-refreshes every 5 seconds. Shows the most recent log events
 * with anomaly highlighting, risk scores, and IOC correlation flags.
 */

import { useState, useEffect, useRef } from "react";
import { api } from "../services/api";

const RISK_BAR_COLOR = (r) => {
  if (r >= 80) return "bg-red-500";
  if (r >= 60) return "bg-orange-500";
  if (r >= 40) return "bg-yellow-500";
  return "bg-blue-500";
};

const LEVEL_COLOR = {
  critical:  "text-red-400",
  emergency: "text-red-400",
  alert:     "text-red-400",
  error:     "text-orange-400",
  warning:   "text-yellow-400",
  notice:    "text-blue-400",
  info:      "text-gray-400",
  debug:     "text-gray-600",
};

const EVENT_BADGE = {
  malware_detected:   "bg-red-900/60 border-red-700 text-red-400",
  c2_beacon:          "bg-red-900/60 border-red-700 text-red-400",
  lateral_movement:   "bg-orange-900/60 border-orange-700 text-orange-400",
  privilege_escalation:"bg-orange-900/60 border-orange-700 text-orange-400",
  data_exfiltration:  "bg-orange-900/60 border-orange-700 text-orange-400",
  network_scan:       "bg-yellow-900/60 border-yellow-700 text-yellow-400",
  auth_failure:       "bg-yellow-900/60 border-yellow-700 text-yellow-400",
  auth_success:       "bg-gray-800 border-gray-700 text-gray-400",
  file_access:        "bg-gray-800 border-gray-700 text-gray-400",
  dns_query:          "bg-gray-800 border-gray-700 text-gray-400",
  process_create:     "bg-gray-800 border-gray-700 text-gray-500",
};

const HIGH_RISK_EVENTS = new Set([
  "malware_detected", "c2_beacon", "lateral_movement",
  "privilege_escalation", "data_exfiltration", "network_scan",
]);

export default function LiveFeed({ lastUpdated, showAlert }) {
  const [logs,         setLogs]         = useState([]);
  const [total,        setTotal]        = useState(0);
  const [loading,      setLoading]      = useState(true);
  const [autoRefresh,  setAutoRefresh]  = useState(true);
  const [anomalyOnly,  setAnomalyOnly]  = useState(false);
  const [newCount,     setNewCount]     = useState(0);
  const prevIds     = useRef(new Set());
  const intervalRef = useRef(null);

  const fetchLogs = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const r = await api.getLogs({
        anomalous: anomalyOnly ? true : undefined,
        limit: 50,
      });
      const fresh = r.logs || [];
      if (prevIds.current.size > 0) {
        const newOnes = fresh.filter((l) => !prevIds.current.has(l.id)).length;
        if (newOnes > 0) setNewCount((n) => n + newOnes);
      }
      prevIds.current = new Set(fresh.map((l) => l.id));
      setLogs(fresh);
      setTotal(r.total || 0);
    } catch (e) {
      if (!silent) showAlert(e.message, "error");
    } finally {
      if (!silent) setLoading(false);
    }
  };

  // Initial load
  useEffect(() => { fetchLogs(); }, [lastUpdated, anomalyOnly]);

  // Auto-refresh every 5 s
  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(() => fetchLogs(true), 5000);
    }
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh, anomalyOnly]);

  const handleTabFocus = () => setNewCount(0);

  return (
    <div className="flex flex-col h-full gap-4">
      {/* ── Toolbar ─────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <span
            className={`inline-block w-2 h-2 rounded-full ${autoRefresh ? "bg-green-500 animate-pulse" : "bg-gray-600"}`}
          />
          <button
            onClick={() => setAutoRefresh((v) => !v)}
            className={`text-xs px-3 py-1.5 rounded border transition-colors ${
              autoRefresh
                ? "bg-green-900/30 border-green-800 text-green-400"
                : "bg-gray-800 border-gray-700 text-gray-400"
            }`}
          >
            {autoRefresh ? "Live (5s)" : "Paused"}
          </button>
        </div>

        <button
          onClick={() => setAnomalyOnly((v) => !v)}
          className={`text-xs px-3 py-1.5 rounded border transition-colors ${
            anomalyOnly
              ? "bg-red-900/30 border-red-800 text-red-400"
              : "bg-gray-800 border-gray-700 text-gray-400"
          }`}
        >
          {anomalyOnly ? "Anomalies only" : "All events"}
        </button>

        <button
          onClick={() => { setNewCount(0); fetchLogs(); handleTabFocus(); }}
          className="text-xs px-3 py-1.5 rounded border bg-gray-800 border-gray-700 text-gray-400 hover:border-blue-700 hover:text-blue-400"
        >
          ↻ Refresh
        </button>

        <span className="ml-auto text-xs text-gray-600">
          {total.toLocaleString()} total logs
        </span>

        {newCount > 0 && (
          <span
            onClick={() => setNewCount(0)}
            className="text-xs bg-green-900/40 border border-green-700 text-green-400 px-2 py-0.5 rounded-full cursor-pointer animate-pulse"
          >
            +{newCount} new
          </span>
        )}
      </div>

      {/* ── Log table ────────────────────────────────────────────────────── */}
      <div className="flex-1 bg-gray-900 border border-gray-800 rounded-lg overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center h-32 text-gray-600 animate-pulse">
            Loading feed…
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-900 z-10">
              <tr className="border-b border-gray-800 text-gray-500 uppercase tracking-widest">
                <th className="text-left p-2 pl-3">Time</th>
                <th className="text-left p-2">Source</th>
                <th className="text-left p-2">Event</th>
                <th className="text-left p-2">Src IP</th>
                <th className="text-left p-2">User</th>
                <th className="text-left p-2">Risk</th>
                <th className="text-left p-2 pr-3">Message</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr
                  key={log.id}
                  className={`border-b border-gray-800/40 transition-colors ${
                    log.is_anomalous
                      ? HIGH_RISK_EVENTS.has(log.event_type)
                        ? "bg-red-950/20 hover:bg-red-950/40"
                        : "bg-orange-950/10 hover:bg-orange-950/20"
                      : "hover:bg-gray-800/30"
                  }`}
                >
                  <td className="p-2 pl-3 text-gray-600 whitespace-nowrap font-mono">
                    {log.timestamp
                      ? new Date(log.timestamp).toLocaleTimeString([], {
                          hour:   "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                        })
                      : "–"}
                  </td>
                  <td className="p-2 text-gray-500 whitespace-nowrap">{log.source}</td>
                  <td className="p-2 whitespace-nowrap">
                    <span
                      className={`px-1.5 py-0.5 rounded border text-xs ${
                        EVENT_BADGE[log.event_type] || "bg-gray-800 border-gray-700 text-gray-500"
                      }`}
                    >
                      {log.event_type || "unknown"}
                    </span>
                  </td>
                  <td className="p-2 font-mono text-gray-400 whitespace-nowrap">
                    {log.ip_src || "–"}
                  </td>
                  <td className="p-2 text-gray-500 max-w-[8rem] truncate">{log.user || "–"}</td>
                  <td className="p-2 whitespace-nowrap">
                    <div className="flex items-center gap-1">
                      <div className="w-10 h-1.5 bg-gray-800 rounded overflow-hidden">
                        <div
                          className={`h-full rounded ${RISK_BAR_COLOR(log.risk_score)}`}
                          style={{ width: `${log.risk_score}%` }}
                        />
                      </div>
                      <span
                        className={`font-mono ${
                          log.risk_score >= 80 ? "text-red-400" :
                          log.risk_score >= 60 ? "text-orange-400" :
                          log.risk_score >= 40 ? "text-yellow-400" : "text-gray-500"
                        }`}
                      >
                        {Math.round(log.risk_score)}
                      </span>
                    </div>
                  </td>
                  <td className="p-2 pr-3 text-gray-400 max-w-xs truncate">
                    {log.is_anomalous && (
                      <span className="text-red-500 mr-1" title="Anomaly detected">⚠</span>
                    )}
                    {log.incident_id && (
                      <span className="text-orange-400 mr-1" title={`Incident #${log.incident_id}`}>
                        #{log.incident_id}
                      </span>
                    )}
                    {log.message}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-gray-600">
                    No logs yet — run{" "}
                    <code className="text-gray-500">python scripts/simulate_logs.py</code> to generate events.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Stats footer ─────────────────────────────────────────────────── */}
      {logs.length > 0 && (
        <div className="flex gap-6 text-xs text-gray-600">
          <span>
            Showing <span className="text-gray-400">{logs.length}</span> of{" "}
            <span className="text-gray-400">{total.toLocaleString()}</span>
          </span>
          <span>
            Anomalous:{" "}
            <span className="text-red-400">
              {logs.filter((l) => l.is_anomalous).length}
            </span>
          </span>
          <span>
            Avg risk:{" "}
            <span className="text-gray-400">
              {logs.length > 0
                ? Math.round(logs.reduce((s, l) => s + l.risk_score, 0) / logs.length)
                : 0}
            </span>
          </span>
        </div>
      )}
    </div>
  );
}
