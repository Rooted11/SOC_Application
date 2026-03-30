/**
 * LiveFeed — Real-time log stream with clickable detail panel.
 * Auto-refreshes every 5 seconds. Click any log row to inspect it.
 */

import { useState, useEffect, useRef } from "react";
import { api } from "../services/api";

const RISK_COLOR = (r) => {
  if (r >= 80) return "text-red-400";
  if (r >= 60) return "text-orange-400";
  if (r >= 40) return "text-yellow-400";
  return "text-gray-500";
};

const RISK_BAR = (r) => {
  if (r >= 80) return "bg-red-500";
  if (r >= 60) return "bg-orange-500";
  if (r >= 40) return "bg-yellow-500";
  return "bg-blue-500";
};

const LEVEL_BADGE = {
  critical: "bg-red-900/60 text-red-300",
  error:    "bg-red-900/40 text-red-400",
  warning:  "bg-yellow-900/40 text-yellow-400",
  info:     "bg-gray-800 text-gray-400",
  debug:    "bg-gray-800 text-gray-600",
};

const EVENT_BADGE = {
  malware_detected:     "bg-red-900/60 border-red-700 text-red-400",
  c2_beacon:            "bg-red-900/60 border-red-700 text-red-400",
  data_exfiltration:    "bg-red-900/60 border-red-700 text-red-400",
  lateral_movement:     "bg-orange-900/60 border-orange-700 text-orange-400",
  privilege_escalation: "bg-orange-900/60 border-orange-700 text-orange-400",
  network_scan:         "bg-yellow-900/60 border-yellow-700 text-yellow-400",
  auth_failure:         "bg-yellow-900/60 border-yellow-700 text-yellow-400",
  firewall_event:       "bg-yellow-900/60 border-yellow-700 text-yellow-400",
  auth_success:         "bg-green-900/40 border-green-800 text-green-400",
  ssh_event:            "bg-blue-900/40 border-blue-800 text-blue-400",
  scheduled_task:       "bg-gray-800 border-gray-700 text-gray-400",
  system_event:         "bg-gray-800 border-gray-700 text-gray-400",
  account_change:       "bg-orange-900/40 border-orange-700 text-orange-400",
  sensitive_file_access:"bg-red-900/40 border-red-700 text-red-400",
  syslog:               "bg-gray-800 border-gray-700 text-gray-500",
};

const HIGH_RISK = new Set([
  "malware_detected","c2_beacon","lateral_movement",
  "privilege_escalation","data_exfiltration","network_scan",
  "sensitive_file_access",
]);

function formatTime(ts) {
  if (!ts) return "--:--:--";
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDate(ts) {
  if (!ts) return "";
  return new Date(ts).toLocaleString();
}

// --- Detail Panel (right side when a log is selected) ---
function LogDetail({ log, onClose, onDelete, setPage }) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  if (!log) return null;

  const fields = [
    { label: "Log ID",     value: `#${log.id}` },
    { label: "Timestamp",  value: formatDate(log.timestamp) },
    { label: "Source",      value: log.source },
    { label: "Event Type",  value: log.event_type || "unknown" },
    { label: "Log Level",   value: log.log_level || "info" },
    { label: "Source IP",   value: log.ip_src || "N/A" },
    { label: "Dest IP",     value: log.ip_dst || "N/A" },
    { label: "User",        value: log.user || "N/A" },
    { label: "Risk Score",  value: `${Math.round(log.risk_score || 0)} / 100` },
    { label: "Anomalous",   value: log.is_anomalous ? "YES" : "No" },
    { label: "Anomaly Score",value: log.anomaly_score?.toFixed(4) || "0" },
  ];

  return (
    <div className="w-96 bg-gray-900 border-l border-gray-800 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b border-gray-800">
        <h3 className="text-sm font-semibold text-gray-200">Log Detail</h3>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-lg leading-none">&times;</button>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-4">
        {/* Severity banner */}
        {log.is_anomalous && (
          <div className={`rounded-lg p-3 border ${
            log.risk_score >= 80 ? "bg-red-950/40 border-red-800" :
            log.risk_score >= 60 ? "bg-orange-950/30 border-orange-800" :
            "bg-yellow-950/30 border-yellow-800"
          }`}>
            <div className="flex items-center gap-2 text-sm font-medium">
              <span className="text-lg">!</span>
              <span className={RISK_COLOR(log.risk_score)}>
                Anomaly Detected &mdash; Risk {Math.round(log.risk_score)}/100
              </span>
            </div>
            {log.explanation && (
              <p className="text-xs text-gray-400 mt-1">{log.explanation}</p>
            )}
          </div>
        )}

        {/* Linked incident */}
        {log.incident_id && (
          <button
            onClick={() => setPage && setPage("incidents")}
            className="w-full text-left rounded-lg p-3 bg-orange-950/20 border border-orange-800 hover:bg-orange-950/40 transition-colors"
          >
            <div className="text-xs text-orange-400 font-medium">Linked Incident</div>
            <div className="text-sm text-orange-300 mt-0.5">Incident #{log.incident_id}</div>
            <div className="text-xs text-gray-500 mt-1">Click to view in Incidents tab</div>
          </button>
        )}

        {/* Fields */}
        <div className="space-y-1.5">
          {fields.map(({ label, value }) => (
            <div key={label} className="flex justify-between text-xs">
              <span className="text-gray-500">{label}</span>
              <span className={`text-gray-300 font-mono ${
                label === "Risk Score" ? RISK_COLOR(log.risk_score) :
                label === "Anomalous" && log.is_anomalous ? "text-red-400 font-bold" : ""
              }`}>{value}</span>
            </div>
          ))}
        </div>

        {/* Risk bar */}
        <div>
          <div className="text-xs text-gray-500 mb-1">Risk Assessment</div>
          <div className="w-full h-2 bg-gray-800 rounded overflow-hidden">
            <div className={`h-full rounded ${RISK_BAR(log.risk_score)}`} style={{ width: `${log.risk_score}%` }} />
          </div>
          <div className="flex justify-between text-xs text-gray-600 mt-0.5">
            <span>0</span><span>50</span><span>100</span>
          </div>
        </div>

        {/* Full message */}
        <div>
          <div className="text-xs text-gray-500 mb-1">Full Message</div>
          <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-gray-300 font-mono break-all max-h-40 overflow-y-auto">
            {log.message || "No message"}
          </div>
        </div>

        {/* Analysis (manual, no AI) */}
        <div>
          <div className="text-xs text-gray-500 mb-1">Quick Analysis</div>
          <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs space-y-2">
            {log.is_anomalous ? (
              <>
                <p className="text-yellow-400">This log was flagged as anomalous by the ML detection engine.</p>
                {log.risk_score >= 80 && <p className="text-red-400">CRITICAL: Immediate investigation recommended. Check for active compromise.</p>}
                {log.risk_score >= 60 && log.risk_score < 80 && <p className="text-orange-400">HIGH: Investigate source IP and user activity in the past hour.</p>}
                {log.risk_score >= 40 && log.risk_score < 60 && <p className="text-yellow-400">MEDIUM: Monitor for recurrence. Review correlated events.</p>}
                {log.event_type === "auth_failure" && <p className="text-gray-400">Check if multiple failures from this IP indicate brute force.</p>}
                {log.event_type === "privilege_escalation" && <p className="text-gray-400">Verify this privilege change was authorized and within change window.</p>}
                {log.event_type === "c2_beacon" && <p className="text-red-400">Potential C2 communication. Isolate host and check for malware.</p>}
                {log.event_type === "lateral_movement" && <p className="text-orange-400">Cross-host activity detected. Check if user should have access to both systems.</p>}
                {log.event_type === "data_exfiltration" && <p className="text-red-400">Large data transfer flagged. Check if this is expected (backup, sync) or malicious.</p>}
              </>
            ) : (
              <p className="text-green-400">This log appears normal. No anomalies detected.</p>
            )}
            {log.event_type === "auth_failure" && !log.is_anomalous && (
              <p className="text-gray-400">Single auth failure is normal. Becomes concerning with 5+ from same source.</p>
            )}
            {log.event_type === "firewall_event" && (
              <p className="text-gray-400">Blocked traffic. Check if source IP is known-bad or scanning.</p>
            )}
          </div>
        </div>

        {/* Raw data */}
        {log.raw_data && (
          <div>
            <div className="text-xs text-gray-500 mb-1">Raw Data</div>
            <pre className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-gray-400 font-mono break-all max-h-32 overflow-y-auto">
              {JSON.stringify(log.raw_data, null, 2)}
            </pre>
          </div>
        )}

        {/* Delete button */}
        {onDelete && (
          <div className="pt-2 border-t border-gray-800">
            {!confirmDelete ? (
              <button
                onClick={() => setConfirmDelete(true)}
                className="w-full text-xs px-3 py-2 rounded border border-red-900/50 text-red-500 hover:bg-red-950/30 hover:border-red-700 transition-colors"
              >
                Delete This Log
              </button>
            ) : (
              <div className="flex gap-2">
                <button
                  onClick={() => onDelete(log.id)}
                  className="flex-1 text-xs px-3 py-2 rounded bg-red-700 hover:bg-red-600 text-white font-semibold"
                >
                  Confirm Delete
                </button>
                <button
                  onClick={() => setConfirmDelete(false)}
                  className="text-xs px-3 py-2 rounded border border-gray-700 text-gray-400 hover:text-gray-300"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// --- Event type filter buttons ---
const EVENT_FILTERS = [
  { label: "All",       value: "" },
  { label: "Auth Fail", value: "auth_failure", cls: "text-yellow-400" },
  { label: "Auth OK",   value: "auth_success", cls: "text-green-400" },
  { label: "Priv Esc",  value: "privilege_escalation", cls: "text-orange-400" },
  { label: "Lateral",   value: "lateral_movement", cls: "text-orange-400" },
  { label: "C2",        value: "c2_beacon", cls: "text-red-400" },
  { label: "Malware",   value: "malware_detected", cls: "text-red-400" },
  { label: "Firewall",  value: "firewall_event", cls: "text-yellow-400" },
  { label: "SSH",       value: "ssh_event", cls: "text-blue-400" },
  { label: "Exfil",     value: "data_exfiltration", cls: "text-red-400" },
];

// Map a log to its asset by matching source/hostname or ip_src to asset records
function resolveAsset(log, assets) {
  if (!assets || assets.length === 0) return null;
  const src = (log.source || "").toLowerCase();
  const ip = (log.ip_src || "").toLowerCase();
  return assets.find(
    (a) =>
      (a.hostname && src.includes(a.hostname.toLowerCase())) ||
      (a.ip_address && (a.ip_address === ip || a.ip_address === src)) ||
      (a.hostname && a.hostname.toLowerCase() === src)
  ) || null;
}

const ASSET_ICON = {
  server:      "S",
  workstation: "W",
  firewall:    "F",
  switch:      "N",
  router:      "R",
};

const ASSET_COLOR = {
  server:      "bg-blue-900/40 border-blue-700 text-blue-400",
  workstation: "bg-purple-900/40 border-purple-700 text-purple-400",
  firewall:    "bg-green-900/40 border-green-700 text-green-400",
  switch:      "bg-cyan-900/40 border-cyan-700 text-cyan-400",
  router:      "bg-teal-900/40 border-teal-700 text-teal-400",
};

export default function LiveFeed({ lastUpdated, showAlert, setPage }) {
  const [logs,           setLogs]           = useState([]);
  const [total,          setTotal]          = useState(0);
  const [loading,        setLoading]        = useState(true);
  const [autoRefresh,    setAutoRefresh]    = useState(true);
  const [anomalyOnly,    setAnomalyOnly]    = useState(false);
  const [newCount,       setNewCount]       = useState(0);
  const [sourceFilter,   setSourceFilter]   = useState("");
  const [eventFilter,    setEventFilter]    = useState("");
  const [selectedLog,    setSelectedLog]    = useState(null);
  const [assets,         setAssets]         = useState([]);
  const [confirmAction,  setConfirmAction]  = useState(null); // "clear" | "archive" | null
  const prevIds     = useRef(new Set());
  const intervalRef = useRef(null);

  const handleClearAll = async () => {
    try {
      const result = await api.deleteLogsBulk({ all: true });
      showAlert(`Cleared ${result.deleted_logs} logs, ${result.deleted_incidents} incidents`, "success");
      setSelectedLog(null);
      setConfirmAction(null);
      fetchLogs();
    } catch (e) {
      showAlert(e.message, "error");
    }
  };

  const handleArchive = async () => {
    try {
      const result = await api.archiveLogs();
      if (result.archived === 0) {
        showAlert(result.message || "No logs old enough to archive", "info");
      } else {
        showAlert(`Archived ${result.archived} logs and purged from DB`, "success");
      }
      setConfirmAction(null);
      fetchLogs();
    } catch (e) {
      showAlert(e.message, "error");
    }
  };

  const handleDeleteLog = async (logId) => {
    try {
      const result = await api.deleteLog(logId);
      showAlert(`Deleted log #${logId}` + (result.deleted_incidents ? ` and ${result.deleted_incidents} linked incident(s)` : ""), "success");
      setSelectedLog(null);
      fetchLogs();
    } catch (e) {
      showAlert(e.message, "error");
    }
  };

  // Fetch assets once on mount
  useEffect(() => {
    api.getAssets().then((r) => setAssets(r.assets || r || [])).catch(() => {});
  }, []);

  const fetchLogs = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const r = await api.getLogs({
        anomalous: anomalyOnly ? true : undefined,
        source: sourceFilter || undefined,
        limit: 100,
      });
      let fresh = r.logs || [];
      // Client-side event type filter
      if (eventFilter) {
        fresh = fresh.filter((l) => l.event_type === eventFilter);
      }
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

  useEffect(() => { fetchLogs(); }, [lastUpdated, anomalyOnly, sourceFilter, eventFilter]);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(() => fetchLogs(true), 5000);
    }
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh, anomalyOnly, eventFilter]);

  return (
    <div className="flex h-full gap-0">
      {/* Main feed */}
      <div className="flex-1 flex flex-col gap-3 min-w-0">
        {/* ── Toolbar ─────────────────────────────────────────────────── */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <span className={`inline-block w-2 h-2 rounded-full ${autoRefresh ? "bg-green-500 animate-pulse" : "bg-gray-600"}`} />
            <button
              onClick={() => setAutoRefresh((v) => !v)}
              className={`text-xs px-3 py-1.5 rounded border transition-colors ${
                autoRefresh ? "bg-green-900/30 border-green-800 text-green-400" : "bg-gray-800 border-gray-700 text-gray-400"
              }`}
            >
              {autoRefresh ? "Live" : "Paused"}
            </button>
          </div>

          <button
            onClick={() => setAnomalyOnly((v) => !v)}
            className={`text-xs px-3 py-1.5 rounded border transition-colors ${
              anomalyOnly ? "bg-red-900/30 border-red-800 text-red-400" : "bg-gray-800 border-gray-700 text-gray-400"
            }`}
          >
            {anomalyOnly ? "Anomalies" : "All"}
          </button>

          <button
            onClick={() => { setNewCount(0); fetchLogs(); }}
            className="text-xs px-3 py-1.5 rounded border bg-gray-800 border-gray-700 text-gray-400 hover:border-blue-700 hover:text-blue-400"
          >
            Refresh
          </button>

          <button
            onClick={() => setConfirmAction(confirmAction === "archive" ? null : "archive")}
            className={`text-xs px-3 py-1.5 rounded border transition-colors ${
              confirmAction === "archive"
                ? "bg-yellow-900/40 border-yellow-700 text-yellow-400"
                : "bg-gray-800 border-gray-700 text-gray-400 hover:border-yellow-700 hover:text-yellow-400"
            }`}
          >
            Archive & Purge
          </button>

          <button
            onClick={() => setConfirmAction(confirmAction === "clear" ? null : "clear")}
            className={`text-xs px-3 py-1.5 rounded border transition-colors ${
              confirmAction === "clear"
                ? "bg-red-900/40 border-red-700 text-red-400"
                : "bg-gray-800 border-gray-700 text-gray-400 hover:border-red-700 hover:text-red-400"
            }`}
          >
            Clear All
          </button>

          <div className="flex items-center gap-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-400">
            <input
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              placeholder="Filter source..."
              className="bg-transparent outline-none text-gray-200 placeholder:text-gray-600 w-24"
            />
            {sourceFilter && (
              <button onClick={() => setSourceFilter("")} className="text-gray-500 hover:text-gray-300">x</button>
            )}
          </div>

          <span className="ml-auto text-xs text-gray-600">{total.toLocaleString()} total</span>

          {newCount > 0 && (
            <span
              onClick={() => setNewCount(0)}
              className="text-xs bg-green-900/40 border border-green-700 text-green-400 px-2 py-0.5 rounded-full cursor-pointer animate-pulse"
            >
              +{newCount} new
            </span>
          )}
        </div>

        {/* ── Confirm banner ───────────────────────────────────────────── */}
        {confirmAction && (
          <div className={`flex items-center gap-3 px-3 py-2 rounded-lg border text-xs ${
            confirmAction === "clear"
              ? "bg-red-950/30 border-red-800 text-red-400"
              : "bg-yellow-950/30 border-yellow-800 text-yellow-400"
          }`}>
            <span className="font-medium">
              {confirmAction === "clear"
                ? `Delete ALL ${total.toLocaleString()} logs and linked incidents? This cannot be undone.`
                : "Archive logs older than retention period to gzip, then purge from database?"}
            </span>
            <button
              onClick={confirmAction === "clear" ? handleClearAll : handleArchive}
              className={`px-3 py-1 rounded font-semibold ${
                confirmAction === "clear"
                  ? "bg-red-700 hover:bg-red-600 text-white"
                  : "bg-yellow-700 hover:bg-yellow-600 text-white"
              }`}
            >
              Confirm
            </button>
            <button
              onClick={() => setConfirmAction(null)}
              className="text-gray-500 hover:text-gray-300"
            >
              Cancel
            </button>
          </div>
        )}

        {/* ── Event type filters ──────────────────────────────────────── */}
        <div className="flex gap-1 flex-wrap">
          {EVENT_FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => setEventFilter(f.value)}
              className={`text-xs px-2 py-1 rounded border transition-colors ${
                eventFilter === f.value
                  ? "bg-blue-900/40 border-blue-700 text-blue-300"
                  : "bg-gray-800/50 border-gray-700/50 text-gray-500 hover:text-gray-300"
              } ${f.cls && eventFilter === f.value ? f.cls : ""}`}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* ── Log table ───────────────────────────────────────────────── */}
        <div className="flex-1 bg-gray-900 border border-gray-800 rounded-lg overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center h-32 text-gray-600 animate-pulse">Loading feed...</div>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-gray-900 z-10">
                <tr className="border-b border-gray-800 text-gray-500 uppercase tracking-widest">
                  <th className="text-left p-2 pl-3 w-8"></th>
                  <th className="text-left p-2">Time</th>
                  <th className="text-left p-2">Source</th>
                  <th className="text-left p-2">Event</th>
                  <th className="text-left p-2">IP</th>
                  <th className="text-left p-2">User</th>
                  <th className="text-left p-2">Risk</th>
                  <th className="text-left p-2 pr-3">Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => {
                  const isSelected = selectedLog?.id === log.id;
                  const rowBg = isSelected
                    ? "bg-blue-950/30"
                    : log.is_anomalous
                      ? HIGH_RISK.has(log.event_type) ? "bg-red-950/20 hover:bg-red-950/30" : "bg-orange-950/10 hover:bg-orange-950/20"
                      : "hover:bg-gray-800/30";

                  return (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedLog(isSelected ? null : log)}
                      className={`border-b border-gray-800/40 cursor-pointer transition-colors ${rowBg} ${
                        isSelected ? "ring-1 ring-blue-800" : ""
                      }`}
                    >
                      {/* Indicator column */}
                      <td className="p-2 pl-3 text-center">
                        {log.is_anomalous ? (
                          <span className={`inline-block w-2 h-2 rounded-full ${
                            log.risk_score >= 80 ? "bg-red-500 animate-pulse" :
                            log.risk_score >= 60 ? "bg-orange-500" : "bg-yellow-500"
                          }`} title={`Risk: ${Math.round(log.risk_score)}`} />
                        ) : (
                          <span className="inline-block w-2 h-2 rounded-full bg-gray-700" />
                        )}
                      </td>
                      <td className="p-2 text-gray-500 whitespace-nowrap font-mono">{formatTime(log.timestamp)}</td>
                      <td className="p-2 text-gray-500 whitespace-nowrap">{log.source}</td>
                      <td className="p-2 whitespace-nowrap">
                        <span className={`px-1.5 py-0.5 rounded border text-xs ${
                          EVENT_BADGE[log.event_type] || "bg-gray-800 border-gray-700 text-gray-500"
                        }`}>
                          {(log.event_type || "unknown").replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="p-2 font-mono text-gray-400 whitespace-nowrap">{log.ip_src || "--"}</td>
                      <td className="p-2 text-gray-500 max-w-[6rem] truncate">{log.user || "--"}</td>
                      <td className="p-2 whitespace-nowrap">
                        <div className="flex items-center gap-1">
                          <div className="w-8 h-1.5 bg-gray-800 rounded overflow-hidden">
                            <div className={`h-full rounded ${RISK_BAR(log.risk_score)}`} style={{ width: `${log.risk_score}%` }} />
                          </div>
                          <span className={`font-mono ${RISK_COLOR(log.risk_score)}`}>{Math.round(log.risk_score)}</span>
                        </div>
                      </td>
                      <td className="p-2 pr-3 text-gray-400 max-w-xs truncate">
                        {log.incident_id && (
                          <span className="text-orange-400 mr-1 font-semibold" title={`Linked to Incident #${log.incident_id}`}>
                            #{log.incident_id}
                          </span>
                        )}
                        {log.message}
                      </td>
                    </tr>
                  );
                })}
                {logs.length === 0 && (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-gray-600">
                      No logs match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {/* ── Stats footer ────────────────────────────────────────────── */}
        {logs.length > 0 && (
          <div className="flex gap-6 text-xs text-gray-600">
            <span>Showing <span className="text-gray-400">{logs.length}</span> of <span className="text-gray-400">{total.toLocaleString()}</span></span>
            <span>Anomalous: <span className="text-red-400">{logs.filter((l) => l.is_anomalous).length}</span></span>
            <span>Avg risk: <span className="text-gray-400">{Math.round(logs.reduce((s, l) => s + (l.risk_score||0), 0) / logs.length)}</span></span>
            {selectedLog && <span className="ml-auto text-blue-400">Log #{selectedLog.id} selected</span>}
          </div>
        )}
      </div>

      {/* ── Detail panel ──────────────────────────────────────────────── */}
      {selectedLog && (
        <LogDetail log={selectedLog} onClose={() => setSelectedLog(null)} onDelete={handleDeleteLog} setPage={setPage} />
      )}
    </div>
  );
}
