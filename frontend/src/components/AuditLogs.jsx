import { useEffect, useState } from "react";
import { api } from "../services/api";
import { formatMountainDateTime } from "../utils/time";

export default function AuditLogs({ showAlert }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        setLoading(true);
        const data = await api.getAuditLogs();
        if (!active) return;
        setLogs(data);
      } catch (err) {
        setError(err.message);
        showAlert?.(err.message, "error");
      } finally {
        setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-white">Audit Logs</h2>
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
        {loading ? (
          <div className="text-slate-400 text-sm">Loading…</div>
        ) : error ? (
          <div className="text-rose-300 text-sm">{error}</div>
        ) : (
          <div className="space-y-3">
            {logs.map((log) => (
              <div key={log.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="flex items-center justify-between text-sm text-slate-200">
                  <span>{log.actor}</span>
                  <span className="text-xs text-slate-500">{formatMountainDateTime(log.created_at)}</span>
                </div>
                <div className="text-xs text-slate-400">
                  {log.action} {log.entity_type} {log.entity_id}
                </div>
              </div>
            ))}
            {logs.length === 0 && <div className="text-slate-400 text-sm">No audit entries.</div>}
          </div>
        )}
      </div>
    </div>
  );
}
