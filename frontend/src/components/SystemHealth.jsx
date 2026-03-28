import { useEffect, useState } from "react";
import { api } from "../services/api";

export default function SystemHealth({ showAlert }) {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        setLoading(true);
        const res = await api.getSystemHealth();
        if (!active) return;
        setHealth(res);
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
      <h2 className="text-lg font-semibold text-white">System Health</h2>
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
        {loading ? (
          <div className="text-slate-400 text-sm">Loading…</div>
        ) : error ? (
          <div className="text-rose-300 text-sm">{error}</div>
        ) : (
          <div className="text-sm text-slate-300 space-y-2">
            <div>Redis: {health?.redis ? "OK" : "Unavailable"}</div>
            <div>Queue depth: {health?.queue_depth ?? "n/a"}</div>
            <div>Timestamp: {health?.timestamp ? new Date(health.timestamp * 1000).toLocaleTimeString() : "n/a"}</div>
          </div>
        )}
      </div>
    </div>
  );
}
