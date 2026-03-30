/**
 * SystemHealth — Comprehensive service monitoring dashboard.
 * Shows real-time health of all SOC components: backend, Redis, database,
 * worker, and queue status with auto-refresh.
 */

import { useEffect, useState, useCallback } from "react";
import { api } from "../services/api";

function ServiceCard({ name, status, detail, icon, pulse }) {
  const isOk = status === true || status === "ok" || status === "running";
  return (
    <div className={`rounded-xl border p-4 transition-all ${
      isOk
        ? "border-emerald-500/30 bg-emerald-950/10"
        : "border-red-500/30 bg-red-950/10"
    }`}>
      <div className="flex items-center gap-3">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg ${
          isOk ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"
        }`}>
          {icon}
        </div>
        <div className="flex-1">
          <div className="text-sm font-medium text-white">{name}</div>
          <div className={`text-xs mt-0.5 ${isOk ? "text-emerald-400" : "text-red-400"}`}>
            {isOk ? "Operational" : "Degraded"}
          </div>
        </div>
        <div className="flex-shrink-0">
          <span className={`inline-block w-3 h-3 rounded-full ${
            isOk ? "bg-emerald-500" : "bg-red-500"
          } ${pulse ? "animate-pulse" : ""}`} />
        </div>
      </div>
      {detail && (
        <div className="mt-3 text-xs text-slate-400 bg-slate-950/50 rounded-lg p-2.5 font-mono">
          {detail}
        </div>
      )}
    </div>
  );
}

function QueueGauge({ depth, label }) {
  const color = depth > 1000 ? "text-red-400" : depth > 100 ? "text-orange-400" : depth > 10 ? "text-yellow-400" : "text-emerald-400";
  const barColor = depth > 1000 ? "bg-red-500" : depth > 100 ? "bg-orange-500" : depth > 10 ? "bg-yellow-500" : "bg-emerald-500";
  const pct = Math.min(100, (depth / 500) * 100);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500">{label}</div>
      <div className={`text-3xl font-bold mt-2 font-mono ${color}`}>{depth.toLocaleString()}</div>
      <div className="mt-2 h-2 bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${barColor} transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
      <div className="flex justify-between text-[10px] text-slate-600 mt-1">
        <span>0</span>
        <span>{depth > 100 ? "High" : depth > 10 ? "Normal" : "Low"}</span>
        <span>500+</span>
      </div>
    </div>
  );
}

export default function SystemHealth({ lastUpdated, showAlert }) {
  const [health, setHealth] = useState(null);
  const [logStats, setLogStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastCheck, setLastCheck] = useState(null);
  const [history, setHistory] = useState([]);

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [h, ls] = await Promise.all([
        api.getSystemHealth().catch(() => null),
        api.getLogStats().catch(() => null),
      ]);
      setHealth(h);
      setLogStats(ls);
      setLastCheck(new Date());
      // Add to history (keep last 20)
      if (h) {
        setHistory((prev) => [
          ...prev.slice(-19),
          { time: new Date(), queueDepth: h.queue_depth || 0, redis: h.redis }
        ]);
      }
    } catch (err) {
      if (!silent) showAlert?.(err.message, "error");
    } finally {
      if (!silent) setLoading(false);
    }
  }, [showAlert]);

  useEffect(() => { refresh(); }, [lastUpdated, refresh]);

  // Auto-refresh every 10s
  useEffect(() => {
    const timer = setInterval(() => refresh(true), 10000);
    return () => clearInterval(timer);
  }, [refresh]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 animate-pulse">
        Checking system health...
      </div>
    );
  }

  const backendOnline = health !== null;
  const redisOk = health?.redis === true;
  const queueDepth = health?.queue_depth || 0;
  const timestamp = health?.timestamp;

  return (
    <div className="space-y-5">
      {/* ── Status header ─────────────────────────────────────────────── */}
      <div className={`rounded-xl border p-5 ${
        backendOnline && redisOk
          ? "border-emerald-500/30 bg-gradient-to-r from-emerald-950/20 to-transparent"
          : "border-red-500/30 bg-gradient-to-r from-red-950/20 to-transparent"
      }`}>
        <div className="flex items-center gap-4">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-2xl ${
            backendOnline && redisOk ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"
          }`}>
            {backendOnline && redisOk ? "\u2665" : "\u26A0"}
          </div>
          <div className="flex-1">
            <div className="text-lg font-semibold text-white">
              {backendOnline && redisOk ? "All Systems Operational" : "System Issues Detected"}
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Last checked: {lastCheck ? lastCheck.toLocaleTimeString() : "Never"}
              {" \u00B7 "}Auto-refreshing every 10s
            </div>
          </div>
          <button
            onClick={() => refresh()}
            className="text-xs px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-slate-400 hover:border-cyan-500/30 hover:text-cyan-400 transition-colors"
          >
            Refresh Now
          </button>
        </div>
      </div>

      {/* ── Service grid ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <ServiceCard
          name="Backend API"
          status={backendOnline}
          icon={"\u25C9"}
          pulse
          detail={timestamp ? `Uptime: ${new Date(timestamp * 1000).toLocaleString()}` : "Unable to reach"}
        />
        <ServiceCard
          name="Redis Queue"
          status={redisOk}
          icon={"R"}
          pulse
          detail={redisOk ? `Queue depth: ${queueDepth}` : "Connection failed"}
        />
        <ServiceCard
          name="PostgreSQL"
          status={backendOnline}
          icon={"\u25A3"}
          detail={logStats ? `${logStats.total_logs?.toLocaleString() || 0} logs stored` : "Checking..."}
        />
        <ServiceCard
          name="Worker Process"
          status={redisOk}
          icon={"\u25B6"}
          detail={redisOk ? "Processing stream" : "Waiting for Redis"}
        />
      </div>

      {/* ── Metrics row ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <QueueGauge depth={queueDepth} label="Queue Depth" />
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500">Total Logs</div>
          <div className="text-3xl font-bold mt-2 text-white font-mono">{(logStats?.total_logs || 0).toLocaleString()}</div>
          <div className="text-xs text-slate-500 mt-2">
            Anomalous: <span className="text-red-400">{logStats?.anomalous_logs || 0}</span>
            {" \u00B7 "}
            Rate: <span className="text-slate-300">{logStats?.anomaly_rate_pct || 0}%</span>
          </div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500">Avg Risk Score</div>
          <div className={`text-3xl font-bold mt-2 font-mono ${
            (logStats?.avg_risk_score || 0) >= 60 ? "text-red-400" :
            (logStats?.avg_risk_score || 0) >= 40 ? "text-orange-400" :
            "text-emerald-400"
          }`}>
            {logStats?.avg_risk_score || 0}
          </div>
          <div className="text-xs text-slate-500 mt-2">
            {logStats?.by_source ? `${Object.keys(logStats.by_source).length} log sources` : "No sources"}
          </div>
        </div>
      </div>

      {/* ── Log source breakdown ──────────────────────────────────────── */}
      {logStats?.by_source && Object.keys(logStats.by_source).length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h3 className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-3">Log Sources</h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {Object.entries(logStats.by_source)
              .sort(([, a], [, b]) => b - a)
              .map(([source, count]) => {
                const total = logStats.total_logs || 1;
                const pct = ((count / total) * 100).toFixed(1);
                return (
                  <div key={source} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                    <div className="text-xs font-medium text-slate-300 truncate">{source}</div>
                    <div className="flex items-baseline gap-1 mt-1">
                      <span className="text-lg font-bold text-white font-mono">{count.toLocaleString()}</span>
                      <span className="text-[10px] text-slate-500">{pct}%</span>
                    </div>
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* ── Health history ─────────────────────────────────────────────── */}
      {history.length > 1 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h3 className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-3">Queue Depth History (this session)</h3>
          <div className="flex items-end gap-1 h-16">
            {history.map((h, i) => {
              const maxH = Math.max(1, ...history.map((x) => x.queueDepth));
              const height = Math.max(2, (h.queueDepth / maxH) * 100);
              const color = !h.redis ? "bg-red-500" : h.queueDepth > 100 ? "bg-orange-500" : "bg-cyan-500/60";
              return (
                <div
                  key={i}
                  className={`flex-1 rounded-t ${color} transition-all duration-300`}
                  style={{ height: `${height}%` }}
                  title={`${h.time.toLocaleTimeString()}: ${h.queueDepth} msgs`}
                />
              );
            })}
          </div>
          <div className="flex justify-between text-[10px] text-slate-600 mt-1">
            <span>{history[0]?.time.toLocaleTimeString()}</span>
            <span>{history[history.length - 1]?.time.toLocaleTimeString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}
