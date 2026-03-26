/**
 * CommandCenter — SOC Overview
 * The primary landing view showing the overall security posture,
 * key metrics, hot assets, and recent incidents in one glance.
 * Uses the /api/overview endpoint.
 */

import { useState, useEffect } from "react";
import { api } from "../services/api";

const POSTURE_COLOR = (score) => {
  if (score >= 80) return { ring: "border-green-500",  text: "text-green-400",  label: "HEALTHY",   bg: "bg-green-500" };
  if (score >= 60) return { ring: "border-yellow-500", text: "text-yellow-400", label: "ELEVATED",  bg: "bg-yellow-500" };
  if (score >= 40) return { ring: "border-orange-500", text: "text-orange-400", label: "DEGRADED",  bg: "bg-orange-500" };
  return              { ring: "border-red-500",    text: "text-red-400",    label: "CRITICAL",  bg: "bg-red-500" };
};

const SEV_DOT = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
};

const SEV_TEXT = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-blue-400",
};

function MetricCard({ label, value, sub, accent = "border-gray-800", valueClass = "text-gray-100" }) {
  return (
    <div className={`bg-gray-900 border rounded-lg p-4 ${accent}`}>
      <div className="text-xs text-gray-500 uppercase tracking-widest mb-1">{label}</div>
      <div className={`text-3xl font-bold ${valueClass}`}>{value}</div>
      {sub && <div className="text-xs text-gray-500 mt-1">{sub}</div>}
    </div>
  );
}

function PostureGauge({ score }) {
  const c      = POSTURE_COLOR(score);
  const radius = 52;
  const circ   = 2 * Math.PI * radius;
  const dash   = (score / 100) * circ;

  return (
    <div className={`bg-gray-900 border-2 ${c.ring} rounded-2xl p-6 flex flex-col items-center justify-center`}>
      <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">Security Posture</div>
      <div className="relative">
        <svg width="130" height="130" className="-rotate-90">
          <circle cx="65" cy="65" r={radius} fill="none" stroke="#1f2937" strokeWidth="10" />
          <circle
            cx="65" cy="65" r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth="10"
            strokeDasharray={`${dash} ${circ}`}
            strokeLinecap="round"
            className={c.text}
            style={{ transition: "stroke-dasharray 0.8s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-4xl font-bold ${c.text}`}>{score}</span>
          <span className="text-xs text-gray-500">/100</span>
        </div>
      </div>
      <div className={`mt-3 text-sm font-semibold tracking-widest ${c.text}`}>{c.label}</div>
    </div>
  );
}

function MiniBar({ label, count, max, colorClass }) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-32 truncate text-gray-400 text-right">{label}</span>
      <div className="flex-1 h-2 bg-gray-800 rounded overflow-hidden">
        <div className={`h-full rounded ${colorClass}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-6 text-right text-gray-500">{count}</span>
    </div>
  );
}

export default function CommandCenter({ lastUpdated, showAlert }) {
  const [overview, setOverview] = useState(null);
  const [loading,  setLoading]  = useState(true);

  useEffect(() => {
    setLoading(true);
    api.getOverview()
      .then(setOverview)
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setLoading(false));
  }, [lastUpdated]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-600 animate-pulse">
        Loading command center…
      </div>
    );
  }

  if (!overview) return null;

  const h   = overview.headline   || {};
  const res = overview.response   || {};
  const ast = overview.assets     || {};
  const int = overview.intel      || {};
  const evt = overview.top_event_types || [];
  const hot = overview.hot_assets || [];
  const rec = overview.recent_incidents || [];

  const maxEvt = Math.max(1, ...evt.map((e) => e.count));
  const maxHot = Math.max(1, ...hot.map((a) => a.count));

  return (
    <div className="space-y-5">
      {/* ── Row 1: Posture + headline stats ─────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="md:col-span-1">
          <PostureGauge score={h.posture_score ?? 50} />
        </div>

        <div className="md:col-span-4 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <MetricCard
            label="Open Incidents"
            value={h.open_incidents ?? 0}
            sub={`${h.critical_open ?? 0} critical`}
            accent={h.critical_open > 0 ? "border-red-800" : "border-gray-800"}
            valueClass={h.critical_open > 0 ? "text-red-400" : "text-gray-100"}
          />
          <MetricCard
            label="Logs (24h)"
            value={(h.recent_logs_24h ?? 0).toLocaleString()}
            sub={`${h.recent_anomalies_24h ?? 0} anomalous`}
            accent="border-gray-800"
          />
          <MetricCard
            label="Containment Rate"
            value={`${res.containment_rate_pct ?? 0}%`}
            sub={`${res.resolved_incidents ?? 0} resolved`}
            accent="border-green-900"
            valueClass="text-green-400"
          />
          <MetricCard
            label="Automation Rate"
            value={`${res.automation_rate_pct ?? 0}%`}
            sub="Playbooks executed"
            accent="border-blue-900"
            valueClass="text-blue-400"
          />
        </div>
      </div>

      {/* ── Row 2: Response + Asset + Intel ─────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Response metrics */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-3">Response Metrics</h2>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Avg Resolution</span>
              <span className="text-gray-200 font-mono">
                {res.avg_resolution_hours > 0
                  ? `${res.avg_resolution_hours.toFixed(1)}h`
                  : "–"}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Critical Open</span>
              <span className={`font-mono font-bold ${h.critical_open > 0 ? "text-red-400" : "text-green-400"}`}>
                {h.critical_open ?? 0}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">High Open</span>
              <span className={`font-mono font-bold ${h.high_open > 0 ? "text-orange-400" : "text-green-400"}`}>
                {h.high_open ?? 0}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Anomaly Rate (24h)</span>
              <span className="text-gray-200 font-mono">
                {h.recent_logs_24h > 0
                  ? `${((h.recent_anomalies_24h / h.recent_logs_24h) * 100).toFixed(1)}%`
                  : "0%"}
              </span>
            </div>
          </div>
        </div>

        {/* Asset status */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-3">Asset Status</h2>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Total Assets</span>
              <span className="text-gray-200 font-mono">{ast.total ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Critical Assets</span>
              <span className="text-orange-400 font-mono font-bold">{ast.critical ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Isolated</span>
              <span className={`font-mono font-bold ${ast.isolated > 0 ? "text-red-400" : "text-green-400"}`}>
                {ast.isolated ?? 0}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Isolation Rate</span>
              <span className="text-gray-200 font-mono">{ast.isolation_rate_pct ?? 0}%</span>
            </div>
          </div>
        </div>

        {/* Threat intel */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-3">Threat Intelligence</h2>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Active IOCs</span>
              <span className="text-gray-200 font-mono">{int.active_iocs ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Critical / High IOCs</span>
              <span className={`font-mono font-bold ${int.critical_iocs > 0 ? "text-red-400" : "text-green-400"}`}>
                {int.critical_iocs ?? 0}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Row 3: Top event types + Hot assets ─────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-4">Top Event Types</h2>
          {evt.length === 0 ? (
            <p className="text-gray-600 text-sm">No data yet.</p>
          ) : (
            <div className="space-y-2">
              {evt.map((e) => (
                <MiniBar
                  key={e.event_type}
                  label={e.event_type}
                  count={e.count}
                  max={maxEvt}
                  colorClass="bg-red-700/70"
                />
              ))}
            </div>
          )}
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-4">Most Active Assets</h2>
          {hot.length === 0 ? (
            <p className="text-gray-600 text-sm">No incident data yet.</p>
          ) : (
            <div className="space-y-2">
              {hot.map((a) => (
                <MiniBar
                  key={a.hostname}
                  label={a.hostname}
                  count={a.count}
                  max={maxHot}
                  colorClass="bg-orange-600/70"
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Row 4: Recent incidents ──────────────────────────────────────── */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h2 className="text-xs uppercase tracking-widest text-gray-500 mb-4">Recent Incidents</h2>
        {rec.length === 0 ? (
          <p className="text-gray-600 text-sm">No recent incidents.</p>
        ) : (
          <div className="space-y-2">
            {rec.map((inc) => (
              <div
                key={inc.id}
                className="flex items-center gap-3 px-3 py-2 rounded bg-gray-800/50 border border-gray-800"
              >
                <span className={`flex-shrink-0 w-2 h-2 rounded-full ${SEV_DOT[inc.severity] || "bg-gray-500"}`} />
                <span className="flex-1 text-sm text-gray-300 truncate">{inc.title}</span>
                <span className={`text-xs font-mono ${SEV_TEXT[inc.severity] || "text-gray-400"}`}>
                  {Math.round(inc.risk_score)}/100
                </span>
                <span className="text-xs text-gray-600 w-20 text-right">
                  {inc.created_at
                    ? new Date(inc.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
                    : "–"}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
