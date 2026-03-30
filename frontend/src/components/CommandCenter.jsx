/**
 * CommandCenter — SOC Overview with fully clickable metrics.
 * Every card, metric, incident row, and asset navigates to the relevant page.
 */

import { useState, useEffect } from "react";
import { api } from "../services/api";

const POSTURE_COLOR = (score) => {
  if (score >= 80) return { ring: "border-green-500",  text: "text-green-400",  label: "HEALTHY",   bg: "bg-green-500", glow: "shadow-[0_0_30px_rgba(34,197,94,0.2)]" };
  if (score >= 60) return { ring: "border-yellow-500", text: "text-yellow-400", label: "ELEVATED",  bg: "bg-yellow-500", glow: "shadow-[0_0_30px_rgba(234,179,8,0.2)]" };
  if (score >= 40) return { ring: "border-orange-500", text: "text-orange-400", label: "DEGRADED",  bg: "bg-orange-500", glow: "shadow-[0_0_30px_rgba(249,115,22,0.2)]" };
  return              { ring: "border-red-500",    text: "text-red-400",    label: "CRITICAL",  bg: "bg-red-500", glow: "shadow-[0_0_30px_rgba(239,68,68,0.25)]" };
};

const SEV_DOT = { critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500" };
const SEV_TEXT = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-blue-400" };
const SEV_BORDER = { critical: "border-l-red-500", high: "border-l-orange-500", medium: "border-l-yellow-500", low: "border-l-blue-500" };

function MetricCard({ label, value, sub, accent = "border-slate-800", valueClass = "text-white", onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`text-left bg-slate-900/70 border rounded-xl p-4 transition-all hover:scale-[1.02] hover:shadow-lg ${accent} ${onClick ? "cursor-pointer hover:border-cyan-500/30" : ""}`}
    >
      <div className="text-[10px] text-slate-500 uppercase tracking-[0.25em] mb-1">{label}</div>
      <div className={`text-3xl font-bold ${valueClass}`}>{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </button>
  );
}

function PostureGauge({ score }) {
  const c = POSTURE_COLOR(score);
  const radius = 52;
  const circ = 2 * Math.PI * radius;
  const dash = (score / 100) * circ;

  return (
    <div className={`bg-slate-900/70 border-2 ${c.ring} rounded-2xl p-6 flex flex-col items-center justify-center ${c.glow}`}>
      <div className="text-[10px] text-slate-500 uppercase tracking-[0.25em] mb-4">Security Posture</div>
      <div className="relative">
        <svg width="130" height="130" className="-rotate-90">
          <circle cx="65" cy="65" r={radius} fill="none" stroke="#1e293b" strokeWidth="10" />
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
          <span className="text-xs text-slate-500">/100</span>
        </div>
      </div>
      <div className={`mt-3 text-sm font-semibold tracking-[0.2em] ${c.text}`}>{c.label}</div>
    </div>
  );
}

function MiniBar({ label, count, max, colorClass, onClick }) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-2 text-xs w-full hover:bg-slate-800/30 rounded-lg px-1 py-0.5 transition-colors text-left"
    >
      <span className="w-32 truncate text-slate-400 text-right">{label}</span>
      <div className="flex-1 h-2 bg-slate-800 rounded overflow-hidden">
        <div className={`h-full rounded ${colorClass}`} style={{ width: `${pct}%`, transition: "width 0.5s ease" }} />
      </div>
      <span className="w-8 text-right text-slate-500 font-mono">{count}</span>
    </button>
  );
}

export default function CommandCenter({ lastUpdated, showAlert, setPage }) {
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api.getOverview()
      .then(setOverview)
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setLoading(false));
  }, [lastUpdated]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-600 animate-pulse">
        <span className="w-2 h-2 rounded-full bg-cyan-500 animate-ping mr-3" />
        Loading command center...
      </div>
    );
  }
  if (!overview) return null;

  const h = overview.headline || {};
  const res = overview.response || {};
  const ast = overview.assets || {};
  const int = overview.intel || {};
  const evt = overview.top_event_types || [];
  const hot = overview.hot_assets || [];
  const rec = overview.recent_incidents || [];
  const maxEvt = Math.max(1, ...evt.map((e) => e.count));
  const maxHot = Math.max(1, ...hot.map((a) => a.count));

  return (
    <div className="space-y-5">
      {/* ── Row 1: Posture + headline stats ──────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="md:col-span-1">
          <PostureGauge score={h.posture_score ?? 50} />
        </div>
        <div className="md:col-span-4 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <MetricCard
            label="Open Incidents"
            value={h.open_incidents ?? 0}
            sub={`${h.critical_open ?? 0} critical`}
            accent={h.critical_open > 0 ? "border-red-800/60" : "border-slate-800"}
            valueClass={h.critical_open > 0 ? "text-red-400" : "text-white"}
            onClick={() => setPage("incidents")}
          />
          <MetricCard
            label="Logs (24h)"
            value={(h.recent_logs_24h ?? 0).toLocaleString()}
            sub={`${h.recent_anomalies_24h ?? 0} anomalous`}
            accent="border-slate-800"
            onClick={() => setPage("feed")}
          />
          <MetricCard
            label="Containment Rate"
            value={`${res.containment_rate_pct ?? 0}%`}
            sub={`${res.resolved_incidents ?? 0} resolved`}
            accent="border-green-900/60"
            valueClass="text-green-400"
            onClick={() => setPage("incidents")}
          />
          <MetricCard
            label="Automation Rate"
            value={`${res.automation_rate_pct ?? 0}%`}
            sub="Playbooks executed"
            accent="border-blue-900/60"
            valueClass="text-blue-400"
            onClick={() => setPage("playbooks")}
          />
        </div>
      </div>

      {/* ── Row 2: Response + Asset + Intel ───────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Response metrics */}
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <h2 className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-3">Response Metrics</h2>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Avg Resolution</span>
              <span className="text-slate-200 font-mono">{res.avg_resolution_hours > 0 ? `${res.avg_resolution_hours.toFixed(1)}h` : "\u2013"}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Critical Open</span>
              <span className={`font-mono font-bold ${h.critical_open > 0 ? "text-red-400" : "text-green-400"}`}>{h.critical_open ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">High Open</span>
              <span className={`font-mono font-bold ${h.high_open > 0 ? "text-orange-400" : "text-green-400"}`}>{h.high_open ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Anomaly Rate (24h)</span>
              <span className="text-slate-200 font-mono">
                {h.recent_logs_24h > 0 ? `${((h.recent_anomalies_24h / h.recent_logs_24h) * 100).toFixed(1)}%` : "0%"}
              </span>
            </div>
          </div>
        </div>

        {/* Asset status - clickable */}
        <button
          type="button"
          onClick={() => setPage("assets")}
          className="text-left bg-slate-900/70 border border-slate-800 rounded-xl p-4 hover:border-cyan-500/30 transition-all hover:shadow-lg"
        >
          <h2 className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-3">Asset Status</h2>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Total Assets</span>
              <span className="text-slate-200 font-mono">{ast.total ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Critical Assets</span>
              <span className="text-orange-400 font-mono font-bold">{ast.critical ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Isolated</span>
              <span className={`font-mono font-bold ${ast.isolated > 0 ? "text-red-400" : "text-green-400"}`}>{ast.isolated ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Isolation Rate</span>
              <span className="text-slate-200 font-mono">{ast.isolation_rate_pct ?? 0}%</span>
            </div>
          </div>
        </button>

        {/* Threat intel - clickable */}
        <button
          type="button"
          onClick={() => setPage("threats")}
          className="text-left bg-slate-900/70 border border-slate-800 rounded-xl p-4 hover:border-cyan-500/30 transition-all hover:shadow-lg"
        >
          <h2 className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-3">Threat Intelligence</h2>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Active IOCs</span>
              <span className="text-slate-200 font-mono">{int.active_iocs ?? 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Critical / High IOCs</span>
              <span className={`font-mono font-bold ${int.critical_iocs > 0 ? "text-red-400" : "text-green-400"}`}>{int.critical_iocs ?? 0}</span>
            </div>
          </div>
        </button>
      </div>

      {/* ── Row 3: Top event types + Hot assets ──────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <h2 className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-4">Top Event Types</h2>
          {evt.length === 0 ? (
            <p className="text-slate-600 text-sm">No data yet.</p>
          ) : (
            <div className="space-y-2">
              {evt.map((e) => (
                <MiniBar
                  key={e.event_type}
                  label={e.event_type}
                  count={e.count}
                  max={maxEvt}
                  colorClass="bg-cyan-500/70"
                  onClick={() => setPage("feed")}
                />
              ))}
            </div>
          )}
        </div>

        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <h2 className="text-[10px] uppercase tracking-[0.25em] text-slate-500 mb-4">Most Active Assets</h2>
          {hot.length === 0 ? (
            <p className="text-slate-600 text-sm">No incident data yet.</p>
          ) : (
            <div className="space-y-2">
              {hot.map((a) => (
                <MiniBar
                  key={a.hostname}
                  label={a.hostname}
                  count={a.count}
                  max={maxHot}
                  colorClass="bg-orange-500/70"
                  onClick={() => setPage("assets")}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Row 4: Recent incidents ──────────────────────────────────── */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-[10px] uppercase tracking-[0.25em] text-slate-500">Recent Incidents</h2>
          <button
            onClick={() => setPage("incidents")}
            className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            View all &rarr;
          </button>
        </div>
        {rec.length === 0 ? (
          <p className="text-slate-600 text-sm">No recent incidents.</p>
        ) : (
          <div className="space-y-2">
            {rec.map((inc) => (
              <button
                key={inc.id}
                type="button"
                onClick={() => setPage("incidents")}
                className={`flex items-center gap-3 w-full text-left px-3 py-2.5 rounded-lg bg-slate-800/40 border border-slate-800 border-l-2 ${SEV_BORDER[inc.severity] || ""} hover:bg-slate-800/70 hover:border-cyan-500/20 transition-all`}
              >
                <span className={`flex-shrink-0 w-2 h-2 rounded-full ${SEV_DOT[inc.severity] || "bg-slate-500"} ${
                  inc.severity === "critical" ? "animate-pulse" : ""
                }`} />
                <span className="flex-1 text-sm text-slate-300 truncate">{inc.title}</span>
                <span className={`text-xs font-mono ${SEV_TEXT[inc.severity] || "text-slate-400"}`}>
                  {Math.round(inc.risk_score)}/100
                </span>
                <span className="text-xs text-slate-600 w-20 text-right">
                  {inc.created_at ? new Date(inc.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "\u2013"}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
