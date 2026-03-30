/**
 * Alarms — Full alarm management console.
 * Live-updating alarm feed with severity filtering, bulk actions,
 * expandable detail cards, and visual urgency indicators.
 */

import { useEffect, useState, useCallback } from "react";
import { api } from "../services/api";

const SEV = {
  critical: {
    border: "border-red-500/40",
    bg: "bg-red-950/30",
    text: "text-red-400",
    badge: "bg-red-500/20 text-red-400 border-red-500/30",
    dot: "bg-red-500",
    glow: "shadow-[0_0_15px_rgba(239,68,68,0.15)]",
    label: "CRITICAL",
  },
  high: {
    border: "border-orange-500/40",
    bg: "bg-orange-950/20",
    text: "text-orange-400",
    badge: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    dot: "bg-orange-500",
    glow: "shadow-[0_0_10px_rgba(249,115,22,0.1)]",
    label: "HIGH",
  },
  medium: {
    border: "border-yellow-500/30",
    bg: "bg-yellow-950/15",
    text: "text-yellow-400",
    badge: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25",
    dot: "bg-yellow-500",
    glow: "",
    label: "MEDIUM",
  },
  low: {
    border: "border-blue-500/30",
    bg: "bg-blue-950/15",
    text: "text-blue-400",
    badge: "bg-blue-500/15 text-blue-400 border-blue-500/25",
    dot: "bg-blue-500",
    glow: "",
    label: "LOW",
  },
};

function getSev(severity) {
  return SEV[severity] || SEV.medium;
}

function timeAgo(dateStr) {
  if (!dateStr) return "";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function Alarms({ lastUpdated, showAlert }) {
  const [alarms, setAlarms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [filterSev, setFilterSev] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [form, setForm] = useState({ source: "", message: "", severity: "medium" });
  const [showForm, setShowForm] = useState(false);

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data = await api.getAlarms();
      setAlarms(Array.isArray(data) ? data : []);
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

  async function handleCreate(e) {
    e.preventDefault();
    try {
      await api.createAlarm(form);
      setForm({ source: "", message: "", severity: "medium" });
      setShowForm(false);
      showAlert?.("Alarm created", "success");
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  async function handleAck(id) {
    try {
      await api.ackAlarm(id);
      showAlert?.("Alarm acknowledged", "success");
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  async function handleAckAll() {
    const unacked = alarms.filter((a) => a.status !== "acknowledged");
    for (const a of unacked) {
      try { await api.ackAlarm(a.id); } catch { /* continue */ }
    }
    showAlert?.(`${unacked.length} alarms acknowledged`, "success");
    refresh();
  }

  const filtered = alarms.filter((a) => {
    if (filterSev && a.severity !== filterSev) return false;
    if (filterStatus === "unacked" && a.status === "acknowledged") return false;
    if (filterStatus === "acked" && a.status !== "acknowledged") return false;
    return true;
  });

  const unackedCount = alarms.filter((a) => a.status !== "acknowledged").length;
  const critCount = alarms.filter((a) => a.severity === "critical" && a.status !== "acknowledged").length;
  const highCount = alarms.filter((a) => a.severity === "high" && a.status !== "acknowledged").length;

  return (
    <div className="space-y-4">
      {/* ── Header with stats ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500">Total Alarms</div>
          <div className="text-3xl font-bold text-white mt-1">{alarms.length}</div>
        </div>
        <div className={`rounded-xl border p-4 ${unackedCount > 0 ? "border-amber-500/30 bg-amber-950/20" : "border-slate-800 bg-slate-900/60"}`}>
          <div className="text-[10px] uppercase tracking-[0.25em] text-amber-400">Unacknowledged</div>
          <div className={`text-3xl font-bold mt-1 ${unackedCount > 0 ? "text-amber-400" : "text-white"}`}>{unackedCount}</div>
        </div>
        <div className={`rounded-xl border p-4 ${critCount > 0 ? "border-red-500/30 bg-red-950/20" : "border-slate-800 bg-slate-900/60"}`}>
          <div className="text-[10px] uppercase tracking-[0.25em] text-red-400">Critical Active</div>
          <div className={`text-3xl font-bold mt-1 ${critCount > 0 ? "text-red-400 animate-pulse" : "text-white"}`}>{critCount}</div>
        </div>
        <div className={`rounded-xl border p-4 ${highCount > 0 ? "border-orange-500/30 bg-orange-950/20" : "border-slate-800 bg-slate-900/60"}`}>
          <div className="text-[10px] uppercase tracking-[0.25em] text-orange-400">High Active</div>
          <div className={`text-3xl font-bold mt-1 ${highCount > 0 ? "text-orange-400" : "text-white"}`}>{highCount}</div>
        </div>
      </div>

      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* Severity filter */}
        {["", "critical", "high", "medium", "low"].map((s) => (
          <button
            key={s || "all"}
            onClick={() => setFilterSev(s)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
              filterSev === s
                ? s ? `${getSev(s).badge} border` : "bg-cyan-500/15 border-cyan-500/40 text-cyan-300"
                : "bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600"
            }`}
          >
            {s ? getSev(s).label : "All"}
          </button>
        ))}

        <div className="w-px h-5 bg-slate-700" />

        {/* Status filter */}
        {[
          { v: "", l: "Any Status" },
          { v: "unacked", l: "Unacked" },
          { v: "acked", l: "Acknowledged" },
        ].map(({ v, l }) => (
          <button
            key={v || "any"}
            onClick={() => setFilterStatus(v)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
              filterStatus === v
                ? "bg-slate-800 border-slate-600 text-white"
                : "bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600"
            }`}
          >
            {l}
          </button>
        ))}

        <div className="flex-1" />

        {/* Actions */}
        {unackedCount > 0 && (
          <button
            onClick={handleAckAll}
            className="text-xs px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-950/30 text-emerald-400 hover:bg-emerald-950/50 transition-colors"
          >
            Ack All ({unackedCount})
          </button>
        )}

        <button
          onClick={() => setShowForm((v) => !v)}
          className="text-xs px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/30 text-cyan-400 hover:bg-cyan-950/50 transition-colors"
        >
          {showForm ? "Cancel" : "+ Raise Alarm"}
        </button>

        <button
          onClick={() => refresh()}
          className="text-xs px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-slate-400 hover:border-slate-600 transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* ── Create form ──────────────────────────────────────────────── */}
      {showForm && (
        <form
          onSubmit={handleCreate}
          className="rounded-xl border border-cyan-500/20 bg-slate-900/80 p-4 space-y-3"
        >
          <div className="text-xs uppercase tracking-[0.2em] text-cyan-400 font-medium">Raise New Alarm</div>
          <div className="grid gap-3 sm:grid-cols-3">
            <input
              className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
              placeholder="Source (e.g. firewall, IDS, manual)"
              value={form.source}
              onChange={(e) => setForm({ ...form, source: e.target.value })}
              required
            />
            <select
              className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white focus:border-cyan-500/50 focus:outline-none"
              value={form.severity}
              onChange={(e) => setForm({ ...form, severity: e.target.value })}
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <input
              className="sm:col-span-3 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
              placeholder="Alarm message..."
              value={form.message}
              onChange={(e) => setForm({ ...form, message: e.target.value })}
              required
            />
          </div>
          <button
            type="submit"
            className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400 transition-colors"
          >
            Create Alarm
          </button>
        </form>
      )}

      {/* ── Alarm list ───────────────────────────────────────────────── */}
      <div className="space-y-2">
        {loading ? (
          <div className="flex items-center justify-center h-32 text-slate-500 animate-pulse">Loading alarms...</div>
        ) : filtered.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-8 text-center">
            <div className="text-2xl text-slate-600 mb-2">{filterSev || filterStatus ? "\u2A09" : "\u2714"}</div>
            <div className="text-sm text-slate-500">
              {filterSev || filterStatus ? "No alarms match the current filters" : "No alarms. All quiet."}
            </div>
          </div>
        ) : (
          filtered.map((a) => {
            const s = getSev(a.severity);
            const isExpanded = expanded === a.id;
            const isAcked = a.status === "acknowledged";

            return (
              <div
                key={a.id}
                onClick={() => setExpanded(isExpanded ? null : a.id)}
                className={`rounded-xl border transition-all duration-200 cursor-pointer ${s.border} ${isExpanded ? s.bg : "bg-slate-900/60"} ${s.glow} ${
                  !isAcked && a.severity === "critical" ? "ring-1 ring-red-500/20" : ""
                }`}
              >
                {/* Summary row */}
                <div className="flex items-center gap-3 px-4 py-3">
                  {/* Status dot */}
                  <div className="flex-shrink-0">
                    {!isAcked ? (
                      <span className={`inline-block w-2.5 h-2.5 rounded-full ${s.dot} ${
                        a.severity === "critical" ? "animate-pulse" : ""
                      }`} />
                    ) : (
                      <span className="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
                    )}
                  </div>

                  {/* Severity badge */}
                  <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold tracking-wider ${s.badge}`}>
                    {s.label}
                  </span>

                  {/* Source */}
                  <span className="text-xs text-slate-400 font-medium">{a.source}</span>

                  {/* Message preview */}
                  <span className="flex-1 text-sm text-slate-300 truncate">{a.message}</span>

                  {/* Time */}
                  <span className="text-xs text-slate-500 whitespace-nowrap">{timeAgo(a.created_at)}</span>

                  {/* Ack button */}
                  <button
                    onClick={(e) => { e.stopPropagation(); handleAck(a.id); }}
                    disabled={isAcked}
                    className={`flex-shrink-0 rounded-lg px-3 py-1 text-xs font-medium border transition-colors ${
                      isAcked
                        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 cursor-default"
                        : "border-amber-500/30 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20"
                    }`}
                  >
                    {isAcked ? "\u2714 Acked" : "Acknowledge"}
                  </button>

                  {/* Expand indicator */}
                  <span className={`text-slate-500 text-xs transition-transform ${isExpanded ? "rotate-180" : ""}`}>
                    {"\u25BC"}
                  </span>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="border-t border-slate-800/50 px-4 py-3 space-y-2 text-xs">
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <span className="text-slate-500">Alarm ID:</span>
                        <span className="text-slate-300 ml-2 font-mono">#{a.id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Status:</span>
                        <span className={`ml-2 ${isAcked ? "text-emerald-400" : "text-amber-400"}`}>
                          {isAcked ? "Acknowledged" : "Pending"}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Created:</span>
                        <span className="text-slate-300 ml-2">{a.created_at ? new Date(a.created_at).toLocaleString() : "Unknown"}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Acknowledged:</span>
                        <span className="text-slate-300 ml-2">{a.acknowledged_at ? new Date(a.acknowledged_at).toLocaleString() : "Not yet"}</span>
                      </div>
                    </div>
                    <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500 mb-1">Full Message</div>
                      <div className="text-sm text-slate-300 leading-relaxed">{a.message}</div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Footer count */}
      {filtered.length > 0 && (
        <div className="text-xs text-slate-500 text-center">
          Showing {filtered.length} of {alarms.length} alarms
          {unackedCount > 0 && <span className="text-amber-400 ml-2">({unackedCount} unacknowledged)</span>}
        </div>
      )}
    </div>
  );
}
