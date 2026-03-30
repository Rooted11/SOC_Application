/**
 * NotificationsPage — Notification channel management + live activity feed.
 * Shows a real-time feed of recent incidents, alarms, and system events
 * alongside the notification channel configuration.
 */

import { useEffect, useState, useCallback } from "react";
import { api } from "../services/api";

const CHANNEL_ICONS = {
  email: "\u2709",
  slack: "#",
  webhook: "\u21C4",
  syslog: "\u25A3",
  pagerduty: "\u260E",
};

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

const SEV_STYLE = {
  critical: "border-red-500/30 bg-red-950/20 text-red-400",
  high: "border-orange-500/30 bg-orange-950/20 text-orange-400",
  medium: "border-yellow-500/30 bg-yellow-950/20 text-yellow-400",
  low: "border-blue-500/30 bg-blue-950/20 text-blue-400",
  info: "border-slate-700 bg-slate-800/40 text-slate-400",
};

export default function NotificationsPage({ showAlert }) {
  const [channels, setChannels] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [alarms, setAlarms] = useState([]);
  const [form, setForm] = useState({ name: "", channel: "email" });
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [chData, incData, almData] = await Promise.all([
        api.getNotificationChannels().catch(() => []),
        api.getIncidents({ limit: 15 }).catch(() => ({ incidents: [] })),
        api.getAlarms().catch(() => []),
      ]);
      setChannels(chData);
      setIncidents(incData.incidents || []);
      setAlarms(Array.isArray(almData) ? almData : []);
    } catch (err) {
      showAlert?.(err.message, "error");
    } finally {
      setLoading(false);
    }
  }, [showAlert]);

  useEffect(() => { refresh(); }, [refresh]);

  // Auto-refresh
  useEffect(() => {
    const timer = setInterval(refresh, 15000);
    return () => clearInterval(timer);
  }, [refresh]);

  async function handleCreate(e) {
    e.preventDefault();
    try {
      await api.createNotificationChannel({ name: form.name, channel: form.channel, enabled: true, config: {} });
      setForm({ name: "", channel: "email" });
      setShowForm(false);
      showAlert?.("Notification channel created", "success");
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  async function toggle(ch) {
    try {
      await api.updateNotificationChannel(ch.id, { enabled: !ch.enabled });
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  async function remove(ch) {
    try {
      await api.deleteNotificationChannel(ch.id);
      showAlert?.(`Channel "${ch.name}" removed`, "success");
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  // Merge incidents and alarms into a unified activity feed, sorted by time
  const feed = [
    ...incidents.map((i) => ({
      type: "incident",
      id: `inc-${i.id}`,
      title: i.title,
      severity: i.severity,
      status: i.status,
      time: i.created_at,
    })),
    ...alarms.map((a) => ({
      type: "alarm",
      id: `alm-${a.id}`,
      title: a.message,
      severity: a.severity,
      status: a.status === "acknowledged" ? "acked" : "pending",
      time: a.created_at,
    })),
  ].sort((a, b) => new Date(b.time) - new Date(a.time)).slice(0, 20);

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_400px] gap-5">
        {/* ── Left: Channels ──────────────────────────────────────────── */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Notification Channels</h2>
              <p className="text-xs text-slate-500 mt-0.5">Configure where alerts are dispatched</p>
            </div>
            <button
              onClick={() => setShowForm((v) => !v)}
              className="text-xs px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/30 text-cyan-400 hover:bg-cyan-950/50 transition-colors"
            >
              {showForm ? "Cancel" : "+ Add Channel"}
            </button>
          </div>

          {showForm && (
            <form onSubmit={handleCreate} className="rounded-xl border border-cyan-500/20 bg-slate-900/80 p-4 space-y-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <input
                  className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                  placeholder="Channel name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  required
                />
                <select
                  className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white focus:border-cyan-500/50 focus:outline-none"
                  value={form.channel}
                  onChange={(e) => setForm({ ...form, channel: e.target.value })}
                >
                  <option value="email">Email</option>
                  <option value="slack">Slack</option>
                  <option value="webhook">Webhook</option>
                  <option value="syslog">Syslog</option>
                  <option value="pagerduty">PagerDuty</option>
                </select>
              </div>
              <button type="submit" className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400 transition-colors">
                Create Channel
              </button>
            </form>
          )}

          {loading ? (
            <div className="text-slate-500 text-sm animate-pulse py-8 text-center">Loading channels...</div>
          ) : channels.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-8 text-center">
              <div className="text-2xl text-slate-600 mb-2">{"\u266A"}</div>
              <div className="text-sm text-slate-500">No notification channels configured</div>
              <div className="text-xs text-slate-600 mt-1">Add a channel to receive alerts via email, Slack, or webhook</div>
            </div>
          ) : (
            <div className="space-y-2">
              {channels.map((ch) => (
                <div
                  key={ch.id}
                  className={`rounded-xl border p-4 flex items-center gap-4 transition-colors ${
                    ch.enabled
                      ? "border-emerald-500/20 bg-slate-900/60"
                      : "border-slate-800 bg-slate-900/40 opacity-60"
                  }`}
                >
                  {/* Icon */}
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg ${
                    ch.enabled ? "bg-emerald-500/10 text-emerald-400" : "bg-slate-800 text-slate-500"
                  }`}>
                    {CHANNEL_ICONS[ch.channel] || "\u2B58"}
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-white">{ch.name}</div>
                    <div className="text-xs text-slate-500 mt-0.5">{ch.channel.toUpperCase()}</div>
                  </div>

                  {/* Toggle */}
                  <button
                    onClick={() => toggle(ch)}
                    className={`rounded-full w-10 h-5 relative transition-colors ${
                      ch.enabled ? "bg-emerald-500" : "bg-slate-700"
                    }`}
                  >
                    <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${
                      ch.enabled ? "left-5" : "left-0.5"
                    }`} />
                  </button>

                  {/* Delete */}
                  <button
                    onClick={() => remove(ch)}
                    className="text-slate-500 hover:text-red-400 transition-colors text-sm"
                    title="Remove channel"
                  >
                    {"\u2716"}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Right: Activity feed ────────────────────────────────────── */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center gap-2 mb-4">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <h3 className="text-sm font-semibold text-white">Live Activity Feed</h3>
            <span className="text-[10px] text-slate-500 ml-auto uppercase tracking-wider">Auto-updating</span>
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto">
            {feed.length === 0 ? (
              <div className="text-sm text-slate-500 text-center py-8">No recent activity</div>
            ) : (
              feed.map((item) => (
                <div
                  key={item.id}
                  className={`rounded-lg border px-3 py-2.5 ${SEV_STYLE[item.severity] || SEV_STYLE.info}`}
                >
                  <div className="flex items-start gap-2">
                    <span className="text-xs mt-0.5">
                      {item.type === "incident" ? "\u26A0" : "\u23F0"}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-medium truncate">{item.title}</div>
                      <div className="flex items-center gap-2 mt-1 text-[10px] opacity-70">
                        <span className="uppercase">{item.type}</span>
                        <span>{"\u00B7"}</span>
                        <span>{item.severity}</span>
                        <span>{"\u00B7"}</span>
                        <span>{item.status}</span>
                        <span className="ml-auto">{timeAgo(item.time)}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
