import { useEffect, useState } from "react";
import { api } from "../services/api";

export default function Alarms({ showAlert }) {
  const [alarms, setAlarms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [form, setForm] = useState({ source: "", message: "", severity: "medium" });

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getAlarms();
      setAlarms(data);
    } catch (err) {
      setError(err.message);
      showAlert?.(err.message, "error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function handleCreate(e) {
    e.preventDefault();
    try {
      await api.createAlarm(form);
      setForm({ source: "", message: "", severity: "medium" });
      showAlert?.("Alarm created", "success");
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  async function handleAck(id) {
    try {
      await api.ackAlarm(id);
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-white">Alarms</h2>

      <form onSubmit={handleCreate} className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-3">
        <div className="text-sm text-slate-300 font-semibold">Raise Alarm</div>
        <div className="grid gap-3 md:grid-cols-3">
          <input
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            placeholder="Source"
            value={form.source}
            onChange={(e) => setForm({ ...form, source: e.target.value })}
            required
          />
          <select
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            value={form.severity}
            onChange={(e) => setForm({ ...form, severity: e.target.value })}
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <input
            className="md:col-span-3 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            placeholder="Message"
            value={form.message}
            onChange={(e) => setForm({ ...form, message: e.target.value })}
            required
          />
        </div>
        <button
          type="submit"
          className="self-start rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
        >
          Create Alarm
        </button>
      </form>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
        {loading ? (
          <div className="text-slate-400 text-sm">Loading…</div>
        ) : error ? (
          <div className="text-rose-300 text-sm">{error}</div>
        ) : (
          <div className="space-y-3">
            {alarms.map((a) => (
              <div key={a.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-white font-semibold">{a.source}</div>
                    <div className="text-xs text-slate-500">{a.severity}</div>
                  </div>
                  <button
                    onClick={() => handleAck(a.id)}
                    className={`rounded-full px-3 py-1 text-[11px] border ${
                      a.status === "acknowledged"
                        ? "border-emerald-400/60 bg-emerald-500/15 text-emerald-100"
                        : "border-amber-400/60 bg-amber-500/15 text-amber-100"
                    }`}
                  >
                    {a.status === "acknowledged" ? "Acknowledged" : "Ack"}
                  </button>
                </div>
                <div className="mt-1 text-xs text-slate-400">{a.message}</div>
                <div className="mt-1 text-[11px] text-slate-500">
                  Created: {new Date(a.created_at).toLocaleString()}
                  {a.acknowledged_at ? ` • Ack at ${new Date(a.acknowledged_at).toLocaleString()}` : ""}
                </div>
              </div>
            ))}
            {alarms.length === 0 && <div className="text-slate-400 text-sm">No alarms.</div>}
          </div>
        )}
      </div>
    </div>
  );
}
