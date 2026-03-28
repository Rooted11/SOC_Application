import { useEffect, useState } from "react";
import { api } from "../services/api";

export default function IntegrationsPage({ showAlert }) {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState({
    name: "",
    type: "email",
  });
  const [showForm, setShowForm] = useState(true);
  const [showList, setShowList] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getIntegrations();
      setItems(data);
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
      await api.createIntegration({ name: form.name, type: form.type, enabled: true, config: {} });
      setForm({ name: "", type: "email" });
      showAlert?.("Integration created", "success");
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  async function toggle(item) {
    try {
      await api.updateIntegration(item.id, { enabled: !item.enabled });
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Integrations</h2>
        <div className="flex gap-2 text-xs">
          <button
            type="button"
            onClick={() => setShowForm((v) => !v)}
            className="rounded-full border border-slate-700 px-3 py-1 text-slate-200 hover:border-cyan-400"
          >
            {showForm ? "Hide Form" : "Show Form"}
          </button>
          <button
            type="button"
            onClick={() => setShowList((v) => !v)}
            className="rounded-full border border-slate-700 px-3 py-1 text-slate-200 hover:border-cyan-400"
          >
            {showList ? "Hide List" : "Show List"}
          </button>
        </div>
      </div>
      {showForm && (
      <form onSubmit={handleCreate} className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-3">
        <div className="text-sm text-slate-300 font-semibold">Add Integration</div>
        <div className="grid gap-3 md:grid-cols-2">
          <input
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            placeholder="Name"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            required
          />
          <select
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            value={form.type}
            onChange={(e) => setForm({ ...form, type: e.target.value })}
          >
            <option value="email">Email</option>
            <option value="slack">Slack</option>
            <option value="webhook">Webhook</option>
            <option value="syslog">Syslog</option>
            <option value="pagerduty">PagerDuty</option>
          </select>
        </div>
        <button
          type="submit"
          className="self-start rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
        >
          Create Integration
        </button>
      </form>
      )}
      {showList && (
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
        {loading ? (
          <div className="text-slate-400 text-sm">Loading…</div>
        ) : error ? (
          <div className="text-rose-300 text-sm">{error}</div>
        ) : (
          <div className="grid gap-3">
            {items.map((i) => (
              <div key={i.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="flex items-center justify-between">
                  <div className="text-white font-semibold">{i.name}</div>
                  <span className="text-xs text-slate-500">{i.type}</span>
                  <button
                    onClick={() => toggle(i)}
                    className={`rounded-full px-3 py-1 text-[11px] border ${
                      i.enabled
                        ? "border-emerald-400/60 bg-emerald-500/15 text-emerald-100"
                        : "border-slate-700 bg-slate-800 text-slate-300"
                    }`}
                  >
                    {i.enabled ? "Enabled" : "Disabled"}
                  </button>
                </div>
              </div>
            ))}
            {items.length === 0 && <div className="text-slate-400 text-sm">No integrations configured.</div>}
          </div>
        )}
      </div>
      )}
    </div>
  );
}
