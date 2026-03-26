import { useEffect, useState } from "react";
import { api } from "../services/api";

export default function Detections({ showAlert }) {
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState({
    name: "",
    description: "",
    rule_type: "rule",
    severity: "medium",
  });
  const [showForm, setShowForm] = useState(true);
  const [showList, setShowList] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDetections();
      setRules(data);
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
      await api.createDetection({
        name: form.name,
        description: form.description,
        rule_type: form.rule_type,
        severity: form.severity,
        enabled: true,
        conditions: {},
        suppression: {},
      });
      showAlert?.("Detection rule created", "success");
      setForm({ name: "", description: "", rule_type: "rule", severity: "medium" });
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  async function toggleRule(rule) {
    try {
      await api.updateDetection(rule.id, { enabled: !rule.enabled });
      refresh();
    } catch (err) {
      showAlert?.(err.message, "error");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Detection Rules</h2>
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
        <div className="text-sm text-slate-300 font-semibold">Add Rule</div>
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
            value={form.rule_type}
            onChange={(e) => setForm({ ...form, rule_type: e.target.value })}
          >
            <option value="rule">Rule</option>
            <option value="threshold">Threshold</option>
            <option value="ioc">IOC</option>
            <option value="correlation">Correlation</option>
          </select>
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
            className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            placeholder="Description"
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
        </div>
        <button
          type="submit"
          className="self-start rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
        >
          Create Rule
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
            {rules.map((r) => (
              <div key={r.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-white font-semibold">{r.name}</div>
                    <div className="text-xs text-slate-500">{r.rule_type}</div>
                  </div>
                  <button
                    onClick={() => toggleRule(r)}
                    className={`rounded-full px-3 py-1 text-[11px] border ${
                      r.enabled
                        ? "border-emerald-400/60 bg-emerald-500/15 text-emerald-100"
                        : "border-slate-700 bg-slate-800 text-slate-300"
                    }`}
                  >
                    {r.enabled ? "Enabled" : "Disabled"}
                  </button>
                </div>
                <div className="mt-1 text-xs text-slate-400">{r.description}</div>
                <div className="mt-2 text-xs text-slate-500">Severity: {r.severity}</div>
              </div>
            ))}
            {rules.length === 0 && <div className="text-slate-400 text-sm">No rules yet.</div>}
          </div>
        )}
      </div>
      )}
    </div>
  );
}
