import { useEffect, useState } from "react";
import { api } from "../services/api";

export default function SettingsPage({ showAlert }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        setLoading(true);
        const res = await api.getSettings();
        if (!active) return;
        setData(res);
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
      <h2 className="text-lg font-semibold text-white">Platform Settings</h2>
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Organization" loading={loading} error={error}>
          {data && (
            <div className="text-sm text-slate-300 space-y-1">
              <div>Org: {data.org.org_name}</div>
              <div>Timezone: {data.org.timezone}</div>
              <div>Retention: {data.org.retention_days} days</div>
            </div>
          )}
        </Card>
        <Card title="AI" loading={loading} error={error}>
          {data && (
            <div className="text-sm text-slate-300 space-y-1">
              <div>Provider: {data.ai.provider}</div>
              <div>Model: {data.ai.model}</div>
              <div>Status: {data.ai.enabled ? "Enabled" : "Disabled"}</div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function Card({ title, loading, error, children }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-slate-200 font-semibold mb-2">{title}</div>
      {loading ? <div className="text-slate-400 text-sm">Loading…</div> : error ? <div className="text-rose-300 text-sm">{error}</div> : children}
    </div>
  );
}
