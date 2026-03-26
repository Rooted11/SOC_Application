import { useEffect, useState } from "react";
import { api } from "../services/api";

export default function UsersRoles({ showAlert }) {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [showUsers, setShowUsers] = useState(true);
  const [showRoles, setShowRoles] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let active = true;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [u, r] = await Promise.all([api.getUsers(), api.getRoles()]);
        if (!active) return;
        setUsers(u);
        setRoles(r);
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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <SectionTitle title="Users" />
        <button
          type="button"
          onClick={() => setShowUsers((v) => !v)}
          className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-200 hover:border-cyan-400"
        >
          {showUsers ? "Hide" : "Show"}
        </button>
      </div>
      {showUsers && (
      <DataCard loading={loading} error={error}>
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-slate-400">
              <th className="px-3 py-2 text-left">Username</th>
              <th className="px-3 py-2 text-left">Roles</th>
              <th className="px-3 py-2 text-left">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {users.map((u) => (
              <tr key={u.id} className="text-slate-200">
                <td className="px-3 py-2">{u.username}</td>
                <td className="px-3 py-2 text-slate-400">{u.roles.join(", ") || "—"}</td>
                <td className="px-3 py-2">
                  <span className={`rounded-full px-2 py-1 text-xs ${u.is_active ? "bg-emerald-500/20 text-emerald-200" : "bg-slate-700 text-slate-300"}`}>
                    {u.is_active ? "Active" : "Disabled"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataCard>
      )}

      <div className="flex items-center justify-between">
        <SectionTitle title="Roles" />
        <button
          type="button"
          onClick={() => setShowRoles((v) => !v)}
          className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-200 hover:border-cyan-400"
        >
          {showRoles ? "Hide" : "Show"}
        </button>
      </div>
      {showRoles && (
      <DataCard loading={loading} error={error}>
        <ul className="divide-y divide-slate-800">
          {roles.map((r) => (
            <li key={r.id} className="py-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-slate-200 font-semibold">{r.name}</div>
                  <div className="text-xs text-slate-500">{r.description}</div>
                </div>
                <span className="text-[10px] uppercase tracking-[0.25em] text-slate-500">{r.built_in ? "Built-in" : ""}</span>
              </div>
              <div className="mt-2 text-xs text-slate-400">
                Permissions: {r.permissions.join(", ")}
              </div>
            </li>
            ))}
          </ul>
      </DataCard>
      )}
    </div>
  );
}

function SectionTitle({ title }) {
  return <h2 className="text-lg font-semibold text-white">{title}</h2>;
}

function DataCard({ loading, error, children }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 shadow">
      {loading ? <div className="text-slate-400 text-sm">Loading…</div> : error ? <div className="text-rose-300 text-sm">{error}</div> : children}
    </div>
  );
}
