/**
 * AssetInventory — Internal asset management view
 * Shows all known assets, their criticality, isolation status,
 * and allows analysts to trigger isolation directly.
 */

import { useState, useEffect } from "react";
import { api } from "../services/api";

const CRIT_CONFIG = {
  critical: { badge: "bg-red-900/50 border-red-700 text-red-400",    dot: "bg-red-500",    order: 0 },
  high:     { badge: "bg-orange-900/50 border-orange-700 text-orange-400", dot: "bg-orange-500", order: 1 },
  medium:   { badge: "bg-yellow-900/50 border-yellow-700 text-yellow-400", dot: "bg-yellow-500", order: 2 },
  low:      { badge: "bg-blue-900/50 border-blue-700 text-blue-400",  dot: "bg-blue-500",   order: 3 },
};

const TYPE_ICON = {
  server:      "▪",
  workstation: "▫",
  network:     "◈",
  user:        "◉",
};

export default function AssetInventory({ lastUpdated, showAlert }) {
  const [assets,  setAssets]  = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterCrit, setFilterCrit] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterDept, setFilterDept] = useState("");
  const [search,     setSearch]     = useState("");
  const [createForm, setCreateForm] = useState({
    hostname: "",
    ip_address: "",
    asset_type: "server",
    department: "",
    criticality: "medium",
  });
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [editForm, setEditForm] = useState({ department: "", criticality: "medium" });
  const [savingEdit, setSavingEdit] = useState(false);
  const [isolatingId, setIsolatingId] = useState(null);

  const fetchAssets = () => {
    setLoading(true);
    api.getAssets()
      .then((r) => {
        setAssets(r.assets || []);
        setSummary(r.summary || {});
      })
      .catch((e) => showAlert(e.message, "error"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchAssets(); }, [lastUpdated]);

  const departments = [...new Set(assets.map((a) => a.department).filter(Boolean))].sort();
  const criticalities = ["critical", "high", "medium", "low"];
  const types = ["server", "workstation", "network", "user", "domain"];

  const filtered = assets.filter((a) => {
    if (filterCrit && a.criticality !== filterCrit) return false;
    if (filterType && a.asset_type  !== filterType)  return false;
    if (filterDept && a.department  !== filterDept)  return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        a.hostname?.toLowerCase().includes(q) ||
        a.ip_address?.toLowerCase().includes(q) ||
        a.department?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-5">
      {/* ── Summary bar ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-1">Total Assets</div>
          <div className="text-3xl font-bold text-gray-100">{summary?.total ?? 0}</div>
        </div>
        <div className="bg-gray-900 border border-red-900 rounded-lg p-4">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-1">Critical</div>
          <div className="text-3xl font-bold text-red-400">{summary?.critical ?? 0}</div>
          <div className="text-xs text-gray-600 mt-1">Require highest protection</div>
        </div>
        <div className="bg-gray-900 border border-orange-900 rounded-lg p-4">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-1">Isolated</div>
          <div className={`text-3xl font-bold ${summary?.isolated > 0 ? "text-orange-400" : "text-green-400"}`}>
            {summary?.isolated ?? 0}
          </div>
          <div className="text-xs text-gray-600 mt-1">Quarantined by playbook</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-1">Departments</div>
          <div className="text-3xl font-bold text-gray-100">{departments.length}</div>
        </div>
      </div>

      {/* ── Add asset ───────────────────────────────────────────────────── */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-4 space-y-3">
        <div className="flex items-center gap-3">
          <div className="text-xs uppercase tracking-[0.25em] text-gray-500">Add Asset</div>
          {creating && <div className="text-xs text-cyan-400">Saving…</div>}
        </div>
        <div className="flex flex-wrap gap-3">
          <input
            className="bg-gray-950 border border-gray-700 text-gray-200 text-xs rounded px-3 py-2 w-48"
            placeholder="Hostname"
            value={createForm.hostname}
            onChange={(e) => setCreateForm((f) => ({ ...f, hostname: e.target.value }))}
          />
          <input
            className="bg-gray-950 border border-gray-700 text-gray-200 text-xs rounded px-3 py-2 w-44"
            placeholder="IP address"
            value={createForm.ip_address}
            onChange={(e) => setCreateForm((f) => ({ ...f, ip_address: e.target.value }))}
          />
          <input
            className="bg-gray-950 border border-gray-700 text-gray-200 text-xs rounded px-3 py-2 w-40"
            placeholder="Department (optional)"
            value={createForm.department}
            onChange={(e) => setCreateForm((f) => ({ ...f, department: e.target.value }))}
          />
          <select
            className="bg-gray-950 border border-gray-700 text-gray-200 text-xs rounded px-3 py-2"
            value={createForm.asset_type}
            onChange={(e) => setCreateForm((f) => ({ ...f, asset_type: e.target.value }))}
          >
            {types.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <select
            className="bg-gray-950 border border-gray-700 text-gray-200 text-xs rounded px-3 py-2"
            value={createForm.criticality}
            onChange={(e) => setCreateForm((f) => ({ ...f, criticality: e.target.value }))}
          >
            {criticalities.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
          <button
            type="button"
            disabled={creating || !createForm.hostname || !createForm.ip_address}
            onClick={async () => {
              setCreating(true);
              try {
                await api.createAsset({
                  ...createForm,
                  department: createForm.department || null,
                });
                showAlert("Asset added.", "success");
                setCreateForm({
                  hostname: "",
                  ip_address: "",
                  asset_type: "server",
                  department: "",
                  criticality: "medium",
                });
                fetchAssets();
              } catch (e) {
                showAlert(e.message, "error");
              } finally {
                setCreating(false);
              }
            }}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold rounded px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Add
          </button>
        </div>
      </div>

      {/* ── Filters ─────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-2 items-center">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search hostname, IP, dept…"
          className="bg-gray-900 border border-gray-700 text-gray-300 text-xs rounded px-3 py-1.5 w-56 placeholder-gray-600 focus:outline-none focus:border-blue-700"
        />
        <select
          value={filterCrit}
          onChange={(e) => setFilterCrit(e.target.value)}
          className="bg-gray-900 border border-gray-700 text-gray-300 text-xs rounded px-2 py-1.5"
        >
          <option value="">All Criticalities</option>
          {criticalities.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="bg-gray-900 border border-gray-700 text-gray-300 text-xs rounded px-2 py-1.5"
        >
          <option value="">All Types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={filterDept}
          onChange={(e) => setFilterDept(e.target.value)}
          className="bg-gray-900 border border-gray-700 text-gray-300 text-xs rounded px-2 py-1.5"
        >
          <option value="">All Departments</option>
          {departments.map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
        <span className="ml-auto text-xs text-gray-600">
          {filtered.length} of {assets.length} assets
        </span>
      </div>

      {/* ── Asset grid ──────────────────────────────────────────────────── */}
      {loading ? (
        <div className="flex items-center justify-center h-32 text-gray-600 animate-pulse">
          Loading assets…
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center text-gray-600 py-16">No assets match current filters.</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((asset) => {
            const cc = CRIT_CONFIG[asset.criticality] || CRIT_CONFIG.medium;
            return (
              <div
                key={asset.id}
                className={`relative bg-gray-900 border rounded-lg p-4 ${
                  asset.is_isolated
                    ? "border-red-800 bg-red-950/10"
                    : "border-gray-800"
                }`}
              >
                {/* Isolated banner */}
                {asset.is_isolated && (
                  <div className="absolute top-0 right-0 text-xs bg-red-900/70 text-red-400 border border-red-800 rounded-tr-lg rounded-bl-lg px-2 py-0.5 font-semibold tracking-widest">
                    ISOLATED
                  </div>
                )}

                {/* Header */}
                <div className="flex items-start gap-3 mb-3">
                  <span className="text-2xl text-gray-500 mt-0.5">
                    {TYPE_ICON[asset.asset_type] || "▪"}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-gray-200 font-semibold truncate">
                      {asset.hostname}
                    </div>
                    <div className="text-xs font-mono text-gray-500 mt-0.5">
                      {asset.ip_address}
                    </div>
                  </div>
                </div>

                {/* Details */}
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Department</span>
                    <span className="text-gray-300">{asset.department || "–"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Type</span>
                    <span className="text-gray-300 capitalize">{asset.asset_type}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Criticality</span>
                    <span className={`px-1.5 py-0.5 rounded border text-xs ${cc.badge}`}>
                      {asset.criticality}
                    </span>
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap gap-2 text-xs">
                  {asset.is_isolated ? (
                    <button
                      type="button"
                      disabled={isolatingId === asset.id}
                      onClick={async () => {
                        setIsolatingId(asset.id);
                        try {
                          await api.updateAsset(asset.id, { is_isolated: false });
                          showAlert("Asset released.", "success");
                          fetchAssets();
                        } catch (e) {
                          showAlert(e.message, "error");
                        } finally {
                          setIsolatingId(null);
                        }
                      }}
                      className="rounded bg-emerald-600 hover:bg-emerald-500 px-3 py-1 font-semibold text-slate-950 disabled:opacity-60"
                    >
                      Release
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled={isolatingId === asset.id}
                      onClick={async () => {
                        setIsolatingId(asset.id);
                        try {
                          await api.updateAsset(asset.id, { is_isolated: true });
                          showAlert("Asset isolated.", "success");
                          fetchAssets();
                        } catch (e) {
                          showAlert(e.message, "error");
                        } finally {
                          setIsolatingId(null);
                        }
                      }}
                      className="rounded bg-orange-600 hover:bg-orange-500 px-3 py-1 font-semibold text-slate-950 disabled:opacity-60"
                    >
                      Isolate
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => {
                      setEditingId(asset.id);
                      setEditForm({
                        department: asset.department || "",
                        criticality: asset.criticality || "medium",
                      });
                    }}
                    className="rounded border border-gray-700 px-3 py-1 text-gray-200 hover:border-cyan-500 hover:text-white"
                  >
                    Edit
                  </button>
                </div>

                {editingId === asset.id && (
                  <div className="mt-3 space-y-2 rounded border border-gray-800 bg-gray-950/70 p-3">
                    <div className="flex gap-2 items-center">
                      <span className="text-gray-500 w-20">Dept</span>
                      <input
                        className="flex-1 bg-gray-900 border border-gray-700 text-gray-200 text-xs rounded px-2 py-1"
                        value={editForm.department}
                        onChange={(e) => setEditForm((f) => ({ ...f, department: e.target.value }))}
                      />
                    </div>
                    <div className="flex gap-2 items-center">
                      <span className="text-gray-500 w-20">Criticality</span>
                      <select
                        className="bg-gray-900 border border-gray-700 text-gray-200 text-xs rounded px-2 py-1"
                        value={editForm.criticality}
                        onChange={(e) => setEditForm((f) => ({ ...f, criticality: e.target.value }))}
                      >
                        {criticalities.map((c) => (
                          <option key={c} value={c}>{c}</option>
                        ))}
                      </select>
                    </div>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={savingEdit}
                        onClick={async () => {
                          setSavingEdit(true);
                          try {
                            await api.updateAsset(asset.id, {
                              department: editForm.department || null,
                              criticality: editForm.criticality,
                            });
                            showAlert("Asset updated.", "success");
                            setEditingId(null);
                            fetchAssets();
                          } catch (e) {
                            showAlert(e.message, "error");
                          } finally {
                            setSavingEdit(false);
                          }
                        }}
                        className="rounded bg-cyan-500 hover:bg-cyan-400 px-3 py-1 text-slate-950 font-semibold disabled:opacity-60"
                      >
                        Save
                      </button>
                      <button
                        type="button"
                        onClick={() => setEditingId(null)}
                        className="rounded border border-gray-700 px-3 py-1 text-gray-300 hover:border-gray-500"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
