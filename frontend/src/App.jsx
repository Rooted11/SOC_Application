import { useEffect, useState } from "react";
import CommandCenter from "./components/CommandCenter";
import Dashboard from "./components/Dashboard";
import IncidentList from "./components/IncidentList";
import ThreatTrends from "./components/ThreatTrends";
import AIAdvisor from "./components/AIAdvisor";
import LiveFeed from "./components/LiveFeed";
import AssetInventory from "./components/AssetInventory";
import LoginScreen from "./components/LoginScreen";
import UsersRoles from "./components/UsersRoles";
import Detections from "./components/Detections";
import PlaybooksPage from "./components/PlaybooksPage";
import IntegrationsPage from "./components/IntegrationsPage";
import NotificationsPage from "./components/NotificationsPage";
import SettingsPage from "./components/SettingsPage";
import SystemHealth from "./components/SystemHealth";
import AuditLogs from "./components/AuditLogs";
import Alarms from "./components/Alarms";
import { api, authStorage } from "./services/api";

const NAV_GROUPS = [
  {
    title: "Operations",
    items: [
      { id: "command", label: "Command Center", short: "CMD" },
      { id: "dashboard", label: "Analytics", short: "OPS" },
      { id: "incidents", label: "Incident Queue", short: "IR" },
      { id: "advisor", label: "AI Analyst", short: "AI" },
      { id: "feed", label: "Live Feed", short: "LOG" },
    ],
  },
  {
    title: "Intel & Assets",
    items: [
      { id: "threats", label: "Threat Intel", short: "IOC" },
      { id: "assets", label: "Assets", short: "AST" },
    ],
  },
  {
    title: "Configuration",
    items: [
      { id: "detections", label: "Detections", short: "DR" },
      { id: "playbooks", label: "Playbooks", short: "PB" },
      { id: "integrations", label: "Integrations", short: "INT" },
      { id: "notifications", label: "Notifications", short: "NTF" },
      { id: "users", label: "Users & Roles", short: "ADM" },
      { id: "settings", label: "Settings", short: "CFG" },
    ],
  },
  {
    title: "Ops Health",
    items: [
      { id: "alarms", label: "Alarms", short: "ALM" },
      { id: "health", label: "System Health", short: "HLT" },
      { id: "audit", label: "Audit Logs", short: "AUD" },
    ],
  },
];
const NAV_ITEMS = NAV_GROUPS.flatMap((g) => g.items);

function FullscreenState({ title, message, actionLabel, onAction }) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.16),_transparent_28%),radial-gradient(circle_at_80%_20%,_rgba(249,115,22,0.12),_transparent_22%),linear-gradient(180deg,_#020617_0%,_#020617_55%,_#08111f_100%)]" />
      <div className="mx-auto flex min-h-screen max-w-3xl items-center justify-center px-6 py-12">
          <div className="w-full rounded-[28px] border border-slate-800 bg-slate-950/80 p-10 text-center shadow-[0_30px_80px_rgba(2,6,23,0.55)] backdrop-blur">
            <div className="text-[11px] uppercase tracking-[0.35em] text-cyan-400">
              Ataraxia
            </div>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight text-white">
            {title}
          </h1>
          <p className="mt-3 text-sm leading-7 text-slate-400">{message}</p>
          {onAction && (
            <button
              type="button"
              onClick={onAction}
              className="mt-8 inline-flex items-center justify-center rounded-2xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
            >
              {actionLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState("command");
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [alertBanner, setAlertBanner] = useState(null);
  const [booting, setBooting] = useState(true);
  const [bootError, setBootError] = useState(null);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [user, setUser] = useState(null);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [eventSource, setEventSource] = useState(null);
  const [openGroups, setOpenGroups] = useState(() =>
    NAV_GROUPS.reduce((acc, g) => ({ ...acc, [g.title]: true }), {})
  );

  function showAlert(msg, type = "info") {
    setAlertBanner({ msg, type });
    window.clearTimeout(showAlert.timeoutId);
    showAlert.timeoutId = window.setTimeout(() => setAlertBanner(null), 4000);
  }

  useEffect(() => {
    const refresh = () => setLastUpdated(new Date());
    const tick = () => {
      if (document.visibilityState === "visible") {
        refresh();
      }
    };
    const timer = setInterval(tick, 15_000);
    const reloadTimer = setTimeout(() => {
      window.location.reload();
    }, 30 * 60 * 1000); // 30 minutes
    document.addEventListener("visibilitychange", tick);
    return () => {
      clearInterval(timer);
      clearTimeout(reloadTimer);
      document.removeEventListener("visibilitychange", tick);
    };
  }, []);

  useEffect(() => {
    if (eventSource) return;
    const es = new EventSource("/api/events/stream");
    es.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === "incident_created" || data.type === "log_processed") {
          setLastUpdated(new Date());
        }
      } catch {
        /* ignore parse errors */
      }
    };
    es.onerror = () => {
      es.close();
      setEventSource(null);
    };
    setEventSource(es);
    return () => es.close();
  }, [eventSource]);

  useEffect(() => {
    let active = true;

    async function bootstrapSession() {
      setBooting(true);
      setBootError(null);
      setAuthError(null);

      try {
        const status = await api.getAuthStatus();
        if (!active) {
          return;
        }

        const enabled = Boolean(status.auth_enabled);
        setAuthEnabled(enabled);
        setMfaEnabled(Boolean(status.mfa_enabled));

        if (!enabled) {
          setUser({ username: "local-dev", mfaAuthenticated: false, roles: ["super_admin"], permissions: ["*"] });
          setBooting(false);
          return;
        }

        const token = authStorage.getToken();
        if (!token) {
          setUser(null);
          setBooting(false);
          return;
        }

        try {
          const me = await api.getCurrentUser();
          if (active) {
            setUser({
              username: me.username,
              mfaAuthenticated: Boolean(me.mfa_authenticated),
              roles: me.roles || [],
              permissions: me.permissions || [],
            });
          }
        } catch {
          if (active) {
            authStorage.clear();
            setUser(null);
          }
        }
      } catch (error) {
        if (active) {
          setBootError(error.message || "Could not reach the authentication service.");
        }
      } finally {
        if (active) {
          setBooting(false);
        }
      }
    }

    bootstrapSession();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    function handleUnauthorized() {
      setPage("command");
      setUser(null);
      setAuthError("Session expired. Please sign in again.");
    }

    window.addEventListener("obsidian:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("obsidian:unauthorized", handleUnauthorized);
  }, []);

  async function handleLogin({ username, password, otpCode }) {
    setAuthBusy(true);
    setAuthError(null);

    try {
      const session = await api.login(username, password, otpCode);
      authStorage.setToken(session.access_token);
      const me = await api.getCurrentUser();
      setUser({
        username: me.username,
        mfaAuthenticated: Boolean(me.mfa_authenticated),
        roles: me.roles || [],
        permissions: me.permissions || [],
      });
      showAlert(`Signed in as ${me.username}.`, "success");
    } catch (error) {
      authStorage.clear();
      if (error.message.includes("Valid one-time code required")) {
        setAuthError("Enter the current 6-digit code from your authenticator app.");
      } else if (error.message.startsWith("API 401")) {
        setAuthError("Invalid username, password, or one-time code.");
      } else if (error.message.startsWith("API 429")) {
        setAuthError("Too many sign-in attempts. Wait a moment and try again.");
      } else {
        setAuthError(error.message);
      }
    } finally {
      setAuthBusy(false);
    }
  }

  function handleLogout() {
    authStorage.clear();
    setPage("command");
    setUser(null);
    setAuthError(null);
    showAlert("Signed out.", "info");
  }

  if (booting) {
    return (
      <FullscreenState
        title="Preparing secure operator session"
        message="Checking runtime security mode and backend connectivity."
      />
    );
  }

  if (bootError) {
    return (
      <FullscreenState
        title="Authentication bootstrap failed"
        message={bootError}
        actionLabel="Reload"
        onAction={() => window.location.reload()}
      />
    );
  }

  if (authEnabled && !user) {
    return (
      <LoginScreen
        busy={authBusy}
        error={authError}
        mfaEnabled={mfaEnabled}
        onSubmit={handleLogin}
      />
    );
  }

  return (
    <div className="min-h-screen text-slate-100 relative overflow-hidden">
      <div className="fixed inset-0 -z-20 bg-[radial-gradient(circle_at_20%_20%,rgba(56,189,248,0.12),transparent_35%),radial-gradient(circle_at_80%_0%,rgba(249,115,22,0.14),transparent_30%),linear-gradient(145deg,#020617,#050a19,#0b1c2e)]" />
      <div className="fixed inset-0 -z-10 opacity-25 bg-[url('data:image/svg+xml,%3Csvg width%3D%27160%27 height%3D%27160%27 viewBox%3D%270 0 160 160%27 xmlns%3D%27http://www.w3.org/2000/svg%27%3E%3Cpath d%3D%27M0 80h160M80 0v160%27 stroke%3D%27%23374151%27 stroke-width%3D%271%27 stroke-opacity%3D%270.35%27/%3E%3C/svg%3E')]" />

      <div className="grid min-h-screen lg:grid-cols-[280px_minmax(0,1fr)]">
        <aside className="border-r border-cyan-500/10 bg-slate-950/70 backdrop-blur-xl">
          <div className="border-b border-cyan-500/10 px-6 py-6">
          <div className="text-[11px] uppercase tracking-[0.35em] text-cyan-400">
            Ataraxia
          </div>
          <div className="mt-2 text-2xl font-semibold tracking-tight text-white">
            Nexus Deck
          </div>
          <p className="mt-2 max-w-xs text-sm leading-6 text-slate-400">
            Live detection, response, and threat posture in one operator surface.
          </p>
          </div>

          <nav className="space-y-3 px-4 py-5">
            {NAV_GROUPS.map((group) => (
              <div key={group.title} className="space-y-2">
                <button
                  type="button"
                  onClick={() =>
                    setOpenGroups((prev) => ({ ...prev, [group.title]: !prev[group.title] }))
                  }
                  className="flex w-full items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-2 text-left text-slate-200 hover:border-cyan-400/40"
                >
                  <span className="text-xs uppercase tracking-[0.25em] text-slate-400">{group.title}</span>
                  <span className="text-slate-500 text-sm">{openGroups[group.title] ? "▾" : "▸"}</span>
                </button>
                {openGroups[group.title] && (
                  <div className="space-y-2">
                    {group.items.map((item) => {
                      const active = page === item.id;
                      return (
                        <button
                          key={item.id}
                          onClick={() => setPage(item.id)}
                          className={`flex w-full items-center gap-3 rounded-2xl border px-4 py-3 text-left transition ${
                            active
                              ? "border-cyan-400/60 bg-gradient-to-r from-cyan-500/15 via-cyan-400/10 to-blue-500/10 text-white shadow-[0_12px_40px_rgba(34,211,238,0.15)]"
                              : "border-slate-800/80 bg-slate-900/50 text-slate-400 hover:border-cyan-400/40 hover:text-white hover:shadow-[0_10px_30px_rgba(34,211,238,0.08)]"
                          }`}
                        >
                          <span
                            className={`inline-flex h-10 w-10 items-center justify-center rounded-xl text-xs font-semibold ${
                              active
                                ? "bg-gradient-to-br from-cyan-500/30 to-blue-500/30 text-cyan-100 border border-cyan-400/40"
                                : "bg-slate-800/70 text-slate-500 border border-slate-700/60"
                            }`}
                          >
                            {item.short}
                          </span>
                          <span className="text-sm font-medium">{item.label}</span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            ))}
          </nav>

          <div className="mt-auto border-t border-cyan-500/10 px-6 py-5 text-sm text-slate-400">
            <div className="flex items-center justify-between">
              <span>Last sync</span>
              <span className="text-slate-200">
                {lastUpdated.toLocaleTimeString()}
              </span>
            </div>
            <div className="mt-3 flex items-center gap-2 text-xs uppercase tracking-[0.25em] text-emerald-400">
              <span className="inline-block h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(74,222,128,0.8)]" />
              Monitoring active
            </div>
            <div className="mt-4 rounded-2xl border border-cyan-500/10 bg-slate-900/70 px-4 py-3 shadow-[0_8px_30px_rgba(6,182,212,0.08)]">
              <div className="text-[11px] uppercase tracking-[0.25em] text-slate-500">
                Session
              </div>
              <div className="mt-2 text-sm text-slate-200">
                {authEnabled ? user?.username : "local-dev"}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                {authEnabled
                  ? user?.mfaAuthenticated
                    ? "Protected operator access with MFA"
                    : mfaEnabled
                      ? "Protected operator access pending MFA"
                      : "Protected operator access"
                  : "Development mode"}
              </div>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-col">
          <header className="border-b border-cyan-500/10 bg-slate-950/60 px-6 py-5 backdrop-blur-xl shadow-[0_10px_40px_rgba(6,182,212,0.08)]">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <div className="text-[11px] uppercase tracking-[0.35em] text-slate-500">
                  Security Operations Center
                </div>
                <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">
                  {NAV_ITEMS.find((item) => item.id === page)?.label}
                </h1>
              </div>

              <div className="flex flex-wrap items-center gap-3 text-xs uppercase tracking-[0.25em] text-slate-400">
                <div className="rounded-full border border-slate-800 bg-slate-900/70 px-4 py-2">
                  Auto refresh 15s (visible tab)
                </div>
                <div className="rounded-full border border-slate-800 bg-slate-900/70 px-4 py-2">
                  {authEnabled
                    ? user?.mfaAuthenticated
                      ? `MFA active: ${user?.username}`
                      : `Signed in: ${user?.username}`
                    : "Local dev"}
                </div>
                <div className="rounded-full border border-slate-800 bg-slate-900/70 px-4 py-2">
                  Playbooks armed
                </div>
                {authEnabled && (
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="rounded-full border border-slate-800 bg-slate-900/70 px-4 py-2 text-slate-300 transition hover:border-slate-700 hover:text-white"
                  >
                    Sign out
                  </button>
                )}
              </div>
            </div>
          </header>

          {alertBanner && (
            <div
              className={`mx-6 mt-4 rounded-2xl border px-4 py-3 text-sm ${
                alertBanner.type === "error"
                  ? "border-rose-500/30 bg-rose-500/10 text-rose-200"
                  : alertBanner.type === "success"
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                    : "border-cyan-500/30 bg-cyan-500/10 text-cyan-200"
              }`}
            >
              {alertBanner.msg}
            </div>
          )}

          <main className="min-w-0 flex-1 overflow-auto px-6 py-6">
            {page === "command" && <CommandCenter lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "dashboard" && <Dashboard lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "incidents" && <IncidentList lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "advisor" && <AIAdvisor lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "feed" && <LiveFeed lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "threats" && <ThreatTrends lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "assets" && <AssetInventory lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "detections" && <Detections showAlert={showAlert} />}
            {page === "playbooks" && <PlaybooksPage showAlert={showAlert} />}
            {page === "integrations" && <IntegrationsPage showAlert={showAlert} />}
            {page === "notifications" && <NotificationsPage showAlert={showAlert} />}
            {page === "users" && <UsersRoles showAlert={showAlert} />}
            {page === "settings" && <SettingsPage showAlert={showAlert} />}
            {page === "health" && <SystemHealth showAlert={showAlert} />}
            {page === "alarms" && <Alarms showAlert={showAlert} />}
            {page === "audit" && <AuditLogs showAlert={showAlert} />}
          </main>
        </div>
      </div>
    </div>
  );
}
