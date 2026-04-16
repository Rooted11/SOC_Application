import { useEffect, useMemo, useState, useRef, useCallback } from "react";
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
import HelpCenter from "./components/HelpCenter";
import { api, authStorage } from "./services/api";

/* ── Navigation map ────────────────────────────────────────────────────── */

const NAV_GROUPS = [
  {
    title: "Operations",
    icon: "OP",
    items: [
      { id: "command", label: "Command Center", short: "CMD", icon: "\u25C9" },
      { id: "dashboard", label: "Analytics", short: "OPS", icon: "\u25B2" },
      { id: "incidents", label: "Incident Queue", short: "IR", icon: "\u26A0" },
      { id: "advisor", label: "AI Analyst", short: "AI", icon: "\u2726" },
      { id: "feed", label: "Live Feed", short: "LOG", icon: "\u25CE" },
    ],
  },
  {
    title: "Intel & Assets",
    icon: "IA",
    items: [
      { id: "threats", label: "Threat Intel", short: "IOC", icon: "\u2622" },
      { id: "assets", label: "Assets", short: "AST", icon: "\u2B22" },
    ],
  },
  {
    title: "Configuration",
    icon: "CF",
    items: [
      { id: "detections", label: "Detections", short: "DR", icon: "\u2609" },
      { id: "playbooks", label: "Playbooks", short: "PB", icon: "\u25B6" },
      { id: "integrations", label: "Integrations", short: "INT", icon: "\u2B58" },
      { id: "notifications", label: "Notifications", short: "NTF", icon: "\u266A" },
      { id: "users", label: "Users & Roles", short: "ADM", icon: "\u2605" },
      { id: "settings", label: "Settings", short: "CFG", icon: "\u2699" },
    ],
  },
  {
    title: "Ops Health",
    icon: "OH",
    items: [
      { id: "alarms", label: "Alarms", short: "ALM", icon: "\u23F0" },
      { id: "health", label: "System Health", short: "HLT", icon: "\u2665" },
      { id: "audit", label: "Audit Logs", short: "AUD", icon: "\u2637" },
      { id: "help", label: "Help", short: "HLP", icon: "?" },
    ],
  },
];
const NAV_ITEMS = NAV_GROUPS.flatMap((g) => g.items);
const PAGE_HELP = {
  command: "Control automation, playbooks, and quick investigations from one curated panel.",
  dashboard: "Review risk trends, anomaly scoring, and top insights before triaging.",
  incidents: "Prioritize open incidents, adjust severity, and dispatch response teams.",
  advisor: "Ask the AI analyst for recommendations and incident summaries.",
  feed: "Tail the live log stream to confirm what is hitting the pipeline right now.",
  threats: "Investigate IOC hits, threat feeds, and correlations with your environment.",
  assets: "See the current inventory, exposure warnings, and asset ownership notes.",
  detections: "Tune detection rules, thresholds, and suppression policies with confidence.",
  playbooks: "Build and simulate automated response steps for repeatable incidents.",
  integrations: "Wire in alerting, ticketing, and automation partners for faster action.",
  notifications: "Fine-tune notification channels so the right people hear about alerts.",
  users: "Manage roles, MFA, and access scopes for your SOC crew.",
  settings: "Adjust global configurations, secrets, and feature flags safely.",
  alarms: "Acknowledge and investigate alarms that need operator attention.",
  health: "Check the health of services, queues, and containerized workloads.",
  audit: "Review the latest operator actions, config changes, and system events.",
  help: "Learn operator workflows, troubleshooting steps, and quick navigation paths.",
};
const PAGE_TIPS = {
  command: [
    "Kick off weekly playbooks when new critical incidents appear.",
    "Check the live feed link if a quick log sweep is needed."
  ],
  dashboard: [
    "Use the timeline visuals to confirm that anomaly scoring matches your expectations.",
    "Open an incident directly from the Risk Trends chart for faster response."
  ],
  incidents: [
    "Sort by risk score to focus on the highest-impact tickets first.",
    "Click Playbooks to trigger containment directly from high-priority cases."
  ],
  advisor: [
    "Pick a quick prompt to let Claude outline a containment plan in seconds.",
    "Type a question to dive into the incident's narrative or gaps."
  ],
  feed: [
    "Filter by log level to surface alerts that match your current hunt.",
    "Pin the live feed to another screen for continuous visibility."
  ],
  threats: [
    "Use IOC history to decide if you need to update block lists.",
    "Correlate threat intelligence with open incidents for faster attribution."
  ],
  assets: [
    "Flag critical assets that need extra monitoring or isolation.",
    "Review ownership notes before escalating to system owners."
  ],
  detections: [
    "Adjust thresholds conservatively—run tests before applying to production.",
    "Suppress noisy sources for the next 24h if they are already under investigation."
  ],
  playbooks: [
    "Sequence commonly used steps into a single, repeatable playbook.",
    "Attach Slack/PagerDuty notifications to the response actions you want to trigger."
  ],
  integrations: [
    "Double-check webhook URLs before enabling a new connector.",
    "Use the test button to confirm alerts are reaching the external system."
  ],
  notifications: [
    "Group contacts (pager, email, Slack) by shift coverage to avoid missed alerts.",
    "Use escalation rules for critical incidents to notify multiple teams sequentially."
  ],
  users: [
    "Enable MFA for the SOC leads and analysts.",
    "Audit role permissions monthly to keep least-privilege policies tight."
  ],
  settings: [
    "Review `ANTHROPIC_API_KEY` and toggle AI assists as needed.",
    "Update rate limits to match your concentrated testing windows."
  ],
  alarms: [
    "Acknowledge alarms you are already investigating to clear the badge.",
    "Create a temporary alert rule when drilling down on a specific sensor."
  ],
  health: [
    "Restart flaky containers directly from the System Health view.",
    "Use the Redis/DB health indicators to know when to scale resources."
  ],
  audit: [
    "Filter by operator to trace who acknowledged or resolved incidents.",
    "Export logs when you need to brief compliance teams."
  ],
  help: [
    "Use this guide as the first stop when behavior feels inconsistent across modules.",
    "Open Incident Queue, Threat Intel, or Live Feed directly from quick links."
  ],
};

/* ── Notification toast stack ──────────────────────────────────────────── */

function ToastStack({ toasts, onDismiss }) {
  return (
    <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none max-w-sm">
      {toasts.map((t) => (
        <div
          key={t.id}
          onClick={() => onDismiss(t.id)}
          className={`pointer-events-auto cursor-pointer rounded-xl border px-4 py-3 text-sm shadow-2xl backdrop-blur-xl animate-slideIn ${
            t.type === "error"
              ? "border-rose-500/40 bg-rose-950/90 text-rose-200"
              : t.type === "success"
                ? "border-emerald-500/40 bg-emerald-950/90 text-emerald-200"
                : t.type === "alarm"
                  ? "border-amber-500/40 bg-amber-950/90 text-amber-200"
                  : "border-cyan-500/40 bg-cyan-950/90 text-cyan-200"
          }`}
        >
          <div className="flex items-start gap-2">
            <span className="text-lg leading-none mt-0.5">
              {t.type === "error" ? "\u2716" : t.type === "success" ? "\u2714" : t.type === "alarm" ? "\u23F0" : "\u25CF"}
            </span>
            <div className="flex-1 min-w-0">
              {t.title && <div className="font-semibold text-xs uppercase tracking-wider mb-0.5">{t.title}</div>}
              <div className="leading-snug">{t.msg}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ── Fullscreen loading/error ──────────────────────────────────────────── */

function FullscreenState({ title, message, actionLabel, onAction }) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.16),_transparent_28%),radial-gradient(circle_at_80%_20%,_rgba(249,115,22,0.12),_transparent_22%),linear-gradient(180deg,_#020617_0%,_#020617_55%,_#08111f_100%)]" />
      <div className="mx-auto flex min-h-screen max-w-3xl items-center justify-center px-6 py-12">
        <div className="w-full rounded-[28px] border border-slate-800 bg-slate-950/80 p-10 text-center shadow-[0_30px_80px_rgba(2,6,23,0.55)] backdrop-blur">
          <div className="text-[11px] uppercase tracking-[0.35em] text-cyan-400">Ataraxia</div>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight text-white">{title}</h1>
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

/* ── Main App ──────────────────────────────────────────────────────────── */

export default function App() {
  const [page, setPage] = useState("command");
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [toasts, setToasts] = useState([]);
  const toastIdRef = useRef(0);
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
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [navQuery, setNavQuery] = useState("");

  // Live counters for badges
  const [alarmCount, setAlarmCount] = useState(0);
  const [incidentCount, setIncidentCount] = useState(0);
  const [criticalCount, setCriticalCount] = useState(0);

  const showAlert = useCallback((msg, type = "info", title = null) => {
    const id = ++toastIdRef.current;
    setToasts((prev) => [...prev.slice(-4), { id, msg, type, title }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5000);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const handleNavSuggestionSelect = useCallback(
    (id) => {
      setPage(id);
      setNavQuery("");
    },
    [setPage, setNavQuery]
  );

  const navMatches = useMemo(() => {
    const query = navQuery.trim().toLowerCase();
    if (!query) return [];
    return NAV_ITEMS.filter(
      (item) =>
        item.label.toLowerCase().includes(query) ||
        item.short.toLowerCase().includes(query)
    ).slice(0, 4);
  }, [navQuery]);

  const pageDescription = useMemo(
    () => PAGE_HELP[page] || "This view keeps you ahead of incidents and alerts.",
    [page]
  );

  const handleNavInputKeyDown = useCallback(
    (event) => {
      if (event.key === "Enter" && navMatches.length > 0) {
        handleNavSuggestionSelect(navMatches[0].id);
      }
    },
    [navMatches, handleNavSuggestionSelect]
  );

  // Fetch live badge counts
  const fetchCounts = useCallback(async () => {
    try {
      const [alarmData, overview] = await Promise.all([
        api.getAlarms().catch(() => []),
        api.getOverview().catch(() => null),
      ]);
      const unacked = Array.isArray(alarmData)
        ? alarmData.filter((a) => a.status !== "acknowledged").length
        : 0;
      setAlarmCount(unacked);
      if (overview?.headline) {
        setIncidentCount(overview.headline.open_incidents || 0);
        setCriticalCount(overview.headline.critical_open || 0);
      }
    } catch {
      /* silent */
    }
  }, []);

  // Auto-refresh and real-time
  useEffect(() => {
    const refresh = () => setLastUpdated(new Date());
    const tick = () => {
      if (document.visibilityState === "visible") refresh();
    };
    const timer = setInterval(tick, 15_000);
    const reloadTimer = setTimeout(() => window.location.reload(), 10 * 60 * 1000);
    document.addEventListener("visibilitychange", tick);
    return () => {
      clearInterval(timer);
      clearTimeout(reloadTimer);
      document.removeEventListener("visibilitychange", tick);
    };
  }, []);

  // Fetch counts on every update
  useEffect(() => {
    fetchCounts();
  }, [lastUpdated, fetchCounts]);

  // SSE for real-time events
  useEffect(() => {
    if (eventSource) return;
    const es = new EventSource("/api/events/stream");
    es.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === "incident_created") {
          setLastUpdated(new Date());
          showAlert(
            data.title || "New incident detected",
            "alarm",
            `INCIDENT #${data.id || "?"}`
          );
        } else if (data.type === "log_processed") {
          setLastUpdated(new Date());
        } else if (data.type === "alarm_created") {
          setLastUpdated(new Date());
          showAlert(data.message || "New alarm raised", "alarm", "ALARM");
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
  }, [eventSource, showAlert]);

  // Auth bootstrap
  useEffect(() => {
    let active = true;
    async function bootstrapSession() {
      setBooting(true);
      setBootError(null);
      setAuthError(null);
      try {
        const status = await api.getAuthStatus();
        if (!active) return;
        const enabled = Boolean(status.auth_enabled);
        setAuthEnabled(enabled);
        setMfaEnabled(Boolean(status.mfa_enabled));
        if (!enabled) {
          setUser({ username: "local-dev", mfaAuthenticated: false, roles: ["super_admin"], permissions: ["*"] });
          setBooting(false);
          return;
        }
        const token = authStorage.getToken();
        if (!token) { setUser(null); setBooting(false); return; }
        try {
          const me = await api.getCurrentUser();
          if (active) {
            setUser({ username: me.username, mfaAuthenticated: Boolean(me.mfa_authenticated), roles: me.roles || [], permissions: me.permissions || [] });
          }
        } catch {
          if (active) { authStorage.clear(); setUser(null); }
        }
      } catch (error) {
        if (active) setBootError(error.message || "Could not reach the authentication service.");
      } finally {
        if (active) setBooting(false);
      }
    }
    bootstrapSession();
    return () => { active = false; };
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
      setUser({ username: me.username, mfaAuthenticated: Boolean(me.mfa_authenticated), roles: me.roles || [], permissions: me.permissions || [] });
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
    return <FullscreenState title="Preparing secure operator session" message="Checking runtime security mode and backend connectivity." />;
  }
  if (bootError) {
    return <FullscreenState title="Authentication bootstrap failed" message={bootError} actionLabel="Reload" onAction={() => window.location.reload()} />;
  }
  if (authEnabled && !user) {
    return <LoginScreen busy={authBusy} error={authError} mfaEnabled={mfaEnabled} onSubmit={handleLogin} />;
  }

  const currentLabel = NAV_ITEMS.find((item) => item.id === page)?.label || "Command Center";

  return (
    <div className="min-h-screen text-slate-100 relative overflow-hidden">
      {/* Background */}
      <div className="fixed inset-0 -z-20 bg-[radial-gradient(circle_at_20%_20%,rgba(56,189,248,0.08),transparent_35%),radial-gradient(circle_at_80%_0%,rgba(249,115,22,0.1),transparent_30%),linear-gradient(145deg,#020617,#050a19,#0b1c2e)]" />
      <div className="fixed inset-0 -z-10 opacity-[0.15] bg-[url('data:image/svg+xml,%3Csvg width%3D%27160%27 height%3D%27160%27 viewBox%3D%270 0 160 160%27 xmlns%3D%27http://www.w3.org/2000/svg%27%3E%3Cpath d%3D%27M0 80h160M80 0v160%27 stroke%3D%27%23374151%27 stroke-width%3D%271%27 stroke-opacity%3D%270.35%27/%3E%3C/svg%3E')]" />

      {/* Toasts */}
      <ToastStack toasts={toasts} onDismiss={dismissToast} />

      <div className={`grid min-h-screen transition-all duration-300 ${sidebarCollapsed ? "lg:grid-cols-[64px_minmax(0,1fr)]" : "lg:grid-cols-[280px_minmax(0,1fr)]"}`}>

        {/* ── Sidebar ────────────────────────────────────────────────── */}
        <aside className="border-r border-cyan-500/10 bg-slate-950/80 backdrop-blur-xl flex flex-col overflow-hidden">
          {/* Logo */}
          <div className="border-b border-cyan-500/10 px-4 py-5 flex items-center gap-3">
            <button
              onClick={() => { setPage("command"); }}
              className="flex items-center gap-3 hover:opacity-80 transition-opacity"
            >
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white font-bold text-sm shadow-lg shadow-cyan-500/20">
                A
              </div>
              {!sidebarCollapsed && (
                <div>
                  <div className="text-[10px] uppercase tracking-[0.35em] text-cyan-400 leading-none">Ataraxia</div>
                  <div className="text-sm font-semibold text-white mt-0.5">Nexus Deck</div>
                </div>
              )}
            </button>
            <button
              onClick={() => setSidebarCollapsed((v) => !v)}
              className="ml-auto text-slate-500 hover:text-cyan-400 transition-colors text-xs"
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {sidebarCollapsed ? "\u25B6" : "\u25C0"}
            </button>
          </div>

          {/* Nav */}
          <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-1">
            {NAV_GROUPS.map((group) => (
              <div key={group.title}>
                <button
                  type="button"
                  onClick={() => setOpenGroups((prev) => ({ ...prev, [group.title]: !prev[group.title] }))}
                  className={`flex w-full items-center rounded-lg px-2 py-1.5 text-left text-slate-500 hover:text-slate-300 transition-colors ${sidebarCollapsed ? "justify-center" : "justify-between"}`}
                >
                  {!sidebarCollapsed && (
                    <span className="text-[10px] uppercase tracking-[0.25em] font-medium">{group.title}</span>
                  )}
                  {sidebarCollapsed ? (
                    <span className="text-[9px] font-bold tracking-wider">{group.icon}</span>
                  ) : (
                    <span className="text-[10px]">{openGroups[group.title] ? "\u25BE" : "\u25B8"}</span>
                  )}
                </button>
                {(openGroups[group.title] || sidebarCollapsed) && (
                  <div className="space-y-0.5 mt-0.5">
                    {group.items.map((item) => {
                      const active = page === item.id;
                      const badge =
                        item.id === "alarms" && alarmCount > 0 ? alarmCount :
                        item.id === "incidents" && criticalCount > 0 ? criticalCount :
                        null;
                      return (
                        <button
                          key={item.id}
                          onClick={() => setPage(item.id)}
                          title={sidebarCollapsed ? item.label : undefined}
                          className={`flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-left transition-all duration-150 ${
                            active
                              ? "bg-gradient-to-r from-cyan-500/15 via-cyan-400/10 to-transparent border border-cyan-400/30 text-white shadow-[0_0_20px_rgba(34,211,238,0.08)]"
                              : "border border-transparent text-slate-400 hover:bg-slate-800/60 hover:text-white hover:border-slate-700/50"
                          } ${sidebarCollapsed ? "justify-center px-2" : ""}`}
                        >
                          <span className={`text-sm ${active ? "text-cyan-400" : "text-slate-500"}`}>
                            {item.icon}
                          </span>
                          {!sidebarCollapsed && (
                            <>
                              <span className="text-[13px] font-medium flex-1">{item.label}</span>
                              {badge != null && (
                                <span className={`min-w-[18px] h-[18px] flex items-center justify-center rounded-full text-[10px] font-bold ${
                                  item.id === "alarms" ? "bg-amber-500/20 text-amber-400 border border-amber-500/30" :
                                  "bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse"
                                }`}>
                                  {badge}
                                </span>
                              )}
                            </>
                          )}
                          {sidebarCollapsed && badge != null && (
                            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                          )}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            ))}
          </nav>

          {/* Footer */}
          {!sidebarCollapsed && (
            <div className="border-t border-cyan-500/10 px-4 py-4 space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span>Last sync</span>
                <span className="text-slate-300 font-mono">{lastUpdated.toLocaleTimeString()}</span>
              </div>
              <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.25em] text-emerald-400">
                <span className="inline-block h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(74,222,128,0.6)] animate-pulse" />
                Monitoring Active
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-900/70 px-3 py-2.5">
                <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Operator</div>
                <div className="text-sm text-slate-200 mt-1 font-medium">
                  {authEnabled ? user?.username : "local-dev"}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">
                  {authEnabled
                    ? user?.mfaAuthenticated ? "MFA verified" : "Authenticated"
                    : "Development mode"}
                </div>
              </div>
            </div>
          )}
        </aside>

        {/* ── Main content ───────────────────────────────────────────── */}
        <div className="flex min-w-0 flex-col">
          {/* Header */}
          <header className="border-b border-cyan-500/10 bg-slate-950/60 backdrop-blur-xl">
            <div className="flex flex-col gap-3 px-6 py-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <div className="text-[10px] uppercase tracking-[0.35em] text-slate-500">
                    Security Operations Center
                  </div>
                  <h1 className="mt-1 text-2xl font-semibold tracking-tight text-white">
                    {currentLabel}
                  </h1>
                </div>

                <div className="flex items-center gap-2">
                  {criticalCount > 0 && (
                    <button
                      onClick={() => setPage("incidents")}
                      className="flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-950/60 px-3 py-1.5 text-xs text-red-400 hover:bg-red-950/80 transition-colors animate-pulse"
                    >
                      <span className="w-2 h-2 rounded-full bg-red-500" />
                      {criticalCount} Critical
                    </button>
                  )}
                  {incidentCount > 0 && (
                    <button
                      onClick={() => setPage("incidents")}
                      className="flex items-center gap-1.5 rounded-full border border-orange-500/30 bg-orange-950/40 px-3 py-1.5 text-xs text-orange-400 hover:bg-orange-950/60 transition-colors"
                    >
                      {incidentCount} Open
                    </button>
                  )}

                  <button
                    onClick={() => setPage("alarms")}
                    className={`relative rounded-full border px-3 py-1.5 text-xs transition-colors ${
                      alarmCount > 0
                        ? "border-amber-500/40 bg-amber-950/50 text-amber-400 hover:bg-amber-950/70"
                        : "border-slate-700 bg-slate-900/70 text-slate-400 hover:border-slate-600"
                    }`}
                  >
                    <span className="mr-1">{"\u23F0"}</span>
                    {alarmCount > 0 ? `${alarmCount} Alarms` : "Alarms"}
                    {alarmCount > 0 && (
                      <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-amber-500 animate-ping opacity-75" />
                    )}
                  </button>

                  <button
                    onClick={() => setPage("feed")}
                    className="rounded-full border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-xs text-slate-400 hover:border-cyan-500/40 hover:text-cyan-400 transition-colors"
                  >
                    Live Feed
                  </button>

                  <button
                    onClick={() => setPage("help")}
                    className="rounded-full border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-xs text-slate-400 hover:border-cyan-500/40 hover:text-cyan-400 transition-colors"
                  >
                    Help
                  </button>

                  {authEnabled && (
                    <button
                      type="button"
                      onClick={handleLogout}
                      className="rounded-full border border-slate-800 bg-slate-900/70 px-3 py-1.5 text-xs text-slate-400 transition hover:border-slate-700 hover:text-white"
                    >
                      Sign out
                    </button>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div className="flex-1 min-w-[240px]">
                  <label className="text-[10px] uppercase tracking-[0.25em] text-slate-500">
                    Jump to section
                  </label>
                  <div className="relative mt-1">
                    <input
                      type="text"
                      value={navQuery}
                      onChange={(event) => setNavQuery(event.target.value)}
                      onKeyDown={handleNavInputKeyDown}
                      placeholder="Search for analytics, incidents, playbooks..."
                      className="w-full rounded-2xl border border-slate-800 bg-slate-900/80 px-4 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-600/40"
                    />
                    {navMatches.length > 0 && (
                      <div className="absolute left-0 right-0 top-full z-20 mt-2 rounded-2xl border border-slate-800 bg-slate-950/95 py-2 shadow-2xl backdrop-blur">
                        {navMatches.map((item) => (
                          <button
                            key={item.id}
                            onClick={() => handleNavSuggestionSelect(item.id)}
                            className="flex w-full items-center gap-3 px-4 py-2 text-left text-sm text-slate-100 hover:bg-slate-900/70"
                          >
                            <span className="text-cyan-400">{item.icon}</span>
                            <div className="flex flex-col">
                              <span className="font-semibold">{item.label}</span>
                              <span className="text-xs text-slate-500">{item.short}</span>
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
                <div className="text-xs text-slate-400">
                  Type a name, abbreviation, or badge label and press Enter to jump.
                </div>
              </div>
            </div>
          </header>

          <div className="border-b border-slate-800 bg-slate-950/40 px-6 py-3 text-sm text-slate-300">
            <div>{pageDescription}</div>
            {PAGE_TIPS[page] && (
              <div className="mt-2 grid gap-1 text-[13px] text-slate-400">
                {PAGE_TIPS[page].map((tip) => (
                  <div key={tip} className="flex items-start gap-2">
                    <span className="text-cyan-400 font-semibold">•</span>
                    <span className="leading-tight">{tip}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          {/* Page content */}
          <main className="min-w-0 flex-1 overflow-auto px-6 py-6">
            {page === "command" && <CommandCenter lastUpdated={lastUpdated} showAlert={showAlert} setPage={setPage} />}
            {page === "dashboard" && <Dashboard lastUpdated={lastUpdated} showAlert={showAlert} setPage={setPage} />}
            {page === "incidents" && <IncidentList lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "advisor" && <AIAdvisor lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "feed" && <LiveFeed lastUpdated={lastUpdated} showAlert={showAlert} setPage={setPage} />}
            {page === "threats" && <ThreatTrends lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "assets" && <AssetInventory lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "detections" && <Detections showAlert={showAlert} />}
            {page === "playbooks" && <PlaybooksPage showAlert={showAlert} />}
            {page === "integrations" && <IntegrationsPage showAlert={showAlert} />}
            {page === "notifications" && <NotificationsPage showAlert={showAlert} />}
            {page === "users" && <UsersRoles showAlert={showAlert} />}
            {page === "settings" && <SettingsPage showAlert={showAlert} />}
            {page === "health" && <SystemHealth lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "alarms" && <Alarms lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "audit" && <AuditLogs showAlert={showAlert} />}
            {page === "help" && <HelpCenter setPage={setPage} />}
          </main>
        </div>
      </div>

      {/* Slide-in animation style */}
      <style>{`
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .animate-slideIn { animation: slideIn 0.3s ease-out; }
      `}</style>
    </div>
  );
}
