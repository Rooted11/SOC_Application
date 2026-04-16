/*
 * Central API client for the Ataraxia frontend.
 *
 * Defaults to relative /api requests so the app works with the Vite proxy
 * in development and with nginx in a production image. An absolute browser-
 * reachable base URL can still be supplied via VITE_API_URL when needed.
 *
 * If you build/preview the app on Windows (without the Vite proxy), set
 * VITE_API_URL=http://<WIN_HOST_IP>:8000 so requests hit the Ubuntu backend.
 */

// VITE_API_BASE_URL = backend origin, e.g. http://<SOC_UBUNTU_IP>:8000
// All request paths already include /api/... so we just prepend the origin.
const ORIGIN = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");
const TOKEN_KEY = "obsidian-nexus-access-token";

function buildUrl(path) {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  // If an absolute origin is set, prefix it; otherwise use relative paths (Vite proxy)
  return ORIGIN ? `${ORIGIN}${normalizedPath}` : normalizedPath;
}

function dispatchUnauthorized() {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("obsidian:unauthorized"));
  }
}

export const authStorage = {
  getToken() {
    if (typeof window === "undefined") {
      return null;
    }
    return window.localStorage.getItem(TOKEN_KEY);
  },

  setToken(token) {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(TOKEN_KEY, token);
    }
  },

  clear() {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(TOKEN_KEY);
    }
  },
};

async function request(path, options = {}) {
  const { auth = true, ...fetchOptions } = options;
  const headers = {
    "Content-Type": "application/json",
    ...fetchOptions.headers,
  };

  if (auth) {
    const token = authStorage.getToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }

  const res = await fetch(buildUrl(path), {
    ...fetchOptions,
    headers,
  });

  if (res.status === 401 && auth) {
    authStorage.clear();
    dispatchUnauthorized();
    throw new Error("Session expired. Please sign in again.");
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }

  if (res.status === 204) {
    return null;
  }

  return res.json();
}

export const api = {
  getAuthStatus: () => request("/api/auth/status", { auth: false }),

  login: (username, password, otpCode) =>
    request("/api/auth/login", {
      method: "POST",
      auth: false,
      body: JSON.stringify({
        username,
        password,
        otp_code: otpCode || undefined,
      }),
    }),

  getCurrentUser: () => request("/api/auth/me"),

  getOverview: () => request("/api/overview"),

  getIncidents: (params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, value]) => value != null))
    ).toString();
    return request(`/api/incidents${qs ? `?${qs}` : ""}`);
  },

  getIncidentStats: () => request("/api/incidents/stats"),
  getIncident: (id) => request(`/api/incidents/${id}`),

  updateIncident: (id, payload) =>
    request(`/api/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  triggerPlaybook: (id, payload = {}) =>
    request(`/api/incidents/${id}/respond`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getPlaybookActions: (id) => request(`/api/incidents/${id}/actions`),

  getLogs: (params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, value]) => value != null))
    ).toString();
    return request(`/api/logs${qs ? `?${qs}` : ""}`);
  },

  getLogStats: () => request("/api/logs/stats"),

  ingestLogs: (logs) =>
    request("/api/logs/ingest", {
      method: "POST",
      body: JSON.stringify({ logs }),
    }),

  deleteLog: (id) =>
    request(`/api/logs/${id}`, { method: "DELETE" }),

  deleteLogsBulk: (params = {}) =>
    request("/api/logs", {
      method: "DELETE",
      body: JSON.stringify(params),
    }),

  archiveLogs: () =>
    request("/api/logs/archive", { method: "POST" }),

  getThreatIntel: (params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, value]) => value != null))
    ).toString();
    return request(`/api/threat-intel${qs ? `?${qs}` : ""}`);
  },

  refreshThreatFeed: () =>
    request("/api/threat-intel/refresh", { method: "POST" }),

  purgeThreatIntel: (payload) =>
    request("/api/threat-intel", {
      method: "DELETE",
      body: JSON.stringify(payload),
    }),

  getAssets: () => request("/api/assets"),
  createAsset: (payload) =>
    request("/api/assets", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateAsset: (id, payload) =>
    request(`/api/assets/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  aiQuery: (incident_id, query) =>
    request("/api/ai/query", {
      method: "POST",
      body: JSON.stringify({ incident_id, query }),
    }),

  aiReport: (incident_id) =>
    request(`/api/ai/report/${incident_id}`, { method: "POST" }),

  // RBAC / Config
  getUsers: () => request("/api/admin/users"),
  getRoles: () => request("/api/admin/roles"),
  getDetections: () => request("/api/config/detections"),
  createDetection: (payload) =>
    request("/api/config/detections", { method: "POST", body: JSON.stringify(payload) }),
  updateDetection: (id, payload) =>
    request(`/api/config/detections/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteDetection: (id) => request(`/api/config/detections/${id}`, { method: "DELETE" }),
  getPlaybookDefs: () => request("/api/config/playbooks"),
  createPlaybookDef: (payload) =>
    request("/api/config/playbooks", { method: "POST", body: JSON.stringify(payload) }),
  updatePlaybookDef: (id, payload) =>
    request(`/api/config/playbooks/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deletePlaybookDef: (id) =>
    request(`/api/config/playbooks/${id}`, { method: "DELETE" }),
  getIntegrations: () => request("/api/config/integrations"),
  createIntegration: (payload) =>
    request("/api/config/integrations", { method: "POST", body: JSON.stringify(payload) }),
  updateIntegration: (id, payload) =>
    request(`/api/config/integrations/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteIntegration: (id) =>
    request(`/api/config/integrations/${id}`, { method: "DELETE" }),
  getNotificationChannels: () => request("/api/config/notifications"),
  createNotificationChannel: (payload) =>
    request("/api/config/notifications", { method: "POST", body: JSON.stringify(payload) }),
  updateNotificationChannel: (id, payload) =>
    request(`/api/config/notifications/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteNotificationChannel: (id) =>
    request(`/api/config/notifications/${id}`, { method: "DELETE" }),
  getSettings: () => request("/api/config/settings"),
  getAuditLogs: (params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, v]) => v != null))
    ).toString();
    return request(`/api/audit/logs${qs ? `?${qs}` : ""}`);
  },
  getSystemHealth: () => request("/api/system/health"),
  // Alarms
  getAlarms: () => request("/api/alarms"),
  createAlarm: (payload) =>
    request("/api/alarms", { method: "POST", body: JSON.stringify(payload) }),
  ackAlarm: (id) => request(`/api/alarms/${id}/ack`, { method: "POST" }),
};
