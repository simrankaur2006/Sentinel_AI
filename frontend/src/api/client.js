// Thin API client. Every function maps 1:1 to a route implemented in backend/app/api.
export const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function buildUrl(path, params) {
  const url = new URL(API_BASE + path);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "") return;
    (Array.isArray(v) ? v : [v]).forEach((x) => url.searchParams.append(k, x));
  });
  return url.toString();
}

function detailMessage(body, status) {
  const d = body && body.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map((e) => `${(e.loc || []).slice(1).join(".")}: ${e.msg}`).join("; ");
  return `Request failed with status ${status}.`;
}

export async function request(path, { method = "GET", params, body, form } = {}) {
  const init = { method, headers: {} };
  if (form) init.body = form;
  else if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(buildUrl(path, params), init);
  } catch {
    throw new ApiError(0, `Cannot reach the SentinelAI API at ${API_BASE}. Is the backend running?`);
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* empty or non-JSON body */
  }
  if (!res.ok) throw new ApiError(res.status, detailMessage(data, res.status));
  return data;
}

export const api = {
  health: () => request("/health"),
  systemInfo: () => request("/system/info"),
  aiStatus: () => request("/ai/status"),
  samples: () => request("/ingest/samples"),
  loadSample: (id) => request(`/ingest/sample/${encodeURIComponent(id)}`, { method: "POST" }),
  upload: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/ingest/upload", { method: "POST", form });
  },
  batches: () => request("/ingest/batches"),
  events: (params) => request("/events", { params }),
  dashboard: (params) => request("/dashboard/metrics", { params }),
  runDetection: (body) => request("/detection/run", { method: "POST", body }),
  runs: () => request("/detection/runs"),
  getConfig: () => request("/detection/config"),
  putConfig: (config) => request("/detection/config", { method: "PUT", body: config }),
  resetConfig: () => request("/detection/config/reset", { method: "POST" }),
  rules: () => request("/detection/rules"),
  alerts: (params) => request("/alerts", { params }),
  alert: (id) => request(`/alerts/${id}`),
  updateAlert: (id, status) => request(`/alerts/${id}`, { method: "PATCH", body: { status } }),
  incidents: (params) => request("/incidents", { params }),
  incident: (id) => request(`/incidents/${id}`),
  createIncident: (body) => request("/incidents", { method: "POST", body }),
  updateIncident: (id, body) => request(`/incidents/${id}`, { method: "PATCH", body }),
  addAlerts: (id, alert_ids) => request(`/incidents/${id}/alerts`, { method: "POST", body: { alert_ids } }),
  addNote: (id, body) => request(`/incidents/${id}/notes`, { method: "POST", body }),
  analyze: (id, provider) => request(`/incidents/${id}/analysis`, { method: "POST", body: { provider } }),
  createReport: (id, body) => request(`/incidents/${id}/reports`, { method: "POST", body }),
  reports: (params) => request("/reports", { params }),
  report: (id) => request(`/reports/${id}`),
};

export const reportDownloadUrl = (id, format) => buildUrl(`/reports/${id}/download`, { format });
