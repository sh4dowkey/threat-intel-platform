import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000",
  headers: { "Content-Type": "application/json" },
  timeout: 30000,
});

// ── Alerts ────────────────────────────────────────────────────────────────────
export const analyzeFlow = (payload) =>
  api.post("/api/alerts/analyze", payload).then((r) => r.data);

export const listAlerts = (params = {}) =>
  api.get("/api/alerts", { params }).then((r) => r.data);

export const getAlert = (id) =>
  api.get(`/api/alerts/${id}`).then((r) => r.data);

export const updateAlert = (id, status) =>
  api.patch(`/api/alerts/${id}`, { status }).then((r) => r.data);

// ── IOC ───────────────────────────────────────────────────────────────────────
export const lookupIOC = (value) =>
  api.post("/api/ioc/lookup", { value }).then((r) => r.data);

export const bulkLookupIOC = (values) =>
  api.post("/api/ioc/bulk", { values }).then((r) => r.data);

// ── ML ────────────────────────────────────────────────────────────────────────
export const mlStatus = () =>
  api.get("/api/ml/status").then((r) => r.data);

export const scoreFlow = (features) =>
  api.post("/api/ml/score", { features }).then((r) => r.data);

// ── Health ────────────────────────────────────────────────────────────────────
export const healthCheck = () =>
  api.get("/health").then((r) => r.data);

export default api;
