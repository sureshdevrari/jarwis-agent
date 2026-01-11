// Feature flags for Jarwis frontend dashboard
// Toggle via environment variables; defaults are safe/off.
const dashboardEnv = (process.env.REACT_APP_USE_NEW_DASHBOARD || "").toLowerCase();

export const featureFlags = {
  // Default on; allow explicit disable via REACT_APP_USE_NEW_DASHBOARD=false
  useNewDashboard: dashboardEnv ? dashboardEnv === "true" : true,
};
