import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000, // 10 second timeout
});

export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

export const startScan = async (scanConfig) => {
  const response = await api.post('/scan/start', scanConfig);
  return response.data;
};

export const getScanStatus = async (scanId) => {
  const response = await api.get(`/scan/${scanId}/status`);
  return response.data;
};

export const getScanLogs = async (scanId, since = null) => {
  const params = since ? { since } : {};
  const response = await api.get(`/scan/${scanId}/logs`, { params });
  return response.data;
};

export const stopScan = async (scanId) => {
  const response = await api.post(`/scan/${scanId}/stop`);
  return response.data;
};

export const listScans = async () => {
  const response = await api.get('/scans');
  return response.data;
};

export const listAllScans = async (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.type && filters.type !== 'all') params.append('type', filters.type);
  if (filters.status && filters.status !== 'all') params.append('status', filters.status);
  if (filters.search) params.append('search', filters.search);
  
  const response = await api.get(`/scans/all?${params.toString()}`);
  return response.data;
};

export const getRunningScans = async () => {
  const response = await api.get('/scans/running');
  return response.data;
};

export const listReports = async () => {
  const response = await api.get('/reports');
  return response.data;
};

export const getReportUrl = (report) => {
  const BASE_URL = 'http://localhost:5000';
  
  // Handle both string filename and report object with path
  if (typeof report === 'string') {
    return `${BASE_URL}/api/reports/${report}`;
  }
  // If report has a path, use it directly (path already includes /api/reports/)
  if (report.path) {
    return `${BASE_URL}${report.path}`;
  }
  // Fallback to name with dir if available
  if (report.dir && report.name) {
    return `${BASE_URL}/api/reports/${report.dir}/${report.name}`;
  }
  return `${BASE_URL}/api/reports/${report.name || report}`;
};

export const getLastScan = async () => {
  const response = await api.get('/scans/last');
  return response.data;
};

export const getLatestReport = async () => {
  const response = await api.get('/reports/latest');
  return response.data;
};

// Mobile Security Scan
export const startMobileScan = async (config) => {
  const response = await api.post('/scan/mobile/start', config);
  return response.data;
};

export const getMobileScanStatus = async (scanId) => {
  const response = await api.get(`/scan/mobile/${scanId}/status`);
  return response.data;
};

export const getMobileScanLogs = async (scanId, since = null) => {
  const params = since ? { since } : {};
  const response = await api.get(`/scan/mobile/${scanId}/logs`, { params });
  return response.data;
};

export const stopMobileScan = async (scanId) => {
  const response = await api.post(`/scan/mobile/${scanId}/stop`);
  return response.data;
};

export const listMobileScans = async () => {
  const response = await api.get('/scans/mobile');
  return response.data;
};

// Cloud Security Scan
export const startCloudScan = async (config) => {
  const response = await api.post('/scan/cloud/start', config);
  return response.data;
};

export const getCloudScanStatus = async (scanId) => {
  const response = await api.get(`/scan/cloud/${scanId}/status`);
  return response.data;
};

export const listCloudScans = async () => {
  const response = await api.get('/scans/cloud');
  return response.data;
};

export const getCloudProviders = async () => {
  const response = await api.get('/scan/cloud/providers');
  return response.data;
};

export default api;
