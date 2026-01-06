// src/services/api.js
// API Service for communicating with FastAPI backend

import axios from 'axios';

// Base URL for the API
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Token refresh interval (5 minutes in milliseconds) - shorter for better security
const TOKEN_REFRESH_INTERVAL = 5 * 60 * 1000;
const TOKEN_REFRESH_BUFFER = 1 * 60 * 1000; // Refresh 1 minute before expiry

// Session inactivity timeout (3 hours for production)
const SESSION_INACTIVITY_TIMEOUT = 3 * 60 * 60 * 1000; // 3 hours

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 second timeout
});

// Token storage keys
const ACCESS_TOKEN_KEY = 'jarwis_access_token';
const REFRESH_TOKEN_KEY = 'jarwis_refresh_token';
const USER_KEY = 'jarwis_user';
const TOKEN_EXPIRY_KEY = 'jarwis_token_expiry';
const LAST_ACTIVITY_KEY = 'jarwis_last_activity';

// ============== Token Management ==============

export const getAccessToken = () => localStorage.getItem(ACCESS_TOKEN_KEY);
export const getRefreshToken = () => localStorage.getItem(REFRESH_TOKEN_KEY);
export const getTokenExpiry = () => {
  const expiry = localStorage.getItem(TOKEN_EXPIRY_KEY);
  return expiry ? parseInt(expiry, 10) : null;
};
export const getStoredUser = () => {
  const user = localStorage.getItem(USER_KEY);
  return user ? JSON.parse(user) : null;
};

export const setTokens = (accessToken, refreshToken, expiresIn = 900) => {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  // Store expiry time (default 15 minutes = 900 seconds)
  const expiryTime = Date.now() + (expiresIn * 1000);
  localStorage.setItem(TOKEN_EXPIRY_KEY, expiryTime.toString());
  updateLastActivity();
};

export const setStoredUser = (user) => {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
};

export const clearAuth = () => {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem(TOKEN_EXPIRY_KEY);
  localStorage.removeItem(LAST_ACTIVITY_KEY);
};

// Track user activity for session management
export const updateLastActivity = () => {
  localStorage.setItem(LAST_ACTIVITY_KEY, Date.now().toString());
};

export const getLastActivity = () => {
  const activity = localStorage.getItem(LAST_ACTIVITY_KEY);
  return activity ? parseInt(activity, 10) : null;
};

// Check if token needs refresh (within buffer time of expiry)
export const shouldRefreshToken = () => {
  const expiry = getTokenExpiry();
  if (!expiry) return false;
  
  // Refresh if within 2 minutes of expiry
  return Date.now() > (expiry - TOKEN_REFRESH_BUFFER);
};

// Check if session is inactive (no activity for 5 minutes)
export const isSessionInactive = () => {
  const lastActivity = getLastActivity();
  if (!lastActivity) return false;
  
  // 5 minute inactivity timeout - will be increased later
  return Date.now() - lastActivity > SESSION_INACTIVITY_TIMEOUT;
};

// Auto refresh token if needed
let refreshPromise = null;
export const autoRefreshToken = async () => {
  // Avoid multiple simultaneous refresh attempts
  if (refreshPromise) {
    return refreshPromise;
  }
  
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    throw new Error('No refresh token');
  }
  
  refreshPromise = axios.post(`${API_BASE_URL}/api/auth/refresh`, {
    refresh_token: refreshToken,
  }).then(response => {
    const { access_token, refresh_token: newRefreshToken, expires_in } = response.data;
    setTokens(access_token, newRefreshToken, expires_in || 900);
    return response.data;
  }).finally(() => {
    refreshPromise = null;
  });
  
  return refreshPromise;
};

// ============== Request Interceptor ==============

// Auth endpoints that should skip session/token checks
const AUTH_ENDPOINTS = ['/api/auth/login', '/api/auth/register', '/api/auth/refresh', '/api/oauth'];

const isAuthEndpoint = (url) => {
  if (!url) return false;
  return AUTH_ENDPOINTS.some(endpoint => url.includes(endpoint));
};

// Add token to requests and check for proactive refresh
api.interceptors.request.use(
  async (config) => {
    // Skip session checks for auth endpoints (login, register, etc.)
    if (isAuthEndpoint(config.url)) {
      return config;
    }
    
    // DO NOT update activity on API requests - only user interactions should reset timer
    // Background API calls (dashboard refresh, etc.) should not prevent inactivity logout
    
    // Check if session is inactive - force logout (only for authenticated requests)
    if (isSessionInactive() && getAccessToken()) {
      clearAuth();
      window.location.href = '/login?reason=inactive';
      return Promise.reject(new Error('Session inactive'));
    }
    
    // Proactive token refresh if token is about to expire
    if (shouldRefreshToken() && getRefreshToken()) {
      try {
        await autoRefreshToken();
      } catch (refreshError) {
        console.warn('Proactive token refresh failed:', refreshError);
        // Don't block the request, let the response interceptor handle 401
      }
    }
    
    const token = getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ============== Response Interceptor ==============

// Handle token refresh on 401 and subscription errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Skip redirect logic for auth endpoints - let calling code handle errors
    if (isAuthEndpoint(originalRequest?.url)) {
      return Promise.reject(error);
    }

    // Handle subscription-related errors (403 with specific error types)
    if (error.response?.status === 403) {
      const detail = error.response?.data?.detail;
      if (detail?.error === 'subscription_limit_exceeded' || 
          detail?.error === 'feature_not_available' ||
          detail?.error === 'subscription_expired') {
        // Let the calling code handle subscription errors
        return Promise.reject(error);
      }
    }

    // If 401 and we haven't tried to refresh yet
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = getRefreshToken();
        if (!refreshToken) {
          clearAuth();
          window.location.href = '/login?reason=session_expired';
          return Promise.reject(error);
        }

        // Try to refresh the token
        await autoRefreshToken();

        // Retry the original request with new token
        const newToken = getAccessToken();
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh failed, clear auth and redirect to login
        clearAuth();
        window.location.href = '/login?reason=session_expired';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

// ============== Auth API ==============

export const authAPI = {
  // Register new user
  register: async (data) => {
    const response = await api.post('/api/auth/register', {
      email: data.email,
      username: data.username || data.email.split('@')[0],
      password: data.password,
      full_name: data.name || data.full_name,
      company: data.company,
    });
    return response.data;
  },

  // Login with email and password
  login: async (email, password) => {
    const response = await api.post('/api/auth/login', { email, password });
    const { access_token, refresh_token, user } = response.data;
    
    // Store tokens and user
    setTokens(access_token, refresh_token);
    setStoredUser(user);
    
    return response.data;
  },

  // Logout
  logout: async () => {
    try {
      const refreshToken = getRefreshToken();
      if (refreshToken) {
        await api.post('/api/auth/logout', { refresh_token: refreshToken });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      clearAuth();
    }
  },

  // Logout from all devices
  logoutAll: async () => {
    try {
      await api.post('/api/auth/logout/all');
    } finally {
      clearAuth();
    }
  },

  // Get current user profile
  getProfile: async () => {
    const response = await api.get('/api/auth/me');
    setStoredUser(response.data);
    return response.data;
  },

  // Update profile
  updateProfile: async (data) => {
    const response = await api.put('/api/auth/me', data);
    setStoredUser(response.data);
    return response.data;
  },

  // Change password
  changePassword: async (currentPassword, newPassword) => {
    const response = await api.post('/api/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
    return response.data;
  },

  // Refresh token
  refreshToken: async () => {
    const refreshToken = getRefreshToken();
    if (!refreshToken) throw new Error('No refresh token');
    
    const response = await axios.post(`${API_BASE_URL}/api/auth/refresh`, {
      refresh_token: refreshToken,
    });
    
    const { access_token, refresh_token: newRefreshToken } = response.data;
    setTokens(access_token, newRefreshToken);
    
    return response.data;
  },
};

// ============== Admin API ==============

export const adminAPI = {
  // Get dashboard stats
  getDashboardStats: async () => {
    const response = await api.get('/api/admin/dashboard');
    return response.data;
  },

  // List users
  getUsers: async (params = {}) => {
    const response = await api.get('/api/admin/users', { params });
    return response.data;
  },

  // Get user details
  getUserDetails: async (userId) => {
    const response = await api.get(`/api/admin/users/${userId}`);
    return response.data;
  },

  // Update user
  updateUser: async (userId, data) => {
    const response = await api.put(`/api/admin/users/${userId}`, data);
    return response.data;
  },

  // Approve user
  approveUser: async (userId, plan = 'free') => {
    const response = await api.post(`/api/admin/users/${userId}/approve`, { plan });
    return response.data;
  },

  // Reject user
  rejectUser: async (userId) => {
    const response = await api.post(`/api/admin/users/${userId}/reject`);
    return response.data;
  },

  // Reset user status
  resetUserStatus: async (userId) => {
    const response = await api.post(`/api/admin/users/${userId}/reset-status`);
    return response.data;
  },

  // Set user plan
  setUserPlan: async (userId, plan) => {
    const response = await api.post(`/api/admin/users/${userId}/set-plan`, { plan });
    return response.data;
  },

  // Get available plans
  getPlans: async () => {
    const response = await api.get('/api/admin/plans');
    return response.data;
  },

  // Delete user
  deleteUser: async (userId) => {
    const response = await api.delete(`/api/admin/users/${userId}`);
    return response.data;
  },

  // Make user admin
  makeAdmin: async (userId) => {
    const response = await api.post(`/api/admin/users/${userId}/make-admin`);
    return response.data;
  },

  // Remove admin
  removeAdmin: async (userId) => {
    const response = await api.post(`/api/admin/users/${userId}/remove-admin`);
    return response.data;
  },

  // Get contact submissions (admin only)
  getContactSubmissions: async () => {
    const response = await api.get('/api/admin/contact-submissions');
    return response.data;
  },

  // Delete contact submission (admin only)
  deleteContactSubmission: async (submissionId) => {
    const response = await api.delete(`/api/admin/contact-submissions/${submissionId}`);
    return response.data;
  },
};

// ============== Scan API ==============

export const scanAPI = {
  // Start a new web scan
  startScan: async (data) => {
    // Transform frontend format to backend format
    const scanRequest = {
      target_url: data.target?.url || data.target_url || '',
      scan_type: 'web',
      login_url: data.auth?.login_url || data.login_url || '',
      username: data.auth?.username || data.username || '',
      password: data.auth?.password || data.password || '',
    };
    const response = await api.post('/api/scans/', scanRequest);
    return response.data;
  },

  // Get scan status (combined status + logs for live updates)
  getScanStatus: async (scanId) => {
    const response = await api.get(`/api/scans/${scanId}`);
    // Also fetch logs for live output
    try {
      const logsResponse = await api.get(`/api/scans/${scanId}/logs`);
      return { ...response.data, logs: logsResponse.data?.logs || [] };
    } catch {
      return response.data;
    }
  },

  // Alias for backward compatibility
  getStatus: async (scanId) => {
    return scanAPI.getScanStatus(scanId);
  },

  // Get scan logs with optional since timestamp for incremental updates
  getScanLogs: async (scanId, since = null) => {
    const params = since ? { since } : {};
    const response = await api.get(`/api/scans/${scanId}/logs`, { params });
    return response.data;
  },

  // Get scan results
  getScanResults: async (scanId) => {
    const response = await api.get(`/api/scans/${scanId}`);
    return response.data;
  },

  // Get scan findings/vulnerabilities
  getScanFindings: async (scanId, severity = null) => {
    const params = severity ? `?severity=${severity}` : '';
    const response = await api.get(`/api/scans/${scanId}/findings${params}`);
    return response.data;
  },

  // Get all vulnerabilities across all scans
  getAllVulnerabilities: async () => {
    const response = await api.get('/api/vulnerabilities');
    return response.data;
  },

  // Stop a scan
  stopScan: async (scanId) => {
    const response = await api.post(`/api/scans/${scanId}/stop`);
    return response.data;
  },

  // List all scans with optional filters
  listScans: async (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.type && filters.type !== 'all') params.append('type', filters.type);
    if (filters.status && filters.status !== 'all') params.append('status', filters.status);
    if (filters.search) params.append('search', filters.search);
    
    const response = await api.get(`/api/scans/all?${params.toString()}`);
    return response.data;
  },

  // Get running scans
  getRunningScans: async () => {
    const response = await api.get('/api/scans/running');
    return response.data;
  },

  // Get last scan
  getLastScan: async () => {
    const response = await api.get('/api/scans/last');
    return response.data;
  },

  // Get scan report URL
  getReportUrl: (scanId) => `${API_BASE_URL}/api/scans/${scanId}/report`,

  // Get scan report PDF URL
  getReportPdfUrl: (scanId) => `${API_BASE_URL}/api/scan/${scanId}/report/pdf`,

  // List reports
  listReports: async () => {
    const response = await api.get('/api/reports');
    return response.data;
  },

  // Get latest report
  getLatestReport: async () => {
    const response = await api.get('/api/reports/latest');
    return response.data;
  },

  // Get full report URL
  getFullReportUrl: (report) => {
    if (typeof report === 'string') {
      return `${API_BASE_URL}/api/reports/${report}`;
    }
    if (report.path) {
      return `${API_BASE_URL}${report.path}`;
    }
    if (report.dir && report.name) {
      return `${API_BASE_URL}/api/reports/${report.dir}/${report.name}`;
    }
    return `${API_BASE_URL}/api/reports/${report.name || report}`;
  },

  // Get full report PDF URL
  getFullReportPdfUrl: (report) => {
    if (typeof report === 'string') {
      return `${API_BASE_URL}/api/reports/${report}/pdf`;
    }
    if (report.path) {
      return `${API_BASE_URL}${report.path}/pdf`;
    }
    if (report.dir && report.name) {
      return `${API_BASE_URL}/api/reports/${report.dir}/${report.name}/pdf`;
    }
    return `${API_BASE_URL}/api/reports/${report.name || report}/pdf`;
  },

  // Download PDF report
  downloadReportPdf: async (report) => {
    const url = typeof report === 'string' 
      ? `${API_BASE_URL}/api/reports/${report}/pdf`
      : report.dir && report.name 
        ? `${API_BASE_URL}/api/reports/${report.dir}/${report.name}/pdf`
        : `${API_BASE_URL}${report.path}/pdf`;
    
    try {
      const response = await api.get(url, { responseType: 'blob' });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      
      // Extract filename from report
      const filename = typeof report === 'string' 
        ? report.replace('.html', '.pdf')
        : (report.name || 'jarwis_report').replace('.html', '.pdf');
      
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
      return { success: true };
    } catch (error) {
      console.error('PDF download failed:', error);
      throw error;
    }
  },
};

// ============== Mobile Scan API ==============

export const mobileScanAPI = {
  // Start mobile scan with file upload
  startScan: async (config, file) => {
    const formData = new FormData();
    if (file) {
      formData.append('app_file', file);
    }
    // Append config fields
    Object.entries(config).forEach(([key, value]) => {
      if (value !== null && value !== undefined) {
        formData.append(key, typeof value === 'boolean' ? value.toString() : value);
      }
    });
    
    const response = await api.post('/api/scan/mobile/start', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000, // 2 min timeout for file upload
    });
    return response.data;
  },

  // Get mobile scan status
  getScanStatus: async (scanId) => {
    const response = await api.get(`/api/scan/mobile/${scanId}/status`);
    return response.data;
  },

  // Get mobile scan logs
  getScanLogs: async (scanId, since = null) => {
    const params = since ? { since } : {};
    const response = await api.get(`/api/scan/mobile/${scanId}/logs`, { params });
    return response.data;
  },

  // Stop mobile scan
  stopScan: async (scanId) => {
    const response = await api.post(`/api/scan/mobile/${scanId}/stop`);
    return response.data;
  },

  // List mobile scans
  listScans: async () => {
    const response = await api.get('/api/scans/mobile');
    return response.data;
  },
};

// ============== Cloud Scan API ==============

export const cloudScanAPI = {
  // Start cloud scan
  startScan: async (config) => {
    const response = await api.post('/api/scan/cloud/start', config);
    return response.data;
  },

  // Get cloud scan status
  getScanStatus: async (scanId) => {
    const response = await api.get(`/api/scan/cloud/${scanId}/status`);
    return response.data;
  },

  // List cloud scans
  listScans: async () => {
    const response = await api.get('/api/scans/cloud');
    return response.data;
  },

  // Get available cloud providers
  getProviders: async () => {
    const response = await api.get('/api/scan/cloud/providers');
    return response.data;
  },
};

// ============== Chat API ==============

export const chatAPI = {
  // Send a message to Jarwis AGI (streaming)
  sendMessage: async (message, scanId = null, modelMode = "jarwis") => {
    const response = await fetch(`${API_BASE_URL}/api/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getAccessToken()}`,
      },
      body: JSON.stringify({ message, scan_id: scanId, model_mode: modelMode }),
    });
    return response;
  },

  // Upload file for analysis (streaming)
  uploadFile: async (file, scanId = null) => {
    const formData = new FormData();
    formData.append('file', file);
    if (scanId) formData.append('scan_id', scanId);

    const response = await fetch(`${API_BASE_URL}/api/chat/upload`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${getAccessToken()}`,
      },
      body: formData,
    });
    return response;
  },
};

// ============== Contact API ==============

export const contactAPI = {
  submit: async (formData) => {
    const response = await api.post('/api/contact', formData);
    return response.data;
  },
};

// ============== Domain Verification API ==============

export const domainVerificationAPI = {
  // Get verification status for a domain
  getVerificationStatus: async (domain) => {
    try {
      const response = await api.get(`/api/domains/verify/status?domain=${encodeURIComponent(domain)}`);
      return response.data;
    } catch (error) {
      // If endpoint doesn't exist yet, return not verified
      return { verified: false, domain };
    }
  },

  // Generate a verification code for a domain
  generateVerificationCode: async (domain) => {
    const response = await api.post('/api/domains/verify/generate', { domain });
    return response.data;
  },

  // Check if TXT record is properly set up
  checkTxtRecord: async (domain) => {
    try {
      const response = await api.post('/api/domains/verify/check-txt', { domain });
      return response.data;
    } catch (error) {
      return { verified: false, error: error.message };
    }
  },

  // Verify domain ownership
  verifyDomain: async (domain, method = 'txt') => {
    const response = await api.post('/api/domains/verify', { domain, method });
    return response.data;
  },

  // List verified domains
  listVerifiedDomains: async () => {
    try {
      const response = await api.get('/api/domains/verified');
      return response.data;
    } catch {
      return { domains: [] };
    }
  },
};

// ============== Health Check ==============

export const healthCheck = async () => {
  const response = await api.get('/api/health');
  return response.data;
};

// Export the axios instance for custom requests
export default api;
