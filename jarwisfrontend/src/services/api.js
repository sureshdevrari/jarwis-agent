// src/services/api.js
// API Service for communicating with FastAPI backend

import axios from 'axios';

// Base URL for the API
// In development with proxy (package.json), use empty string for relative URLs
// In production or if REACT_APP_API_URL is set, use absolute URL
const API_BASE_URL = process.env.REACT_APP_API_URL || '';

console.log('[API] Base URL:', API_BASE_URL || '(using proxy/relative URLs)');

// Token refresh interval (5 minutes in milliseconds) - shorter for better security
const TOKEN_REFRESH_INTERVAL = 5 * 60 * 1000;
const TOKEN_REFRESH_BUFFER = 1 * 60 * 1000; // Refresh 1 minute before expiry

// Session inactivity timeout (3 hours for production)
const SESSION_INACTIVITY_TIMEOUT = 3 * 60 * 60 * 1000; // 3 hours

// Create axios instance with default config
// Timeout increased to 60s for scan operations that may take longer
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 60000, // 60 second timeout (increased for scan operations)
  withCredentials: true, // IMPORTANT: Send HttpOnly cookies with every request
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
// Now uses HttpOnly cookies - browser sends them automatically
let refreshPromise = null;
export const autoRefreshToken = async () => {
  // Avoid multiple simultaneous refresh attempts
  if (refreshPromise) {
    return refreshPromise;
  }
  
  // With HttpOnly cookies, refresh token is sent automatically by browser
  // We also send localStorage version as fallback for backwards compatibility
  const refreshToken = getRefreshToken();
  
  refreshPromise = axios.post(`${API_BASE_URL}/api/auth/refresh`, 
    refreshToken ? { refresh_token: refreshToken } : {},
    { withCredentials: true }  // Send HttpOnly cookies
  ).then(response => {
    const { access_token, refresh_token: newRefreshToken, expires_in } = response.data;
    // Still store in localStorage for backwards compatibility and session tracking
    setTokens(access_token, newRefreshToken, expires_in || 900);
    return response.data;
  }).finally(() => {
    refreshPromise = null;
  });
  
  return refreshPromise;
};

// ============== CSRF Token Management ==============

const CSRF_COOKIE_NAME = 'jarwis_csrf_token';
const CSRF_HEADER_NAME = 'X-CSRF-Token';

// Read CSRF token from cookie
const getCSRFToken = () => {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === CSRF_COOKIE_NAME) {
      return value;
    }
  }
  return null;
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
    // Add CSRF token for state-changing requests
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(config.method?.toUpperCase())) {
      const csrfToken = getCSRFToken();
      if (csrfToken) {
        config.headers[CSRF_HEADER_NAME] = csrfToken;
      }
    }
    
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
  // Returns { two_factor_required: true, two_factor_token, two_factor_method } if 2FA is enabled
  login: async (email, password) => {
    const response = await api.post('/api/auth/login', { email, password });
    
    // Check if 2FA is required
    if (response.data.two_factor_required) {
      return {
        two_factor_required: true,
        two_factor_token: response.data.two_factor_token,
        two_factor_method: response.data.two_factor_method || 'email',
        message: response.data.message,
      };
    }
    
    const { access_token, refresh_token, user } = response.data;
    
    // Store tokens and user
    setTokens(access_token, refresh_token);
    setStoredUser(user);
    
    return response.data;
  },

  // Complete login with 2FA code
  loginWith2FA: async (twoFactorToken, code, useBackupCode = false) => {
    const response = await api.post('/api/auth/login/2fa', {
      two_factor_token: twoFactorToken,
      code: code,
      use_backup_code: useBackupCode,
    });
    
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

  // Get login history
  getLoginHistory: async (limit = 10) => {
    const response = await api.get(`/api/auth/login-history?limit=${limit}`);
    return response.data;
  },

  // Get active sessions
  getActiveSessions: async () => {
    const response = await api.get('/api/auth/sessions');
    return response.data;
  },

  // Revoke a specific session
  revokeSession: async (sessionId) => {
    const response = await api.delete(`/api/auth/sessions/${sessionId}`);
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
    // Extract auth credentials
    const loginUrl = data.auth?.login_url || data.login_url || '';
    const username = data.auth?.username || data.username || '';
    const password = data.auth?.password || data.password || '';
    
    // Determine auth_method based on provided credentials or explicit method
    let authMethod = data.auth?.method || 'none';
    if (authMethod === 'none') {
      // Auto-detect from credentials
      if (username && password) {
        authMethod = 'username_password';
      } else if (data.session_cookie || data.session_token) {
        authMethod = 'manual_session';
      } else if (data.social_providers?.length > 0) {
        authMethod = 'social_login';
      } else if (data.phone_number) {
        authMethod = 'phone_otp';
      }
    }
    
    // Build 2FA config if provided
    let twoFactorConfig = null;
    if (data.two_factor?.enabled) {
      twoFactorConfig = {
        enabled: true,
        type: data.two_factor.type || 'email',
        email: data.two_factor.email || null,
        phone: data.two_factor.phone || null,
      };
    }
    
    // Transform frontend format to backend format
    const scanRequest = {
      target_url: data.target?.url || data.target_url || '',
      scan_type: 'web',
      scan_name: data.scan_name || null,
      // Auth fields
      auth_method: authMethod,
      login_url: loginUrl,
      username: username,
      password: password,
      // Phone OTP auth
      phone_number: data.phone_number || null,
      // Manual session auth
      session_cookie: data.session_cookie || null,
      session_token: data.session_token || null,
      // Social login auth
      social_providers: data.social_providers || null,
      // 2FA config
      two_factor: twoFactorConfig,
      // Pass config with scan profile, rate limit, scope
      config: {
        scan_profile: data.scan_type || 'full',  // full, quick, api, authenticated
        rate_limit: data.rate_limit || 10,
        attacks: data.attacks || null,
        scope: data.scope || null,
      },
    };
    console.log('scanAPI.startScan request:', scanRequest);
    try {
      const response = await api.post('/api/scans/', scanRequest);
      console.log('scanAPI.startScan response:', response.data);
      return response.data;
    } catch (error) {
      console.error('scanAPI.startScan error:', error.response?.data || error.message);
      throw error;
    }
  },

  // Get scan status (combined status + logs for live updates)
  getScanStatus: async (scanId) => {
    const response = await api.get(`/api/scans/${scanId}`);
    // Also fetch logs for live output
    try {
      const logsResponse = await api.get(`/api/scans/${scanId}/logs`);
      return { 
        ...response.data, 
        logs: logsResponse.data?.logs || [],
        // Include manual auth waiting states from logs response
        waiting_for_manual_auth: logsResponse.data?.waiting_for_manual_auth || false,
        waiting_for_otp: logsResponse.data?.waiting_for_otp || false
      };
    } catch {
      return response.data;
    }
  },

  // Alias for backward compatibility
  getStatus: async (scanId) => {
    return scanAPI.getScanStatus(scanId);
  },

  // Alias for backward compatibility - startWebScan is alias to startScan
  startWebScan: async (data) => {
    return scanAPI.startScan(data);
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

  // Get a single finding/vulnerability by ID
  getVulnerability: async (vulnId) => {
    const response = await api.get(`/api/scans/findings/${vulnId}`);
    return response.data;
  },

  // Mark a finding as false positive (effectively changing its status)
  updateVulnerabilityStatus: async (vulnId, status) => {
    // Map status to is_false_positive boolean
    const isFalsePositive = status === 'false_positive' || status === 'Resolved';
    const response = await api.patch(`/api/scans/findings/${vulnId}/false-positive?is_false_positive=${isFalsePositive}`);
    return response.data;
  },

  // Stop a scan
  stopScan: async (scanId, confirmed = false) => {
    const response = await api.post(`/api/scans/${scanId}/stop?confirmed=${confirmed}`);
    return response.data;
  },
  // Resume a failed/stopped scan from checkpoint
  resumeScan: async (scanId) => {
    const response = await api.post(`/api/scans/${scanId}/resume`);
    return response.data;
  },

  // Retry a failed scan (creates new scan with same config)
  retryScan: async (scanId) => {
    const response = await api.post(`/api/scans/${scanId}/retry`);
    return response.data;
  },

  // Get detailed diagnostics for a failed scan
  getScanDiagnostics: async (scanId) => {
    const response = await api.get(`/api/scans/${scanId}/diagnostics`);
    return response.data;
  },

  // Get recovery status for a scan (checkpoint info, circuit breakers)
  getRecoveryStatus: async (scanId) => {
    const response = await api.get(`/api/scans/${scanId}/recovery-status`);
    return response.data;
  },

  // Run preflight validation before starting scan
  runPreflight: async () => {
    const response = await api.get('/api/scans/preflight');
    return response.data;
  },

  // Get scanner health (circuit breaker states)
  getScannerHealth: async () => {
    const response = await api.get('/api/scans/scanners/health');
    return response.data;
  },

  // Reset circuit breaker for a scanner
  resetScannerCircuit: async (scannerName) => {
    const response = await api.post(`/api/scans/scanners/${scannerName}/reset-circuit`);
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

  // Get scan report URL (uses /api/scan/ singular to match server routes)
  getReportUrl: (scanId) => `${API_BASE_URL}/api/scan/${scanId}/report`,

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
  // Note: Accepts (file, config) to match NewScan.jsx call pattern
  startScan: async (file, config) => {
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
  stopScan: async (scanId, confirmed = false) => {
    const response = await api.post(`/api/scan/mobile/${scanId}/stop?confirmed=${confirmed}`);
    return response.data;
  },

  // List mobile scans
  listScans: async () => {
    const response = await api.get('/api/scan/mobile/');
    return response.data;
  },

  // Get mobile scan findings
  getScanFindings: async (scanId) => {
    const response = await api.get(`/api/scan/mobile/${scanId}/findings`);
    return response.data;
  },
};

// ============== Cloud Scan API ==============

export const cloudScanAPI = {
  // Start cloud scan
  // Accepts either (provider, credentials) or a full config object
  startScan: async (providerOrConfig, credentials = null) => {
    let payload;
    if (typeof providerOrConfig === 'object' && providerOrConfig !== null && !credentials) {
      // Full config object passed
      payload = providerOrConfig;
    } else {
      // Legacy: (provider, credentials) format
      payload = {
        provider: providerOrConfig,
        credentials
      };
    }
    const response = await api.post('/api/scan/cloud/start', payload);
    return response.data;
  },

  // Get cloud scan status
  getScanStatus: async (scanId) => {
    const response = await api.get(`/api/scan/cloud/${scanId}/status`);
    return response.data;
  },

  // Get cloud scan results/findings
  getScanResults: async (scanId) => {
    const response = await api.get(`/api/scan/cloud/${scanId}/logs`);
    return response.data;
  },

  // Get cloud scan findings
  getScanFindings: async (scanId) => {
    const response = await api.get(`/api/scan/cloud/${scanId}/findings`);
    return response.data;
  },

  // Get attack paths for a cloud scan
  getAttackPaths: async (scanId) => {
    const response = await api.get(`/api/scan/cloud/${scanId}/attack-paths`);
    return response.data;
  },

  // Get compliance scores for a cloud scan
  getComplianceScores: async (scanId) => {
    const response = await api.get(`/api/scan/cloud/${scanId}/compliance`);
    return response.data;
  },

  // Export cloud scan results
  exportResults: async (scanId, format = 'json') => {
    const response = await api.get(`/api/scan/cloud/${scanId}/export?format=${format}`, {
      responseType: format === 'json' ? 'json' : 'blob'
    });
    return response.data;
  },

  // Validate cloud credentials before scan
  validateCredentials: async (provider, credentials) => {
    const response = await api.post('/api/scan/cloud/validate-credentials', credentials, {
      params: { provider }
    });
    return response.data;
  },

  // Stop a running cloud scan
  stopScan: async (scanId, confirmed = true) => {
    const response = await api.post(`/api/scan/cloud/${scanId}/stop`, null, {
      params: { confirmed }
    });
    return response.data;
  },

  // List cloud scans
  listScans: async () => {
    const response = await api.get('/api/scan/cloud/');
    return response.data;
  },

  // Get available cloud providers
  getProviders: async () => {
    const response = await api.get('/api/scan/cloud/providers');
    return response.data;
  },

  // Get scan logs (real-time)
  getScanLogs: async (scanId, since = null) => {
    const params = since ? `?since=${encodeURIComponent(since)}` : '';
    const response = await api.get(`/api/scan/cloud/${scanId}/logs${params}`);
    return response.data;
  },

  // Generate external ID for AWS cross-account role
  generateExternalId: async () => {
    const response = await api.post('/api/scan/cloud/generate-external-id');
    return response.data;
  },

  // Get onboarding template for a cloud provider
  getOnboardingTemplate: async (provider) => {
    const response = await api.get(`/api/scan/cloud/onboarding-template/${provider}`);
    return response.data;
  },

  // Get available services for a cloud provider
  getServices: async (provider) => {
    const response = await api.get(`/api/scan/cloud/services/${provider}`);
    return response.data;
  },
};

// ============== Network Scan API ==============

export const networkScanAPI = {
  // Start network scan
  startScan: async (scanConfig) => {
    const response = await api.post('/api/network/scan', scanConfig);
    return response.data;
  },

  // Get network scan status
  getScanStatus: async (scanId) => {
    const response = await api.get(`/api/network/scan/${scanId}`);
    return response.data;
  },

  // Get network scan findings
  getScanFindings: async (scanId) => {
    const response = await api.get(`/api/network/scan/${scanId}/findings`);
    return response.data;
  },

  // Get network scan logs (real-time)
  getScanLogs: async (scanId) => {
    const response = await api.get(`/api/network/scan/${scanId}/logs`);
    return response.data;
  },

  // Stop a running network scan
  stopScan: async (scanId) => {
    const response = await api.delete(`/api/network/scan/${scanId}`);
    return response.data;
  },

  // List network scans
  listScans: async () => {
    const response = await api.get('/api/network/scans');
    return response.data;
  },

  // Get network scan tools/capabilities
  getTools: async () => {
    const response = await api.get('/api/network/tools');
    return response.data;
  },

  // Get network dashboard summary (aggregated stats)
  getDashboardSummary: async () => {
    const response = await api.get('/api/network/dashboard/summary');
    return response.data;
  },

  // Export network scan results
  exportResults: async (scanId, format = 'json') => {
    const response = await api.get(`/api/network/scan/${scanId}/export?format=${format}`, {
      responseType: format === 'json' ? 'json' : 'blob'
    });
    return response.data;
  },

  // ============== Agent Management ==============
  
  // Get list of registered agents
  getAgents: async () => {
    const response = await api.get('/api/network/agents');
    return response.data;
  },

  // Register a new agent
  registerAgent: async (agentData) => {
    const response = await api.post('/api/network/agents', agentData);
    return response.data;
  },

  // Delete an agent
  deleteAgent: async (agentId) => {
    const response = await api.delete(`/api/network/agents/${agentId}`);
    return response.data;
  },

  // Get agent status
  getAgentStatus: async (agentId) => {
    const response = await api.get(`/api/network/agents/${agentId}/status`);
    return response.data;
  },

  // Get agent deployment instructions
  getAgentSetupInstructions: async () => {
    const response = await api.get('/api/network/agents/setup-instructions');
    return response.data;
  },
};

// ============== SAST (Source Code Review) API ==============

export const sastScanAPI = {
  // Start a SAST scan
  startScan: async (scanConfig) => {
    const response = await api.post('/api/scan/sast/start', scanConfig);
    return response.data;
  },

  // List SAST scans
  listScans: async (limit = 10) => {
    const response = await api.get(`/api/scan/sast?limit=${limit}`);
    return response.data;
  },

  // Get SAST scan status
  getScanStatus: async (scanId) => {
    const response = await api.get(`/api/scan/sast/${scanId}/status`);
    return response.data;
  },

  // Get SAST scan logs (for real-time updates)
  getScanLogs: async (scanId, since = 0) => {
    const response = await api.get(`/api/scan/sast/${scanId}/logs?since=${since}`);
    return response.data;
  },

  // Stop a running SAST scan
  stopScan: async (scanId) => {
    const response = await api.post(`/api/scan/sast/${scanId}/stop`);
    return response.data;
  },

  // ============== SCM Connection APIs ==============

  // Connect to GitHub (get OAuth URL)
  connectGitHub: async () => {
    const response = await api.get('/api/scan/sast/github/connect');
    return response.data;
  },

  // Connect to GitLab (get OAuth URL)
  connectGitLab: async (baseUrl = null) => {
    const params = baseUrl ? `?base_url=${encodeURIComponent(baseUrl)}` : '';
    const response = await api.get(`/api/scan/sast/gitlab/connect${params}`);
    return response.data;
  },

  // List all SCM connections
  listConnections: async () => {
    const response = await api.get('/api/scan/sast/connections');
    return response.data;
  },

  // Disconnect an SCM provider
  disconnectProvider: async (connectionId) => {
    const response = await api.delete(`/api/scan/sast/connections/${connectionId}`);
    return response.data;
  },

  // List repositories from a connected SCM
  listRepositories: async (provider) => {
    const response = await api.get(`/api/scan/sast/repositories?provider=${provider}`);
    return response.data;
  },

  // Validate a personal access token
  validateToken: async (provider, accessToken) => {
    const response = await api.post('/api/scan/sast/validate-token', {
      provider,
      access_token: accessToken,
    });
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
  // Check if user has any verified domains (for routing decisions)
  hasVerifiedDomains: async () => {
    try {
      const response = await api.get('/api/domains/has-verified');
      return response.data;
    } catch (error) {
      console.error('Failed to check verified domains:', error);
      return { 
        has_domains: false, 
        is_personal_email: true, 
        can_scan: false,
        error: error.message 
      };
    }
  },

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

  // Check if user is authorized to scan a target URL
  checkAuthorization: async (targetUrl) => {
    try {
      const response = await api.get(`/api/domains/check-authorization?target_url=${encodeURIComponent(targetUrl)}`);
      return response.data;
    } catch (error) {
      // Return unauthorized with helpful message
      return {
        authorized: false,
        reason: 'error',
        message: error.response?.data?.detail || 'Failed to check authorization'
      };
    }
  },

  // Remove a verified domain
  removeVerifiedDomain: async (domain) => {
    const response = await api.delete(`/api/domains/verified/${encodeURIComponent(domain)}`);
    return response.data;
  },
};

// ============== Dashboard API ==============

export const dashboardAPI = {
  // Get overall security score (0-100) with platform breakdown
  getSecurityScore: async (days = 30) => {
    const response = await api.get(`/api/dashboard/security-score?days=${days}`);
    return response.data;
  },

  // Get risk heatmap matrix (Platform × Severity)
  getRiskHeatmap: async (days = 30) => {
    const response = await api.get(`/api/dashboard/risk-heatmap?days=${days}`);
    return response.data;
  },

  // Get platform risk breakdown for horizontal bars
  getPlatformBreakdown: async (days = 30) => {
    const response = await api.get(`/api/dashboard/platform-breakdown?days=${days}`);
    return response.data;
  },

  // Get aggregated scan statistics
  getScanStats: async (days = 30) => {
    const response = await api.get(`/api/dashboard/scan-stats?days=${days}`);
    return response.data;
  },

  // Get complete dashboard overview (optimized single call)
  getOverview: async (days = 30) => {
    const response = await api.get(`/api/dashboard/overview?days=${days}`);
    return response.data;
  },
};

// ============== Scan Manual Auth API ==============
// For handling social login (Google/Facebook/etc) and phone OTP targets

export const scanAuthAPI = {
  // Get manual auth status for a scan
  getStatus: async (scanId) => {
    const response = await api.get(`/api/scan-auth/${scanId}/status`);
    return response.data;
  },

  // Confirm user has completed manual login
  confirmLogin: async (scanId, options = {}) => {
    const response = await api.post(`/api/scan-auth/${scanId}/confirm`, {
      cookies: options.cookies || null,
      token: options.token || null,
    });
    return response.data;
  },

  // Cancel manual auth (continue scan unauthenticated)
  cancel: async (scanId) => {
    const response = await api.post(`/api/scan-auth/${scanId}/cancel`);
    return response.data;
  },

  // Provide session cookie/token directly
  provideSession: async (scanId, sessionData) => {
    const response = await api.post(`/api/scan-auth/${scanId}/session`, {
      session_cookie: sessionData.cookie || null,
      session_token: sessionData.token || null,
      cookie_name: sessionData.cookieName || 'session',
    });
    return response.data;
  },
};

// ============== Scan OTP API ==============
// For handling target app 2FA/OTP during scanning

export const scanOtpAPI = {
  // Get OTP status for a scan
  getStatus: async (scanId) => {
    const response = await api.get(`/api/scan-otp/${scanId}/status`);
    return response.data;
  },

  // Submit OTP code
  submitOtp: async (scanId, otpCode) => {
    const response = await api.post(`/api/scan-otp/${scanId}/submit`, {
      otp: otpCode,
    });
    return response.data;
  },

  // Get 2FA configuration for a scan
  get2faConfig: async (scanId) => {
    const response = await api.get(`/api/scan-otp/${scanId}/2fa-config`);
    return response.data;
  },
};

// ============== Two-Factor Authentication API ==============
// Uses backend 2FA system (not Firebase) for secure OTP via email/SMS

export const twoFactorAPI = {
  // Get user's current 2FA status
  getStatus: async () => {
    const response = await api.get('/api/2fa/status');
    return response.data;
  },

  // Initiate 2FA setup (sends OTP to email or phone)
  initiateSetup: async (channel, phoneNumber = null) => {
    const payload = { channel };
    if (channel === 'sms' && phoneNumber) {
      payload.phone_number = phoneNumber;
    }
    const response = await api.post('/api/2fa/setup/initiate', payload);
    return response.data;
  },

  // Verify OTP and complete 2FA setup
  verifySetup: async (otp) => {
    const response = await api.post('/api/2fa/setup/verify', { otp });
    return response.data;
  },

  // Update phone number for SMS 2FA
  updatePhone: async (phoneNumber) => {
    const response = await api.post('/api/2fa/setup/phone', { phone_number: phoneNumber });
    return response.data;
  },

  // Disable 2FA (requires password verification)
  disable: async (password, otp = null) => {
    const payload = { password };
    if (otp) payload.otp = otp;
    const response = await api.post('/api/2fa/disable', payload);
    return response.data;
  },

  // Send OTP code for login verification (called during login flow)
  sendCode: async (userId = null, channel = null) => {
    const payload = {};
    if (userId) payload.user_id = userId;
    if (channel) payload.channel = channel;
    const response = await api.post('/api/2fa/send-code', payload);
    return response.data;
  },

  // Verify OTP during login
  verify: async (otp, purpose = 'login_2fa') => {
    const response = await api.post('/api/2fa/verify', { otp, purpose });
    return response.data;
  },

  // Generate new backup codes (requires password confirmation for security)
  generateBackupCodes: async (password = null) => {
    const response = await api.post('/api/2fa/backup-codes/regenerate', { password });
    return response.data;
  },

  // Verify backup code (for account recovery)
  verifyBackupCode: async (code) => {
    const response = await api.post('/api/2fa/backup-codes/verify', { code });
    return response.data;
  },
};

// ============== User Settings API ==============
// Extended profile and preferences management

export const userSettingsAPI = {
  // Update extended profile (bio, job_title, social links)
  updateProfile: async (profileData) => {
    const response = await api.put('/api/users/me/profile', profileData);
    return response.data;
  },

  // Upload profile avatar
  uploadAvatar: async (file) => {
    const formData = new FormData();
    formData.append('avatar', file);
    const response = await api.post('/api/users/me/avatar', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },

  // Update notification settings
  updateNotifications: async (settings) => {
    const response = await api.put('/api/users/me/notifications', settings);
    return response.data;
  },

  // Update scan preferences
  updatePreferences: async (preferences) => {
    const response = await api.put('/api/users/me/preferences', preferences);
    return response.data;
  },

  // Export all user data (GDPR compliance)
  exportData: async () => {
    const response = await api.get('/api/users/me/export', {
      responseType: 'blob',
    });
    return response.data;
  },

  // Delete account (requires password confirmation)
  deleteAccount: async (password) => {
    const response = await api.delete('/api/users/me', {
      data: { password },
    });
    return response.data;
  },

  // Delete all scan data (soft delete)
  deleteAllData: async (password) => {
    const response = await api.delete('/api/users/me/data', {
      data: { password },
    });
    return response.data;
  },
};

// ============== Domain Verification API ==============

export const domainAPI = {
  // Generate verification code for a domain
  generateVerificationCode: async (domain) => {
    const response = await api.post('/api/domains/verify/generate', { domain });
    return response.data;
  },

  // Verify domain ownership
  verifyDomain: async (domain, method = 'txt') => {
    const response = await api.post('/api/domains/verify', { domain, method });
    return response.data;
  },

  // Check verification status
  checkStatus: async (domain) => {
    const response = await api.get(`/api/domains/verify/status?domain=${encodeURIComponent(domain)}`);
    return response.data;
  },

  // List verified domains
  listVerified: async () => {
    const response = await api.get('/api/domains/verified');
    return response.data;
  },

  // Remove verified domain
  removeVerified: async (domain) => {
    const response = await api.delete(`/api/domains/verified/${encodeURIComponent(domain)}`);
    return response.data;
  },
};

// ============== Health Check ==============

export const healthCheck = async () => {
  const response = await api.get('/api/health');
  return response.data;
};

// Export the axios instance for custom requests
export default api;
