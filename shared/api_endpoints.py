"""
API Endpoints - Single Source of Truth

ALL API endpoints are defined here. Backend routes and frontend
must use these definitions to ensure consistency.

Usage (Backend):
    from shared.api_endpoints import APIEndpoints
    router = APIRouter(prefix=APIEndpoints.AUTH_PREFIX, ...)

Usage (Frontend - auto-generated):
    import { ENDPOINTS } from './config/endpoints';
    await api.get(ENDPOINTS.AUTH.ME);

To add a new endpoint:
1. Add it here with proper documentation
2. Run: python shared/generate_frontend_types.py
3. Frontend endpoints.js is automatically updated
"""

from typing import Optional


def build_endpoint(template: str, **kwargs) -> str:
    """Build endpoint URL from template with parameters"""
    result = template
    for key, value in kwargs.items():
        result = result.replace(f"{{{key}}}", str(value))
    return result


class APIEndpoints:
    """
    All API endpoints organized by module.
    
    Naming convention:
    - PREFIX: Router prefix (e.g., /api/auth)
    - Endpoint names: VERB_RESOURCE (e.g., GET_ME, POST_LOGIN)
    """
    
    # ==================== AUTH ====================
    AUTH_PREFIX = "/api/auth"
    
    # Auth endpoints (relative to prefix)
    AUTH_REGISTER = "/register"
    AUTH_LOGIN = "/login"
    AUTH_LOGOUT = "/logout"
    AUTH_LOGOUT_ALL = "/logout/all"
    AUTH_REFRESH = "/refresh"
    AUTH_ME = "/me"
    AUTH_CHANGE_PASSWORD = "/change-password"
    AUTH_FORGOT_PASSWORD = "/forgot-password"
    AUTH_RESET_PASSWORD = "/reset-password"
    AUTH_LOGIN_HISTORY = "/login-history"
    AUTH_SESSIONS = "/sessions"
    
    # Full paths (for frontend)
    @classmethod
    def auth_full(cls, endpoint: str) -> str:
        return f"{cls.AUTH_PREFIX}{endpoint}"
    
    # ==================== USERS ====================
    USERS_PREFIX = "/api/users"
    
    USERS_LIST = "/"
    USERS_GET = "/{user_id}"
    USERS_UPDATE = "/{user_id}"
    USERS_DELETE = "/{user_id}"
    USERS_SUBSCRIPTION = "/{user_id}/subscription"
    
    # ==================== SCANS ====================
    SCANS_PREFIX = "/api/scans"
    
    SCANS_CREATE = "/"
    SCANS_LIST = "/all"
    SCANS_RUNNING = "/running"
    SCANS_LAST = "/last"
    SCANS_GET = "/{scan_id}"
    SCANS_STOP = "/{scan_id}/stop"
    SCANS_LOGS = "/{scan_id}/logs"
    SCANS_FINDINGS = "/{scan_id}/findings"
    SCANS_REPORT = "/{scan_id}/report"
    SCANS_REPORT_PDF = "/{scan_id}/report/pdf"
    SCANS_REPORT_JSON = "/{scan_id}/report/json"
    SCANS_REPORT_SARIF = "/{scan_id}/report/sarif"
    
    @classmethod
    def scan_by_id(cls, scan_id: str, endpoint: str = "") -> str:
        """Build scan endpoint with ID"""
        base = f"{cls.SCANS_PREFIX}/{scan_id}"
        return f"{base}{endpoint}" if endpoint else base
    
    # ==================== MOBILE SCANS ====================
    MOBILE_PREFIX = "/api/scan/mobile"
    
    MOBILE_START = "/start"
    MOBILE_LIST = "/"
    MOBILE_STATUS = "/{scan_id}/status"
    MOBILE_LOGS = "/{scan_id}/logs"
    MOBILE_STOP = "/{scan_id}/stop"
    
    # ==================== CLOUD SCANS ====================
    CLOUD_PREFIX = "/api/scan/cloud"
    
    CLOUD_START = "/start"
    CLOUD_LIST = "/"
    CLOUD_STATUS = "/{scan_id}/status"
    CLOUD_PROVIDERS = "/providers"
    
    # ==================== NETWORK SCANS ====================
    NETWORK_PREFIX = "/api/network"
    
    NETWORK_TOOLS = "/tools"
    NETWORK_QUICK_SCAN = "/quick-scan"
    NETWORK_FULL_SCAN = "/full-scan"
    NETWORK_STATUS = "/{scan_id}/status"
    NETWORK_STOP = "/{scan_id}/stop"
    NETWORK_DASHBOARD_SUMMARY = "/dashboard/summary"
    NETWORK_SCANS_LIST = "/scans"
    
    # ==================== DOMAINS ====================
    DOMAINS_PREFIX = "/api/domains"
    
    DOMAINS_VERIFY_STATUS = "/verify/status"
    DOMAINS_VERIFY_GENERATE = "/verify/generate"
    DOMAINS_VERIFY_CHECK_TXT = "/verify/check-txt"
    DOMAINS_VERIFY = "/verify"
    DOMAINS_LIST_VERIFIED = "/verified"
    
    # ==================== SCAN OTP ====================
    SCAN_OTP_PREFIX = "/api/scan-otp"
    
    SCAN_OTP_STATUS = "/{scan_id}/status"
    SCAN_OTP_SUBMIT = "/{scan_id}/submit"
    SCAN_OTP_CONFIG = "/{scan_id}/2fa-config"
    
    # ==================== TWO FACTOR ====================
    TWO_FACTOR_PREFIX = "/api/2fa"
    
    TWO_FACTOR_SETUP = "/setup"
    TWO_FACTOR_VERIFY = "/verify"
    TWO_FACTOR_DISABLE = "/disable"
    TWO_FACTOR_STATUS = "/status"
    TWO_FACTOR_SEND_CODE = "/send-code"
    TWO_FACTOR_BACKUP_CODES = "/backup-codes"
    TWO_FACTOR_REGENERATE_BACKUP = "/backup-codes/regenerate"
    
    # ==================== AUTH 2FA ====================
    AUTH_LOGIN_2FA = "/login/2fa"  # For 2FA verification during login
    
    # ==================== USER SETTINGS ====================
    USER_SETTINGS_PREFIX = "/api/users/me"
    
    USER_SETTINGS_ACCOUNT = "/account"
    USER_SETTINGS_PROFILE = "/profile"
    USER_SETTINGS_PREFERENCES = "/preferences"
    USER_SETTINGS_NOTIFICATIONS = "/notifications"
    USER_SETTINGS_PASSWORD = "/password"
    USER_SETTINGS_DELETE = "/delete"
    USER_SETTINGS_EXPORT = "/data/export"
    USER_SETTINGS_DELETE_DATA = "/data/delete"
    USER_SETTINGS_SESSIONS = "/sessions"
    USER_SETTINGS_SESSION_REVOKE = "/sessions/{session_id}/revoke"
    USER_SETTINGS_WEBHOOKS = "/webhooks"
    USER_SETTINGS_WEBHOOK_DETAIL = "/webhooks/{webhook_id}"
    USER_SETTINGS_WEBHOOK_TEST = "/webhooks/{webhook_id}/test"
    
    # ==================== CHAT ====================
    CHAT_PREFIX = "/api/chat"
    
    CHAT_SEND = ""  # POST /api/chat
    CHAT_UPLOAD = "/upload"
    CHAT_HISTORY = "/history"
    CHAT_USAGE = "/usage"
    
    # ==================== ADMIN ====================
    ADMIN_PREFIX = "/api/admin"
    
    ADMIN_DASHBOARD = "/dashboard"
    ADMIN_USERS = "/users"
    ADMIN_USER_DETAIL = "/users/{user_id}"
    ADMIN_USER_APPROVE = "/users/{user_id}/approve"
    ADMIN_USER_REJECT = "/users/{user_id}/reject"
    ADMIN_USER_SET_PLAN = "/users/{user_id}/set-plan"
    ADMIN_PLANS = "/plans"
    ADMIN_CONTACT_SUBMISSIONS = "/contact-submissions"
    
    # ==================== PAYMENTS ====================
    PAYMENTS_PREFIX = "/api/payments"
    
    PAYMENTS_CREATE_ORDER = "/create-order"
    PAYMENTS_VERIFY = "/verify"
    PAYMENTS_HISTORY = "/history"
    PAYMENTS_PLANS = "/plans"
    
    # ==================== CONTACT ====================
    CONTACT_PREFIX = "/api"
    CONTACT_SUBMIT = "/contact"
    
    # ==================== REPORTS ====================
    REPORTS_PREFIX = "/api/reports"
    
    REPORTS_LIST = "/"
    REPORTS_LATEST = "/latest"
    REPORTS_GET = "/{report_name}"
    REPORTS_PDF = "/{report_name}/pdf"
    
    # ==================== HEALTH ====================
    HEALTH = "/api/health"
    
    # ==================== DASHBOARD ====================
    DASHBOARD_PREFIX = "/api/dashboard"
    
    DASHBOARD_SECURITY_SCORE = "/security-score"
    DASHBOARD_RISK_HEATMAP = "/risk-heatmap"
    DASHBOARD_PLATFORM_BREAKDOWN = "/platform-breakdown"
    DASHBOARD_SCAN_STATS = "/scan-stats"
    DASHBOARD_OVERVIEW = "/overview"
    
    # ==================== OAUTH ====================
    OAUTH_PREFIX = "/api/oauth"
    
    OAUTH_GOOGLE = "/google"
    OAUTH_GOOGLE_CALLBACK = "/google/callback"
    
    # ==================== SAST (Source Code Analysis) ====================
    SAST_PREFIX = "/api/scan/sast"
    
    SAST_START = "/start"
    SAST_LIST = "/"
    SAST_STATUS = "/{scan_id}/status"
    SAST_LOGS = "/{scan_id}/logs"
    SAST_STOP = "/{scan_id}/stop"
    
    # SCM Integration endpoints
    SAST_CONNECT_GITHUB = "/github/connect"
    SAST_GITHUB_CALLBACK = "/github/callback"
    SAST_CONNECT_GITLAB = "/gitlab/connect"
    SAST_GITLAB_CALLBACK = "/gitlab/callback"
    SAST_REPOSITORIES = "/repositories"
    SAST_CONNECTIONS = "/connections"
    SAST_DISCONNECT = "/connections/{connection_id}"
    SAST_VALIDATE_TOKEN = "/validate-token"


# Export for easy frontend generation
ENDPOINT_GROUPS = {
    "AUTH": {
        "prefix": APIEndpoints.AUTH_PREFIX,
        "endpoints": {
            "REGISTER": APIEndpoints.AUTH_REGISTER,
            "LOGIN": APIEndpoints.AUTH_LOGIN,
            "LOGIN_2FA": APIEndpoints.AUTH_LOGIN_2FA,
            "LOGOUT": APIEndpoints.AUTH_LOGOUT,
            "LOGOUT_ALL": APIEndpoints.AUTH_LOGOUT_ALL,
            "REFRESH": APIEndpoints.AUTH_REFRESH,
            "ME": APIEndpoints.AUTH_ME,
            "CHANGE_PASSWORD": APIEndpoints.AUTH_CHANGE_PASSWORD,
            "LOGIN_HISTORY": APIEndpoints.AUTH_LOGIN_HISTORY,
            "SESSIONS": APIEndpoints.AUTH_SESSIONS,
        }
    },
    "SCANS": {
        "prefix": APIEndpoints.SCANS_PREFIX,
        "endpoints": {
            "CREATE": APIEndpoints.SCANS_CREATE,
            "LIST": APIEndpoints.SCANS_LIST,
            "RUNNING": APIEndpoints.SCANS_RUNNING,
            "LAST": APIEndpoints.SCANS_LAST,
            "GET": APIEndpoints.SCANS_GET,
            "STOP": APIEndpoints.SCANS_STOP,
            "LOGS": APIEndpoints.SCANS_LOGS,
            "FINDINGS": APIEndpoints.SCANS_FINDINGS,
            "REPORT": APIEndpoints.SCANS_REPORT,
            "REPORT_PDF": APIEndpoints.SCANS_REPORT_PDF,
        }
    },
    "MOBILE": {
        "prefix": APIEndpoints.MOBILE_PREFIX,
        "endpoints": {
            "START": APIEndpoints.MOBILE_START,
            "LIST": APIEndpoints.MOBILE_LIST,
            "STATUS": APIEndpoints.MOBILE_STATUS,
            "LOGS": APIEndpoints.MOBILE_LOGS,
            "STOP": APIEndpoints.MOBILE_STOP,
        }
    },
    "CLOUD": {
        "prefix": APIEndpoints.CLOUD_PREFIX,
        "endpoints": {
            "START": APIEndpoints.CLOUD_START,
            "LIST": APIEndpoints.CLOUD_LIST,
            "STATUS": APIEndpoints.CLOUD_STATUS,
            "PROVIDERS": APIEndpoints.CLOUD_PROVIDERS,
        }
    },
    "NETWORK": {
        "prefix": APIEndpoints.NETWORK_PREFIX,
        "endpoints": {
            "TOOLS": APIEndpoints.NETWORK_TOOLS,
            "QUICK_SCAN": APIEndpoints.NETWORK_QUICK_SCAN,
            "FULL_SCAN": APIEndpoints.NETWORK_FULL_SCAN,
            "STATUS": APIEndpoints.NETWORK_STATUS,
            "STOP": APIEndpoints.NETWORK_STOP,
            "DASHBOARD_SUMMARY": APIEndpoints.NETWORK_DASHBOARD_SUMMARY,
            "LIST": APIEndpoints.NETWORK_SCANS_LIST,
        }
    },
    "DOMAINS": {
        "prefix": APIEndpoints.DOMAINS_PREFIX,
        "endpoints": {
            "VERIFY_STATUS": APIEndpoints.DOMAINS_VERIFY_STATUS,
            "VERIFY_GENERATE": APIEndpoints.DOMAINS_VERIFY_GENERATE,
            "VERIFY_CHECK_TXT": APIEndpoints.DOMAINS_VERIFY_CHECK_TXT,
            "VERIFY": APIEndpoints.DOMAINS_VERIFY,
            "LIST_VERIFIED": APIEndpoints.DOMAINS_LIST_VERIFIED,
        }
    },
    "SCAN_OTP": {
        "prefix": APIEndpoints.SCAN_OTP_PREFIX,
        "endpoints": {
            "STATUS": APIEndpoints.SCAN_OTP_STATUS,
            "SUBMIT": APIEndpoints.SCAN_OTP_SUBMIT,
            "CONFIG": APIEndpoints.SCAN_OTP_CONFIG,
        }
    },
    "TWO_FACTOR": {
        "prefix": APIEndpoints.TWO_FACTOR_PREFIX,
        "endpoints": {
            "SETUP": APIEndpoints.TWO_FACTOR_SETUP,
            "VERIFY": APIEndpoints.TWO_FACTOR_VERIFY,
            "DISABLE": APIEndpoints.TWO_FACTOR_DISABLE,
            "STATUS": APIEndpoints.TWO_FACTOR_STATUS,
            "SEND_CODE": APIEndpoints.TWO_FACTOR_SEND_CODE,
            "BACKUP_CODES": APIEndpoints.TWO_FACTOR_BACKUP_CODES,
            "REGENERATE_BACKUP": APIEndpoints.TWO_FACTOR_REGENERATE_BACKUP,
        }
    },
    "USER_SETTINGS": {
        "prefix": APIEndpoints.USER_SETTINGS_PREFIX,
        "endpoints": {
            "ACCOUNT": APIEndpoints.USER_SETTINGS_ACCOUNT,
            "PROFILE": APIEndpoints.USER_SETTINGS_PROFILE,
            "PREFERENCES": APIEndpoints.USER_SETTINGS_PREFERENCES,
            "NOTIFICATIONS": APIEndpoints.USER_SETTINGS_NOTIFICATIONS,
            "PASSWORD": APIEndpoints.USER_SETTINGS_PASSWORD,
            "DELETE": APIEndpoints.USER_SETTINGS_DELETE,
            "EXPORT": APIEndpoints.USER_SETTINGS_EXPORT,
            "DELETE_DATA": APIEndpoints.USER_SETTINGS_DELETE_DATA,
            "SESSIONS": APIEndpoints.USER_SETTINGS_SESSIONS,
            "SESSION_REVOKE": APIEndpoints.USER_SETTINGS_SESSION_REVOKE,
            "WEBHOOKS": APIEndpoints.USER_SETTINGS_WEBHOOKS,
            "WEBHOOK_DETAIL": APIEndpoints.USER_SETTINGS_WEBHOOK_DETAIL,
            "WEBHOOK_TEST": APIEndpoints.USER_SETTINGS_WEBHOOK_TEST,
        }
    },
    "CHAT": {
        "prefix": APIEndpoints.CHAT_PREFIX,
        "endpoints": {
            "SEND": APIEndpoints.CHAT_SEND,
            "UPLOAD": APIEndpoints.CHAT_UPLOAD,
            "HISTORY": APIEndpoints.CHAT_HISTORY,
            "USAGE": APIEndpoints.CHAT_USAGE,
        }
    },
    "ADMIN": {
        "prefix": APIEndpoints.ADMIN_PREFIX,
        "endpoints": {
            "DASHBOARD": APIEndpoints.ADMIN_DASHBOARD,
            "USERS": APIEndpoints.ADMIN_USERS,
            "USER_DETAIL": APIEndpoints.ADMIN_USER_DETAIL,
            "USER_APPROVE": APIEndpoints.ADMIN_USER_APPROVE,
            "USER_REJECT": APIEndpoints.ADMIN_USER_REJECT,
            "USER_SET_PLAN": APIEndpoints.ADMIN_USER_SET_PLAN,
            "PLANS": APIEndpoints.ADMIN_PLANS,
        }
    },
    "PAYMENTS": {
        "prefix": APIEndpoints.PAYMENTS_PREFIX,
        "endpoints": {
            "CREATE_ORDER": APIEndpoints.PAYMENTS_CREATE_ORDER,
            "VERIFY": APIEndpoints.PAYMENTS_VERIFY,
            "HISTORY": APIEndpoints.PAYMENTS_HISTORY,
            "PLANS": APIEndpoints.PAYMENTS_PLANS,
        }
    },
    "REPORTS": {
        "prefix": APIEndpoints.REPORTS_PREFIX,
        "endpoints": {
            "LIST": APIEndpoints.REPORTS_LIST,
            "LATEST": APIEndpoints.REPORTS_LATEST,
            "GET": APIEndpoints.REPORTS_GET,
            "PDF": APIEndpoints.REPORTS_PDF,
        }
    },
    "DASHBOARD": {
        "prefix": APIEndpoints.DASHBOARD_PREFIX,
        "endpoints": {
            "SECURITY_SCORE": APIEndpoints.DASHBOARD_SECURITY_SCORE,
            "RISK_HEATMAP": APIEndpoints.DASHBOARD_RISK_HEATMAP,
            "PLATFORM_BREAKDOWN": APIEndpoints.DASHBOARD_PLATFORM_BREAKDOWN,
            "SCAN_STATS": APIEndpoints.DASHBOARD_SCAN_STATS,
            "OVERVIEW": APIEndpoints.DASHBOARD_OVERVIEW,
        }
    },
    "SAST": {
        "prefix": APIEndpoints.SAST_PREFIX,
        "endpoints": {
            "START": APIEndpoints.SAST_START,
            "LIST": APIEndpoints.SAST_LIST,
            "STATUS": APIEndpoints.SAST_STATUS,
            "LOGS": APIEndpoints.SAST_LOGS,
            "STOP": APIEndpoints.SAST_STOP,
            "CONNECT_GITHUB": APIEndpoints.SAST_CONNECT_GITHUB,
            "GITHUB_CALLBACK": APIEndpoints.SAST_GITHUB_CALLBACK,
            "CONNECT_GITLAB": APIEndpoints.SAST_CONNECT_GITLAB,
            "GITLAB_CALLBACK": APIEndpoints.SAST_GITLAB_CALLBACK,
            "REPOSITORIES": APIEndpoints.SAST_REPOSITORIES,
            "CONNECTIONS": APIEndpoints.SAST_CONNECTIONS,
            "DISCONNECT": APIEndpoints.SAST_DISCONNECT,
            "VALIDATE_TOKEN": APIEndpoints.SAST_VALIDATE_TOKEN,
        }
    },
    "HEALTH": {
        "prefix": "",
        "endpoints": {
            "CHECK": APIEndpoints.HEALTH,
        }
    }
}
