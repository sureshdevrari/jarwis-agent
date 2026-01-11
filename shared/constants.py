"""
Shared Constants - Single Source of Truth

All constants shared between frontend and backend.
Frontend version is auto-generated from this file.

Usage:
    from shared.constants import PLAN_LIMITS, TokenLimits
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum


# ==================== SCAN TYPES ====================
class ScanTypes(str, Enum):
    WEB = "web"
    MOBILE = "mobile"
    CLOUD = "cloud"
    NETWORK = "network"
    API = "api"
    SAST = "sast"  # Source Code Analysis (Static Application Security Testing)


# ==================== SEVERITY LEVELS ====================
class SeverityLevels(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ==================== OWASP CATEGORIES ====================
class OWASPCategories(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021"
    A03_INJECTION = "A03:2021"
    A04_INSECURE_DESIGN = "A04:2021"
    A05_SECURITY_MISCONFIGURATION = "A05:2021"
    A06_VULNERABLE_COMPONENTS = "A06:2021"
    A07_AUTH_FAILURES = "A07:2021"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021"
    A09_LOGGING_FAILURES = "A09:2021"
    A10_SSRF = "A10:2021"


# ==================== PERSONAL EMAIL PROVIDERS ====================
# Users with personal emails must verify domains before scanning
FREE_EMAIL_PROVIDERS = [
    # Gmail and Google
    'gmail.com', 'googlemail.com',
    # Yahoo
    'yahoo.com', 'yahoo.co.in', 'yahoo.co.uk', 'yahoo.co.jp', 'yahoo.fr', 'yahoo.de',
    'ymail.com', 'rocketmail.com',
    # Microsoft
    'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'hotmail.co.uk',
    # AOL
    'aol.com', 'aim.com',
    # Apple
    'icloud.com', 'me.com', 'mac.com',
    # Privacy-focused
    'protonmail.com', 'proton.me', 'tutanota.com', 'tutamail.com',
    # Other free providers
    'zoho.com', 'mail.com', 'yandex.com', 'gmx.com', 'gmx.net',
    'rediffmail.com', 'inbox.com', 'fastmail.com',
    # Temporary/Disposable emails
    'mailinator.com', 'guerrillamail.com', 'tempmail.com',
    'throwaway.email', '10minutemail.com', 'temp-mail.org',
    'fakeinbox.com', 'getnada.com', 'mohmal.com',
]


def is_personal_email(email: str) -> bool:
    """
    Check if email is from a personal/free email provider.
    
    Personal email users must verify domain ownership before scanning.
    Corporate email users (e.g., user@company.com) can scan their own domain.
    
    Args:
        email: User's email address
        
    Returns:
        True if personal email, False if corporate email
    """
    if not email or '@' not in email:
        return True  # Invalid email treated as personal
    
    domain = email.split('@')[1].lower()
    return domain in FREE_EMAIL_PROVIDERS


# ==================== TOKEN LIMITS ====================
@dataclass
class TokenLimits:
    """Token limits per subscription plan (monthly)"""
    TRIAL = 0           # No chatbot access (admin assigns scans)
    FREE = 0            # No chatbot access (admin assigns scans after approval)
    INDIVIDUAL = 0      # No chatbot access (web-only scanning)
    PROFESSIONAL = 500_000  # 500K tokens/month (Suru 1.1 model)
    ENTERPRISE = 5_000_000  # 5M tokens/month (Savi 3.1 Thinking)


# ==================== RATE LIMITS ====================
@dataclass
class RateLimits:
    """Rate limits per endpoint category (requests/minute)"""
    AUTH_LOGIN = 5          # Brute force protection
    AUTH_REGISTER = 3       # Prevent spam
    SCAN_START = 10         # Scan rate
    CHAT_MESSAGE = 30       # Chat rate
    GENERAL_API = 60        # General API calls
    ADMIN_API = 100         # Admin operations


# ==================== PLAN FEATURES ====================
@dataclass
class PlanFeatures:
    """Features available in a plan"""
    basic_dast: bool = False
    owasp_top10: bool = False
    sans_top25: bool = False
    api_testing: bool = False
    credential_scanning: bool = False
    authenticated_scanning: bool = False
    mobile_app_testing: bool = False
    cloud_scanning: bool = False
    sast_scanning: bool = False  # Source Code Review
    chatbot_access: bool = False
    compliance_reports: bool = False
    ci_cd_integration: bool = False
    webhooks: bool = False
    api_access: bool = False
    custom_branding: bool = False
    sso_integration: bool = False
    dedicated_support: bool = False
    slack_integration: bool = False
    jira_integration: bool = False
    priority_scanning: bool = False
    advanced_reporting: bool = False
    scheduled_scans: bool = False
    real_time_alerts: bool = False
    export_formats: List[str] = None

    def __post_init__(self):
        if self.export_formats is None:
            self.export_formats = ["html"]


# ==================== PLAN LIMITS ====================
@dataclass
class PlanLimits:
    """Complete plan configuration"""
    id: str
    name: str
    price_monthly: int
    max_scans_per_month: int
    max_pages_per_scan: int
    max_team_members: int
    tokens_per_month: int
    report_retention_days: int
    support_level: str
    features: PlanFeatures
    display_features: List[str]
    limitations: List[str]


# Plan definitions - SINGLE SOURCE OF TRUTH
PLAN_LIMITS: Dict[str, PlanLimits] = {
    "trial": PlanLimits(
        id="trial",
        name="Trial",
        price_monthly=0,
        max_scans_per_month=3,
        max_pages_per_scan=50,
        max_team_members=1,
        tokens_per_month=0,
        report_retention_days=14,
        support_level="community",
        features=PlanFeatures(
            basic_dast=True,
            owasp_top10=True,
            sans_top25=True,
            export_formats=["html"],
        ),
        display_features=[
            "3 Scans per month",
            "Basic OWASP Top 10 detection",
            "14-day report access",
            "Corporate email required",
        ],
        limitations=[
            "Corporate email required",
            "Limited to public-facing pages only",
            "No API testing",
            "No credential-based scanning",
            "No chatbot access",
        ],
    ),
    
    "individual": PlanLimits(
        id="individual",
        name="Individual",
        price_monthly=100,  # Per scan pricing
        max_scans_per_month=1,  # 1 website only
        max_pages_per_scan=100,
        max_team_members=1,
        tokens_per_month=0,  # No chatbot access
        report_retention_days=7,  # Dashboard access up to 7 days
        support_level="email",
        features=PlanFeatures(
            basic_dast=True,
            owasp_top10=True,
            sans_top25=True,
            api_testing=False,  # No API testing
            credential_scanning=False,  # No credential-based scanning
            authenticated_scanning=False,  # No authenticated scanning
            mobile_app_testing=False,  # Web only
            cloud_scanning=False,  # Web only
            chatbot_access=False,  # No Jarwis AGI
            export_formats=["html", "pdf"],
        ),
        display_features=[
            "1 Website Only",
            "DAST (Public Facing Pages Only)",
            "OWASP Top 10 + SANS 25",
            "PDF Reports",
            "7-day dashboard access",
        ],
        limitations=[
            "No API testing",
            "No credential-based scanning",
            "No chatbot access",
            "Web scanning only",
            "1 user only",
        ],
    ),
    
    "free": PlanLimits(
        id="free",
        name="Free",
        price_monthly=0,
        max_scans_per_month=0,  # Admin assigns scans after approval
        max_pages_per_scan=50,
        max_team_members=1,
        tokens_per_month=0,
        report_retention_days=7,
        support_level="community",
        features=PlanFeatures(
            basic_dast=True,
            owasp_top10=True,
            sans_top25=True,
            api_testing=False,
            credential_scanning=False,
            authenticated_scanning=False,
            mobile_app_testing=False,
            cloud_scanning=False,
            chatbot_access=False,
            export_formats=["html"],
        ),
        display_features=[
            "Corporate email required",
            "Admin assigns scan quota",
            "Basic OWASP Top 10 detection",
            "HTML Reports",
        ],
        limitations=[
            "Corporate email required for registration",
            "Requires admin approval",
            "Scan quota set by admin",
            "No API testing",
            "No credential-based scanning",
            "No chatbot access",
        ],
    ),
    
    "professional": PlanLimits(
        id="professional",
        name="Professional",
        price_monthly=200,  # Per month
        max_scans_per_month=10,
        max_pages_per_scan=500,
        max_team_members=3,
        tokens_per_month=500_000,  # Suru 1.1 model
        report_retention_days=0,  # Until plan is active
        support_level="priority",
        features=PlanFeatures(
            basic_dast=True,
            owasp_top10=True,
            sans_top25=True,
            api_testing=True,
            credential_scanning=True,
            authenticated_scanning=True,
            mobile_app_testing=True,   # All scan types
            cloud_scanning=True,       # All scan types
            sast_scanning=True,        # Source code analysis
            chatbot_access=True,
            compliance_reports=True,
            advanced_reporting=True,
            scheduled_scans=True,
            export_formats=["html", "pdf", "json", "sarif"],
        ),
        display_features=[
            "10 Scans per month (Web, Mobile, Cloud, SAST)",
            "DAST with Credentials-based scanning",
            "Includes API Testing",
            "Mobile & Cloud Security Scanning",
            "Jarwis AGI - Suru 1.1 (500K tokens/month)",
            "Up to 3 Users can access dashboard",
            "Dashboard Access until plan is active",
        ],
        limitations=[
            "10 scans limit per month",
        ],
    ),
    
    "enterprise": PlanLimits(
        id="enterprise",
        name="Enterprise",
        price_monthly=499,
        max_scans_per_month=999999,  # Unlimited
        max_pages_per_scan=999999,   # Unlimited
        max_team_members=999999,     # Unlimited
        tokens_per_month=5_000_000,
        report_retention_days=365,
        support_level="dedicated",
        features=PlanFeatures(
            basic_dast=True,
            owasp_top10=True,
            sans_top25=True,
            api_testing=True,
            credential_scanning=True,
            authenticated_scanning=True,
            mobile_app_testing=True,
            cloud_scanning=True,
            sast_scanning=True,  # Source code analysis
            chatbot_access=True,
            compliance_reports=True,
            ci_cd_integration=True,
            webhooks=True,
            api_access=True,
            custom_branding=True,
            sso_integration=True,
            dedicated_support=True,
            slack_integration=True,
            jira_integration=True,
            priority_scanning=True,
            advanced_reporting=True,
            scheduled_scans=True,
            real_time_alerts=True,
            export_formats=["html", "pdf", "json", "sarif", "csv"],
        ),
        display_features=[
            "Unlimited scans",
            "All security testing features (SAST included)",
            "Mobile & Cloud scanning",
            "AI Chatbot (5M tokens)",
            "Unlimited team members",
            "365-day report retention",
            "CI/CD integration",
            "Dedicated support",
            "Custom branding",
            "SSO integration",
        ],
        limitations=[],
    ),
    
    # TODO: REMOVE BEFORE PRODUCTION - Developer testing account
    "developer": PlanLimits(
        id="developer",
        name="Developer",
        price_monthly=0,
        max_scans_per_month=999999999,  # Unlimited
        max_pages_per_scan=999999999,   # Unlimited
        max_team_members=999999,        # Unlimited
        tokens_per_month=999999999,     # Unlimited
        report_retention_days=999999,   # Forever
        support_level="internal",
        features=PlanFeatures(
            basic_dast=True,
            owasp_top10=True,
            sans_top25=True,
            api_testing=True,
            credential_scanning=True,
            authenticated_scanning=True,
            mobile_app_testing=True,
            cloud_scanning=True,
            sast_scanning=True,
            chatbot_access=True,
            compliance_reports=True,
            ci_cd_integration=True,
            webhooks=True,
            api_access=True,
            custom_branding=True,
            sso_integration=True,
            dedicated_support=True,
            slack_integration=True,
            jira_integration=True,
            priority_scanning=True,
            advanced_reporting=True,
            scheduled_scans=True,
            real_time_alerts=True,
            export_formats=["html", "pdf", "json", "sarif", "csv", "xml"],
        ),
        display_features=[
            "DEVELOPER ACCESS - UNLIMITED EVERYTHING",
            "For internal testing only",
        ],
        limitations=[],
    ),
}


# ==================== SESSION SETTINGS ====================
@dataclass
class SessionSettings:
    """Session and token settings"""
    ACCESS_TOKEN_EXPIRE_MINUTES = 15
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    SESSION_INACTIVITY_TIMEOUT_HOURS = 3
    MAX_SESSIONS_PER_USER = 5


# ==================== SCAN SETTINGS ====================
@dataclass
class ScanSettings:
    """Default scan configuration"""
    DEFAULT_RATE_LIMIT = 10  # requests/second
    MAX_CRAWL_DEPTH = 5
    MAX_URLS_PER_SCAN = 500
    SCAN_TIMEOUT_MINUTES = 60
    OTP_TIMEOUT_SECONDS = 300
    OTP_MAX_ATTEMPTS = 3


# ==================== FILE UPLOAD SETTINGS ====================
@dataclass
class FileUploadSettings:
    """File upload constraints"""
    MAX_APK_SIZE_MB = 100
    MAX_IPA_SIZE_MB = 200
    ALLOWED_MOBILE_EXTENSIONS = [".apk", ".ipa", ".aab"]
    UPLOAD_DIR = "uploads"


# Export for frontend generation
def get_plan_limits_for_frontend() -> dict:
    """Convert plan limits to frontend-compatible format"""
    result = {}
    for plan_id, plan in PLAN_LIMITS.items():
        result[plan_id] = {
            "id": plan.id,
            "name": plan.name,
            "priceMonthly": plan.price_monthly,
            "maxScansPerMonth": plan.max_scans_per_month,
            "maxPagesPerScan": plan.max_pages_per_scan,
            "maxTeamMembers": plan.max_team_members,
            "tokensPerMonth": plan.tokens_per_month,
            "reportRetentionDays": plan.report_retention_days,
            "supportLevel": plan.support_level,
            "features": {
                "basicDAST": plan.features.basic_dast,
                "owaspTop10": plan.features.owasp_top10,
                "sansTop25": plan.features.sans_top25,
                "apiTesting": plan.features.api_testing,
                "credentialScanning": plan.features.credential_scanning,
                "authenticatedScanning": plan.features.authenticated_scanning,
                "mobileAppTesting": plan.features.mobile_app_testing,
                "cloudScanning": plan.features.cloud_scanning,
                "sastScanning": plan.features.sast_scanning,
                "chatbotAccess": plan.features.chatbot_access,
                "complianceReports": plan.features.compliance_reports,
                "ciCdIntegration": plan.features.ci_cd_integration,
                "webhooks": plan.features.webhooks,
                "apiAccess": plan.features.api_access,
                "customBranding": plan.features.custom_branding,
                "ssoIntegration": plan.features.sso_integration,
                "dedicatedSupport": plan.features.dedicated_support,
                "slackIntegration": plan.features.slack_integration,
                "jiraIntegration": plan.features.jira_integration,
                "priorityScanning": plan.features.priority_scanning,
                "advancedReporting": plan.features.advanced_reporting,
                "scheduledScans": plan.features.scheduled_scans,
                "realTimeAlerts": plan.features.real_time_alerts,
                "exportFormats": plan.features.export_formats,
            },
            "displayFeatures": plan.display_features,
            "limitations": plan.limitations,
        }
    return result
