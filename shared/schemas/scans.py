"""
Scan Response Schemas

All scan-related request/response models.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime
from uuid import UUID
from enum import Enum


class ScanType(str, Enum):
    WEB = "web"
    MOBILE = "mobile"
    CLOUD = "cloud"
    NETWORK = "network"
    API = "api"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    WAITING_FOR_OTP = "waiting_for_otp"
    WAITING_FOR_MANUAL_AUTH = "waiting_for_manual_auth"  # Social/manual login


class AuthMethod(str, Enum):
    """Authentication method for target app scanning"""
    NONE = "none"                      # Skip auth, test unauthenticated only
    USERNAME_PASSWORD = "username_password"  # Traditional login form
    SOCIAL_LOGIN = "social_login"       # Google/Facebook/LinkedIn/Apple - manual
    PHONE_OTP = "phone_otp"            # Phone number + OTP
    EMAIL_MAGIC_LINK = "email_magic_link"  # Passwordless email link
    MANUAL_SESSION = "manual_session"   # User provides session cookie/token


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ==================== Scan Responses ====================
class ScanResponse(BaseModel):
    """Scan creation/status response"""
    id: UUID
    scan_id: str  # Friendly scan ID
    target_url: str
    scan_type: ScanType
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0  # 0-100
    phase: Optional[str] = None  # Current scan phase
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    can_resume: bool = False  # Whether a failed/stopped scan can be resumed
    
    class Config:
        from_attributes = True


class ScanStatusResponse(BaseModel):
    """Detailed scan status with logs"""
    id: UUID
    scan_id: str
    status: ScanStatus
    progress: int
    current_phase: Optional[str] = None
    message: Optional[str] = None
    logs: List[str] = []
    # OTP fields
    waiting_for_otp: bool = False
    otp_type: Optional[str] = None
    otp_contact: Optional[str] = None
    # Manual auth fields (for social login / manual session)
    waiting_for_manual_auth: bool = False
    auth_method: Optional[str] = None  # social_login, manual_session, etc.
    manual_auth_url: Optional[str] = None  # URL to open for manual login
    manual_auth_instructions: Optional[str] = None  # Instructions for user


class ScanListResponse(BaseModel):
    """List of scans response"""
    scans: List[ScanResponse]
    total: int
    page: int = 1
    page_size: int = 20


# ==================== Finding Responses ====================
class FindingResponse(BaseModel):
    """Individual vulnerability finding"""
    id: str
    scan_id: str
    category: str  # OWASP category: A01, A02, etc.
    severity: SeverityLevel
    title: str
    description: str
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    poc: Optional[str] = None  # Proof of concept
    reasoning: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = []
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    detected_at: datetime
    
    class Config:
        from_attributes = True


class FindingListResponse(BaseModel):
    """List of findings response"""
    findings: List[FindingResponse]
    total: int
    by_severity: Dict[str, int] = {}


# ==================== Report Responses ====================
class ReportResponse(BaseModel):
    """Report metadata"""
    name: str
    path: str
    scan_id: str
    created_at: datetime
    format: str  # html, pdf, json, sarif
    size_bytes: int


class ReportListResponse(BaseModel):
    """List of reports"""
    reports: List[ReportResponse]
    total: int


# ==================== Scan Requests ====================
class ScanCreateRequest(BaseModel):
    """Create new scan request"""
    target_url: str
    scan_type: ScanType = ScanType.WEB
    # Authentication configuration
    auth_method: AuthMethod = AuthMethod.NONE  # How to authenticate to target
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    # For phone OTP auth
    phone_number: Optional[str] = None
    # For manual session (user-provided cookies/tokens)
    session_cookie: Optional[str] = None
    session_token: Optional[str] = None
    # Social login providers enabled on target
    social_providers: Optional[List[str]] = None  # ["google", "facebook", "linkedin", "apple"]
    config: Optional[Dict[str, Any]] = None


class MobileScanCreateRequest(BaseModel):
    """Create mobile scan request"""
    app_name: Optional[str] = None
    platform: str = "android"  # android, ios
    deep_scan: bool = False
    check_permissions: bool = True
    check_ssl: bool = True
    check_storage: bool = True


class CloudScanCreateRequest(BaseModel):
    """Create cloud scan request"""
    provider: str  # aws, azure, gcp
    credentials: Dict[str, str]
    scan_iam: bool = True
    scan_storage: bool = True
    scan_network: bool = True


class NetworkScanCreateRequest(BaseModel):
    """Create network scan request"""
    target: str  # IP, CIDR, or hostname
    scan_type: str = "quick"  # quick, full, stealth
    port_range: str = "1-1000"
    include_vuln_scan: bool = False
