"""
Pydantic Schemas for API Request/Response
"""

import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ============== User Schemas ==============

class UserBase(BaseModel):
    """Base user schema"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    full_name: Optional[str] = None
    company: Optional[str] = None


class UserCreate(UserBase):
    """Schema for user registration"""
    password: str = Field(..., min_length=8, max_length=100)


class UserUpdate(BaseModel):
    """Schema for updating user profile"""
    full_name: Optional[str] = None
    company: Optional[str] = None
    email: Optional[EmailStr] = None


class UserResponse(UserBase):
    """Schema for user response"""
    id: uuid.UUID
    is_active: bool
    is_verified: bool
    plan: str
    approval_status: str = "pending"
    # Subscription limits
    max_users: int = 1
    max_websites: int = 1
    scans_this_month: int = 0
    dashboard_access_days: int = 7
    has_api_testing: bool = False
    has_credential_scanning: bool = False
    has_chatbot_access: bool = False
    has_mobile_pentest: bool = False
    has_compliance_audits: bool = False
    has_dedicated_support: bool = False
    subscription_start: Optional[datetime] = None
    subscription_end: Optional[datetime] = None
    created_at: datetime
    last_login: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class UserInDB(UserResponse):
    """Schema for user in database (includes hashed password)"""
    hashed_password: str


# ============== Auth Schemas ==============

class Token(BaseModel):
    """JWT token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class TokenPayload(BaseModel):
    """JWT token payload"""
    sub: str  # user_id
    exp: datetime
    type: str  # access or refresh


class LoginRequest(BaseModel):
    """Login request schema - accepts email or username"""
    email: str = Field(..., description="Email address or username")
    password: str


class RefreshRequest(BaseModel):
    """Token refresh request"""
    refresh_token: str


class PasswordChange(BaseModel):
    """Password change request"""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)


class PasswordReset(BaseModel):
    """Password reset request"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation"""
    token: str
    new_password: str = Field(..., min_length=8, max_length=100)


# ============== API Key Schemas ==============

class APIKeyCreate(BaseModel):
    """Create API key request"""
    name: str = Field(..., min_length=1, max_length=100)
    expires_in_days: Optional[int] = None  # None = never expires


class APIKeyResponse(BaseModel):
    """API key response (only shown once on creation)"""
    id: uuid.UUID
    name: str
    key: str  # The actual API key - only shown once!
    created_at: datetime
    expires_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class APIKeyInfo(BaseModel):
    """API key info (without the actual key)"""
    id: uuid.UUID
    name: str
    is_active: bool
    last_used_at: Optional[datetime] = None
    usage_count: int
    created_at: datetime
    expires_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


# ============== Network Scan Credential Schemas (Nessus-style) ==============

class SSHCredential(BaseModel):
    """SSH credential for authenticated network scanning"""
    username: str
    auth_method: str = Field(default="password", pattern="^(password|key|key_passphrase)$")
    password: Optional[str] = None
    private_key: Optional[str] = None  # PEM format
    private_key_passphrase: Optional[str] = None
    port: int = 22
    known_hosts_checking: bool = False
    privilege_escalation: Optional[str] = Field(default=None, pattern="^(sudo|su|pbrun|cisco_enable)$")
    escalation_account: Optional[str] = None
    escalation_password: Optional[str] = None


class WindowsCredential(BaseModel):
    """Windows credential for authenticated network scanning"""
    username: str
    password: str
    domain: Optional[str] = None
    auth_method: str = Field(default="password", pattern="^(password|ntlm|kerberos)$")


class SNMPCredential(BaseModel):
    """SNMP credential for network device scanning"""
    version: str = Field(default="v2c", pattern="^(v1|v2c|v3)$")
    community_string: Optional[str] = None  # For v1/v2c
    # SNMPv3 fields
    security_level: Optional[str] = Field(default=None, pattern="^(noAuthNoPriv|authNoPriv|authPriv)$")
    username: Optional[str] = None
    auth_protocol: Optional[str] = Field(default=None, pattern="^(MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)$")
    auth_password: Optional[str] = None
    privacy_protocol: Optional[str] = Field(default=None, pattern="^(DES|3DES|AES|AES-192|AES-256)$")
    privacy_password: Optional[str] = None


class DatabaseCredential(BaseModel):
    """Database credential for database security scanning"""
    db_type: str = Field(..., pattern="^(mysql|postgresql|mssql|oracle|mongodb)$")
    username: str
    password: str
    port: Optional[int] = None  # Uses default if not specified
    database: Optional[str] = None
    sid: Optional[str] = None  # For Oracle
    auth_type: str = Field(default="password", pattern="^(password|windows)$")


class NetworkScanCredentials(BaseModel):
    """Container for all network scan credentials (Nessus-style)"""
    enabled: bool = False
    ssh: Optional[SSHCredential] = None
    windows: Optional[WindowsCredential] = None
    snmp: Optional[SNMPCredential] = None
    database: Optional[DatabaseCredential] = None


class NetworkScanConfig(BaseModel):
    """Network scan specific configuration"""
    # Target specification
    targets: str  # IP, subnet (CIDR), or comma-separated list
    exclude_targets: Optional[str] = None  # IPs to exclude from scan
    
    # Discovery settings
    host_discovery: bool = True
    ping_methods: List[str] = Field(default=["icmp", "tcp_syn", "arp"])
    
    # Port scanning
    port_scan_enabled: bool = True
    port_range: str = "1-1024"  # Common ports, "all" for 1-65535
    scan_type: str = Field(default="syn", pattern="^(syn|connect|udp|comprehensive)$")
    
    # Service detection
    service_detection: bool = True
    os_detection: bool = True
    version_detection: bool = True
    
    # Vulnerability scanning
    vuln_scan_enabled: bool = True
    cve_check: bool = True
    compliance_check: bool = False
    
    # Credentials for authenticated scanning
    credentials: Optional[NetworkScanCredentials] = None
    
    # Performance settings
    max_concurrent_hosts: int = 10
    timeout_per_host: int = 300  # seconds
    rate_limit: int = 100  # packets per second
    
    # Safe scan mode (reduces aggressive checks)
    safe_checks: bool = True
    
    # Private network scanning (requires agent)
    use_agent: bool = False
    agent_id: Optional[str] = None


# ============== Scan Schemas ==============

class TwoFactorConfig(BaseModel):
    """2FA configuration for target website scanning"""
    enabled: bool = False  # Whether the target website uses 2FA
    type: str = Field(default="none", pattern="^(none|email|sms|authenticator)$")  # Type of 2FA
    email: Optional[str] = None  # Email for receiving OTP (if email type)
    phone: Optional[str] = None  # Phone number for receiving OTP (if sms type)


class ScanCreate(BaseModel):
    """Create scan request"""
    target_url: str
    scan_type: str = Field(..., pattern="^(web|mobile|cloud|network)$")
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    config: Optional[dict] = None
    # Network-specific fields
    network_config: Optional[NetworkScanConfig] = None
    # 2FA configuration for target website
    two_factor: Optional[TwoFactorConfig] = None


class ScanResponse(BaseModel):
    """Scan response"""
    id: uuid.UUID
    scan_id: str
    target_url: str
    scan_type: str
    status: str
    progress: int
    phase: Optional[str] = None
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    """List of scans response"""
    scans: List[ScanResponse]
    total: int
    page: int
    per_page: int


# ============== Finding Schemas ==============

class FindingResponse(BaseModel):
    """Finding response"""
    id: uuid.UUID
    finding_id: str
    category: str
    severity: str
    title: str
    description: Optional[str] = None
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    poc: Optional[str] = None
    ai_verified: bool
    ai_confidence: Optional[float] = None
    is_false_positive: bool
    remediation: Optional[str] = None
    discovered_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class FindingListResponse(BaseModel):
    """List of findings response"""
    findings: List[FindingResponse]
    total: int
    by_severity: dict


# ============== Common Schemas ==============

class MessageResponse(BaseModel):
    """Generic message response"""
    message: str
    success: bool = True


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None
    success: bool = False
