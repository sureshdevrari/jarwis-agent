"""
Jarwis Scanner Result Schemas
=============================

Pydantic models for standardizing scanner outputs across all scan types.
All scanners should return findings matching these schemas.

Usage:
    from shared.schemas.scanner_results import WebFinding, MobileFinding
    
    finding = WebFinding(
        id="sqli-001",
        category="A03:2021-Injection",
        severity="critical",
        title="SQL Injection in login form",
        description="...",
        url="https://example.com/login",
        method="POST",
        parameter="username"
    )
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    WAITING_FOR_MANUAL_AUTH = "waiting_for_manual_auth"
    WAITING_FOR_OTP = "waiting_for_otp"


class VerificationStatus(str, Enum):
    """Finding verification status"""
    PENDING = "pending"          # Not yet verified
    VERIFIED = "verified"        # AI confirmed as real vulnerability
    UNVERIFIED = "unverified"    # AI verification failed/unavailable - needs manual review
    FALSE_POSITIVE = "false_positive"  # AI determined this is not a real vulnerability
    MANUAL_REVIEW = "manual_review"    # Requires human verification


# ============== Base Finding Schema ==============

class BaseFinding(BaseModel):
    """Base schema for all vulnerability findings"""
    id: str = Field(..., description="Unique finding ID")
    category: str = Field(..., description="OWASP/CWE category")
    severity: Severity = Field(..., description="Severity level")
    title: str = Field(..., description="Short vulnerability title")
    description: str = Field(..., description="Detailed description")
    
    # Optional fields common to all findings
    evidence: Optional[str] = Field(None, description="Proof of vulnerability")
    remediation: Optional[str] = Field(None, description="How to fix")
    cwe_id: Optional[str] = Field(None, description="CWE identifier (e.g., CWE-89)")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    
    # Vulnerability metadata for reporting
    attack_type: Optional[str] = Field(None, description="Attack type key (e.g., sqli, xss)")
    sub_type: Optional[str] = Field(None, description="Attack sub-type (e.g., reflected, stored, error_based)")
    impact: Optional[str] = Field(None, description="Business/technical impact of vulnerability")
    disclosure_days: Optional[int] = Field(None, description="Days to responsible disclosure deadline")
    compliance_refs: List[str] = Field(
        default_factory=list, 
        description="Compliance standards affected (e.g., PCI-DSS 6.5.1, HIPAA)"
    )
    
    # PoC request/response data
    request_data: Optional[str] = Field(None, description="Full HTTP request that triggered the vulnerability")
    response_data: Optional[str] = Field(None, description="Response snippet proving exploitation")
    
    # Verification status
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.PENDING,
        description="AI verification status - pending, verified, unverified, or false_positive"
    )
    verification_confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, 
        description="AI verification confidence score (0.0 to 1.0)"
    )
    verification_reasoning: Optional[str] = Field(
        None, 
        description="AI's reasoning for verification decision"
    )
    
    # Metadata
    discovered_at: Optional[str] = Field(None, description="ISO timestamp")
    scanner_name: Optional[str] = Field(None, description="Scanner that found this")
    
    class Config:
        use_enum_values = True


# ============== Web Scan Finding ==============

class WebFinding(BaseFinding):
    """Finding from web application security scan"""
    url: str = Field(..., description="Affected URL")
    method: str = Field("GET", description="HTTP method (GET, POST, etc.)")
    parameter: Optional[str] = Field(None, description="Vulnerable parameter name")
    
    # Request/Response evidence (Burp-style)
    request: Optional[str] = Field(None, description="Full HTTP request")
    response: Optional[str] = Field(None, description="Full HTTP response")
    
    # Payload info
    payload: Optional[str] = Field(None, description="Attack payload used")
    poc: Optional[str] = Field(None, description="Proof of concept code/command")
    
    # Context
    is_authenticated: bool = Field(False, description="Found in authenticated context")
    endpoint_type: Optional[str] = Field(None, description="api, form, ajax, etc.")


# ============== Mobile Scan Finding ==============

class MobileFinding(BaseFinding):
    """Finding from mobile application security scan"""
    platform: str = Field(..., description="android or ios")
    app_name: str = Field(..., description="Application name")
    package_name: Optional[str] = Field(None, description="Package/bundle ID")
    
    # Location in app
    component: Optional[str] = Field(None, description="Activity, Service, etc.")
    file_path: Optional[str] = Field(None, description="Path in decompiled app")
    line_number: Optional[int] = Field(None, description="Line number if applicable")
    
    # API-related
    api_url: Optional[str] = Field(None, description="If API vulnerability")
    api_method: Optional[str] = Field(None, description="HTTP method")
    
    # Static vs Dynamic
    analysis_type: str = Field("static", description="static or dynamic")
    
    # OWASP Mobile specific
    owasp_mobile_category: Optional[str] = Field(None, description="M1-M10 category")


# ============== Network Scan Finding ==============

class NetworkFinding(BaseFinding):
    """Finding from network security scan"""
    ip_address: str = Field(..., description="Target IP address")
    hostname: Optional[str] = Field(None, description="Resolved hostname")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Affected port")
    protocol: str = Field("tcp", description="tcp, udp, icmp")
    
    # Service info
    service_name: Optional[str] = Field(None, description="Detected service")
    service_version: Optional[str] = Field(None, description="Service version")
    service_banner: Optional[str] = Field(None, description="Banner grab result")
    
    # CVE info
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    cve_description: Optional[str] = Field(None, description="CVE description")
    exploit_available: bool = Field(False, description="Public exploit exists")
    
    # OS detection
    os_type: Optional[str] = Field(None, description="Detected OS type")
    os_version: Optional[str] = Field(None, description="Detected OS version")


# ============== Cloud Scan Finding ==============

class CloudFinding(BaseFinding):
    """Finding from cloud security scan"""
    provider: str = Field(..., description="aws, azure, gcp")
    resource_type: str = Field(..., description="EC2, S3, IAM, etc.")
    resource_id: str = Field(..., description="Resource identifier/ARN")
    resource_name: Optional[str] = Field(None, description="Friendly name")
    region: Optional[str] = Field(None, description="Cloud region")
    
    # Account info
    account_id: Optional[str] = Field(None, description="Cloud account ID")
    subscription_id: Optional[str] = Field(None, description="Azure subscription")
    project_id: Optional[str] = Field(None, description="GCP project")
    
    # Compliance
    compliance_frameworks: List[str] = Field(
        default_factory=list,
        description="CIS, SOC2, PCI-DSS, HIPAA, etc."
    )
    compliance_control: Optional[str] = Field(None, description="Specific control ID")
    
    # CSPM specific
    misconfiguration_type: Optional[str] = Field(None, description="Type of misconfiguration")
    policy_violated: Optional[str] = Field(None, description="Policy that was violated")
    
    # IAM specific
    principal: Optional[str] = Field(None, description="IAM user/role")
    permissions: List[str] = Field(default_factory=list, description="Risky permissions")


# ============== Scan Result Schemas ==============

class BaseScanResult(BaseModel):
    """Base schema for scan results"""
    scan_id: str
    scan_type: str
    status: ScanStatus
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    
    # Counts
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Error handling
    error_message: Optional[str] = None
    
    class Config:
        use_enum_values = True


class WebScanResult(BaseScanResult):
    """Result from web security scan"""
    target_url: str
    endpoints_discovered: int = 0
    requests_sent: int = 0
    pages_crawled: int = 0
    authenticated: bool = False
    findings: List[WebFinding] = Field(default_factory=list)
    report_paths: Dict[str, str] = Field(default_factory=dict)


class MobileScanResult(BaseScanResult):
    """Result from mobile security scan"""
    app_name: str
    platform: str
    package_name: Optional[str] = None
    app_version: Optional[str] = None
    
    # Analysis breakdown
    static_findings: int = 0
    dynamic_findings: int = 0
    api_findings: int = 0
    
    findings: List[MobileFinding] = Field(default_factory=list)


class NetworkScanResult(BaseScanResult):
    """Result from network security scan"""
    target: str  # IP, CIDR, hostname
    hosts_discovered: int = 0
    ports_scanned: int = 0
    services_detected: int = 0
    
    # Scan profile used
    scan_profile: str = "standard"
    
    findings: List[NetworkFinding] = Field(default_factory=list)


class CloudScanResult(BaseScanResult):
    """Result from cloud security scan"""
    provider: str
    account_id: Optional[str] = None
    regions_scanned: List[str] = Field(default_factory=list)
    resources_scanned: int = 0
    
    # Compliance summary
    compliance_score: Optional[float] = None
    frameworks_checked: List[str] = Field(default_factory=list)
    
    findings: List[CloudFinding] = Field(default_factory=list)


# ============== Helper Functions ==============

def create_finding(scan_type: str, **kwargs) -> BaseFinding:
    """Factory function to create appropriate finding type"""
    finding_classes = {
        "web": WebFinding,
        "mobile": MobileFinding,
        "network": NetworkFinding,
        "cloud": CloudFinding,
    }
    
    finding_class = finding_classes.get(scan_type, BaseFinding)
    return finding_class(**kwargs)


def validate_finding(finding: dict, scan_type: str) -> tuple[bool, Optional[str]]:
    """Validate a finding dict matches the expected schema"""
    try:
        create_finding(scan_type, **finding)
        return True, None
    except Exception as e:
        return False, str(e)


def severity_to_score(severity: str) -> int:
    """Convert severity to numeric score for sorting"""
    scores = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }
    return scores.get(severity.lower(), 0)
