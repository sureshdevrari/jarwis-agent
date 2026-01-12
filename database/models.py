"""
SQLAlchemy Database Models
User authentication and scan management models
"""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Integer, 
    ForeignKey, Enum, JSON, Index, TypeDecorator
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# Database-agnostic UUID type that works with both PostgreSQL and SQLite
class UUID(TypeDecorator):
    """Platform-independent UUID type.
    Uses PostgreSQL's UUID type when available, otherwise uses String(36).
    """
    impl = String(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)
        else:
            if isinstance(value, uuid.UUID):
                return str(value)
            return value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            return uuid.UUID(value)
        return value

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PGUUID())
        return dialect.type_descriptor(String(36))


class User(Base):
    """User model for authentication"""
    __tablename__ = "users"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255), 
        unique=True, 
        nullable=False, 
        index=True
    )
    username: Mapped[str] = mapped_column(
        String(100), 
        unique=True, 
        nullable=False, 
        index=True
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Profile info
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    company: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Extended profile fields (for settings page)
    bio: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    job_title: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    linkedin_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    twitter_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    github_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    language: Mapped[Optional[str]] = mapped_column(String(10), default="en")
    
    # Notification settings (JSON: email_enabled, push_enabled, scan_alerts, etc.)
    notification_settings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Scan preferences (JSON: default_scan_type, auto_scan, detailed_logs, etc.)
    scan_preferences: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Subscription/plan
    plan: Mapped[str] = mapped_column(String(50), default="free")  # free, individual, professional, enterprise
    
    # Subscription limits based on plan
    max_users: Mapped[int] = mapped_column(Integer, default=1)  # Max users in team
    max_websites: Mapped[int] = mapped_column(Integer, default=1)  # Max websites per month
    max_scans_per_month: Mapped[int] = mapped_column(Integer, default=0)  # Max scans allowed per month
    scans_this_month: Mapped[int] = mapped_column(Integer, default=0)  # Current month scan count
    dashboard_access_days: Mapped[int] = mapped_column(Integer, default=7)  # Days of dashboard access
    has_api_testing: Mapped[bool] = mapped_column(Boolean, default=False)
    has_credential_scanning: Mapped[bool] = mapped_column(Boolean, default=False)
    has_chatbot_access: Mapped[bool] = mapped_column(Boolean, default=False)
    has_mobile_pentest: Mapped[bool] = mapped_column(Boolean, default=False)
    has_cloud_scanning: Mapped[bool] = mapped_column(Boolean, default=False)
    has_network_scanning: Mapped[bool] = mapped_column(Boolean, default=False)
    has_compliance_audits: Mapped[bool] = mapped_column(Boolean, default=False)
    has_dedicated_support: Mapped[bool] = mapped_column(Boolean, default=False)
    subscription_start: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    subscription_end: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # OAuth fields
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    oauth_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    approval_status: Mapped[str] = mapped_column(String(20), default="pending")
    
    # Two-Factor Authentication (2FA) settings
    two_factor_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    two_factor_channel: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)  # 'email' or 'sms'
    two_factor_phone: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # E.164 format
    two_factor_phone_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    two_factor_backup_codes: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)  # Hashed backup codes
    two_factor_enabled_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    two_factor_last_used: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow, 
        onupdate=datetime.utcnow
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Relationships
    scans: Mapped[List["ScanHistory"]] = relationship(
        "ScanHistory", 
        back_populates="user",
        cascade="all, delete-orphan"
    )
    api_keys: Mapped[List["APIKey"]] = relationship(
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    agents: Mapped[List["Agent"]] = relationship(
        "Agent",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    
    def __repr__(self):
        return f"<User {self.username} ({self.email})>"


class APIKey(Base):
    """API Key model for programmatic access"""
    __tablename__ = "api_keys"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )
    
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    
    # Permissions
    scopes: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Usage tracking
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="api_keys")
    
    def __repr__(self):
        return f"<APIKey {self.name} (user={self.user_id})>"


class ScanHistory(Base):
    """Scan history model to track all security scans"""
    __tablename__ = "scan_history"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Scan details
    scan_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # web, mobile, cloud
    
    # Status
    status: Mapped[str] = mapped_column(
        String(50), 
        default="queued"
    )  # queued, running, completed, error, stopped
    progress: Mapped[int] = mapped_column(Integer, default=0)
    phase: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Configuration used
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Checkpoint data for resumable scans (network scanning)
    checkpoint_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Results summary
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Report paths
    report_html: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    report_json: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    report_sarif: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    report_pdf: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    
    # Stop abuse tracking
    stop_attempts: Mapped[int] = mapped_column(Integer, default=0)  # Track stop button abuse
    refund_blocked: Mapped[bool] = mapped_column(Boolean, default=False)  # If True, no credit refund on stop
    
    # Error tracking for failed scans
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Detailed error message
    last_successful_phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # Last phase before failure
    
    # Timestamps
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
    logs: Mapped[List["ScanLog"]] = relationship(
        "ScanLog",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanLog.created_at"
    )
    
    # Indexes
    __table_args__ = (
        Index("ix_scan_user_status", "user_id", "status"),
        Index("ix_scan_started", "started_at"),
    )
    
    def __repr__(self):
        return f"<ScanHistory {self.scan_id} ({self.status})>"


class ScanLog(Base):
    """Persistent scan log entries for debugging and audit trail"""
    __tablename__ = "scan_logs"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("scan_history.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Log details
    level: Mapped[str] = mapped_column(String(20), default="info")  # info, warning, error, success, phase
    message: Mapped[str] = mapped_column(Text, nullable=False)
    phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan: Mapped["ScanHistory"] = relationship("ScanHistory", back_populates="logs")
    
    def __repr__(self):
        return f"<ScanLog {self.level}: {self.message[:50]}...>"


class Finding(Base):
    """Individual vulnerability finding from a scan"""
    __tablename__ = "findings"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("scan_history.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Finding details
    finding_id: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)  # A01, A02, etc.
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # critical, high, medium, low, info
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    
    # Location
    url: Mapped[str] = mapped_column(String(2048), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Evidence
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    poc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Proof of concept
    reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # NEW: Full request/response for PoC reproduction
    request_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # Full HTTP request
    response_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Full HTTP response
    
    # NEW: Impact and disclosure
    impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # What damage can occur
    disclosure_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Days to fix
    
    # NEW: Compliance and classification
    cwe_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # e.g., CWE-89
    cvss_score: Mapped[Optional[float]] = mapped_column(Integer, nullable=True)  # 0-10
    compliance_refs: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)  # PCI-DSS, HIPAA, etc.
    attack_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # sqli, xss, etc.
    
    # AI verification
    ai_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_confidence: Mapped[Optional[float]] = mapped_column(Integer, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Remediation
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan: Mapped["ScanHistory"] = relationship("ScanHistory", back_populates="findings")
    
    # Indexes
    __table_args__ = (
        Index("ix_finding_severity", "severity"),
        Index("ix_finding_category", "category"),
    )
    
    def __repr__(self):
        return f"<Finding {self.title} ({self.severity})>"


class RefreshToken(Base):
    """Refresh token storage for JWT auth"""
    __tablename__ = "refresh_tokens"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    
    # Token info
    device_info: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    
    # Status
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<RefreshToken user={self.user_id}>"


class OTPToken(Base):
    """OTP tokens for 2FA verification - stored in database for persistence"""
    __tablename__ = "otp_tokens"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # OTP details (never store plain OTP)
    otp_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    salt: Mapped[str] = mapped_column(String(32), nullable=False)
    
    # Purpose and channel
    purpose: Mapped[str] = mapped_column(String(30), nullable=False)  # login_2fa, enable_2fa, etc.
    channel: Mapped[str] = mapped_column(String(10), nullable=False)  # email, sms
    recipient_masked: Mapped[str] = mapped_column(String(100), nullable=False)  # Masked email/phone
    
    # Status
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Indexes for efficient querying
    __table_args__ = (
        Index("ix_otp_user_purpose", "user_id", "purpose"),
        Index("ix_otp_expires", "expires_at"),
    )
    
    def __repr__(self):
        return f"<OTPToken user={self.user_id} purpose={self.purpose}>"


class ContactSubmission(Base):
    """Contact form submission model for persistent storage"""
    __tablename__ = "contact_submissions"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID, 
        primary_key=True, 
        default=uuid.uuid4
    )
    
    # Contact information
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    work_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    company_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    company_website: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    plan: Mapped[str] = mapped_column(String(50), nullable=False)  # Individual, Professional, Enterprise
    
    # Submission metadata
    status: Mapped[str] = mapped_column(
        String(20), 
        default="new"
    )  # new, contacted, converted, archived
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Timestamps
    submitted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<ContactSubmission {self.work_email} - {self.plan}>"
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": str(self.id),
            "firstName": self.first_name,
            "lastName": self.last_name or "",
            "workEmail": self.work_email,
            "companyName": self.company_name or "",
            "companyWebsite": self.company_website or "",
            "plan": self.plan,
            "status": self.status,
            "notes": self.notes,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class ChatTokenUsage(Base):
    """Track AI chatbot token usage per user for billing/limits
    
    Token Limits by Plan (per month):
    - free: 0 tokens (no chatbot access)
    - individual: 0 tokens (no chatbot access)
    - professional: 500,000 tokens/month (Suru 1.1 model)
    - enterprise: 5,000,000 tokens/month (Savi 3.1 Thinking model)
    """
    __tablename__ = "chat_token_usage"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Daily usage tracking
    date: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Unique constraint: one record per user per day
    __table_args__ = (
        Index("ix_token_usage_user_date", "user_id", "date", unique=True),
    )
    
    def __repr__(self):
        return f"<ChatTokenUsage user={self.user_id} date={self.date} tokens={self.tokens_used}>"
    
    # Token limits per plan (tokens per month)
    PLAN_LIMITS = {
        "free": 0,
        "individual": 0,
        "professional": 500000,    # 500K tokens/month (Suru 1.1 model)
        "enterprise": 5000000,     # 5M tokens/month (Savi 3.1 Thinking)
    }


class VerifiedDomain(Base):
    """
    Verified domains for credential-based scanning.
    
    Domain verification protects against unauthorized testing.
    Users must verify domain ownership via:
    1. DNS TXT record verification
    2. Corporate email domain matching (auto-verified)
    
    Corporate Email Rule:
    - User with email user@company.com can scan company.com and subdomains
    - No DNS TXT verification needed for matching email domain
    """
    __tablename__ = "verified_domains"
    
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        primary_key=True, 
        default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Domain info
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    
    # Verification details
    verification_method: Mapped[str] = mapped_column(
        String(20), 
        default="txt"  # txt, html, email_domain
    )
    verification_code: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # For email domain auto-verification
    is_email_domain: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Relationship
    user: Mapped["User"] = relationship("User", backref="verified_domains")
    
    # Unique constraint: one domain per user
    __table_args__ = (
        Index("ix_verified_domain_user", "user_id", "normalized_domain", unique=True),
    )
    
    def __repr__(self):
        return f"<VerifiedDomain {self.domain} user={self.user_id} verified={self.is_verified}>"
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain for consistent matching"""
        domain = domain.lower().strip()
        # Remove protocol
        for prefix in ["https://", "http://", "www."]:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        # Remove path and trailing slash
        domain = domain.split("/")[0].rstrip("/")
        return domain
    
    @staticmethod
    def get_root_domain(domain: str) -> str:
        """Extract root domain (e.g., api.jarwis.ai -> jarwis.ai)"""
        normalized = VerifiedDomain.normalize_domain(domain)
        parts = normalized.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return normalized

class SCMConnection(Base):
    """
    Source Code Management (SCM) OAuth connections for SAST scanning.
    
    Supports:
    - GitHub (OAuth App or Personal Access Token)
    - GitLab (OAuth or PAT)
    - Bitbucket (App Password)
    """
    __tablename__ = "scm_connections"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(), 
        ForeignKey("users.id", ondelete="CASCADE"), 
        nullable=False, 
        index=True
    )
    
    # Provider info
    provider: Mapped[str] = mapped_column(String(20), nullable=False)  # github, gitlab, bitbucket
    
    # OAuth tokens (stored encrypted in production)
    access_token: Mapped[str] = mapped_column(String(500), nullable=False)
    refresh_token: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Provider user info
    provider_user_id: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_username: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Token scopes (for GitHub: repo, read:user, etc.)
    scopes: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    
    # For self-hosted instances (GitLab Enterprise, GitHub Enterprise)
    base_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user: Mapped["User"] = relationship("User", backref="scm_connections")
    
    # Unique: one connection per provider per user
    __table_args__ = (
        Index("ix_scm_user_provider", "user_id", "provider", unique=True),
    )
    
    def __repr__(self):
        return f"<SCMConnection {self.provider}:{self.provider_username} user={self.user_id}>"


class Agent(Base):
    """Jarwis Agent for private network scanning"""
    __tablename__ = "agents"
    
    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(), ForeignKey("users.id"), nullable=False, index=True)
    
    # Agent metadata
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Network configuration
    network_ranges: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=[])
    
    # Status tracking
    status: Mapped[str] = mapped_column(String(20), default="offline")  # online, offline, error
    version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user: Mapped["User"] = relationship("User", back_populates="agents")
    
    def __repr__(self):
        return f"<Agent {self.id} ({self.name}) - {self.status}>"


class LoginHistory(Base):
    """Persistent login history for security auditing"""
    __tablename__ = "login_history"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Login event details
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # Supports IPv6
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # desktop, mobile, tablet
    browser: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)  # City, Country from IP geo
    
    # Login outcome
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    failure_reason: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # wrong_password, 2fa_failed, locked, etc.
    
    # 2FA used
    two_factor_used: Mapped[bool] = mapped_column(Boolean, default=False)
    two_factor_method: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # email, sms, backup_code
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationship
    user: Mapped["User"] = relationship("User", backref="login_history")
    
    # Indexes for efficient querying
    __table_args__ = (
        Index("ix_login_history_user_created", "user_id", "created_at"),
    )
    
    def __repr__(self):
        return f"<LoginHistory {self.user_id} {self.ip_address} {'success' if self.success else 'failed'}>"


class UserSession(Base):
    """Active user sessions for session management"""
    __tablename__ = "user_sessions"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Session token hash (not the actual token - that's in the cookie/localStorage)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    refresh_token_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Device/browser info
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    browser: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    
    # Session metadata
    is_current: Mapped[bool] = mapped_column(Boolean, default=False)  # Is this the current request's session?
    last_active_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Expiration
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # logout, password_change, admin, etc.
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationship
    user: Mapped["User"] = relationship("User", backref="sessions")
    
    # Indexes
    __table_args__ = (
        Index("ix_session_user_active", "user_id", "is_revoked", "expires_at"),
        Index("ix_session_token", "token_hash"),
    )
    
    def __repr__(self):
        return f"<UserSession {self.id} user={self.user_id} {'active' if not self.is_revoked else 'revoked'}>"


class Webhook(Base):
    """User webhooks for integrations"""
    __tablename__ = "webhooks"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Webhook configuration
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # For HMAC signing
    
    # Events to trigger webhook
    events: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=[])  # scan_completed, vulnerability_found, etc.
    
    # Filtering
    severity_filter: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)  # Only trigger for certain severities
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)  # For circuit breaker pattern
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user: Mapped["User"] = relationship("User", backref="webhooks")
    
    def __repr__(self):
        return f"<Webhook {self.name} user={self.user_id}>"