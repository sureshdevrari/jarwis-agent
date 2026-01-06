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
    
    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Subscription/plan
    plan: Mapped[str] = mapped_column(String(50), default="free")  # free, individual, professional, enterprise
    
    # Subscription limits based on plan
    max_users: Mapped[int] = mapped_column(Integer, default=1)  # Max users in team
    max_websites: Mapped[int] = mapped_column(Integer, default=1)  # Max websites per month
    scans_this_month: Mapped[int] = mapped_column(Integer, default=0)  # Current month scan count
    dashboard_access_days: Mapped[int] = mapped_column(Integer, default=7)  # Days of dashboard access
    has_api_testing: Mapped[bool] = mapped_column(Boolean, default=False)
    has_credential_scanning: Mapped[bool] = mapped_column(Boolean, default=False)
    has_chatbot_access: Mapped[bool] = mapped_column(Boolean, default=False)
    has_mobile_pentest: Mapped[bool] = mapped_column(Boolean, default=False)
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
    
    # Indexes
    __table_args__ = (
        Index("ix_scan_user_status", "user_id", "status"),
        Index("ix_scan_started", "started_at"),
    )
    
    def __repr__(self):
        return f"<ScanHistory {self.scan_id} ({self.status})>"


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
