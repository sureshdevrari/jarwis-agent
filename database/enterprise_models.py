"""
Enterprise Database Models for Jarwis Trust & Compliance

This module extends the base models with enterprise-grade features:
- Multi-tenant isolation
- RBAC (Role-Based Access Control)
- Encrypted credential storage
- Comprehensive audit logging
- Compliance evidence tracking
- Data retention management
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict
from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Integer, 
    ForeignKey, JSON, Index, LargeBinary, UniqueConstraint
)
from sqlalchemy.orm import relationship, Mapped, mapped_column

# Import base and UUID type from main models
from database.models import Base, UUID


# ============== Multi-Tenant Models ==============

class Tenant(Base):
    """
    Enterprise tenant for multi-tenant isolation.
    Each enterprise customer gets their own tenant with isolated data.
    """
    __tablename__ = "tenants"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Tenant identification
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # For SSO/SAML
    
    # Subscription
    plan: Mapped[str] = mapped_column(String(50), default="enterprise")
    subscription_start: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    subscription_end: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Limits
    max_users: Mapped[int] = mapped_column(Integer, default=25)
    max_scans_per_month: Mapped[int] = mapped_column(Integer, default=0)  # 0 = unlimited
    max_credentials: Mapped[int] = mapped_column(Integer, default=100)
    max_agents: Mapped[int] = mapped_column(Integer, default=10)
    
    # Features
    enabled_features: Mapped[Dict] = mapped_column(JSON, default=dict)
    
    # Compliance requirements
    required_frameworks: Mapped[List[str]] = mapped_column(JSON, default=list)
    
    # Data residency & encryption
    data_region: Mapped[str] = mapped_column(String(50), default="us-east-1")
    encryption_key_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Data retention
    retention_days: Mapped[int] = mapped_column(Integer, default=365)
    auto_purge_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # SSO/SAML configuration
    sso_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    sso_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # okta, azure_ad, etc.
    sso_config: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    members: Mapped[List["TenantMember"]] = relationship(
        "TenantMember",
        back_populates="tenant",
        cascade="all, delete-orphan"
    )
    credentials: Mapped[List["EncryptedCredential"]] = relationship(
        "EncryptedCredential",
        back_populates="tenant",
        cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="tenant",
        cascade="all, delete-orphan"
    )
    
    def __repr__(self):
        return f"<Tenant {self.name} ({self.slug})>"


class TenantMember(Base):
    """
    User membership in a tenant with role assignment.
    Supports users being members of multiple tenants.
    """
    __tablename__ = "tenant_members"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Role assignment
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="viewer")
    # Roles: owner, admin, security_analyst, developer, auditor, viewer
    
    # Custom permissions (override role defaults)
    custom_permissions: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    
    # Access restrictions
    allowed_targets: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)  # Specific targets user can scan
    denied_targets: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)   # Targets user cannot scan
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    invited_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(), nullable=True)
    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="members")
    user: Mapped["User"] = relationship("User", backref="tenant_memberships")
    
    # Unique constraint: one membership per user per tenant
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_tenant_user"),
    )
    
    def __repr__(self):
        return f"<TenantMember user={self.user_id} tenant={self.tenant_id} role={self.role}>"


# ============== Encrypted Credentials ==============

class EncryptedCredential(Base):
    """
    Securely stored credentials with encryption at rest.
    All sensitive data is encrypted using the tenant's encryption key.
    """
    __tablename__ = "encrypted_credentials"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Credential metadata (not encrypted)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Types: aws_credentials, aws_role, azure_service_principal, gcp_service_account,
    #        ssh_key, ssh_password, database_credentials, api_token, oauth_token, scm_token
    
    # Encrypted data
    encrypted_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_key_id: Mapped[str] = mapped_column(String(100), nullable=False)
    encryption_algorithm: Mapped[str] = mapped_column(String(50), default="AES-256-GCM")
    
    # Access control
    allowed_users: Mapped[List[str]] = mapped_column(JSON, default=list)
    allowed_roles: Mapped[List[str]] = mapped_column(JSON, default=list)
    
    # Rotation policy
    rotation_days: Mapped[int] = mapped_column(Integer, default=90)
    last_rotated: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rotation_reminder_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Usage tracking
    access_count: Mapped[int] = mapped_column(Integer, default=0)
    last_accessed: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_accessed_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(), nullable=True)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="credentials")
    creator: Mapped["User"] = relationship("User", backref="created_credentials")
    
    # Indexes
    __table_args__ = (
        Index("ix_credential_tenant_type", "tenant_id", "credential_type"),
        Index("ix_credential_expires", "expires_at"),
    )
    
    def __repr__(self):
        return f"<EncryptedCredential {self.name} ({self.credential_type})>"


# ============== Comprehensive Audit Logging ==============

class AuditLog(Base):
    """
    Immutable audit log for compliance tracking.
    All sensitive actions are logged with full context.
    """
    __tablename__ = "audit_logs"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    # Timestamp (indexed for efficient queries)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    # Tenant context (for multi-tenant isolation)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(),
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Actor information
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6 compatible
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Action information
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # Actions: auth.login.success, credential.accessed, scan.started, etc.
    
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Request details
    request_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Change tracking (for config/data changes)
    previous_value: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    new_value: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    
    # Outcome
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Additional metadata
    metadata: Mapped[Dict] = mapped_column(JSON, default=dict)
    
    # Relationships
    tenant: Mapped[Optional["Tenant"]] = relationship("Tenant", back_populates="audit_logs")
    user: Mapped[Optional["User"]] = relationship("User", backref="audit_logs")
    
    # Indexes for efficient compliance queries
    __table_args__ = (
        Index("ix_audit_tenant_time", "tenant_id", "timestamp"),
        Index("ix_audit_user_time", "user_id", "timestamp"),
        Index("ix_audit_action_time", "action", "timestamp"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )
    
    def __repr__(self):
        return f"<AuditLog {self.action} by={self.user_id} at={self.timestamp}>"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API/export"""
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "user_id": str(self.user_id) if self.user_id else None,
            "username": self.username,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "request_id": self.request_id,
            "method": self.method,
            "endpoint": self.endpoint,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "success": self.success,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


# ============== Compliance & Evidence ==============

class ComplianceReport(Base):
    """
    Generated compliance reports for auditing.
    Supports SOC2, ISO27001, GDPR, HIPAA, PCI-DSS, etc.
    """
    __tablename__ = "compliance_reports"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    generated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Report details
    framework: Mapped[str] = mapped_column(String(50), nullable=False)
    # Frameworks: soc2_type_ii, iso_27001, gdpr, hipaa, pci_dss, nist_csf, cis_controls
    
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Period covered
    period_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Results summary
    total_controls: Mapped[int] = mapped_column(Integer, default=0)
    compliant_controls: Mapped[int] = mapped_column(Integer, default=0)
    non_compliant_controls: Mapped[int] = mapped_column(Integer, default=0)
    needs_review_controls: Mapped[int] = mapped_column(Integer, default=0)
    compliance_score: Mapped[float] = mapped_column(Integer, default=0)  # Percentage
    
    # Full report data
    report_data: Mapped[Dict] = mapped_column(JSON, nullable=False)
    
    # Export paths
    report_pdf: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    report_json: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Review status
    status: Mapped[str] = mapped_column(String(20), default="draft")
    # Status: draft, pending_review, approved, rejected
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    review_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", backref="compliance_reports")
    generator: Mapped["User"] = relationship("User", foreign_keys=[generated_by])
    evidence: Mapped[List["ComplianceEvidence"]] = relationship(
        "ComplianceEvidence",
        back_populates="report",
        cascade="all, delete-orphan"
    )
    
    def __repr__(self):
        return f"<ComplianceReport {self.framework} score={self.compliance_score}%>"


class ComplianceEvidence(Base):
    """
    Evidence records for compliance control verification.
    Links audit logs, configs, and documentation to controls.
    """
    __tablename__ = "compliance_evidence"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("compliance_reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Control reference
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    control_name: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Evidence details
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Types: audit_log, configuration, screenshot, document, scan_result
    
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Evidence data
    data: Mapped[Dict] = mapped_column(JSON, default=dict)
    attachments: Mapped[List[str]] = mapped_column(JSON, default=list)  # File paths
    
    # Collection info
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    collected_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(), nullable=True)
    
    # Review status
    status: Mapped[str] = mapped_column(String(20), default="collected")
    # Status: collected, reviewed, approved, rejected
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Relationship
    report: Mapped["ComplianceReport"] = relationship("ComplianceReport", back_populates="evidence")
    
    def __repr__(self):
        return f"<ComplianceEvidence {self.control_id}: {self.evidence_type}>"


# ============== Data Retention ==============

class DataRetentionPolicy(Base):
    """
    Configurable data retention policies per tenant.
    Defines how long different types of data are kept.
    """
    __tablename__ = "data_retention_policies"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Policy configuration
    data_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Types: scan_results, audit_logs, reports, credentials, session_data
    
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    
    # Actions
    action: Mapped[str] = mapped_column(String(20), default="delete")
    # Actions: delete, archive, anonymize
    
    archive_location: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_executed: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    items_processed: Mapped[int] = mapped_column(Integer, default=0)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    tenant: Mapped["Tenant"] = relationship("Tenant", backref="retention_policies")
    
    # Unique: one policy per data type per tenant
    __table_args__ = (
        UniqueConstraint("tenant_id", "data_type", name="uq_tenant_data_type"),
    )
    
    def __repr__(self):
        return f"<DataRetentionPolicy {self.data_type}: {self.retention_days} days>"


class DataDeletionRequest(Base):
    """
    GDPR data deletion requests (Right to Erasure).
    Tracks user requests to delete their data.
    """
    __tablename__ = "data_deletion_requests"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(),
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Request details
    request_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Types: full_deletion, data_export, partial_deletion
    
    scope: Mapped[Dict] = mapped_column(JSON, default=dict)
    # Scope: what data types to include/exclude
    
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Verification
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    verified_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(), nullable=True)
    
    # Execution
    status: Mapped[str] = mapped_column(String(20), default="pending")
    # Status: pending, verified, in_progress, completed, failed, cancelled
    
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Results
    items_deleted: Mapped[int] = mapped_column(Integer, default=0)
    deletion_log: Mapped[Dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Timestamps
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationship
    tenant: Mapped[Optional["Tenant"]] = relationship("Tenant", backref="deletion_requests")
    user: Mapped[Optional["User"]] = relationship("User", backref="deletion_requests")
    
    def __repr__(self):
        return f"<DataDeletionRequest {self.request_type} status={self.status}>"


# ============== API Access Control ==============

class RolePermissionOverride(Base):
    """
    Tenant-specific role permission overrides.
    Allows customization of default role permissions per tenant.
    """
    __tablename__ = "role_permission_overrides"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(), primary_key=True, default=uuid.uuid4)
    
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Role being modified
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # Permission modifications
    granted_permissions: Mapped[List[str]] = mapped_column(JSON, default=list)
    revoked_permissions: Mapped[List[str]] = mapped_column(JSON, default=list)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Audit
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    tenant: Mapped["Tenant"] = relationship("Tenant", backref="permission_overrides")
    
    # Unique: one override per role per tenant
    __table_args__ = (
        UniqueConstraint("tenant_id", "role", name="uq_tenant_role"),
    )
    
    def __repr__(self):
        return f"<RolePermissionOverride tenant={self.tenant_id} role={self.role}>"


# Import User for relationship typing
from database.models import User
