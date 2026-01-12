"""Add enterprise trust and compliance models

Revision ID: 005_enterprise_trust
Revises: 004_add_verified_domains
Create Date: 2026-01-11 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '005_enterprise_trust'
down_revision = '004_add_verified_domains'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ========== Tenants Table ==========
    op.create_table(
        'tenants',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False, unique=True, index=True),
        sa.Column('domain', sa.String(255), nullable=True),
        
        # Subscription
        sa.Column('plan', sa.String(50), default='enterprise'),
        sa.Column('subscription_start', sa.DateTime, nullable=True),
        sa.Column('subscription_end', sa.DateTime, nullable=True),
        
        # Limits
        sa.Column('max_users', sa.Integer, default=25),
        sa.Column('max_scans_per_month', sa.Integer, default=0),
        sa.Column('max_credentials', sa.Integer, default=100),
        sa.Column('max_agents', sa.Integer, default=10),
        
        # Features and compliance
        sa.Column('enabled_features', sa.JSON, default=dict),
        sa.Column('required_frameworks', sa.JSON, default=list),
        
        # Data residency and encryption
        sa.Column('data_region', sa.String(50), default='us-east-1'),
        sa.Column('encryption_key_id', sa.String(100), nullable=True),
        
        # Retention
        sa.Column('retention_days', sa.Integer, default=365),
        sa.Column('auto_purge_enabled', sa.Boolean, default=False),
        
        # SSO
        sa.Column('sso_enabled', sa.Boolean, default=False),
        sa.Column('sso_provider', sa.String(50), nullable=True),
        sa.Column('sso_config', sa.JSON, nullable=True),
        
        # Status
        sa.Column('is_active', sa.Boolean, default=True),
        
        # Timestamps
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # ========== Tenant Members Table ==========
    op.create_table(
        'tenant_members',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        
        # Role
        sa.Column('role', sa.String(50), nullable=False, default='viewer'),
        sa.Column('custom_permissions', sa.JSON, nullable=True),
        
        # Access restrictions
        sa.Column('allowed_targets', sa.JSON, nullable=True),
        sa.Column('denied_targets', sa.JSON, nullable=True),
        
        # Status
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('invited_by', sa.String(36), nullable=True),
        sa.Column('accepted_at', sa.DateTime, nullable=True),
        
        # Timestamps
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
        
        # Unique constraint
        sa.UniqueConstraint('tenant_id', 'user_id', name='uq_tenant_user'),
    )
    
    # ========== Encrypted Credentials Table ==========
    op.create_table(
        'encrypted_credentials',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        
        # Metadata
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('credential_type', sa.String(50), nullable=False),
        
        # Encrypted data
        sa.Column('encrypted_data', sa.LargeBinary, nullable=False),
        sa.Column('encryption_key_id', sa.String(100), nullable=False),
        sa.Column('encryption_algorithm', sa.String(50), default='AES-256-GCM'),
        
        # Access control
        sa.Column('allowed_users', sa.JSON, default=list),
        sa.Column('allowed_roles', sa.JSON, default=list),
        
        # Rotation
        sa.Column('rotation_days', sa.Integer, default=90),
        sa.Column('last_rotated', sa.DateTime, nullable=True),
        sa.Column('expires_at', sa.DateTime, nullable=True),
        sa.Column('rotation_reminder_sent', sa.Boolean, default=False),
        
        # Usage tracking
        sa.Column('access_count', sa.Integer, default=0),
        sa.Column('last_accessed', sa.DateTime, nullable=True),
        sa.Column('last_accessed_by', sa.String(36), nullable=True),
        
        # Status
        sa.Column('is_active', sa.Boolean, default=True),
        
        # Timestamps
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # Create index for credential lookup
    op.create_index('ix_credential_tenant_type', 'encrypted_credentials', ['tenant_id', 'credential_type'])
    op.create_index('ix_credential_expires', 'encrypted_credentials', ['expires_at'])
    
    # ========== Audit Logs Table ==========
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('timestamp', sa.DateTime, default=sa.func.now(), index=True),
        
        # Tenant context
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='SET NULL'), nullable=True, index=True),
        
        # Actor info
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('username', sa.String(100), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('session_id', sa.String(100), nullable=True),
        
        # Action
        sa.Column('action', sa.String(100), nullable=False, index=True),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(100), nullable=True),
        
        # Request details
        sa.Column('request_id', sa.String(100), nullable=True),
        sa.Column('method', sa.String(10), nullable=True),
        sa.Column('endpoint', sa.String(500), nullable=True),
        
        # Change tracking
        sa.Column('previous_value', sa.JSON, nullable=True),
        sa.Column('new_value', sa.JSON, nullable=True),
        
        # Outcome
        sa.Column('success', sa.Boolean, default=True),
        sa.Column('error_message', sa.Text, nullable=True),
        
        # Metadata
        sa.Column('metadata', sa.JSON, default=dict),
    )
    
    # Create indexes for audit log queries
    op.create_index('ix_audit_tenant_time', 'audit_logs', ['tenant_id', 'timestamp'])
    op.create_index('ix_audit_user_time', 'audit_logs', ['user_id', 'timestamp'])
    op.create_index('ix_audit_action_time', 'audit_logs', ['action', 'timestamp'])
    op.create_index('ix_audit_resource', 'audit_logs', ['resource_type', 'resource_id'])
    
    # ========== Compliance Reports Table ==========
    op.create_table(
        'compliance_reports',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('generated_by', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        
        # Report details
        sa.Column('framework', sa.String(50), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        
        # Period
        sa.Column('period_start', sa.DateTime, nullable=False),
        sa.Column('period_end', sa.DateTime, nullable=False),
        
        # Results
        sa.Column('total_controls', sa.Integer, default=0),
        sa.Column('compliant_controls', sa.Integer, default=0),
        sa.Column('non_compliant_controls', sa.Integer, default=0),
        sa.Column('needs_review_controls', sa.Integer, default=0),
        sa.Column('compliance_score', sa.Float, default=0),
        
        # Full data
        sa.Column('report_data', sa.JSON, nullable=False),
        
        # Export paths
        sa.Column('report_pdf', sa.String(500), nullable=True),
        sa.Column('report_json', sa.String(500), nullable=True),
        
        # Review
        sa.Column('status', sa.String(20), default='draft'),
        sa.Column('reviewed_by', sa.String(36), nullable=True),
        sa.Column('reviewed_at', sa.DateTime, nullable=True),
        sa.Column('review_notes', sa.Text, nullable=True),
        
        # Timestamps
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # ========== Compliance Evidence Table ==========
    op.create_table(
        'compliance_evidence',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('report_id', sa.String(36), sa.ForeignKey('compliance_reports.id', ondelete='CASCADE'), nullable=False, index=True),
        
        # Control reference
        sa.Column('control_id', sa.String(50), nullable=False),
        sa.Column('control_name', sa.String(255), nullable=False),
        
        # Evidence details
        sa.Column('evidence_type', sa.String(50), nullable=False),
        sa.Column('description', sa.Text, nullable=False),
        
        # Data
        sa.Column('data', sa.JSON, default=dict),
        sa.Column('attachments', sa.JSON, default=list),
        
        # Collection
        sa.Column('collected_at', sa.DateTime, default=sa.func.now()),
        sa.Column('collected_by', sa.String(36), nullable=True),
        
        # Review
        sa.Column('status', sa.String(20), default='collected'),
        sa.Column('reviewed_by', sa.String(36), nullable=True),
        sa.Column('reviewed_at', sa.DateTime, nullable=True),
    )
    
    # ========== Data Retention Policies Table ==========
    op.create_table(
        'data_retention_policies',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        
        # Policy config
        sa.Column('data_type', sa.String(50), nullable=False),
        sa.Column('retention_days', sa.Integer, nullable=False),
        sa.Column('action', sa.String(20), default='delete'),
        sa.Column('archive_location', sa.String(500), nullable=True),
        
        # Status
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('last_executed', sa.DateTime, nullable=True),
        sa.Column('items_processed', sa.Integer, default=0),
        
        # Timestamps
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
        
        # Unique constraint
        sa.UniqueConstraint('tenant_id', 'data_type', name='uq_tenant_data_type'),
    )
    
    # ========== Data Deletion Requests Table (GDPR) ==========
    op.create_table(
        'data_deletion_requests',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='SET NULL'), nullable=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True),
        
        # Request details
        sa.Column('request_type', sa.String(50), nullable=False),
        sa.Column('scope', sa.JSON, default=dict),
        sa.Column('reason', sa.Text, nullable=True),
        
        # Verification
        sa.Column('verified', sa.Boolean, default=False),
        sa.Column('verified_at', sa.DateTime, nullable=True),
        sa.Column('verified_by', sa.String(36), nullable=True),
        
        # Execution
        sa.Column('status', sa.String(20), default='pending'),
        sa.Column('started_at', sa.DateTime, nullable=True),
        sa.Column('completed_at', sa.DateTime, nullable=True),
        
        # Results
        sa.Column('items_deleted', sa.Integer, default=0),
        sa.Column('deletion_log', sa.JSON, default=dict),
        sa.Column('error_message', sa.Text, nullable=True),
        
        # Timestamps
        sa.Column('requested_at', sa.DateTime, default=sa.func.now()),
    )
    
    # ========== Role Permission Overrides Table ==========
    op.create_table(
        'role_permission_overrides',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        
        # Role being modified
        sa.Column('role', sa.String(50), nullable=False),
        
        # Permission modifications
        sa.Column('granted_permissions', sa.JSON, default=list),
        sa.Column('revoked_permissions', sa.JSON, default=list),
        
        # Status
        sa.Column('is_active', sa.Boolean, default=True),
        
        # Audit
        sa.Column('created_by', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
        
        # Unique constraint
        sa.UniqueConstraint('tenant_id', 'role', name='uq_tenant_role'),
    )


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('role_permission_overrides')
    op.drop_table('data_deletion_requests')
    op.drop_table('data_retention_policies')
    op.drop_table('compliance_evidence')
    op.drop_table('compliance_reports')
    
    # Drop audit log indexes
    op.drop_index('ix_audit_resource', 'audit_logs')
    op.drop_index('ix_audit_action_time', 'audit_logs')
    op.drop_index('ix_audit_user_time', 'audit_logs')
    op.drop_index('ix_audit_tenant_time', 'audit_logs')
    op.drop_table('audit_logs')
    
    # Drop credential indexes
    op.drop_index('ix_credential_expires', 'encrypted_credentials')
    op.drop_index('ix_credential_tenant_type', 'encrypted_credentials')
    op.drop_table('encrypted_credentials')
    
    op.drop_table('tenant_members')
    op.drop_table('tenants')
