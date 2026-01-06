"""Initial migration - create all tables

Revision ID: 001_initial
Revises: 
Create Date: 2026-01-03

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('username', sa.String(100), unique=True, nullable=False, index=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('company', sa.String(255), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('is_verified', sa.Boolean(), default=False),
        sa.Column('is_superuser', sa.Boolean(), default=False),
        sa.Column('plan', sa.String(50), default='free'),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('last_login', sa.DateTime(), nullable=True),
    )

    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False, unique=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('scopes', postgresql.JSON(), default={}),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('usage_count', sa.Integer(), default=0),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )

    # Create scan_history table
    op.create_table(
        'scan_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('scan_id', sa.String(50), unique=True, index=True),
        sa.Column('target_url', sa.String(2048), nullable=False),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), default='queued'),
        sa.Column('progress', sa.Integer(), default=0),
        sa.Column('phase', sa.String(255), nullable=True),
        sa.Column('config', postgresql.JSON(), nullable=True),
        sa.Column('findings_count', sa.Integer(), default=0),
        sa.Column('critical_count', sa.Integer(), default=0),
        sa.Column('high_count', sa.Integer(), default=0),
        sa.Column('medium_count', sa.Integer(), default=0),
        sa.Column('low_count', sa.Integer(), default=0),
        sa.Column('info_count', sa.Integer(), default=0),
        sa.Column('report_html', sa.String(512), nullable=True),
        sa.Column('report_json', sa.String(512), nullable=True),
        sa.Column('report_sarif', sa.String(512), nullable=True),
        sa.Column('started_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )
    
    # Create indexes for scan_history
    op.create_index('ix_scan_user_status', 'scan_history', ['user_id', 'status'])
    op.create_index('ix_scan_started', 'scan_history', ['started_at'])

    # Create findings table
    op.create_table(
        'findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_history.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('finding_id', sa.String(100), nullable=False),
        sa.Column('category', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('url', sa.String(2048), nullable=True),
        sa.Column('method', sa.String(10), nullable=True),
        sa.Column('parameter', sa.String(255), nullable=True),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('poc', sa.Text(), nullable=True),
        sa.Column('reasoning', sa.Text(), nullable=True),
        sa.Column('ai_verified', sa.Boolean(), default=False),
        sa.Column('ai_confidence', sa.Integer(), nullable=True),
        sa.Column('is_false_positive', sa.Boolean(), default=False),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('references', postgresql.JSON(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(), default=sa.func.now()),
    )
    
    # Create indexes for findings
    op.create_index('ix_finding_severity', 'findings', ['severity'])
    op.create_index('ix_finding_category', 'findings', ['category'])

    # Create refresh_tokens table
    op.create_table(
        'refresh_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('token_hash', sa.String(255), unique=True, nullable=False),
        sa.Column('device_info', sa.String(500), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('is_revoked', sa.Boolean(), default=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('refresh_tokens')
    op.drop_index('ix_finding_category')
    op.drop_index('ix_finding_severity')
    op.drop_table('findings')
    op.drop_index('ix_scan_started')
    op.drop_index('ix_scan_user_status')
    op.drop_table('scan_history')
    op.drop_table('api_keys')
    op.drop_table('users')
