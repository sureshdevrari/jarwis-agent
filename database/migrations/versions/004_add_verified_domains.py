"""Add verified_domains table for credential-based scan authorization

Revision ID: 004_add_verified_domains
Revises: 003_add_scan_stop_tracking
Create Date: 2026-01-08

This migration adds the verified_domains table to track which domains
users are authorized to scan with credentials.

Features:
- DNS TXT record verification
- Corporate email domain auto-verification
- Prevents unauthorized credential-based testing

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '004_add_verified_domains'
down_revision: Union[str, None] = '003_add_scan_stop_tracking'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create verified_domains table"""
    op.create_table(
        'verified_domains',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('normalized_domain', sa.String(length=255), nullable=False),
        sa.Column('verification_method', sa.String(length=20), server_default='txt', nullable=True),
        sa.Column('verification_code', sa.String(length=100), nullable=True),
        sa.Column('is_verified', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('is_email_domain', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index('ix_verified_domains_user_id', 'verified_domains', ['user_id'], unique=False)
    op.create_index('ix_verified_domains_normalized_domain', 'verified_domains', ['normalized_domain'], unique=False)
    op.create_index('ix_verified_domain_user', 'verified_domains', ['user_id', 'normalized_domain'], unique=True)


def downgrade() -> None:
    """Drop verified_domains table"""
    op.drop_index('ix_verified_domain_user', table_name='verified_domains')
    op.drop_index('ix_verified_domains_normalized_domain', table_name='verified_domains')
    op.drop_index('ix_verified_domains_user_id', table_name='verified_domains')
    op.drop_table('verified_domains')
