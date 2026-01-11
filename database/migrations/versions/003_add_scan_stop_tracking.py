"""Add scan stop tracking columns

Revision ID: 003_add_scan_stop_tracking
Revises: add_chat_token_usage
Create Date: 2026-01-06

This migration adds columns to track stop button abuse:
- stop_attempts: Number of times user tried to stop a scan
- refund_blocked: Whether refund was blocked due to abuse

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '003_add_scan_stop_tracking'
down_revision: Union[str, None] = 'add_chat_token_usage'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add stop_attempts and refund_blocked columns to scan_history"""
    # Add stop_attempts column - tracks how many times user tried to stop
    op.add_column(
        'scan_history',
        sa.Column('stop_attempts', sa.Integer(), nullable=False, server_default='0')
    )
    
    # Add refund_blocked column - True if user abused stop button (3+ attempts)
    op.add_column(
        'scan_history',
        sa.Column('refund_blocked', sa.Boolean(), nullable=False, server_default='false')
    )


def downgrade() -> None:
    """Remove stop tracking columns"""
    op.drop_column('scan_history', 'refund_blocked')
    op.drop_column('scan_history', 'stop_attempts')
