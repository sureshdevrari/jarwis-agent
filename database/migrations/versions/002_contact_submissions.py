"""Add contact_submissions table

Revision ID: 002_contact_submissions
Revises: 001_initial
Create Date: 2026-01-03

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_contact_submissions'
down_revision: Union[str, None] = '001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Check if using PostgreSQL or SQLite
    bind = op.get_bind()
    is_postgresql = bind.dialect.name == 'postgresql'
    
    if is_postgresql:
        from sqlalchemy.dialects import postgresql
        uuid_type = postgresql.UUID(as_uuid=True)
    else:
        # SQLite uses String for UUID
        uuid_type = sa.String(36)
    
    # Create contact_submissions table
    op.create_table(
        'contact_submissions',
        sa.Column('id', uuid_type, primary_key=True),
        sa.Column('first_name', sa.String(100), nullable=False),
        sa.Column('last_name', sa.String(100), nullable=True),
        sa.Column('work_email', sa.String(255), nullable=False, index=True),
        sa.Column('company_name', sa.String(255), nullable=True),
        sa.Column('company_website', sa.String(255), nullable=True),
        sa.Column('plan', sa.String(50), nullable=False),
        sa.Column('status', sa.String(20), default='new'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('submitted_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('contact_submissions')
