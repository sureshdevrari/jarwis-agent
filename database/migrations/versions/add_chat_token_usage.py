"""
Add chat_token_usage table for tracking AI chatbot token limits

Run: alembic revision --autogenerate -m "add_chat_token_usage"
Or manually: python -c "from database.models import Base; from database.connection import engine; Base.metadata.create_all(engine)"
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_chat_token_usage'
down_revision = None  # Update this based on your latest migration
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'chat_token_usage',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('date', sa.DateTime, nullable=False, index=True),
        sa.Column('tokens_used', sa.Integer, default=0),
        sa.Column('request_count', sa.Integer, default=0),
    )
    
    # Create unique index for user_id + date
    op.create_index(
        'ix_token_usage_user_date',
        'chat_token_usage',
        ['user_id', 'date'],
        unique=True
    )


def downgrade() -> None:
    op.drop_index('ix_token_usage_user_date', table_name='chat_token_usage')
    op.drop_table('chat_token_usage')
