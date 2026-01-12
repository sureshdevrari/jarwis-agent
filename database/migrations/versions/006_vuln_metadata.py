"""Add vulnerability metadata fields to findings

Revision ID: 006_vuln_metadata
Revises: 005_enterprise_trust
Create Date: 2026-01-12

Adds new fields to the findings table for complete vulnerability reporting:
- request_data: Full HTTP request for PoC reproduction
- response_data: Full HTTP response  
- impact: What damage the vulnerability can cause
- disclosure_days: Days until responsible disclosure
- cwe_id: CWE identifier
- cvss_score: CVSS 3.1 base score
- compliance_refs: JSON array of compliance references
- attack_type: Internal attack type identifier
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = '006_vuln_metadata'
down_revision = '005_enterprise_trust'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add vulnerability metadata columns."""
    
    # Add new columns to findings table
    with op.batch_alter_table('findings', schema=None) as batch_op:
        # Full request/response for PoC
        batch_op.add_column(sa.Column('request_data', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('response_data', sa.Text(), nullable=True))
        
        # Impact and disclosure
        batch_op.add_column(sa.Column('impact', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('disclosure_days', sa.Integer(), nullable=True))
        
        # Classification
        batch_op.add_column(sa.Column('cwe_id', sa.String(20), nullable=True))
        batch_op.add_column(sa.Column('cvss_score', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('compliance_refs', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('attack_type', sa.String(50), nullable=True))
    
    # Add index on attack_type for filtering
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.create_index('ix_finding_attack_type', ['attack_type'])
        batch_op.create_index('ix_finding_cwe_id', ['cwe_id'])


def downgrade() -> None:
    """Remove vulnerability metadata columns."""
    
    with op.batch_alter_table('findings', schema=None) as batch_op:
        # Drop indexes first
        batch_op.drop_index('ix_finding_attack_type')
        batch_op.drop_index('ix_finding_cwe_id')
        
        # Drop columns
        batch_op.drop_column('request_data')
        batch_op.drop_column('response_data')
        batch_op.drop_column('impact')
        batch_op.drop_column('disclosure_days')
        batch_op.drop_column('cwe_id')
        batch_op.drop_column('cvss_score')
        batch_op.drop_column('compliance_refs')
        batch_op.drop_column('attack_type')
