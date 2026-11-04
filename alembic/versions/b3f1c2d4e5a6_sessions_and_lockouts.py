"""server-side sessions and per-account lockouts

Revision ID: b3f1c2d4e5a6
Revises: 4aa97b5371af
Create Date: 2026-11-04 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3f1c2d4e5a6'
down_revision: Union[str, Sequence[str], None] = '4aa97b5371af'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema. Cookies issued before this revision carry no session id and stop working:
    everyone signs in once more."""
    op.create_table('auth_sessions',
    sa.Column('id', sa.String(length=40), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('subject_id', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('user_agent', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_auth_sessions_subject', 'auth_sessions', ['kind', 'subject_id'], unique=False)
    op.create_table('login_lockouts',
    sa.Column('key', sa.String(length=160), nullable=False),
    sa.Column('failures', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('login_lockouts')
    op.drop_index('ix_auth_sessions_subject', table_name='auth_sessions')
    op.drop_table('auth_sessions')
