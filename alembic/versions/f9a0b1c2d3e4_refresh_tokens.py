"""refresh tokens (hashed, rotating) for short access tokens

Revision ID: f9a0b1c2d3e4
Revises: e8f9a0b1c2d3
Create Date: 2026-11-09 23:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f9a0b1c2d3e4'
down_revision: Union[str, Sequence[str], None] = 'e8f9a0b1c2d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'refresh_tokens',
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('session_id', sa.String(length=40), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('token_hash'),
    )
    op.create_index('ix_refresh_tokens_session', 'refresh_tokens', ['session_id'], unique=False)
    # Sessions signed in before this change carry 14-day tokens with a claim no longer accepted:
    # end them, so everyone signs in once and gets the short token + refresh token pair.
    op.execute("UPDATE auth_sessions SET revoked_at = now() WHERE revoked_at IS NULL AND kind IN ('student', 'admin')")


def downgrade() -> None:
    op.drop_index('ix_refresh_tokens_session', table_name='refresh_tokens')
    op.drop_table('refresh_tokens')
