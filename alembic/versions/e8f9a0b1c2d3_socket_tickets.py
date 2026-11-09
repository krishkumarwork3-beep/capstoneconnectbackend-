"""socket tickets stored as hashes

Revision ID: e8f9a0b1c2d3
Revises: d7e8f9a0b1c2
Create Date: 2026-11-09 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e8f9a0b1c2d3'
down_revision: Union[str, Sequence[str], None] = 'd7e8f9a0b1c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'socket_tickets',
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=64), nullable=False),
        sa.Column('session_id', sa.String(length=40), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('token_hash'),
    )
    op.create_index('ix_socket_tickets_expires_at', 'socket_tickets', ['expires_at'], unique=False)
    # Tickets were signed tokens naming an auth_sessions row; any left are seconds from expiry.
    op.execute("DELETE FROM auth_sessions WHERE kind = 'ws'")


def downgrade() -> None:
    op.drop_index('ix_socket_tickets_expires_at', table_name='socket_tickets')
    op.drop_table('socket_tickets')
