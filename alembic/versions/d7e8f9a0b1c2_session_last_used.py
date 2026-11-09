"""auth_sessions.last_used_at for sliding idle expiry

Revision ID: d7e8f9a0b1c2
Revises: c4d5e6f7a8b9
Create Date: 2026-11-09 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd7e8f9a0b1c2'
down_revision: Union[str, Sequence[str], None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('auth_sessions', sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('auth_sessions', 'last_used_at')
