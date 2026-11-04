"""message client ids and one message per attachment

Revision ID: c4d5e6f7a8b9
Revises: b3f1c2d4e5a6
Create Date: 2026-11-04 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, Sequence[str], None] = 'b3f1c2d4e5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('messages', sa.Column('client_id', sa.String(length=64), nullable=True))
    op.create_index('uq_messages_sender_client', 'messages', ['sender_id', 'client_id'], unique=True,
                    postgresql_where=sa.text('client_id IS NOT NULL'))
    # Rows from before the "sent once" check: keep the attachment on the earliest message only.
    op.execute(
        """
        UPDATE messages m SET attachment_url = NULL
        WHERE attachment_url IS NOT NULL AND EXISTS (
            SELECT 1 FROM messages o WHERE o.attachment_url = m.attachment_url
            AND (o.created_at, o.id) < (m.created_at, m.id)
        )
        """
    )
    op.create_index('uq_messages_attachment', 'messages', ['attachment_url'], unique=True,
                    postgresql_where=sa.text('attachment_url IS NOT NULL'))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('uq_messages_attachment', table_name='messages', postgresql_where=sa.text('attachment_url IS NOT NULL'))
    op.drop_index('uq_messages_sender_client', table_name='messages', postgresql_where=sa.text('client_id IS NOT NULL'))
    op.drop_column('messages', 'client_id')
