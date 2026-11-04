"""store upload paths instead of full urls

Revision ID: 6883dc731d51
Revises: 9e625a17258b
Create Date: 2026-11-04 13:58:47.853543

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6883dc731d51'
down_revision: Union[str, Sequence[str], None] = '9e625a17258b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# A full link to one of our files ("http://host/uploads/resume/res_….pdf"); only the path is kept,
# and the API adds PUBLIC_BASE_URL when it answers, so a domain change keeps links working.
OURS = r"^https?://[^/]+(/uploads/(avatar|resume|attachment)/[a-z]{3}_[0-9a-f]{16}\.(png|jpg|pdf|zip|docx))$"
COLUMNS = (("users", "avatar_url"), ("users", "resume_url"), ("messages", "attachment_url"))


def upgrade() -> None:
    """Upgrade schema."""
    for table, column in COLUMNS:
        op.execute(
            sa.text(f"UPDATE {table} SET {column} = regexp_replace({column}, :pattern, '\\1') WHERE {column} ~ :pattern")
            .bindparams(pattern=OURS)
        )


def downgrade() -> None:
    """Downgrade schema."""
    # Nothing to undo: older code also reads paths through the API, and full links can't be
    # rebuilt without knowing the old PUBLIC_BASE_URL.
    pass
