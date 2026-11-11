"""encrypt join_requests.note and recommendations.note

Revision ID: b1c2d3e4f5a6
Revises: a0b1c2d3e4f5
Create Date: 2026-11-11 10:00:00.000000

Batched back-fill with the keys in FIELD_ENCRYPTION_KEYS. A value counts as done only if it is a
valid ciphertext for its row (app.crypto.is_sealed_for), not merely because it starts with
"enc:", so a note that was typed as "enc:..." is still encrypted. Idempotent and reversible.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app import crypto


revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, Sequence[str], None] = 'a0b1c2d3e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BATCH = 500
TABLES = ("join_requests", "recommendations")


def _batches(bind, table: str):
    t = sa.table(table, sa.column("id"), sa.column("note"))
    last = ""
    while True:
        rows = bind.execute(sa.select(t.c.id, t.c.note).where(t.c.id > last).order_by(t.c.id).limit(BATCH)).all()
        if not rows:
            return
        yield t, rows
        last = rows[-1][0]


def upgrade() -> None:
    bind = op.get_bind()
    for table in TABLES:
        for t, rows in _batches(bind, table):
            for row_id, note in rows:
                if not crypto.is_sealed_for(note, table, "note", row_id):
                    bind.execute(sa.update(t).where(t.c.id == row_id).values(note=crypto.encrypt(note, table, "note", row_id)))


def downgrade() -> None:
    bind = op.get_bind()
    for table in TABLES:
        for t, rows in _batches(bind, table):
            for row_id, note in rows:
                if note and crypto.is_sealed_for(note, table, "note", row_id):
                    bind.execute(sa.update(t).where(t.c.id == row_id).values(note=crypto.decrypt(note, table, "note", row_id)))
