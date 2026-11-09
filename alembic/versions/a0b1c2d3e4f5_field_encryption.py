"""field encryption: AES-256-GCM for phones, messages, previews and reports; phone blind indexes

Revision ID: a0b1c2d3e4f5
Revises: f9a0b1c2d3e4
Create Date: 2026-11-10 00:30:00.000000

Back-fills existing rows in batches with the keys in FIELD_ENCRYPTION_KEYS / BLIND_INDEX_KEY (set
them before upgrading). Idempotent: a value already "enc:..." is left alone, so an interrupted run
can simply be run again. Reversible: downgrade decrypts everything back to plaintext.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app import crypto
from app.security import normalize_phone


revision: str = 'a0b1c2d3e4f5'
down_revision: Union[str, Sequence[str], None] = 'f9a0b1c2d3e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BATCH = 500
# (table, id column, encrypted columns)
FIELDS = [
    ("users", "id", ["phone", "phone_normalized"]),
    ("messages", "id", ["text"]),
    ("conversations", "id", ["last_message_text"]),
    ("reports", "id", ["details", "snapshot"]),
]


def _rows(bind, table: str, id_col: str, cols: list[str], where: str):
    last = ""
    while True:
        rows = bind.execute(sa.text(
            f"SELECT {id_col}, {', '.join(cols)} FROM {table} WHERE {id_col} > :last AND ({where}) ORDER BY {id_col} LIMIT {BATCH}"
        ), {"last": last}).all()
        if not rows:
            return
        yield rows
        last = rows[-1][0]


def _encrypt_table(bind, table: str, id_col: str, cols: list[str]) -> None:
    plain = " OR ".join(f"({c} IS NOT NULL AND {c} <> '' AND {c} NOT LIKE 'enc:%')" for c in cols)
    for rows in _rows(bind, table, id_col, cols, plain):
        for row in rows:
            values = {}
            for i, col in enumerate(cols, start=1):
                v = row[i]
                values[col] = v if (v is None or v == "" or v.startswith(crypto.PREFIX)) else crypto.encrypt(v, table, col, row[0])
            sets = ", ".join(f"{c} = :{c}" for c in cols)
            bind.execute(sa.text(f"UPDATE {table} SET {sets} WHERE {id_col} = :row_id"), {**values, "row_id": row[0]})


def _decrypt_table(bind, table: str, id_col: str, cols: list[str], row_id_of=None) -> None:
    sealed = " OR ".join(f"{c} LIKE 'enc:%'" for c in cols)
    for rows in _rows(bind, table, id_col, cols, sealed):
        for row in rows:
            rid = row_id_of(row) if row_id_of else row[0]
            values = {c: (crypto.decrypt(row[i], table, c, rid) if row[i] and row[i].startswith(crypto.PREFIX) else row[i])
                      for i, c in enumerate(cols, start=1)}
            sets = ", ".join(f"{c} = :{c}" for c in cols)
            bind.execute(sa.text(f"UPDATE {table} SET {sets} WHERE {id_col} = :row_id"), {**values, "row_id": row[0]})


def upgrade() -> None:
    bind = op.get_bind()
    # Ciphertext is longer than the plaintext columns allowed.
    op.alter_column('users', 'phone', type_=sa.Text(), existing_type=sa.String(32), existing_nullable=False)
    op.alter_column('users', 'phone_normalized', type_=sa.Text(), existing_type=sa.String(20), existing_nullable=False)
    op.alter_column('banned_phones', 'phone', type_=sa.Text(), existing_type=sa.String(32), existing_nullable=False)
    op.alter_column('banned_phones', 'phone_normalized', type_=sa.Text(), existing_type=sa.String(20), existing_nullable=False)

    # Blind indexes, filled from the plaintext numbers before those are encrypted.
    op.add_column('users', sa.Column('phone_hash', sa.String(length=64), nullable=True))
    for rows in _rows(bind, "users", "id", ["phone_normalized"], "phone_hash IS NULL"):
        for user_id, number in rows:
            plain = crypto.decrypt(number, "users", "phone_normalized", user_id) if number.startswith(crypto.PREFIX) else number
            bind.execute(sa.text("UPDATE users SET phone_hash = :h WHERE id = :id"), {"h": crypto.blind_index(normalize_phone(plain)), "id": user_id})
    op.alter_column('users', 'phone_hash', nullable=False)
    op.drop_constraint('users_phone_normalized_key', 'users', type_='unique')
    op.create_unique_constraint('users_phone_hash_key', 'users', ['phone_hash'])

    op.add_column('banned_phones', sa.Column('phone_hash', sa.String(length=64), nullable=True))
    for number, typed in bind.execute(sa.text("SELECT phone_normalized, phone FROM banned_phones WHERE phone_hash IS NULL")).all():
        h = crypto.blind_index(normalize_phone(number))
        bind.execute(sa.text(
            "UPDATE banned_phones SET phone_hash = :h, phone_normalized = :n, phone = :p WHERE phone_normalized = :old"),
            {"h": h, "n": crypto.encrypt(number, "banned_phones", "phone_normalized", h),
             "p": crypto.encrypt(typed, "banned_phones", "phone", h), "old": number})
    op.alter_column('banned_phones', 'phone_hash', nullable=False)
    op.drop_constraint('banned_phones_pkey', 'banned_phones', type_='primary')
    op.create_primary_key('banned_phones_pkey', 'banned_phones', ['phone_hash'])

    for table, id_col, cols in FIELDS:
        _encrypt_table(bind, table, id_col, cols)

    # Limits and lock-outs were keyed by the number itself: short-lived rows, now keyed by the
    # blind index; the old ones are dropped.
    bind.execute(sa.text("DELETE FROM rate_limits WHERE key LIKE '%:phone:%'"))
    bind.execute(sa.text("DELETE FROM login_lockouts WHERE key LIKE 'student:%'"))


def downgrade() -> None:
    bind = op.get_bind()
    for table, id_col, cols in FIELDS:
        _decrypt_table(bind, table, id_col, cols)
    _decrypt_table(bind, "banned_phones", "phone_hash", ["phone_normalized", "phone"])
    op.drop_constraint('banned_phones_pkey', 'banned_phones', type_='primary')
    op.create_primary_key('banned_phones_pkey', 'banned_phones', ['phone_normalized'])
    op.drop_column('banned_phones', 'phone_hash')
    op.drop_constraint('users_phone_hash_key', 'users', type_='unique')
    op.create_unique_constraint('users_phone_normalized_key', 'users', ['phone_normalized'])
    op.drop_column('users', 'phone_hash')
    op.alter_column('users', 'phone', type_=sa.String(32), existing_type=sa.Text())
    op.alter_column('users', 'phone_normalized', type_=sa.String(20), existing_type=sa.Text())
    op.alter_column('banned_phones', 'phone', type_=sa.String(32), existing_type=sa.Text())
    op.alter_column('banned_phones', 'phone_normalized', type_=sa.String(20), existing_type=sa.Text())
