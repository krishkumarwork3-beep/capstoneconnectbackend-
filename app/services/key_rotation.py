"""Re-encrypts every encrypted field with the active key and recomputes the phone blind indexes.

Rotation: put the new key first in FIELD_ENCRYPTION_KEYS (keep the old one after it), restart the
API, run `python -m app.admin_cli rotate-keys`, then remove the old key. Changing BLIND_INDEX_KEY
works the same way (the indexes are recomputed from the decrypted numbers). Idempotent: rows
already on the active key with a current index are left alone; it can be run again at any time.
SQL is built with SQLAlchemy Core (no strings), on the raw columns, so nothing is cached in between.
"""

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app import crypto
from app.security import normalize_phone

BATCH = 500
FIELDS = [
    ("users", "id", ["phone", "phone_normalized"]),
    ("messages", "id", ["text"]),
    ("conversations", "id", ["last_message_text"]),
    ("reports", "id", ["details", "snapshot"]),
    ("join_requests", "id", ["note"]),
    ("recommendations", "id", ["note"]),
]


def _table(name: str, id_col: str, cols: list[str], *extra: str) -> sa.TableClause:
    return sa.table(name, sa.column(id_col), *(sa.column(c) for c in cols), *(sa.column(c) for c in extra))


def _batches(db: Session, table: sa.TableClause, id_col: str, cols: list[str]):
    last = ""
    key = table.c[id_col]
    while True:
        rows = db.execute(sa.select(key, *(table.c[c] for c in cols)).where(key > last).order_by(key).limit(BATCH)).all()
        if not rows:
            return
        yield rows
        last = rows[-1][0]


def _fresh(value, name: str, column: str, row_id: str, active: str):
    """The value re-encrypted with the active key if it isn't already (None/"" stay as they are)."""
    if not value or crypto.key_id_of(value) == active:
        return value
    return crypto.encrypt(crypto.decrypt(value, name, column, row_id), name, column, row_id)


def rotate(db: Session) -> dict[str, int]:
    """{table: rows changed}. Commits per batch."""
    active, _ = crypto.keys()
    changed: dict[str, int] = {}
    for name, id_col, cols in FIELDS:
        table = _table(name, id_col, cols, "phone_hash") if name == "users" else _table(name, id_col, cols)
        count = 0
        for rows in _batches(db, table, id_col, cols):
            for row in rows:
                row_id, current = row[0], dict(zip(cols, row[1:], strict=True))
                values = {c: _fresh(v, name, c, row_id, active) for c, v in current.items()}
                if name == "users":
                    number = crypto.decrypt(current["phone_normalized"], name, "phone_normalized", row_id)
                    values["phone_hash"] = crypto.blind_index(normalize_phone(number))
                    old_hash = db.execute(sa.select(table.c.phone_hash).where(table.c[id_col] == row_id)).scalar()
                    if values["phone_hash"] == old_hash and all(values[c] == current[c] for c in cols):
                        continue
                elif all(values[c] == current[c] for c in cols):
                    continue
                db.execute(sa.update(table).where(table.c[id_col] == row_id).values(**values))
                count += 1
            db.commit()
        changed[name] = count
    # Blocked numbers: the blind index is also the row id (and the AAD), so a new index re-keys the row.
    banned = _table("banned_phones", "phone_hash", ["phone_normalized", "phone"])
    count = 0
    for old_hash, enc_number, enc_typed in db.execute(sa.select(banned.c.phone_hash, banned.c.phone_normalized, banned.c.phone)).all():
        number = crypto.decrypt(enc_number, "banned_phones", "phone_normalized", old_hash)
        typed = crypto.decrypt(enc_typed, "banned_phones", "phone", old_hash)
        new_hash = crypto.blind_index(normalize_phone(number))
        if new_hash == old_hash and crypto.key_id_of(enc_number) == active and crypto.key_id_of(enc_typed) == active:
            continue
        db.execute(sa.update(banned).where(banned.c.phone_hash == old_hash).values(
            phone_hash=new_hash, phone_normalized=crypto.encrypt(number, "banned_phones", "phone_normalized", new_hash),
            phone=crypto.encrypt(typed, "banned_phones", "phone", new_hash)))
        count += 1
    db.commit()
    changed["banned_phones"] = count
    return changed


def encrypt_pending(db: Session) -> dict[str, int]:
    """Encrypts every value that is not a valid ciphertext for its row: plaintext left behind by
    an interrupted back-fill, or plaintext that happened to start with "enc:" (which the first
    field-encryption migration skipped). Idempotent. {table: values sealed}."""
    sealed: dict[str, int] = {}
    for name, id_col, cols in FIELDS:
        table = _table(name, id_col, cols, "phone_hash") if name == "users" else _table(name, id_col, cols)
        count = 0
        for rows in _batches(db, table, id_col, cols):
            for row in rows:
                row_id, current = row[0], dict(zip(cols, row[1:], strict=True))
                stale = {c: v for c, v in current.items() if not crypto.is_sealed_for(v, name, c, row_id)}
                if not stale:
                    continue
                values = {c: crypto.encrypt(v, name, c, row_id) for c, v in stale.items()}
                if name == "users" and "phone_normalized" in stale:
                    values["phone_hash"] = crypto.blind_index(normalize_phone(stale["phone_normalized"]))
                db.execute(sa.update(table).where(table.c[id_col] == row_id).values(**values))
                count += len(stale)
            db.commit()
        sealed[name] = count
    banned = _table("banned_phones", "phone_hash", ["phone_normalized", "phone"])
    count = 0
    for row_hash, number, typed in db.execute(sa.select(banned.c.phone_hash, banned.c.phone_normalized, banned.c.phone)).all():
        values = {c: crypto.encrypt(v, "banned_phones", c, row_hash) for c, v in (("phone_normalized", number), ("phone", typed))
                  if not crypto.is_sealed_for(v, "banned_phones", c, row_hash)}
        if values:
            db.execute(sa.update(banned).where(banned.c.phone_hash == row_hash).values(**values))
            count += len(values)
    db.commit()
    sealed["banned_phones"] = count
    return sealed
