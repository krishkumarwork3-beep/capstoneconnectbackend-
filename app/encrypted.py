"""Encrypted model attributes: `user.phone` reads and writes plaintext in Python while the column
holds AES-256-GCM ciphertext bound to (table, column, row id) (app.crypto).

    _phone_ct: Mapped[str] = mapped_column("phone", Text)
    phone = EncryptedField("_phone_ct", "users", "phone")

Setting the attribute keeps the plaintext as pending until the next flush, when it is encrypted
with the row's id (ids are assigned in Python, so they are known by then). Reading decrypts once
and caches per loaded ciphertext. With `blind="phone_hash"` the attribute also keeps an HMAC
blind index in that column, set at once, for exact-match queries and uniqueness. The class-level
attribute is not queryable (ciphertext compares to nothing): query the blind index instead.
"""

from sqlalchemy import event
from sqlalchemy.orm import Session

from app import crypto


class _Pending:
    __slots__ = ("value",)

    def __init__(self, value: str):
        self.value = value


class EncryptedField:
    def __init__(self, column_attr: str, table: str, column: str, id_attr: str = "id", blind: str | None = None,
                 blind_of=None):
        self.column_attr, self.table, self.column, self.id_attr = column_attr, table, column, id_attr
        self.blind, self.blind_of = blind, blind_of or (lambda v: v)
        self.name = column

    def __set_name__(self, owner, name):
        self.name = name
        fields = dict(getattr(owner, "__encrypted_fields__", {}))
        fields[name] = self
        owner.__encrypted_fields__ = fields

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        stored = getattr(obj, self.column_attr)
        if stored is None:
            return None
        if isinstance(stored, _Pending):
            return stored.value
        cache = obj.__dict__.setdefault("_decrypted", {})
        hit = cache.get(self.name)
        if hit is not None and hit[0] is stored:
            return hit[1]
        plain = crypto.decrypt(stored, self.table, self.column, getattr(obj, self.id_attr))
        cache[self.name] = (stored, plain)
        return plain

    def __set__(self, obj, value):
        if value is None:
            setattr(obj, self.column_attr, None)
        else:
            setattr(obj, self.column_attr, _Pending(str(value)))
        if self.blind:
            setattr(obj, self.blind, None if value is None else crypto.blind_index(self.blind_of(str(value))))

    def __eq__(self, other):
        # `Message.text == "x"` in a query would compare ciphertext (and silently match nothing).
        raise TypeError(f"{self.table}.{self.column} is encrypted: it can't be compared in a query")

    __hash__ = object.__hash__

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        raise TypeError(f"{self.table}.{self.column} is encrypted: .{name}() can't be used in a query")

    def seal(self, obj) -> None:
        stored = getattr(obj, self.column_attr)
        if isinstance(stored, _Pending):
            setattr(obj, self.column_attr, crypto.encrypt(stored.value, self.table, self.column, getattr(obj, self.id_attr)))


@event.listens_for(Session, "before_flush")
def _encrypt_pending(session: Session, flush_context, instances) -> None:
    for obj in list(session.new) + list(session.dirty):
        for field in getattr(type(obj), "__encrypted_fields__", {}).values():
            field.seal(obj)
