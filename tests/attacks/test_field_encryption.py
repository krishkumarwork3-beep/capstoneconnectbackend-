"""A5 / W4: AES-256-GCM field encryption and HMAC blind indexes. What a stolen database shows,
that tampering and moving ciphertext fail closed, key rotation, lookups and uniqueness by blind
index, no plaintext in logs, the production key checks, and the migration's back-fill."""

import base64
import logging
import os

import pytest
import sqlalchemy as sa
from sqlalchemy import text

from app import crypto
from app.check_config import problems
from app.config import (
    DEV_BLIND_INDEX_KEY,
    DEV_FIELD_ENCRYPTION_KEYS,
    Settings,
    get_settings,
)
from app.db import SessionLocal
from app.models import Message
from app.services.key_rotation import rotate
from tests.conftest import PHONES

LEAD = "usr_1"
NEW = {"name": "Cipher Test", "college": "IIT Delhi", "department": "CS", "passing_year": 2026,
       "phone": "+91 99999 22222", "password": "a-long-password", "bio": "", "skills": []}


def _key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


# --- The primitive ----------------------------------------------------------------------------

def test_round_trip_and_a_fresh_nonce_every_time():
    one = crypto.encrypt("+91 98765 43210", "users", "phone", "usr_x")
    two = crypto.encrypt("+91 98765 43210", "users", "phone", "usr_x")
    assert one != two and one.startswith("enc:dev1:")
    assert crypto.decrypt(one, "users", "phone", "usr_x") == crypto.decrypt(two, "users", "phone", "usr_x") == "+91 98765 43210"


def test_tampering_fails_closed():
    sealed = crypto.encrypt("secret message", "messages", "text", "msg_1")
    head, body = sealed.rsplit(":", 1)
    raw = bytearray(base64.b64decode(body))
    for i in (0, 12, len(raw) - 1):  # nonce, ciphertext, tag
        flipped = raw.copy()
        flipped[i] ^= 1
        with pytest.raises(crypto.FieldCryptoError):
            crypto.decrypt(f"{head}:{base64.b64encode(bytes(flipped)).decode()}", "messages", "text", "msg_1")
    for broken in (sealed[:-8], "enc:dev1:", "enc:nokey:" + body, "plaintext that was never encrypted"):
        with pytest.raises(crypto.FieldCryptoError):
            crypto.decrypt(broken, "messages", "text", "msg_1")


def test_ciphertext_moved_to_another_row_or_column_fails():
    sealed = crypto.encrypt("hello", "messages", "text", "msg_1")
    for table, column, row in (("messages", "text", "msg_2"), ("reports", "snapshot", "msg_1"), ("users", "phone", "msg_1")):
        with pytest.raises(crypto.FieldCryptoError):
            crypto.decrypt(sealed, table, column, row)


def test_moved_ciphertext_in_the_database_is_refused_not_served(as_user):
    lead = as_user(LEAD)
    one = lead.post("/api/conversations/conv_2/messages", json={"text": "first private"}).json()["id"]
    two = lead.post("/api/conversations/conv_2/messages", json={"text": "second private"}).json()["id"]
    with SessionLocal() as db:
        stolen = db.execute(text("SELECT text FROM messages WHERE id = :id"), {"id": one}).scalar()
        db.execute(text("UPDATE messages SET text = :t WHERE id = :id"), {"t": stolen, "id": two})
        db.commit()
    with SessionLocal() as db, pytest.raises(crypto.FieldCryptoError):
        _ = db.get(Message, two).text


def test_queries_on_encrypted_columns_are_refused_not_silently_empty():
    with pytest.raises(TypeError):
        _ = Message.text == "anything"
    with pytest.raises(TypeError):
        Message.text.in_(["a"])


# --- What the database holds ------------------------------------------------------------------

def test_raw_sql_shows_only_ciphertext(client, as_user, admin_client):
    created = client.post("/api/auth/signup", json=NEW)
    assert created.status_code == 201, created.text
    user_id = created.json()["id"]
    lead = as_user(LEAD)
    msg = lead.post("/api/conversations/conv_2/messages", json={"text": "meet at 6, door code 4471"}).json()["id"]
    report = as_user("usr_2").post("/api/reports", json={"target_type": "message", "target_id": msg, "reason": "spam",
                                                         "details": "he shared my number 98765 11111"})
    assert report.status_code == 201, report.text
    admin_client().post("/api/admin/banned-phones", json={"phones": ["+91 98111 22333"], "reason": "x"})
    with SessionLocal() as db:
        user = db.execute(text("SELECT phone, phone_normalized, phone_hash FROM users WHERE id = :id"), {"id": user_id}).one()
        message = db.execute(text("SELECT text FROM messages WHERE id = :id"), {"id": msg}).scalar()
        preview = db.execute(text("SELECT last_message_text FROM conversations WHERE id = 'conv_2'")).scalar()
        rep = db.execute(text("SELECT details, snapshot FROM reports WHERE id = :id"), {"id": report.json()["id"]}).one()
        banned = db.execute(text("SELECT phone, phone_normalized, phone_hash FROM banned_phones")).all()
    for value in (*user[:2], message, preview, *rep, *[v for row in banned for v in row[:2]]):
        assert value.startswith("enc:"), value
    dump = " ".join(str(v) for v in (*user, message, preview, *rep, *[v for row in banned for v in row]))
    for plain in ("9999922222", "99999 22222", "door code", "4471", "98765 11111", "9811122333"):
        assert plain not in dump
    assert len(user[2]) == 64  # the blind index, not the number
    # And the API still serves the plaintext to the people entitled to it.
    assert lead.get("/api/conversations/conv_2/messages").json()[-1]["text"] == "meet at 6, door code 4471"


def test_seeded_rows_are_encrypted_too():
    with SessionLocal() as db:
        rows = db.execute(text("SELECT phone, phone_normalized FROM users")).all()
        texts = db.execute(text("SELECT text FROM messages WHERE text <> ''")).scalars().all()
    assert rows and all(p.startswith("enc:") and n.startswith("enc:") for p, n in rows)
    assert texts and all(t.startswith("enc:") for t in texts)


# --- Lookups and uniqueness by blind index ----------------------------------------------------

def test_login_signup_and_reset_find_numbers_however_they_are_written(client):
    assert client.post("/api/auth/signup", json=NEW).status_code == 201
    # Rewritten to the new contract: a registered number answers like a new one (no 409), and the
    # blind index still finds it, so no second account is stored.
    again = client.post("/api/auth/signup", json={**NEW, "phone": "9999922222"})
    assert again.status_code == 201
    with SessionLocal() as db:
        assert db.scalar(text("SELECT count(*) FROM users WHERE phone_hash = :h"), {"h": crypto.phone_hash("9999922222")}) == 1
    from fastapi.testclient import TestClient

    from app.main import app
    for written in ("+91 99999 22222", "9999922222", "919999922222", "09999922222"):
        assert TestClient(app).post("/api/auth/login", json={"phone": written, "password": NEW["password"]}).status_code == 200, written


def test_the_blind_index_is_unique_in_the_database(client):
    assert client.post("/api/auth/signup", json=NEW).status_code == 201
    with SessionLocal() as db:
        h = db.execute(text("SELECT phone_hash FROM users WHERE phone_hash = :h"), {"h": crypto.phone_hash("9999922222")}).scalar()
        assert h
        with pytest.raises(sa.exc.IntegrityError):
            db.execute(text("UPDATE users SET phone_hash = :h WHERE id = 'usr_2'"), {"h": h})
            db.commit()


def test_the_blind_index_needs_its_own_key():
    digits = "919876543210"
    assert crypto.blind_index(digits) != crypto.blind_index("919876543211")
    import hashlib
    assert crypto.blind_index(digits) != hashlib.sha256(digits.encode()).hexdigest()  # keyed, not a bare hash


def test_blocked_numbers_match_by_blind_index(client, admin_client):
    admin = admin_client()
    assert admin.post("/api/admin/banned-phones", json={"phones": ["99999 22222"], "reason": "x"}).status_code == 201
    assert client.post("/api/auth/signup", json=NEW).status_code == 403
    listed = admin.get("/api/admin/banned-phones").json()
    assert any(r["phone_normalized"] == "919999922222" for r in listed)
    assert admin.get("/api/admin/banned-phones", params={"q": "+91 99999 22222"}).json()[0]["phone_normalized"] == "919999922222"
    assert admin.delete("/api/admin/banned-phones/9999922222").status_code == 204
    assert client.post("/api/auth/signup", json=NEW).status_code == 201


def test_admin_finds_a_student_by_whole_number(admin_client):
    found = admin_client().get("/api/admin/users", params={"q": PHONES[LEAD]}).json()["items"]
    assert [u["id"] for u in found] == [LEAD]


# --- Key rotation -----------------------------------------------------------------------------

def test_key_rotation_re_encrypts_and_the_old_key_can_then_go(as_user, monkeypatch):
    lead = as_user(LEAD)
    lead.post("/api/conversations/conv_2/messages", json={"text": "before rotation"})
    s = get_settings()
    new_spec = f"k2:{_key()},{s.field_encryption_keys}"
    monkeypatch.setattr(s, "field_encryption_keys", new_spec)
    with SessionLocal() as db:
        changed = rotate(db)
        assert changed["users"] > 0 and changed["messages"] > 0
        assert rotate(db)["messages"] == 0  # idempotent
        ids = db.execute(text("SELECT text FROM messages WHERE text <> ''")).scalars().all()
    assert all(crypto.key_id_of(v) == "k2" for v in ids)
    monkeypatch.setattr(s, "field_encryption_keys", new_spec.split(",")[0])  # the old key removed
    assert lead.get("/api/conversations/conv_2/messages").json()[-1]["text"] == "before rotation"
    assert lead.get("/api/auth/me").json()["phone"] == PHONES[LEAD]


def test_blind_index_key_rotation_keeps_logins_and_blocks_working(client, admin_client, monkeypatch):
    admin_client().post("/api/admin/banned-phones", json={"phones": ["+91 98111 22333"], "reason": "x"})
    monkeypatch.setattr(get_settings(), "blind_index_key", _key())
    with SessionLocal() as db:
        rotate(db)
    from fastapi.testclient import TestClient

    from app.main import app
    assert TestClient(app).post("/api/auth/login", json={"phone": PHONES[LEAD], "password": "password123"}).status_code == 200
    assert client.post("/api/auth/signup", json={**NEW, "phone": "+91 98111 22333"}).status_code == 403


# --- Logs -------------------------------------------------------------------------------------

def test_no_plaintext_number_or_message_in_any_log(client, as_user):
    class Lines(logging.Handler):
        def __init__(self):
            super().__init__(level=logging.DEBUG)
            self.lines: list[str] = []

        def emit(self, record):
            self.lines.append(record.getMessage() + " " + str(getattr(record, "args", "")))

    handler, root = Lines(), logging.getLogger()
    old = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        client.post("/api/auth/signup", json=NEW)
        client.post("/api/auth/login", json={"phone": NEW["phone"], "password": "wrong-password"})
        as_user(LEAD).post("/api/conversations/conv_2/messages", json={"text": "do not log this sentence"})
    finally:
        root.removeHandler(handler)
        root.setLevel(old)
    joined = "\n".join(handler.lines)
    assert "9999922222" not in joined and "99999 22222" not in joined and "do not log this sentence" not in joined


# --- Production key checks --------------------------------------------------------------------

def _prod(**overrides) -> Settings:
    base = dict(secret_key="s" * 8 + _key(), cookie_secure=True, field_encryption_keys=f"p1:{_key()}", blind_index_key=_key())
    return Settings(**{**base, **overrides})


def _key_fatal(settings: Settings) -> list[str]:
    return [t for sev, t in problems(settings) if sev == "fatal" and "KEY" in t]


def test_good_keys_pass():
    assert _key_fatal(_prod()) == []


@pytest.mark.parametrize("override", [
    {"field_encryption_keys": DEV_FIELD_ENCRYPTION_KEYS},
    {"blind_index_key": DEV_BLIND_INDEX_KEY},
    {"field_encryption_keys": ""},
    {"blind_index_key": ""},
    {"field_encryption_keys": "p1:" + base64.b64encode(b"short").decode()},
    {"field_encryption_keys": "p1:not base64!"},
])
def test_missing_default_or_malformed_keys_are_fatal(override):
    assert _key_fatal(_prod(**override))


def test_keys_must_differ_from_each_other_and_the_jwt_secret():
    shared = _key()
    assert _key_fatal(_prod(field_encryption_keys=f"p1:{shared}", blind_index_key=shared))
    assert _key_fatal(_prod(secret_key=shared, blind_index_key=shared))


# --- The migration: back-fill, idempotent, reversible -----------------------------------------

def _fill(conn, table: str, values: dict) -> None:
    """Inserts a row giving every NOT NULL column without a default a plausible value."""
    cols = conn.execute(text(
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = :t "
        "AND is_nullable = 'NO' AND column_default IS NULL"), {"t": table}).all()
    sample = {"text": "x", "character varying": "x", "integer": 1, "boolean": False, "jsonb": "{}", "ARRAY": "{}",
              "timestamp with time zone": "2026-01-01T00:00:00Z"}
    row = {name: sample.get(kind, "x") for name, kind in cols} | values
    names = ", ".join(row)
    conn.execute(text(f"INSERT INTO {table} ({names}) VALUES ({', '.join(':' + n for n in row)})"), row)


def _alembic(url: str, *args: str) -> None:
    import subprocess
    import sys
    env = {**os.environ, "DATABASE_URL": url}
    result = subprocess.run([sys.executable, "-m", "alembic", *args], env=env, capture_output=True, text=True,
                            cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    assert result.returncode == 0, result.stderr[-2000:]


def test_the_migration_back_fills_is_idempotent_and_reversible():
    from app.db import engine
    base = engine.url
    url = base.set(database="capstoneconnect_migration_test").render_as_string(hide_password=False)
    admin = sa.create_engine(base.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text("DROP DATABASE IF EXISTS capstoneconnect_migration_test WITH (FORCE)"))
        c.execute(text("CREATE DATABASE capstoneconnect_migration_test"))
    target = sa.create_engine(url)
    try:
        _alembic(url, "upgrade", "f9a0b1c2d3e4")  # before encryption: plaintext columns
        with target.begin() as c:
            _fill(c, "users", {"id": "usr_m1", "phone": "+91 98765 00001", "phone_normalized": "919876500001", "name": "M"})
            _fill(c, "conversations", {"id": "conv_m1", "type": "direct", "last_message_text": "preview text"})
            _fill(c, "messages", {"id": "msg_m1", "conversation_id": "conv_m1", "text": "old plaintext message", "sender_name": "M"})
            _fill(c, "reports", {"id": "rpt_m1", "reporter_id": "usr_m1", "details": "old details", "snapshot": "old snapshot"})
            _fill(c, "banned_phones", {"phone_normalized": "919876500002", "phone": "98765 00002"})
            c.execute(text("INSERT INTO rate_limits (key, count, window_start) VALUES ('login:phone:919876500001', 1, now())"))
        _alembic(url, "upgrade", "head")
        with target.connect() as c:
            user = c.execute(text("SELECT phone, phone_normalized, phone_hash FROM users WHERE id = 'usr_m1'")).one()
            msg = c.execute(text("SELECT text FROM messages WHERE id = 'msg_m1'")).scalar()
            banned = c.execute(text("SELECT phone_hash, phone_normalized FROM banned_phones")).one()
            assert c.execute(text("SELECT count(*) FROM rate_limits WHERE key LIKE '%:phone:%'")).scalar() == 0
        assert user[0].startswith("enc:") and crypto.decrypt(user[1], "users", "phone_normalized", "usr_m1") == "919876500001"
        assert user[2] == crypto.phone_hash("919876500001")
        assert crypto.decrypt(msg, "messages", "text", "msg_m1") == "old plaintext message"
        assert banned[0] == crypto.phone_hash("919876500002")
        assert crypto.decrypt(banned[1], "banned_phones", "phone_normalized", banned[0]) == "919876500002"
        # Idempotent: running the back-fill again changes nothing already encrypted.
        with target.begin() as c:
            before = c.execute(text("SELECT text FROM messages WHERE id = 'msg_m1'")).scalar()
            from importlib.util import module_from_spec, spec_from_file_location
            path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                "alembic", "versions", "a0b1c2d3e4f5_field_encryption.py")
            spec = spec_from_file_location("field_encryption_migration", path)
            migration = module_from_spec(spec)
            spec.loader.exec_module(migration)
            migration._encrypt_table(c, "messages", "id", ["text"])
            assert c.execute(text("SELECT text FROM messages WHERE id = 'msg_m1'")).scalar() == before
        # Reversible.
        _alembic(url, "downgrade", "f9a0b1c2d3e4")
        with target.connect() as c:
            assert c.execute(text("SELECT phone_normalized FROM users WHERE id = 'usr_m1'")).scalar() == "919876500001"
            assert c.execute(text("SELECT text FROM messages WHERE id = 'msg_m1'")).scalar() == "old plaintext message"
            assert c.execute(text("SELECT phone_normalized FROM banned_phones")).scalar() == "919876500002"
        _alembic(url, "upgrade", "head")
        _alembic(url, "check")
    finally:
        target.dispose()
        with admin.connect() as c:
            c.execute(text("DROP DATABASE IF EXISTS capstoneconnect_migration_test WITH (FORCE)"))
        admin.dispose()


# --- F7: notes written by students are encrypted ----------------------------------------------

def test_join_request_and_recommendation_notes_are_ciphertext_at_rest(as_user):
    looking = as_user("usr_8")
    req = looking.post("/api/groups/grp_4/join-requests", json={"note": "my number is 98765 44444"})
    assert req.status_code == 201, req.text
    with SessionLocal() as db:
        raw = db.execute(text("SELECT note FROM join_requests WHERE id = :id"), {"id": req.json()["id"]}).scalar()
    assert raw.startswith("enc:") and "98765" not in raw
    assert crypto.decrypt(raw, "join_requests", "note", req.json()["id"]) == "my number is 98765 44444"
    sent = {r["id"]: r for r in looking.get("/api/requests", params={"direction": "sent"}).json()}
    assert sent[req.json()["id"]]["note"] == "my number is 98765 44444"  # served decrypted to its author


def test_the_notes_migration_seals_plaintext_even_when_it_starts_with_enc(monkeypatch):
    from importlib.util import module_from_spec, spec_from_file_location
    from types import SimpleNamespace

    from app.db import engine
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        "alembic", "versions", "b1c2d3e4f5a6_encrypt_notes.py")
    spec = spec_from_file_location("encrypt_notes_migration", path)
    migration = module_from_spec(spec)
    spec.loader.exec_module(migration)
    with engine.begin() as conn:
        rid = conn.execute(text("SELECT id FROM join_requests LIMIT 1")).scalar()
        conn.execute(text("UPDATE join_requests SET note = 'enc:looks sealed but is not' WHERE id = :id"), {"id": rid})
        monkeypatch.setattr(migration, "op", SimpleNamespace(get_bind=lambda: conn))
        migration.upgrade()
        once = conn.execute(text("SELECT note FROM join_requests WHERE id = :id"), {"id": rid}).scalar()
        migration.upgrade()  # idempotent
        assert conn.execute(text("SELECT note FROM join_requests WHERE id = :id"), {"id": rid}).scalar() == once
        assert crypto.decrypt(once, "join_requests", "note", rid) == "enc:looks sealed but is not"
        migration.downgrade()  # reversible
        assert conn.execute(text("SELECT note FROM join_requests WHERE id = :id"), {"id": rid}).scalar() == "enc:looks sealed but is not"


def test_rotation_covers_the_notes(monkeypatch):
    with SessionLocal() as db:
        rid = db.execute(text("SELECT id FROM join_requests WHERE note IS NOT NULL AND note <> '' LIMIT 1")).scalar()
    s = get_settings()
    monkeypatch.setattr(s, "field_encryption_keys", f"k3:{_key()},{s.field_encryption_keys}")
    with SessionLocal() as db:
        assert rotate(db)["join_requests"] > 0
        assert crypto.key_id_of(db.execute(text("SELECT note FROM join_requests WHERE id = :id"), {"id": rid}).scalar()) == "k3"


# --- F8: values that aren't valid ciphertext are found and sealed ------------------------------

def test_encrypt_pending_seals_plaintext_that_starts_with_enc(as_user):
    from app.services.key_rotation import encrypt_pending

    mid = as_user(LEAD).post("/api/conversations/conv_2/messages", json={"text": "placeholder"}).json()["id"]
    with SessionLocal() as db:
        db.execute(text("UPDATE messages SET text = 'enc:hello' WHERE id = :id"), {"id": mid})
        db.commit()
    with SessionLocal() as db, pytest.raises(crypto.FieldCryptoError):
        _ = db.get(Message, mid).text  # fails closed until sealed
    with SessionLocal() as db:
        assert encrypt_pending(db)["messages"] >= 1
        assert encrypt_pending(db)["messages"] == 0  # idempotent
    with SessionLocal() as db:
        assert db.get(Message, mid).text == "enc:hello"
    assert crypto.is_sealed_for("enc:hello", "messages", "text", mid) is False
