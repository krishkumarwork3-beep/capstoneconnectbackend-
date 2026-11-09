"""A full backup, then a restore into a fresh database: every table and row comes back."""

import importlib.util
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import create_engine, inspect, text

from app import crypto
from app.db import engine

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("db_backup", ROOT / "scripts" / "db_backup.py")
db_backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(db_backup)


def _counts(eng) -> dict[str, int]:
    with eng.connect() as c:
        return {t: c.scalar(text(f'select count(*) from "{t}"')) for t in sorted(inspect(eng).get_table_names())}


def test_backup_then_restore_into_a_fresh_database(tmp_path, as_user):
    try:
        db_backup.tool("pg_dump")
    except SystemExit:
        pytest.skip("pg_dump is not installed")
    # Some activity first, so the dump has more than the seed.
    lead = as_user("usr_1")
    conv = next(c["id"] for c in lead.get("/api/conversations").json() if c["type"] == "group")
    lead.post(f"/api/conversations/{conv}/messages", json={"text": "backed up"})

    source_url = engine.url.render_as_string(hide_password=False)
    dump = db_backup.backup(source_url, tmp_path / "test.dump")
    assert dump.stat().st_size > 1000

    target = engine.url.set(database="capstoneconnect_restore_test")
    admin = engine.url.set(drivername="postgresql", database="postgres").render_as_string(hide_password=False)
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute("DROP DATABASE IF EXISTS capstoneconnect_restore_test WITH (FORCE)")
    db_backup.restore(dump, target.render_as_string(hide_password=False), create=True)

    restored = create_engine(target)
    try:
        assert _counts(restored) == _counts(engine)
        with restored.connect() as c:
            # Messages are encrypted at rest: the dump holds ciphertext, which the same keys decrypt.
            rows = c.execute(text("select id, text from messages where text <> ''")).all()
            assert rows and all(t.startswith("enc:") for _, t in rows)
            assert sum(crypto.decrypt(t, "messages", "text", i) == "backed up" for i, t in rows) == 1
    finally:
        restored.dispose()


def test_the_servers_own_major_version_of_the_tools_is_preferred(tmp_path, monkeypatch):
    """A pg_restore newer than the server writes settings the server rejects (17+ into 16)."""
    (tmp_path / "16" / "bin").mkdir(parents=True)
    (tmp_path / "16" / "bin" / "pg_restore").write_text("")
    monkeypatch.setattr(db_backup, "VERSIONED", str(tmp_path / "{major}" / "bin" / "{name}"))
    assert db_backup.tool("pg_restore", 16) == str(tmp_path / "16" / "bin" / "pg_restore")
    # Not installed for that version: the default tools, as before.
    assert db_backup.tool("pg_restore", 15) != str(tmp_path / "15" / "bin" / "pg_restore")


def test_the_server_version_is_read():
    from app.db import engine

    assert db_backup.server_major(engine.url.render_as_string(hide_password=False)) >= 14
