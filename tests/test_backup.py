"""A full backup, then a restore into a fresh database: every table and row comes back."""

import importlib.util
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import create_engine, inspect, text

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
            assert c.scalar(text("select count(*) from messages where text = 'backed up'")) == 1
    finally:
        restored.dispose()
