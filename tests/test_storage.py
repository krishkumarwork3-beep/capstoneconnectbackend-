"""File storage: the S3 backend (against moto's in-process S3, as no Docker/MinIO is available
here), the local→S3 migration script, paths instead of full links, and old links from before."""

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import get_settings
from app.db import SessionLocal
from app.main import app
from app.services import storage as storage_module

LEAD, MEMBER, OTHER = "usr_1", "usr_9", "usr_8"
PNG = __import__("tests.conftest", fromlist=["REAL_PNG"]).REAL_PNG  # a real 8x8 image (uploads are re-encoded)
PDF = b"%PDF-1.4\n" + b"1" * 64 + b"\n%%EOF\n"
ROOT = Path(__file__).resolve().parent.parent


def _path(url: str) -> str:
    return url[url.index("/uploads/"):]


@pytest.fixture
def s3(monkeypatch):
    """The API on an S3 bucket (moto)."""
    moto = pytest.importorskip("moto")
    with moto.mock_aws():
        import boto3

        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="cc-test")
        settings = get_settings()
        for name, value in {"storage_backend": "s3", "s3_bucket": "cc-test", "s3_region": "us-east-1",
                            "s3_access_key_id": "testing", "s3_secret_access_key": "testing", "s3_prefix": "uploads"}.items():
            monkeypatch.setattr(settings, name, value)
        storage_module.get_storage.cache_clear()
        yield storage_module.get_storage()
        storage_module.get_storage.cache_clear()


def test_s3_backend_keeps_every_rule(s3, as_user, admin_client):
    student, lead, member = as_user(OTHER), as_user(LEAD), as_user(MEMBER)
    avatar = student.post(f"/api/users/{OTHER}/avatar", files={"avatar": ("me.png", PNG, "image/png")}).json()["avatar_url"]
    resume = student.post(f"/api/users/{OTHER}/resume", files={"resume": ("cv.pdf", PDF, "application/pdf")}).json()["resume_url"]
    assert sorted(s3.keys()) == sorted([_path(avatar)[len("/uploads/"):], _path(resume)[len("/uploads/"):]])
    assert s3.client.list_objects_v2(Bucket="cc-test")["KeyCount"] == 2  # under the "uploads/" prefix
    guest = TestClient(app)
    assert guest.get(_path(avatar)).content == PNG
    assert guest.get(_path(resume)).status_code == 401
    assert lead.get(_path(resume)).content == PDF

    conv = next(c["id"] for c in lead.get("/api/conversations").json() if c["type"] == "group")
    att = lead.post("/api/uploads/attachments", files={"file": ("n.pdf", PDF, "application/pdf")}).json()
    assert lead.post(f"/api/conversations/{conv}/messages", json={"text": "", "attachment": att}).status_code == 201
    assert member.get(_path(att["url"])).content == PDF
    assert student.get(_path(att["url"])).status_code == 403
    assert admin_client().get(_path(att["url"])).status_code == 200

    # Removing the photo deletes the object.
    assert admin_client().delete(f"/api/admin/users/{OTHER}/avatar").status_code == 200
    assert not s3.exists(_path(avatar)[len("/uploads/"):])
    assert guest.get(_path(avatar)).status_code == 404


def test_migration_script_copies_local_files_to_s3(tmp_path, s3):
    spec = importlib.util.spec_from_file_location("migrate_uploads", ROOT / "scripts" / "migrate_uploads.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    local = storage_module.LocalStorage(tmp_path)
    local.put("avatar/ava_0123456789abcdef.png", PNG, "image/png")
    local.put("resume/res_0123456789abcdef.pdf", PDF, "application/pdf")
    assert module.migrate(local, s3, dry_run=True) == (2, 0)
    assert s3.keys() == []
    assert module.migrate(local, s3) == (2, 0)
    assert s3.get("resume/res_0123456789abcdef.pdf") == PDF
    assert module.migrate(local, s3) == (0, 2)  # safe to run again


def test_the_database_keeps_paths_and_answers_full_links(as_user, monkeypatch):
    student = as_user(OTHER)
    url = student.post(f"/api/users/{OTHER}/avatar", files={"avatar": ("me.png", PNG, "image/png")}).json()["avatar_url"]
    with SessionLocal() as db:
        stored = db.scalar(text("select avatar_url from users where id = :id"), {"id": OTHER})
    assert stored.startswith("/uploads/avatar/") and url == f"{get_settings().public_base_url}{stored}"
    # A new domain: links follow it without touching the database.
    monkeypatch.setattr(get_settings(), "public_base_url", "https://api.example.com")
    assert student.get("/api/auth/me").json()["avatar_url"] == f"https://api.example.com{stored}"


def test_links_saved_before_the_change_still_work_for_the_right_people(as_user, admin_client):
    """Rows written by the old code held full links (http://localhost:8000/uploads/…)."""
    settings = get_settings()
    folder = settings.upload_dir
    (folder / "resume").mkdir(parents=True, exist_ok=True)
    (folder / "attachment").mkdir(parents=True, exist_ok=True)
    (folder / "resume" / "res_00000000000000aa.pdf").write_bytes(PDF)
    (folder / "attachment" / "att_00000000000000bb.pdf").write_bytes(PDF)
    lead, member, outsider = as_user(LEAD), as_user(MEMBER), as_user(OTHER)
    conv = next(c["id"] for c in lead.get("/api/conversations").json() if c["type"] == "group")
    with SessionLocal() as db:
        db.execute(text("update users set resume_url = 'http://localhost:8000/uploads/resume/res_00000000000000aa.pdf' where id = :id"), {"id": OTHER})
        db.execute(text(
            "insert into messages (id, conversation_id, sender_id, sender_name, text, attachment_name, attachment_url, attachment_size, created_at) "
            "values ('msg_old', :c, :s, 'Aarav', '', 'old.pdf', 'http://old-host.example/uploads/attachment/att_00000000000000bb.pdf', 10, now())"
        ), {"c": conv, "s": LEAD})
        db.commit()

    # Before the migration: the old full links still resolve, with the same rules.
    assert member.get("/uploads/attachment/att_00000000000000bb.pdf").content == PDF
    assert outsider.get("/uploads/attachment/att_00000000000000bb.pdf").status_code == 403
    assert TestClient(app).get("/uploads/resume/res_00000000000000aa.pdf").status_code == 401
    assert lead.get("/uploads/resume/res_00000000000000aa.pdf").content == PDF

    # Old links reach the browser rewritten to the current domain.
    assert member.get("/uploads/attachment/att_00000000000000bb.pdf").content == PDF
    assert outsider.get("/uploads/attachment/att_00000000000000bb.pdf").status_code == 403
    messages = member.get(f"/api/conversations/{conv}/messages").json()
    old = next(m for m in messages if m["id"] == "msg_old")
    assert old["attachment"]["url"] == f"{get_settings().public_base_url}/uploads/attachment/att_00000000000000bb.pdf"
    assert admin_client().get("/uploads/attachment/att_00000000000000bb.pdf").status_code == 200


def test_the_migration_file_uses_the_same_pattern():
    source = (ROOT / "alembic" / "versions" / "6883dc731d51_store_upload_paths_instead_of_full_urls.py").read_text(encoding="utf-8")
    assert r"[a-z]{3}_[0-9a-f]{16}\.(png|jpg|pdf|zip|docx)" in source and "'\\\\1'" in source
