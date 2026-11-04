"""Tests run against a real PostgreSQL test database (never the development one).

The URL is TEST_DATABASE_URL, or DATABASE_URL (from .env) with the database renamed
`capstoneconnect_test`. Each test starts from the demo data.
"""

import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _test_url() -> str:
    if os.environ.get("TEST_DATABASE_URL"):
        return os.environ["TEST_DATABASE_URL"]
    env = (ROOT / ".env").read_text(encoding="utf-8") if (ROOT / ".env").exists() else ""
    match = re.search(r"(?m)^DATABASE_URL=(.+)$", env)
    base = os.environ.get("DATABASE_URL") or (match.group(1).strip() if match else "")
    if not base:
        pytest.exit("Set TEST_DATABASE_URL (or DATABASE_URL in .env) to a PostgreSQL server", 2)
    return re.sub(r"/[^/?]+(\?|$)", r"/capstoneconnect_test\1", base, count=1) if base.count("/") >= 3 else base


# Settings are read once, so the environment is set before the app is imported.
os.environ["DATABASE_URL"] = _test_url()
os.environ["SMS_PROVIDER"] = "console"
# The reset tests read the code from the answer; test_security checks it is off by default.
os.environ["ALLOW_DEV_CODE"] = "true"
os.environ["GITHUB_TOKEN"] = ""
os.environ["DEMO_LOGIN"] = "true"
os.environ["UPLOAD_DIR"] = str(ROOT / ".pytest_cache" / "uploads")
# Tests create their own admins (admin_client); no first admin from .env.
# The test client's Host header.
os.environ["ALLOWED_HOSTS"] = '["localhost","127.0.0.1","testserver"]'
os.environ["ADMIN_EMAIL"] = ""
os.environ["ADMIN_PASSWORD"] = ""

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app import models  # noqa: E402,F401
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import TABLES, seed  # noqa: E402
from app.services.admin import create_admin, reset_lockouts  # noqa: E402

assert "_test" in str(engine.url.database), "tests must not run against the development database"

PASSWORD = "password123"


def _real_png() -> bytes:
    import io

    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (8, 8), (40, 120, 200)).save(out, format="PNG")
    return out.getvalue()


# Uploads are decoded and re-encoded (app.services.upload_checks), so fixtures are real files.
REAL_PNG = _real_png()
REAL_PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >>\nendobj\n%%EOF\n"
PHONES = {
    "usr_1": "+91 98765 43210",  # Group Lead, grp_1 (4 seats, 3 taken)
    "usr_2": "+91 98123 45678",  # Group Lead, grp_2
    "usr_4": None,
    "usr_6": "+91 94567 89012",  # Looking: pending join request to grp_1
    "usr_7": "+91 93678 90123",  # Looking: pending join request to grp_1
    "usr_8": "+91 92789 01234",  # Looking
    "usr_9": None,  # Member of grp_1
    "usr_14": "+91 86345 67890",  # Looking: pending invite from grp_1
}


@pytest.fixture(scope="session", autouse=True)
def schema():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    engine.dispose()


@pytest.fixture(autouse=True)
def demo_data(schema):
    with SessionLocal() as db:
        db.execute(text(f"TRUNCATE {TABLES}, admin_users, banned_phones, audit_log, rate_limits, reports, announcements, auth_sessions, login_lockouts CASCADE"))
        db.commit()
        seed(db)
    reset_lockouts()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def as_user():
    """as_user("usr_1") -> a client signed in as that seeded student (demo login)."""
    clients: list[TestClient] = []

    def make(user_id: str) -> TestClient:
        c = TestClient(app)
        clients.append(c)
        response = c.post(f"/api/auth/demo-login/{user_id}")
        assert response.status_code == 200, response.text
        return c

    yield make
    for c in clients:
        c.close()


ADMIN_PASSWORD = "admin-password-1"


@pytest.fixture
def admin_client():
    """admin_client() -> a client signed in to the admin portal (role "admin" or "viewer")."""
    clients: list[TestClient] = []

    def make(role: str = "admin", email: str | None = None) -> TestClient:
        email = email or f"{role}{len(clients)}@example.com"
        with SessionLocal() as db:
            create_admin(db, email, role.title(), ADMIN_PASSWORD, role)
            db.commit()
        c = TestClient(app)
        clients.append(c)
        response = c.post("/api/admin/auth/login", json={"email": email, "password": ADMIN_PASSWORD})
        assert response.status_code == 200, response.text
        return c

    yield make
    for c in clients:
        c.close()
