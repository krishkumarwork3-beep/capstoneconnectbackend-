"""Part 4: account takeover (reset flow, OTP, host poisoning, guessable passwords), per-account
lock-out with back-off, allowed hosts and header injection."""

import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.db import SessionLocal
from app.main import app
from app.models import AuthSession, LoginLockout, PasswordResetCode
from app.passwords import password_problem
from app.routers.files import _disposition
from app.services import lockout
from tests.conftest import ADMIN_PASSWORD, PASSWORD, PHONES

LEAD = "usr_1"
FORMATS = ["+91 98765 43210", "9876543210", "09876543210", "91-98765-43210", "+91 (98765) 43210", "919876543210", " +91 98765 43210 "]


def _grant(client, phone=PHONES[LEAD]) -> str:
    code = client.post("/api/auth/password/forgot", json={"phone": phone}).json()["dev_code"]
    return client.post("/api/auth/password/verify", json={"phone": phone, "code": code}).json()["reset_token"]


# --- Reset flow -------------------------------------------------------------------------------


def test_reset_grant_works_once(client):
    grant = _grant(client)
    assert client.post("/api/auth/password/reset", json={"reset_token": grant, "password": "first-new-pass-1"}).status_code == 200
    assert TestClient(app).post("/api/auth/password/reset", json={"reset_token": grant, "password": "second-new-pass-2"}).status_code == 400


def test_reset_grant_used_twice_at_the_same_moment_works_once(client):
    grant = _grant(client)
    results: list[int] = []

    def use(password):
        results.append(TestClient(app).post("/api/auth/password/reset", json={"reset_token": grant, "password": password}).status_code)

    threads = [threading.Thread(target=use, args=(f"racing-pass-{i}-x",)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results).count(200) == 1, results


def test_expired_reset_grant_is_refused(client):
    grant = _grant(client)
    with SessionLocal() as db:
        db.execute(update(AuthSession).where(AuthSession.kind == "reset").values(expires_at=AuthSession.created_at - timedelta(seconds=1)))
        db.commit()
    assert client.post("/api/auth/password/reset", json={"reset_token": grant, "password": "late-new-pass-1"}).status_code == 400


def test_a_weak_password_does_not_spend_the_grant(client):
    grant = _grant(client)
    assert client.post("/api/auth/password/reset", json={"reset_token": grant, "password": "password123"}).status_code == 422
    assert client.post("/api/auth/password/reset", json={"reset_token": grant, "password": "a-good-new-pass-5"}).status_code == 200


def test_one_code_gives_one_grant(client):
    code = client.post("/api/auth/password/forgot", json={"phone": PHONES[LEAD]}).json()["dev_code"]
    first = client.post("/api/auth/password/verify", json={"phone": PHONES[LEAD], "code": code})
    second = TestClient(app).post("/api/auth/password/verify", json={"phone": PHONES[LEAD], "code": code})
    assert first.status_code == 200 and second.status_code == 400


def test_parallel_code_guesses_can_not_exceed_the_attempt_limit(client, monkeypatch):
    from app.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "verify_limit_per_phone", 1000)
    monkeypatch.setattr(s, "verify_limit_per_ip", 1000)
    code = client.post("/api/auth/password/forgot", json={"phone": PHONES[LEAD]}).json()["dev_code"]
    wrong = "000000" if code != "000000" else "111111"

    def guess():
        TestClient(app).post("/api/auth/password/verify", json={"phone": PHONES[LEAD], "code": wrong})

    threads = [threading.Thread(target=guess) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with SessionLocal() as db:
        record = db.query(PasswordResetCode).one()
        assert record.used_at is not None  # used up
        assert record.attempts <= s.otp_max_attempts + 20
    # The right code no longer works after the guesses used it up.
    assert client.post("/api/auth/password/verify", json={"phone": PHONES[LEAD], "code": code}).status_code == 400


def test_code_requests_share_one_limit_across_number_formats(client):
    assert client.post("/api/auth/password/forgot", json={"phone": FORMATS[0]}).status_code == 200
    for phone in FORMATS[1:]:
        assert client.post("/api/auth/password/forgot", json={"phone": phone}).status_code == 429, phone


@pytest.mark.parametrize("headers", [{"X-Forwarded-For": "203.0.113.9"}, {"User-Agent": "totally-new-browser"},
                                     {"X-Real-IP": "198.51.100.1"}, {"Forwarded": "for=192.0.2.1"}, {"True-Client-IP": "192.0.2.7"}])
def test_otp_limits_can_not_be_dodged_with_headers(client, headers):
    assert client.post("/api/auth/password/forgot", json={"phone": PHONES[LEAD]}).status_code == 200
    assert client.post("/api/auth/password/forgot", json={"phone": "9876543210"}, headers=headers).status_code == 429


def test_answers_do_not_tell_which_numbers_exist(client):
    a = client.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": "wrong-pass-123"})
    b = client.post("/api/auth/login", json={"phone": "+91 90000 99999", "password": "wrong-pass-123"})
    assert (a.status_code, a.json()["message"]) == (b.status_code, b.json()["message"])
    a = client.post("/api/auth/password/verify", json={"phone": PHONES["usr_2"], "code": "123456"})
    b = client.post("/api/auth/password/verify", json={"phone": "+91 90000 99998", "code": "123456"})
    assert (a.status_code, a.json()["message"]) == (b.status_code, b.json()["message"])


def test_host_header_poisoning_is_refused(client):
    assert client.post("/api/auth/password/forgot", json={"phone": PHONES[LEAD]}, headers={"Host": "evil.example"}).status_code == 400
    assert client.get("/api/health", headers={"Host": "evil.example"}).status_code == 400
    # Forwarded host headers are ignored (no proxy is trusted here) and nothing echoes them.
    r = client.post("/api/auth/password/forgot", json={"phone": PHONES["usr_2"]}, headers={"X-Forwarded-Host": "evil.example"})
    assert r.status_code == 200 and "evil" not in r.text


def test_no_link_is_built_from_the_request_host():
    import ast
    from pathlib import Path

    bad = []
    for path in (Path(__file__).resolve().parents[2] / "app").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr in ("base_url", "url_for"):
                bad.append(f"{path.name}:{node.lineno}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.lower() in ("host", "x-forwarded-host"):
                bad.append(f"{path.name}:{node.lineno}")
    assert bad == []


# --- Guessable passwords --------------------------------------------------------------------------


@pytest.mark.parametrize("password", [
    "password123", "Password123!", "P@ssw0rd2024", "p4ssw0rd!!", "qwerty2025", "Qwerty@123", "iloveyou2024",
    "india@2025", "Cricket#1234", "admin@12345", "welcome2026!", "abcdefgh", "12345678", "87654321", "asdfghjkl",
    "zxcvbnm123", "aaaaaaaa", "abababab", "11112222", "capstone2025", "Student@2026", "letmein!!",
])
def test_breached_and_guessable_passwords_are_refused(password):
    assert password_problem(password) is not None, password


@pytest.mark.parametrize("password", ["correct horse battery", "Gk7#pQ2v-Lm", "my-capstone-is-rockets-2026x", "tulsi.river.42.blue"])
def test_good_passwords_are_accepted(password):
    assert password_problem(password) is None, password


def test_signup_refuses_a_breached_password(client):
    r = client.post("/api/auth/signup", json={"name": "Weak Pass", "college": "X", "passing_year": 2027,
                                              "phone": "+91 90000 22222", "password": "P@ssw0rd2024"})
    assert r.status_code == 422


# --- Lock-out with back-off ---------------------------------------------------------------------


def test_lock_out_doubles_up_to_a_day():
    assert lockout.lock_for(4) is None
    assert lockout.lock_for(5) == timedelta(minutes=15)
    assert lockout.lock_for(6) == timedelta(minutes=30)
    assert lockout.lock_for(7) == timedelta(minutes=60)
    assert lockout.lock_for(50) == timedelta(days=1)


def test_number_formats_share_one_lock_out(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "login_limit_per_phone", 1000)  # only the lock-out counts here
    for phone in FORMATS[:5]:
        assert client.post("/api/auth/login", json={"phone": phone, "password": "wrong-pass-123"}).status_code == 401
    r = client.post("/api/auth/login", json={"phone": FORMATS[5], "password": PASSWORD})  # even the right password
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 800


def test_unknown_numbers_lock_too(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "login_limit_per_phone", 1000)
    for _ in range(5):
        client.post("/api/auth/login", json={"phone": "+91 90000 77777", "password": "wrong-pass-123"})
    assert client.post("/api/auth/login", json={"phone": "+91 90000 77777", "password": "x" * 8}).status_code == 429


def test_lock_out_grows_after_each_further_failure(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "login_limit_per_phone", 1000)
    key = lockout.student_key(PHONES[LEAD])
    with SessionLocal() as db:
        db.merge(LoginLockout(key=key, failures=6, locked_until=None))
        db.commit()
    client.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": "wrong-pass-123"})  # the 7th
    r = client.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD})
    assert r.status_code == 429 and 3500 < int(r.headers["retry-after"]) <= 3600


def test_success_clears_the_count(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "login_limit_per_phone", 1000)
    for _ in range(4):
        client.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": "wrong-pass-123"})
    assert client.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD}).status_code == 200
    for _ in range(4):
        client.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": "wrong-pass-123"})
    assert client.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD}).status_code == 200


def test_admin_lock_out_is_per_account_across_spellings(admin_client, client):
    admin_client()  # admin0@example.com
    for email in ["admin0@example.com", "ADMIN0@example.com", " Admin0@Example.com ", "admin0@EXAMPLE.COM", "admin0@example.com"]:
        assert client.post("/api/admin/auth/login", json={"email": email, "password": "wrong-pass-123"}).status_code == 401
    r = client.post("/api/admin/auth/login", json={"email": "admin0@example.com", "password": ADMIN_PASSWORD})
    assert r.status_code == 429 and "retry-after" in r.headers
    # Kept in the database: another server process sees the same lock.
    with SessionLocal() as db:
        assert db.get(LoginLockout, "admin:admin0@example.com").failures == 5


# --- Hosts and header injection -----------------------------------------------------------------


@pytest.mark.parametrize("host", ["evil.example", "localhost.evil.example", "127.0.0.1.nip.io", "[::2]", "localhost:8000@evil.example"])
def test_unknown_hosts_are_refused(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 400


def test_request_ids_are_never_echoed_raw(client):
    for value in ["abc\tdef", "x" * 200, "<script>", "id;Set-Cookie=x", "a b"]:
        r = client.get("/api/health", headers={"X-Request-ID": value})
        assert r.headers["x-request-id"] != value
        assert "set-cookie" not in r.headers


def test_download_names_can_not_inject_headers():
    for name in ["evil\r\nSet-Cookie: x=1.pdf", "a\nb.pdf", 'quote".pdf', "back\\slash.pdf", "ünïcödé\r\n.pdf"]:
        value = _disposition(False, name, "file.pdf")
        assert "\r" not in value and "\n" not in value and value.startswith("attachment;"), value
        assert value.count('"') == 2
