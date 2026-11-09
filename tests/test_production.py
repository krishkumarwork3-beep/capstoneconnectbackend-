"""Production behaviour: real uvicorn processes (two workers sharing the rate limits; proxy headers
trusted only from the configured proxy), unsafe settings refusing to start, cookie layouts,
request ids and logs, health checks, clean errors, security headers and SMS settings."""

import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import (
    DEV_BLIND_INDEX_KEY,
    DEV_FIELD_ENCRYPTION_KEYS,
    DEV_SECRET_KEY,
    Settings,
    get_settings,
)
from app.main import app
from tests.conftest import PASSWORD, PHONES, ws_connect

ROOT = Path(__file__).resolve().parent.parent
OTHER = "usr_8"
STRONG_KEY = "Q7v-2kLp9xZr4TbW8mNc1yHs6dFg3jEa5uRo0iVq"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _env(**extra) -> dict:
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "ADMIN_EMAIL": "", "ADMIN_PASSWORD": ""}
    env.update({k: str(v) for k, v in extra.items()})
    return env


class Server:
    """`uvicorn app.main:app` in its own process(es), on the test database."""

    def __init__(self, *args: str, **env):
        self.port = _free_port()
        # Output to a file: an unread pipe fills up and blocks the server mid-request.
        self.log = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(self.port), *args],
            cwd=ROOT, env=_env(**env), stdout=self.log, stderr=subprocess.STDOUT, text=True,
        )
        self.url = f"http://127.0.0.1:{self.port}"

    def output(self) -> str:
        self.log.seek(0)
        return self.log.read()

    def wait(self, timeout: float = 60) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"server exited: {self.output()[-2000:]}")
            try:
                if httpx.get(f"{self.url}/api/health", timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        raise AssertionError("server did not start")

    def stop(self) -> None:
        # The whole tree: on Windows, stopping uvicorn's parent leaves its worker processes running.
        import psutil

        try:
            parent = psutil.Process(self.proc.pid)
            family = parent.children(recursive=True) + [parent]
        except psutil.NoSuchProcess:
            family = []
        for proc in family:
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                pass
        psutil.wait_procs(family, timeout=20)


def _login(url: str, phone: str, password: str, forwarded_for: str | None = None) -> int:
    headers = {"Connection": "close"}
    if forwarded_for:
        headers["X-Forwarded-For"] = forwarded_for
    # A new connection per request, so they spread over the workers.
    with httpx.Client(timeout=10) as client:
        return client.post(f"{url}/api/auth/login", json={"phone": phone, "password": password}, headers=headers).status_code


# ---------------------------------------------------------------------------------------------
# d. Two workers share the limits; e. proxy headers
# ---------------------------------------------------------------------------------------------


def test_two_workers_share_the_login_limit():
    """Two API processes on one database share the sign-in limit. Two single-worker servers, so
    each request goes to the process it is sent to: which of `--workers 2` takes a connection is
    the kernel's choice (on a quiet machine it can hand every one to the same worker)."""
    env = {"EXPOSE_WORKER_PID": "true", "LOGIN_LIMIT_PER_IP": "500"}
    one, two = Server(**env), Server(**env)
    try:
        one.wait()
        two.wait()
        pids = {httpx.get(f"{s.url}/api/health", timeout=10).json()["worker"] for s in (one, two)}
        assert len(pids) == 2, pids
        # Five wrong passwords, alternating between the two processes.
        statuses = [_login((one, two)[i % 2].url, PHONES[OTHER], "wrong-password") for i in range(5)]
        assert statuses == [401] * 5
        # The sixth attempt is refused whichever process takes it, and stays refused.
        assert [_login((two, one)[i % 2].url, PHONES[OTHER], PASSWORD) for i in range(4)] == [429] * 4
    finally:
        one.stop()
        two.stop()


def test_forwarded_for_is_believed_only_from_the_trusted_proxy():
    trusted = Server("--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", LOGIN_LIMIT_PER_IP="3", LOGIN_LIMIT_PER_PHONE="500")
    try:
        trusted.wait()
        assert [_login(trusted.url, "+91 90000 00001", "x" * 9, "198.51.100.1") for _ in range(3)] == [401] * 3
        assert _login(trusted.url, "+91 90000 00001", "x" * 9, "198.51.100.1") == 429
        # Another visitor behind the same proxy has their own limit.
        assert _login(trusted.url, "+91 90000 00002", "x" * 9, "198.51.100.2") == 401
    finally:
        trusted.stop()

    untrusted = Server("--proxy-headers", "--forwarded-allow-ips", "10.9.9.9", LOGIN_LIMIT_PER_IP="3", LOGIN_LIMIT_PER_PHONE="500")
    try:
        untrusted.wait()
        assert [_login(untrusted.url, "+91 90000 00003", "x" * 9, f"203.0.113.{i}") for i in range(3)] == [401] * 3
        # A made-up X-Forwarded-For from an untrusted client changes nothing: same address, limited.
        assert _login(untrusted.url, "+91 90000 00004", "x" * 9, "203.0.113.99") == 429
    finally:
        untrusted.stop()


def test_trusted_proxy_setting_inside_the_app(monkeypatch):
    """TRUSTED_PROXY_IPS: the same rule when the server itself does not handle proxy headers."""
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    monkeypatch.setattr(get_settings(), "login_limit_per_ip", 2)
    wrapped = ProxyHeadersMiddleware(app, trusted_hosts=["10.0.0.5"])
    proxy = TestClient(wrapped, client=("10.0.0.5", 4000))
    stranger = TestClient(wrapped, client=("192.0.2.50", 4000))
    login = lambda c, ip, phone: c.post("/api/auth/login", json={"phone": phone, "password": "x" * 9}, headers={"X-Forwarded-For": ip}).status_code  # noqa: E731
    assert [login(proxy, "198.51.100.7", "+91 90000 00011") for _ in range(2)] == [401, 401]
    assert login(proxy, "198.51.100.7", "+91 90000 00012") == 429
    assert login(proxy, "198.51.100.8", "+91 90000 00013") == 401
    assert [login(stranger, f"198.51.100.{i}", "+91 90000 00014") for i in range(20, 22)] == [401, 401]
    assert login(stranger, "198.51.100.99", "+91 90000 00015") == 429


# ---------------------------------------------------------------------------------------------
# f. Unsafe settings
# ---------------------------------------------------------------------------------------------


SAFE = dict(COOKIE_SECURE="true", SECRET_KEY=STRONG_KEY, DEMO_LOGIN="false", ALLOW_DEV_CODE="false", SMS_PROVIDER="twilio",
            TWILIO_ACCOUNT_SID="AC-test", TWILIO_AUTH_TOKEN="t", TWILIO_FROM_NUMBER="+15550000000",
            CORS_ORIGINS='["https://app.example.com"]', PUBLIC_BASE_URL="https://api.example.com", ADMIN_PASSWORD="",
            # Production needs its own field-encryption and blind-index keys (never the development ones).
            FIELD_ENCRYPTION_KEYS="p1:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            BLIND_INDEX_KEY="ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=")


def _check_config(**env) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "app.check_config"], cwd=ROOT, env=_env(**env), capture_output=True, text=True, timeout=60)


def test_check_config_exit_codes():
    assert _check_config(**SAFE).returncode == 0
    unsafe = _check_config(**{**SAFE, "SECRET_KEY": DEV_SECRET_KEY, "DEMO_LOGIN": "true"})
    assert unsafe.returncode == 1 and "SECRET_KEY" in unsafe.stdout and "DEMO_LOGIN" in unsafe.stdout


@pytest.mark.parametrize("override", [
    {"SECRET_KEY": DEV_SECRET_KEY},
    {"DEMO_LOGIN": "true"},
    {"ALLOW_DEV_CODE": "true"},
    {"FIELD_ENCRYPTION_KEYS": DEV_FIELD_ENCRYPTION_KEYS},
    {"BLIND_INDEX_KEY": DEV_BLIND_INDEX_KEY},
])
def test_the_api_refuses_to_start_unsafe_on_https(override):
    server = Server(**{**SAFE, **override})
    try:
        code = server.proc.wait(timeout=60)
        output = server.output()
    finally:
        server.stop()
    assert code != 0
    assert "Unsafe settings for a public server" in output and next(iter(override)) in output


def test_a_safe_https_config_starts():
    server = Server(**SAFE)
    try:
        server.wait()
        r = httpx.get(f"{server.url}/api/health")
        assert r.status_code == 200 and "max-age" in r.headers["strict-transport-security"]
    finally:
        server.stop()


# ---------------------------------------------------------------------------------------------
# Cookie layouts (and the live socket signs in with the cookie in each)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("layout,settings,expect", [
    ("localhost", {}, {"samesite=lax": True, "secure": False, "domain=": False}),
    ("subdomains", {"cookie_secure": True, "cookie_domain": "example.com"}, {"samesite=lax": True, "secure": True, "domain=example.com": True}),
    ("same origin behind a proxy", {"cookie_secure": True}, {"samesite=lax": True, "secure": True, "domain=": False}),
    ("cross-site", {"cookie_secure": True, "cookie_samesite": "none"}, {"samesite=none": True, "secure": True, "domain=": False}),
])
def test_cookie_attributes_for_each_layout(monkeypatch, layout, settings, expect):
    s = get_settings()
    for name, value in settings.items():
        monkeypatch.setattr(s, name, value)
    client = TestClient(app, base_url="https://testserver" if settings.get("cookie_secure") else "http://testserver")
    r = client.post("/api/auth/login", json={"phone": PHONES[OTHER], "password": PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie, layout
    for part, present in expect.items():
        if part == "secure":
            assert ("; secure" in cookie) == present, layout
        else:
            assert (part in cookie) == present, f"{layout}: {part} in {cookie}"
    # The socket signs in with that same cookie.
    name, token = r.headers["set-cookie"].split(";")[0].split("=", 1)
    # Secure and no Domain: the browser pins a __Host- cookie to this host (no subdomain can set it).
    assert name == (f"__Host-{s.cookie_name}" if settings.get("cookie_secure") and not settings.get("cookie_domain") else s.cookie_name), layout
    ws_client = TestClient(app)
    ws_client.cookies.set(name, token)
    with ws_connect(ws_client) as ws:
        assert ws.receive_json()["type"] == "hello"
    # Logging out clears it with the same attributes.
    out = client.post("/api/auth/logout").headers["set-cookie"].lower()
    assert "max-age=0" in out and (("domain=example.com" in out) == ("domain=example.com" in cookie))


def test_cookie_settings_are_validated():
    with pytest.raises(ValueError, match="COOKIE_SAMESITE=none needs COOKIE_SECURE=true"):
        Settings(cookie_samesite="none", cookie_secure=False)
    with pytest.raises(ValueError, match="COOKIE_DOMAIN"):
        Settings(cookie_domain="https://example.com")
    assert Settings(cookie_domain=".example.co.in").cookie_domain == ".example.co.in"


# ---------------------------------------------------------------------------------------------
# Logs, errors, health, headers
# ---------------------------------------------------------------------------------------------


class Captured(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def caplog_(request):
    """Captures log records (pytest's caplog is off when the suite runs with -p no:logging)."""
    handler = Captured()
    loggers = [logging.getLogger(n) for n in ("app.requests", "capstoneconnect.sms", "app.errors")]
    old = [(lg, lg.level) for lg in loggers]
    for lg in loggers:
        lg.addHandler(handler)
        lg.setLevel(logging.DEBUG)
    yield handler
    for lg, level in old:
        lg.removeHandler(handler)
        lg.setLevel(level)


def test_requests_are_logged_with_an_id_and_without_secrets(client, caplog_):
    caplog = caplog_
    r = client.post("/api/auth/login", json={"phone": PHONES[OTHER], "password": PASSWORD}, headers={"X-Request-ID": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"
    line = json.loads(next(rec.getMessage() for rec in caplog.records if rec.name == "app.requests"))
    assert line["request_id"] == "abc-123" and line["path"] == "/api/auth/login" and line["status"] == 200
    everything = " ".join(rec.getMessage() for rec in caplog.records)
    assert PASSWORD not in everything and "phone" not in line
    # A made-up id that isn't safe to log is replaced.
    assert client.get("/api/health", headers={"X-Request-ID": "bad id\n"}).headers["x-request-id"] != "bad id\n"


def test_reset_codes_never_reach_the_log_unless_allowed(client, caplog_, monkeypatch):
    caplog = caplog_
    monkeypatch.setattr(get_settings(), "allow_dev_code", False)
    client.post("/api/auth/password/forgot", json={"phone": PHONES[OTHER]})
    sms = [rec.getMessage() for rec in caplog.records if rec.name == "capstoneconnect.sms"]
    assert sms and all("••••••" in m and "92789" not in m for m in sms)


def test_unexpected_errors_are_a_clean_json_500(monkeypatch):
    import app.routers.system as system

    def boom(*_):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(system.chat, "unread_total", boom)
    client = TestClient(app, raise_server_exceptions=False)
    client.post("/api/auth/login", json={"phone": PHONES[OTHER], "password": PASSWORD})
    r = client.get("/api/counts")
    assert r.status_code == 500
    body = r.json()
    assert body["message"].startswith("Something went wrong") and body["request_id"] == r.headers["x-request-id"]
    assert "secret internal detail" not in r.text and "Traceback" not in r.text


def test_health_reports_a_database_outage(client, monkeypatch):
    from sqlalchemy.orm import Session

    assert client.get("/api/health").json() == {"status": "ok", "database": "ok"}

    def down(*_, **__):
        raise ConnectionError("database is down")

    monkeypatch.setattr(Session, "execute", down)
    r = client.get("/api/health")
    assert r.status_code == 503 and r.json() == {"status": "unavailable", "database": "down"}


def test_security_headers(client, monkeypatch):
    # The admin portal's origin is configured explicitly (CI has no .env; a developer's may differ).
    monkeypatch.setattr(get_settings(), "cors_origins", ["http://localhost:3000", "http://localhost:3100"])
    api = client.get("/api/health")
    assert api.headers["x-content-type-options"] == "nosniff"
    assert api.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in api.headers["content-security-policy"]
    assert api.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    docs = client.get("/docs")
    # The admin portal may frame the API docs; nothing else may.
    assert "frame-ancestors 'self'" in docs.headers["content-security-policy"] and "http://localhost:3100" in docs.headers["content-security-policy"]
    assert "x-frame-options" not in docs.headers


# ---------------------------------------------------------------------------------------------
# SMS settings
# ---------------------------------------------------------------------------------------------


def test_twilio_without_credentials_is_a_clear_error_not_a_crash(client, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "sms_provider", "twilio")
    monkeypatch.setattr(s, "twilio_account_sid", "")
    monkeypatch.setattr(s, "allow_dev_code", False)
    called = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: called.append(a))  # never reach Twilio
    r = client.post("/api/auth/password/forgot", json={"phone": PHONES[OTHER]})
    assert r.status_code == 503 and "not set up" in r.json()["message"]
    assert called == []
    # An unknown number still gets the usual answer (no SMS is attempted, nothing revealed).
    assert client.post("/api/auth/password/forgot", json={"phone": "+91 90000 00099"}).status_code == 200
