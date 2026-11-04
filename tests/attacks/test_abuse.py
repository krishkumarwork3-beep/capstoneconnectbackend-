"""Part 5 and 6: availability limits, per-account write limits, what answers may contain, CORS,
log injection, framing, caching, and the attack classes that don't apply (proven, not assumed)."""

import io
import json
import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import log_safety
from app.config import get_settings
from app.db import SessionLocal, engine
from app.main import app
from app.services import limits
from tests.attacks.payloads import deep_json

GROUP = {"name": "Probe", "description": "x", "max_members": 4, "domain": "Testing"}


# --- Request size, shape and paging --------------------------------------------------------------


def test_oversized_json_bodies_are_refused(as_user):
    big = {"bio": "x" * (get_settings().max_json_body_bytes + 10)}
    assert as_user("usr_8").patch("/api/users/usr_8", json=big).status_code == 413


def test_oversized_bodies_without_a_length_are_cut_off(as_user):
    def chunks():
        yield b'{"bio": "'
        for _ in range(3):
            yield b"x" * (1024 * 1024)
        yield b'"}'

    r = as_user("usr_8").patch("/api/users/usr_8", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


@pytest.mark.parametrize("depth", [40, 500, 5000])
def test_deeply_nested_json_is_refused(as_user, depth):
    body = '{"bio": ' + '{"a":' * depth + "1" + "}" * depth + "}"
    r = as_user("usr_8").patch("/api/users/usr_8", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code in (400, 413, 422)
    assert r.status_code != 500


def test_huge_arrays_are_refused(as_user):
    body = json.dumps({"skills": ["a"] * 20_000})
    r = as_user("usr_8").patch("/api/users/usr_8", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code in (400, 413, 422)


def test_duplicate_json_keys_are_refused(as_user):
    r = as_user("usr_8").patch("/api/users/usr_8", content='{"bio": "a", "bio": "b"}', headers={"Content-Type": "application/json"})
    assert r.status_code == 400


@pytest.mark.parametrize("url", ["/api/users?limit=100000", "/api/groups?limit=5000", "/api/users?cursor=" + "9" * 40,
                                 "/api/users?limit=-1", "/api/groups?limit=0", "/api/groups?cursor=" + "9" * 40])
def test_page_sizes_are_capped(as_user, url):
    assert as_user("usr_8").get(url).status_code == 422


def test_admin_page_sizes_are_capped(admin_client):
    admin = admin_client()
    assert admin.get("/api/admin/users?page_size=100000").status_code == 422
    assert admin.get("/api/admin/users?page=100000000").status_code == 422
    assert admin.get("/api/admin/conversations/conv_1/messages?limit=100000").status_code == 422


def test_duplicate_query_parameters_are_refused(as_user):
    """Parameter pollution: ?search=a&search=b is ambiguous across layers; refused, not guessed."""
    assert as_user("usr_8").get("/api/users?search=a&search=b").status_code == 400


def test_statement_timeout_is_set():
    with engine.connect() as conn:
        value = conn.execute(text("SHOW statement_timeout")).scalar()
    assert value not in ("0", "0ms", None)


def test_a_slow_query_is_cut_off_and_answers_503(monkeypatch):
    """A statement past the timeout is cancelled by PostgreSQL; the visitor gets a retryable 503."""
    from sqlalchemy.exc import OperationalError

    with engine.connect() as conn:
        conn.execute(text("SET statement_timeout = 100"))
        with pytest.raises(OperationalError) as caught:
            conn.execute(text("SELECT pg_sleep(2)"))
    import psycopg

    assert isinstance(caught.value.orig, psycopg.errors.QueryCanceled)

    probe = TestClient(app)

    @app.get("/api/__slow_probe", include_in_schema=False)
    def _slow():  # pragma: no cover - test-only route
        with SessionLocal() as db:
            db.execute(text("SET LOCAL statement_timeout = 50"))
            db.execute(text("SELECT pg_sleep(1)"))

    try:
        r = probe.get("/api/__slow_probe")
        assert r.status_code == 503 and r.headers["retry-after"]
    finally:
        app.router.routes[:] = [rt for rt in app.router.routes if getattr(rt, "path", "") != "/api/__slow_probe"]


# --- Per-account write limits ------------------------------------------------------------------


@pytest.mark.parametrize("action,call", [
    ("message", lambda c, i: c.post("/api/conversations/conv_2/messages", json={"text": f"spam {i}"})),
    ("profile_edit", lambda c, i: c.patch("/api/users/usr_1", json={"bio": f"bio {i}"})),
    ("group_edit", lambda c, i: c.patch("/api/groups/grp_1", json={"description": f"d {i}"})),
    ("upload", lambda c, i: c.post("/api/uploads/attachments", files={"file": ("a.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")})),
    ("report", lambda c, i: c.post("/api/reports", json={"target_type": "group", "target_id": f"grp_{i % 6 + 1}", "reason": "spam", "details": ""})),
])
def test_write_limits_stop_scripts(as_user, monkeypatch, action, call):
    monkeypatch.setitem(limits.WRITE_LIMITS, action, (3, limits.WRITE_LIMITS[action][1]))
    c = as_user("usr_1")
    codes = [call(c, i).status_code for i in range(5)]
    assert 429 in codes, codes
    assert codes.index(429) <= 3


def test_write_limits_are_per_account(as_user, monkeypatch):
    monkeypatch.setitem(limits.WRITE_LIMITS, "message", (2, limits.WRITE_LIMITS["message"][1]))
    lead, other = as_user("usr_1"), as_user("usr_2")
    for i in range(3):
        lead.post("/api/conversations/conv_2/messages", json={"text": f"x{i}"})
    assert lead.post("/api/conversations/conv_2/messages", json={"text": "more"}).status_code == 429
    assert other.post("/api/conversations/conv_2/messages", json={"text": "fine"}).status_code == 201


def test_group_creation_is_limited(as_user, monkeypatch):
    monkeypatch.setitem(limits.WRITE_LIMITS, "group_create", (1, limits.WRITE_LIMITS["group_create"][1]))
    c = as_user("usr_8")
    assert c.post("/api/groups", json=GROUP).status_code == 201
    c.delete(f"/api/groups/{c.get('/api/auth/me').json()['group_id']}")
    assert c.post("/api/groups", json=GROUP).status_code == 429


def test_github_lookups_are_limited_per_address(client, monkeypatch):
    monkeypatch.setitem(limits.WRITE_LIMITS, "github_lookup", (2, limits.WRITE_LIMITS["github_lookup"][1]))
    codes = [client.get("/api/github/verify", params={"username": "not a name!"}).status_code for _ in range(4)]
    assert codes[-1] == 429, codes


# --- What answers contain ----------------------------------------------------------------------

SECRET_KEYS = {"password_hash", "phone_normalized", "code_hash", "secret_key", "reset_token_hash", "ban_reason_internal",
               "user_agent", "pv", "sid"}


def _keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in _keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in _keys(v)}
    return set()


def test_answers_never_carry_internal_fields(as_user, admin_client):
    student, admin = as_user("usr_1"), admin_client()
    seen: set[str] = set()
    for path in ["/api/auth/me", "/api/users", "/api/users/usr_8", "/api/groups", "/api/groups/grp_1", "/api/groups/mine",
                 "/api/requests?direction=received", "/api/recommendations", "/api/conversations", "/api/conversations/conv_1/messages"]:
        r = student.get(path)
        assert r.status_code == 200, path
        seen |= _keys(r.json())
    for path in ["/api/admin/users", "/api/admin/users/usr_1", "/api/admin/groups", "/api/admin/admins", "/api/admin/audit",
                 "/api/admin/conversations", "/api/admin/reports", "/api/admin/stats"]:
        r = admin.get(path)
        assert r.status_code == 200, path
        seen |= _keys(r.json())
    assert not seen & SECRET_KEYS, seen & SECRET_KEYS


def test_every_json_route_declares_what_it_answers():
    """Response models filter fields: a route returning a bare dict could leak a column one day."""
    bare = []
    for path, ops in app.openapi()["paths"].items():
        for method, op in ops.items():
            for code, answer in op.get("responses", {}).items():
                if not code.startswith("2") or code == "204":
                    continue
                schema = (answer.get("content", {}).get("application/json") or {}).get("schema")
                if schema == {} or (schema and schema.get("type") == "object" and not schema.get("properties") and "$ref" not in schema
                                    and not schema.get("additionalProperties")):
                    bare.append(f"{method.upper()} {path}")
    # Reasons and health are fixed shapes; stats are aggregates (their content is checked by the
    # internal-fields test above); files are bytes.
    allowed = {"GET /api/reports/reasons", "GET /api/health", "GET /uploads/{purpose}/{name}", "GET /api/admin/stats"}
    assert set(bare) <= allowed, set(bare) - allowed


# --- CORS ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("origin", ["null", "https://evil.example", "http://localhost:3000.evil.example", "http://evillocalhost:3000",
                                    "http://localhost:30000", "https://localhost:3000", "http://LOCALHOST:3000"])
def test_cors_never_trusts_null_or_look_alike_origins(client, origin):
    r = client.options("/api/auth/me", headers={"Origin": origin, "Access-Control-Request-Method": "GET"})
    assert r.headers.get("access-control-allow-origin") in (None, ""), origin
    r = client.get("/api/groups", headers={"Origin": origin})
    # Without Access-Control-Allow-Origin the browser hands nothing to that page (Starlette may still
    # send allow-credentials on every answer; on its own it grants nothing).
    assert "access-control-allow-origin" not in r.headers


def test_cors_allows_the_site_with_credentials(client):
    r = client.get("/api/groups", headers={"Origin": "http://localhost:3000"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert r.headers["access-control-allow-credentials"] == "true"


# --- Log injection -------------------------------------------------------------------------------


def test_log_lines_can_not_be_forged_or_colour_the_terminal():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(log_safety.SafeLogFilter())
    logger = logging.getLogger("test.injection")
    logger.addHandler(handler)
    try:
        logger.warning("GitHub sync for %s skipped: %s", "usr_1\r\n2026-01-01 INFO app: admin logged in", "\x1b[31mred\x1b[0m\x07")
        logger.warning("token %s", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c3JfMSJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ")
        logger.warning("login failed: password=hunter2-secret, Authorization: Bearer abcdefghijklmnop")
        logger.warning("%s", "A" * 50_000)
    finally:
        logger.removeHandler(handler)
    lines = stream.getvalue().splitlines()
    assert len(lines) == 4
    assert "\x1b" not in stream.getvalue() and "\x07" not in stream.getvalue()
    assert "\\r\\n2026-01-01" in lines[0]
    assert "eyJ" not in lines[1] and "[redacted]" in lines[1]
    assert "hunter2" not in lines[2] and "abcdefghijklmnop" not in lines[2]
    assert len(lines[3]) < log_safety.MAX_MESSAGE + 200


def test_the_filter_is_installed_on_the_app_handlers():
    handlers = logging.getLogger().handlers
    assert handlers and all(any(isinstance(f, log_safety.SafeLogFilter) for f in h.filters) for h in handlers)


# --- Framing, caching ------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/health", "/api/groups", "/api/auth/me", "/uploads/avatar/ava_0123456789abcdef.png"])
def test_api_answers_can_not_be_framed(client, path):
    r = client.get(path)
    assert r.headers["x-frame-options"] == "DENY"
    if path.startswith("/api/"):
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_docs_may_only_be_framed_by_the_portal(client):
    csp = client.get("/docs").headers["content-security-policy"]
    assert "frame-ancestors" in csp and "*" not in csp


def test_api_answers_are_never_cached(as_user):
    r = as_user("usr_1").get("/api/auth/me")
    assert r.headers["cache-control"] == "no-store"


# --- Attack classes that don't apply here: proven ---------------------------------------------


@pytest.mark.parametrize("path", ["/graphql", "/api/graphql", "/api/oauth/authorize", "/oauth/token", "/api/auth/oauth/callback",
                                  "/.well-known/openid-configuration", "/api/auth/mfa", "/api/xmlrpc", "/soap", "/api/import"])
def test_no_graphql_oauth_mfa_xml_or_import_endpoints_exist(client, path):
    assert client.post(path, json={}).status_code in (404, 405)
    assert client.get(path).status_code in (404, 405)


@pytest.mark.parametrize("content_type", ["application/xml", "text/xml", "application/soap+xml", "application/x-yaml",
                                          "application/x-python-pickle", "application/x-www-form-urlencoded"])
def test_no_body_format_but_json_and_multipart_is_read(as_user, content_type):
    r = as_user("usr_8").post("/api/groups", content=b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
                               headers={"Content-Type": content_type})
    assert r.status_code == 415


def test_no_server_side_rendering_of_user_text():
    """Rich text and templates don't exist here: every answer is JSON, every page is the frontends'."""
    html_routes = [f"{m.upper()} {p}" for p, ops in app.openapi()["paths"].items() for m, op in ops.items()
                   for answer in op.get("responses", {}).values() if "text/html" in answer.get("content", {})]
    assert html_routes == []


# --- Third-party assets ----------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_api_docs_load_nothing_from_other_sites(client, path):
    r = client.get(path)
    assert r.status_code == 200
    for host in ("cdn.jsdelivr.net", "unpkg.com", "fonts.googleapis.com", "fastapi.tiangolo.com", "http://", "https://"):
        assert host not in r.text, host
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "https:" not in csp.replace("frame-ancestors", "")[: csp.find("frame-ancestors")]


def test_docs_assets_are_served_by_the_api(client):
    for name in ("swagger-ui-bundle.js", "swagger-ui.css", "redoc.standalone.js"):
        r = client.get(f"/docs-assets/{name}")
        assert r.status_code == 200 and len(r.content) > 10_000
        assert r.headers["x-content-type-options"] == "nosniff"


def test_the_server_itself_caps_frames_and_connections():
    from pathlib import Path

    entry = (Path(__file__).resolve().parents[2] / "docker-entrypoint.sh").read_text(encoding="utf-8")
    assert "--ws-max-size 65536" in entry and "--limit-concurrency" in entry and "--timeout-keep-alive" in entry
    assert "\\n  --" not in entry  # no literal "\n" left in the command: every flag on its own line


def test_uvicorn_coloured_lines_still_show_their_values():
    import logging

    from uvicorn.logging import DefaultFormatter

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(DefaultFormatter("%(levelprefix)s %(message)s", use_colors=True))
    handler.addFilter(log_safety.SafeLogFilter())
    logger = logging.getLogger("test.uvicorn")
    logger.addHandler(handler)
    try:
        logger.info("Started server process [%d]", 1234, extra={"color_message": "Started server process [\x1b[36m%d\x1b[0m]"})
    finally:
        logger.removeHandler(handler)
    assert "[1234]" in stream.getvalue() and "%d" not in stream.getvalue()


def test_uvicorn_access_lines_format_and_are_cleaned():
    """The access formatter unpacks record.args: the filter must keep them (cleaned), not drop
    them (that printed a "--- Logging error ---" traceback for every request)."""
    import logging
    import sys

    from uvicorn.logging import AccessFormatter

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False))
    handler.addFilter(log_safety.SafeLogFilter())
    logger = logging.getLogger("uvicorn.access")
    logger.addHandler(handler)
    errors = io.StringIO()
    old_stderr, sys.stderr = sys.stderr, errors
    try:
        logger.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:5000", "GET", "/api/x\r\nFAKE 200\x1b[31m", "1.1", 200)
    finally:
        sys.stderr = old_stderr
        logger.removeHandler(handler)
    line = stream.getvalue()
    assert "Logging error" not in errors.getvalue(), errors.getvalue()[:300]
    assert line.count("\n") == 1 and "\x1b" not in line and "\r" not in line
    assert "/api/x\\r\\nFAKE" in line and line.rstrip().endswith("200 OK")
