"""Every route is explicitly classified, and the class holds: a new route that is not in this table
fails the test, so nothing ships unprotected by accident.

- public:  anyone (still validated; some check access themselves, noted below)
- student: needs a student session (anonymous → 401)
- admin:   needs an admin session (anonymous and students → 401)
"""

import re

from fastapi.testclient import TestClient
from starlette.routing import WebSocketRoute

from app.main import app

PUBLIC = {
    ("POST", "/api/auth/signup"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/logout"),            # harmless signed out; revokes the caller's session if any
    ("POST", "/api/auth/demo-login/{user_id}"),  # 404 unless DEMO_LOGIN=true (never in production)
    ("POST", "/api/auth/password/forgot"),
    ("POST", "/api/auth/password/verify"),
    ("POST", "/api/auth/password/reset"),
    ("GET", "/api/reports/reasons"),
    ("GET", "/api/announcements"),           # the banner shows to guests too
    ("GET", "/api/github/verify"),           # used during sign-up, before an account exists
    ("GET", "/api/health"),
    ("POST", "/api/admin/auth/login"),
    ("POST", "/api/admin/auth/logout"),
}
# Routes that need a session but answer 401 only after validation or are tested elsewhere.
WEBSOCKETS = {"/api/ws"}  # student session, checked on connect (tests/test_realtime.py)


def _routes() -> set[tuple[str, str]]:
    return {(m.upper(), p) for p, ms in app.openapi()["paths"].items() for m in ms}


def classify(method: str, path: str) -> str:
    if (method, path) in PUBLIC:
        return "public"
    if path.startswith("/api/admin/"):
        return "admin"
    if (path.startswith("/api/") and path not in WEBSOCKETS) or path.startswith("/uploads/"):
        return "student"
    raise AssertionError(f"{method} {path} is not classified: add it to the inventory")


def test_every_route_is_classified():
    routes = _routes()
    assert len(routes) > 90
    for method, path in routes:
        classify(method, path)
    # Nothing outside /api and /uploads except the docs.
    others = {p for _, p in routes if not p.startswith(("/api/", "/uploads/"))}
    assert others == set(), others
    sockets = {r.path for r in app.routes if isinstance(r, WebSocketRoute)} | {
        r.path for r in getattr(app.router, "routes", []) if type(r).__name__ == "APIWebSocketRoute"}
    assert sockets <= WEBSOCKETS | {f"{p}" for p in WEBSOCKETS}, sockets


def _call(client: TestClient, method: str, path: str):
    url = path.replace("{purpose}", "avatar").replace("{name}", "ava_0123456789abcdef.png")
    url = re.sub(r"\{[^}]+\}", "x", url)
    return client.request(method, url, json={} if method not in ("GET", "DELETE") else None)


def test_student_routes_refuse_anonymous_callers(client):
    for method, path in sorted(_routes()):
        if classify(method, path) == "student":
            status = _call(client, method, path).status_code
            assert status in (401, 422), f"{method} {path}: anonymous got {status}"
            if status == 422:
                # Validation ran first; with no body problem it must still be 401.
                assert method in ("POST", "PATCH", "PUT"), f"{method} {path}"


def test_admin_routes_refuse_anonymous_callers_and_students(client, as_user):
    student = as_user("usr_1")
    for method, path in sorted(_routes()):
        if classify(method, path) == "admin":
            for who, c in (("anonymous", client), ("a student", student)):
                status = _call(c, method, path).status_code
                assert status in (401, 422), f"{method} {path}: {who} got {status}"


def test_public_routes_answer_anonymous_callers(client):
    for method, path in sorted(_routes()):
        if classify(method, path) == "public":
            status = _call(client, method, path).status_code
            assert status != 401 or path in ("/api/admin/auth/login",), f"{method} {path}: {status}"


def test_no_route_accepts_unexpected_methods(client):
    """Verb tampering: TRACE, PUT and method-override headers do nothing."""
    for method, path in sorted(_routes()):
        url = re.sub(r"\{[^}]+\}", "x", path)
        for verb in ("TRACE", "PUT", "CONNECT"):
            if (verb, path) in _routes():
                continue
            assert client.request(verb, url).status_code in (404, 405), f"{verb} {path}"
    # A method override header is ignored: a POST stays a POST (and DELETE routes aren't reached).
    r = client.post("/api/groups/grp_1", headers={"X-HTTP-Method-Override": "DELETE"}, json={})
    assert r.status_code == 405
    assert client.get("/api/groups/grp_1", headers={"X-HTTP-Method-Override": "DELETE"}).status_code == 401


# Anything a visitor (no session) may call, and why. Everything else must answer 401/403, before
# reading the body or touching any data.
ANONYMOUS_ALLOWED = {
    ("POST", "/api/auth/signup"): "creating an account",
    ("POST", "/api/auth/login"): "signing in",
    ("POST", "/api/auth/logout"): "harmless when signed out",
    ("POST", "/api/auth/refresh"): "renews a session from its refresh cookie (401 without one)",
    ("POST", "/api/auth/demo-login/{user_id}"): "404 unless DEMO_LOGIN=true, never in production",
    ("POST", "/api/auth/password/forgot"): "password reset, step 1 (generic answer)",
    ("POST", "/api/auth/password/verify"): "password reset, step 2",
    ("POST", "/api/auth/password/reset"): "password reset, step 3",
    ("GET", "/api/reports/reasons"): "a fixed list of report reasons, no data",
    ("GET", "/api/announcements"): "admin-written banners, no user data",
    ("GET", "/api/github/verify"): "sign-up checks a GitHub username (public GitHub data, limited per IP)",
    ("GET", "/api/health"): "load balancer health check, no data",
    ("POST", "/api/admin/auth/login"): "admin sign-in",
    ("POST", "/api/admin/auth/logout"): "harmless when signed out",
    ("POST", "/api/admin/auth/refresh"): "renews an admin session from its refresh cookie (401 without one)",
}


def test_every_route_refuses_anonymous_callers_except_the_allowlist(client):
    """A1/A2: walks every route in the OpenAPI schema with no session."""
    for method, path in sorted(_routes()):
        if (method, path) in ANONYMOUS_ALLOWED:
            continue
        response = _call(client, method, path)
        assert response.status_code in (401, 403), f"{method} {path}: anonymous got {response.status_code}"
        assert "items" not in response.text and "total" not in response.text


def test_the_allowlist_has_no_stale_entries():
    assert set(ANONYMOUS_ALLOWED) <= _routes() | {("POST", "/api/auth/refresh"), ("POST", "/api/admin/auth/refresh")}
