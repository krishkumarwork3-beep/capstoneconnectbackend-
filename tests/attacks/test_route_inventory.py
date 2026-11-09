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
    ("GET", "/api/groups"),                  # guests browse the board
    ("GET", "/api/reports/reasons"),
    ("GET", "/api/announcements"),           # the banner shows to guests too
    ("GET", "/api/github/verify"),           # used during sign-up, before an account exists
    ("GET", "/api/health"),
    ("GET", "/api/stats/signups"),         # one aggregate number, cached, limited per IP
    ("GET", "/uploads/{purpose}/{name}"),    # avatars public; résumés/attachments checked inside
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
    if path.startswith("/api/") and path not in WEBSOCKETS:
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
    url = re.sub(r"\{[^}]+\}", "x", path)
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
