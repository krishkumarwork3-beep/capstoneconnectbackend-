"""Part 4: forged and replayed tokens, server-side sessions, cookies. Each test presents the
hostile token or the stolen cookie and asserts it is refused."""

import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import Settings, get_settings
from app.db import SessionLocal
from app.main import app
from app.models import AdminUser, AuthSession, User
from app.security import AUDIENCES, fingerprint
from app.services import sessions
from tests.conftest import ADMIN_PASSWORD, PASSWORD, PHONES
from tests.conftest import ws_connect

LEAD = "usr_1"


def _row(kind: str, subject: str) -> str:
    """A live session row for this subject; returns its id."""
    with SessionLocal() as db:
        password_hash = (db.get(User, subject) or db.get(AdminUser, subject)).password_hash
        token = sessions.start(db, kind, subject, password_hash, timedelta(hours=1))
        db.commit()
    return jwt.decode(token, options={"verify_signature": False})["sid"]


def _claims(token_kind: str, subject: str, /, **override) -> dict:
    now = datetime.now(UTC)
    with SessionLocal() as db:
        password_hash = (db.get(User, subject) or db.get(AdminUser, subject)).password_hash
    claims = {"iss": get_settings().jwt_issuer, "aud": AUDIENCES[token_kind], "sub": subject, "sid": _row(token_kind, subject),
              "kind": token_kind, "pv": fingerprint(password_hash), "iat": now, "exp": now + timedelta(hours=1)}
    claims.update(override)
    return {k: v for k, v in claims.items() if v is not None}


def _sign(claims: dict, key: str | None = None, alg: str = "HS256") -> str:
    return jwt.encode(claims, key or get_settings().secret_key, algorithm=alg)


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, default=str).encode()).rstrip(b"=").decode()


def _me(token: str) -> int:
    return TestClient(app).get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code


def test_a_well_formed_token_works():
    assert _me(_sign(_claims("student", LEAD))) == 200


def _forgeries() -> dict[str, str]:
    good = _claims("student", LEAD)
    now = datetime.now(UTC)
    header_none = _b64({"alg": "none", "typ": "JWT"})
    payload = _b64({**good, "iat": int(now.timestamp()), "exp": int((now + timedelta(hours=1)).timestamp())})
    signed = _sign(good)
    head, body, sig = signed.split(".")
    tampered_body = _b64({**json.loads(base64.urlsafe_b64decode(body + "==")), "sub": "usr_2"})
    return {
        "alg none": f"{header_none}.{payload}.",
        "alg None, no dot": f"{_b64({'alg': 'None'})}.{payload}",
        "HS512": _sign(good, alg="HS512"),
        "HS384": _sign(good, alg="HS384"),
        "wrong key": _sign(good, key="x" * 48),
        "another 32-character key": _sign(good, key="-" * 32),
        "tampered payload": f"{head}.{tampered_body}.{sig}",
        "tampered signature": f"{head}.{body}.{sig[:-2]}{'AA' if not sig.endswith('AA') else 'BB'}",
        "admin audience": _sign(_claims("student", LEAD, aud=AUDIENCES["admin"])),
        "reset audience": _sign(_claims("student", LEAD, aud=AUDIENCES["reset"])),
        "no audience": _sign(_claims("student", LEAD, aud=None)),
        "wrong issuer": _sign(_claims("student", LEAD, iss="someone-else")),
        "no issuer": _sign(_claims("student", LEAD, iss=None)),
        "no exp": _sign(_claims("student", LEAD, exp=None)),
        "expired": _sign(_claims("student", LEAD, iat=now - timedelta(days=30), exp=now - timedelta(minutes=5))),
        "no iat": _sign(_claims("student", LEAD, iat=None)),
        "iat in the future": _sign(_claims("student", LEAD, iat=now + timedelta(hours=2))),
        "wrong kind": _sign(_claims("student", LEAD, kind="admin")),
        "no sid": _sign(_claims("student", LEAD, sid=None)),
        "unknown sid": _sign(_claims("student", LEAD, sid="ses_" + "0" * 32)),
        "sid of someone else": _sign(_claims("student", LEAD, sid=_row("student", "usr_2"))),
        "a reset grant's row": _sign(_claims("student", LEAD, sid=_row("reset", LEAD))),
        "old password fingerprint": _sign(_claims("student", LEAD, pv="0" * 16)),
        "garbage": "not.a.token",
        "huge": "a" * 5000,
    }


FORGERY_NAMES = [
    "alg none", "alg None, no dot", "HS512", "HS384", "wrong key", "another 32-character key", "tampered payload",
    "tampered signature", "admin audience", "reset audience", "no audience", "wrong issuer", "no issuer", "no exp",
    "expired", "no iat", "iat in the future", "wrong kind", "no sid", "unknown sid", "sid of someone else",
    "a reset grant's row", "old password fingerprint", "garbage", "huge",
]


@pytest.mark.parametrize("name", FORGERY_NAMES)
def test_forged_student_tokens_are_refused(name):
    forgeries = _forgeries()
    assert sorted(forgeries) == sorted(FORGERY_NAMES)
    token = forgeries[name]
    assert _me(token) == 401, name
    c = TestClient(app)
    c.cookies.set(get_settings().cookie_name, token)
    assert c.get("/api/auth/me").status_code == 401, name


def test_tokens_never_cross_audiences(admin_client, as_user):
    """A student cookie in the admin cookie's place, an admin cookie as a student, a reset grant as either."""
    student = as_user(LEAD)
    student_token = student.cookies.get(get_settings().cookie_name)
    admin = admin_client()
    admin_token = admin.cookies.get(get_settings().admin_cookie_name)
    c = TestClient(app)
    c.cookies.set(get_settings().admin_cookie_name, student_token)
    assert c.get("/api/admin/auth/me").status_code == 401
    assert _me(admin_token) == 401
    reset = _sign(_claims("reset", LEAD))
    assert _me(reset) == 401
    c2 = TestClient(app)
    c2.cookies.set(get_settings().admin_cookie_name, reset)
    assert c2.get("/api/admin/auth/me").status_code == 401


def test_forged_admin_tokens_are_refused(admin_client):
    admin_client()  # creates admin0@example.com
    with SessionLocal() as db:
        admin_id = db.query(AdminUser.id).filter(AdminUser.email == "admin0@example.com").scalar()
    good = _claims("admin", admin_id)
    for name, token in {
        "valid": _sign(good),
        "student audience": _sign({**good, "aud": AUDIENCES["student"]}),
        "wrong key": _sign(good, key="y" * 48),
        "HS512": _sign(good, alg="HS512"),
        "no exp": _sign({k: v for k, v in good.items() if k != "exp"}),
        "unknown sid": _sign({**good, "sid": "ses_" + "1" * 32}),
    }.items():
        c = TestClient(app)
        c.cookies.set(get_settings().admin_cookie_name, token)
        assert c.get("/api/admin/auth/me").status_code == (200 if name == "valid" else 401), name


def test_short_or_default_secret_keys_are_refused():
    with pytest.raises(ValueError):
        Settings(secret_key="short-secret")
    with pytest.raises(ValueError):
        Settings(secret_key="x" * 31)
    assert Settings(secret_key="x" * 32).secret_key == "x" * 32


# --- Server-side sessions: replay a stolen cookie after each way a session ends ----------------


def _cookie(client) -> str:
    return client.cookies.get(get_settings().cookie_name)


def _replay(token: str) -> int:
    """The stolen cookie, presented from another machine (as a cookie and as a Bearer token)."""
    c = TestClient(app)
    c.cookies.set(get_settings().cookie_name, token)
    as_cookie = c.get("/api/auth/me").status_code
    as_bearer = _me(token)
    assert as_cookie == as_bearer
    return as_cookie


def test_stolen_cookie_dies_with_logout(as_user):
    victim = as_user(LEAD)
    stolen = _cookie(victim)
    assert _replay(stolen) == 200
    assert victim.post("/api/auth/logout").status_code == 204
    assert _replay(stolen) == 401


def test_stolen_cookie_dies_with_logout_by_bearer():
    c = TestClient(app)
    token = c.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD}).cookies.get(get_settings().cookie_name)
    assert TestClient(app).post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 204
    assert _replay(token) == 401


def test_sign_out_everywhere(as_user):
    laptop, phone = TestClient(app), TestClient(app)
    for c in (laptop, phone):
        assert c.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD}).status_code == 200
    stolen = _cookie(phone)
    assert laptop.post("/api/auth/logout-all").status_code == 204
    assert phone.get("/api/auth/me").status_code == 401
    assert _replay(stolen) == 401
    assert laptop.get("/api/auth/me").status_code == 401
    assert TestClient(app).post("/api/auth/logout-all").status_code == 401  # needs a session


def test_login_always_issues_a_new_session_and_revokes_the_old(as_user):
    """No session fixation: a cookie planted before sign-in is never the signed-in session."""
    c = TestClient(app)
    c.post("/api/auth/login", json={"phone": PHONES["usr_8"], "password": PASSWORD})
    planted = _cookie(c)
    c.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD})
    fresh = _cookie(c)
    assert fresh != planted
    assert jwt.decode(fresh, options={"verify_signature": False})["sid"] != jwt.decode(planted, options={"verify_signature": False})["sid"]
    assert _replay(planted) == 401
    assert _replay(fresh) == 200


def test_password_reset_ends_every_session(client, as_user):
    stolen = _cookie(as_user(LEAD))
    code = client.post("/api/auth/password/forgot", json={"phone": PHONES[LEAD]}).json()["dev_code"]
    grant = client.post("/api/auth/password/verify", json={"phone": PHONES[LEAD], "code": code}).json()["reset_token"]
    assert client.post("/api/auth/password/reset", json={"reset_token": grant, "password": "brand-new-pass-77"}).status_code == 200
    assert _replay(stolen) == 401


@pytest.mark.parametrize("action", ["ban", "password", "delete", "block"])
def test_admin_actions_end_sessions_for_good(admin_client, as_user, action):
    stolen = _cookie(as_user(LEAD))
    admin = admin_client()
    if action == "ban":
        admin.post(f"/api/admin/users/{LEAD}/ban", json={"reason": "x"})
        admin.post(f"/api/admin/users/{LEAD}/unban")
    elif action == "password":
        admin.post(f"/api/admin/users/{LEAD}/password", json={"password": "a-brand-new-pass-1"})
    elif action == "delete":
        admin.delete(f"/api/admin/users/{LEAD}")
    else:
        admin.post("/api/admin/banned-phones", json={"phones": [PHONES[LEAD]], "reason": "x"})
        admin.delete(f"/api/admin/banned-phones/{PHONES[LEAD].replace(' ', '').lstrip('+')}")
    # Even after the suspension is lifted (or the number unblocked), the old cookie stays dead.
    assert _replay(stolen) in (401, 403)
    with SessionLocal() as db:
        live = db.query(AuthSession).filter(AuthSession.subject_id == LEAD, AuthSession.kind == "student",
                                            AuthSession.revoked_at.is_(None)).count()
    assert live == 0


def test_stolen_cookie_can_not_open_the_socket_after_logout(as_user):
    victim = as_user(LEAD)
    stolen = _cookie(victim)
    victim.post("/api/auth/logout")
    thief = TestClient(app)
    thief.cookies.set(get_settings().cookie_name, stolen)
    with ws_connect(thief) as ws:
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
    assert closed.value.code == 4401


def test_admin_stolen_cookie_dies_with_logout_and_logout_all(admin_client):
    admin = admin_client()
    name = get_settings().admin_cookie_name
    stolen = admin.cookies.get(name)
    thief = TestClient(app)
    thief.cookies.set(name, stolen)
    assert thief.get("/api/admin/auth/me").status_code == 200
    admin.post("/api/admin/auth/logout")
    assert thief.get("/api/admin/auth/me").status_code == 401

    other = admin_client()
    second = TestClient(app)
    second.post("/api/admin/auth/login", json={"email": "admin1@example.com", "password": ADMIN_PASSWORD})
    stolen = second.cookies.get(name)
    assert other.post("/api/admin/auth/logout-all").status_code == 204
    thief = TestClient(app)
    thief.cookies.set(name, stolen)
    assert thief.get("/api/admin/auth/me").status_code == 401


def test_admin_deactivation_and_password_change_end_sessions(admin_client):
    boss, target = admin_client(), admin_client(email="target@example.com")
    name = get_settings().admin_cookie_name
    stolen = target.cookies.get(name)
    with SessionLocal() as db:
        target_id = db.query(AdminUser.id).filter(AdminUser.email == "target@example.com").scalar()
    assert boss.patch(f"/api/admin/admins/{target_id}", json={"active": False}).status_code == 200
    assert boss.patch(f"/api/admin/admins/{target_id}", json={"active": True}).status_code == 200
    thief = TestClient(app)
    thief.cookies.set(name, stolen)
    assert thief.get("/api/admin/auth/me").status_code == 401  # reactivation does not revive it

    other_device = TestClient(app)
    other_device.post("/api/admin/auth/login", json={"email": "admin0@example.com", "password": ADMIN_PASSWORD})
    assert boss.post("/api/admin/auth/password", json={"current_password": ADMIN_PASSWORD, "new_password": "another-admin-pass-9"}).status_code == 204
    assert boss.get("/api/admin/auth/me").status_code == 200  # this session got a new cookie
    assert other_device.get("/api/admin/auth/me").status_code == 401


# --- Cookies -----------------------------------------------------------------------------------


def test_session_cookies_are_httponly_samesite_and_host_only():
    r = TestClient(app).post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie and "domain=" not in cookie


def test_secure_cookies_use_the_host_prefix(monkeypatch, admin_client):
    s = get_settings()
    monkeypatch.setattr(s, "cookie_secure", True)
    https = TestClient(app, base_url="https://testserver")
    r = https.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD})
    assert r.headers["set-cookie"].startswith(f"__Host-{s.cookie_name}=")
    assert "; secure" in r.headers["set-cookie"].lower()
    assert https.get("/api/auth/me").status_code == 200
    # The unprefixed name (which a subdomain or plain-http page could plant) is not read.
    token = r.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    planted = TestClient(app, base_url="https://testserver")
    planted.cookies.set(s.cookie_name, token)
    assert planted.get("/api/auth/me").status_code == 401
