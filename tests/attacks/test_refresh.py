"""B1-B7: short access tokens with exactly seven claims, opaque refresh tokens stored hashed and
rotated on every use, a replayed refresh token ends the whole session (and its socket), logout
deletes them, and /refresh is CSRF-checked and rate limited. Same pattern for admins."""

import json
from datetime import timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app.config import get_settings
from app.db import SessionLocal
from app.main import app
from app.models import AuthSession, RefreshToken, utcnow
from app.security import CLAIMS
from app.services import limits
from tests.attacks.ws_tools import closed_code, frames_until, open_socket
from tests.conftest import PASSWORD, PHONES

LEAD = "usr_1"
SITE = {"Origin": "http://localhost:3000"}


def _login() -> TestClient:
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD}).status_code == 200
    return c


def _cookie(c: TestClient, name: str) -> str | None:
    return c.cookies.get(name)


def _refresh(c: TestClient, **kw):
    return c.post("/api/auth/refresh", headers=SITE, **kw)


def _age_spent_tokens(seconds: int = 60) -> None:
    """Moves every spent refresh token's use into the past (out of the two-tab grace window)."""
    with SessionLocal() as db:
        db.execute(update(RefreshToken).where(RefreshToken.used_at.is_not(None)).values(used_at=utcnow() - timedelta(seconds=seconds)))
        db.commit()


def test_access_token_is_short_and_carries_only_the_seven_claims():
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD})
    access = c.cookies.get(get_settings().cookie_name)
    claims = jwt.decode(access, options={"verify_signature": False})
    assert set(claims) == CLAIMS
    assert claims["exp"] - claims["iat"] <= 15 * 60
    assert PHONES[LEAD][-5:] not in json.dumps(claims) and "role" not in claims
    access_cookie = next(h for h in r.headers.get_list("set-cookie") if h.startswith(get_settings().cookie_name + "="))
    assert "max-age=900" in access_cookie.lower()


def test_refresh_tokens_are_opaque_and_stored_only_as_hashes():
    c = _login()
    token = _cookie(c, get_settings().refresh_cookie_name)
    assert token and token.count(".") == 0 and len(token) >= 40  # not a JWT
    with SessionLocal() as db:
        stored = list(db.scalars(select(RefreshToken.token_hash)))
    assert stored and token not in stored and all(len(h) == 64 for h in stored)


def test_an_expired_access_token_is_renewed_by_the_refresh_token(monkeypatch):
    c = _login()
    c.cookies.delete(get_settings().cookie_name)  # the browser dropped it after 15 minutes
    assert c.get("/api/auth/me").status_code == 401
    before = _cookie(c, get_settings().refresh_cookie_name)
    assert _refresh(c).status_code == 204
    assert c.get("/api/auth/me").status_code == 200
    assert _cookie(c, get_settings().refresh_cookie_name) != before  # rotated


def test_a_replayed_refresh_token_ends_the_session_and_its_socket():
    c = _login()
    stolen = _cookie(c, get_settings().refresh_cookie_name)
    with open_socket(c) as ws:
        assert _refresh(c).status_code == 204  # the real owner rotates; the socket stays open
        ws.send_text('{"type":"ping"}')
        frames_until(ws, "pong")
        _age_spent_tokens()
        thief = TestClient(app)
        thief.cookies.set(get_settings().refresh_cookie_name, stolen)
        assert _refresh(thief).status_code == 401
        assert closed_code(ws, 4) == 4401  # the whole family ended: the owner's socket closes too
    assert c.get("/api/auth/me").status_code == 401  # and the owner's access token is dead
    assert _refresh(c).status_code == 401  # and the owner's newer refresh token


def test_two_tabs_refreshing_at_once_do_not_sign_the_student_out():
    c = _login()
    old = _cookie(c, get_settings().refresh_cookie_name)
    assert _refresh(c).status_code == 204
    other_tab = TestClient(app)
    other_tab.cookies.set(get_settings().refresh_cookie_name, old)
    r = _refresh(other_tab)  # within the grace window: a fresh access token, no new refresh token
    assert r.status_code == 204
    assert not any(h.startswith(get_settings().refresh_cookie_name + "=") for h in r.headers.get_list("set-cookie"))
    assert c.get("/api/auth/me").status_code == 200


def test_logout_deletes_the_refresh_tokens_and_the_session():
    c = _login()
    token = _cookie(c, get_settings().refresh_cookie_name)
    assert c.post("/api/auth/logout", headers=SITE).status_code == 204
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(RefreshToken)) == 0
    again = TestClient(app)
    again.cookies.set(get_settings().refresh_cookie_name, token)
    assert _refresh(again).status_code == 401


def test_logout_with_only_the_refresh_cookie_still_ends_the_session():
    c = _login()
    c.cookies.delete(get_settings().cookie_name)  # access expired
    token = _cookie(c, get_settings().refresh_cookie_name)
    assert c.post("/api/auth/logout", headers=SITE).status_code == 204
    replay = TestClient(app)
    replay.cookies.set(get_settings().refresh_cookie_name, token)
    assert _refresh(replay).status_code == 401


def test_sign_out_everywhere_kills_every_refresh_token():
    one, two = _login(), _login()
    assert one.post("/api/auth/logout-all", headers=SITE).status_code == 204
    assert _refresh(two).status_code == 401


def test_refresh_needs_an_allowed_origin():
    c = _login()
    r = c.post("/api/auth/refresh", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert c.get("/api/auth/me").status_code == 200  # nothing was rotated or revoked


def test_refresh_is_rate_limited(monkeypatch):
    monkeypatch.setitem(limits.WRITE_LIMITS, "refresh", (2, limits.WRITE_LIMITS["refresh"][1]))
    c = _login()
    assert [_refresh(c).status_code for _ in range(3)] == [204, 204, 429]


def test_a_refresh_answers_the_same_whatever_is_wrong():
    for value in (None, "x" * 43, "a" * 500, "not-a-token"):
        c = TestClient(app)
        if value:
            c.cookies.set(get_settings().refresh_cookie_name, value)
        r = _refresh(c)
        assert r.status_code == 401 and r.json() == {"message": "Sign in to continue"}


def test_idle_and_absolute_limits_hold_for_refresh():
    c = _login()
    with SessionLocal() as db:
        db.execute(update(AuthSession).where(AuthSession.kind == "student", AuthSession.revoked_at.is_(None))
                   .values(last_used_at=utcnow() - timedelta(days=8)))
        db.commit()
    assert _refresh(c).status_code == 401
    c = _login()
    with SessionLocal() as db:
        db.execute(update(AuthSession).where(AuthSession.kind == "student", AuthSession.revoked_at.is_(None))
                   .values(created_at=utcnow() - timedelta(days=31), last_used_at=utcnow()))
        db.commit()
    assert _refresh(c).status_code == 401


def test_a_suspended_student_cannot_refresh(admin_client):
    c = _login()
    assert admin_client().post(f"/api/admin/users/{LEAD}/ban", json={"reason": "x"}).status_code in (200, 204)
    assert _refresh(c).status_code == 401


def test_admins_refresh_their_own_way_and_never_with_a_student_token(admin_client):
    s = get_settings()
    admin = admin_client()
    admin.cookies.delete(s.admin_cookie_name)
    assert admin.get("/api/admin/auth/me").status_code == 401
    assert admin.post("/api/admin/auth/refresh").status_code == 204
    assert admin.get("/api/admin/auth/me").status_code == 200
    # A student's refresh token is not an admin's, and the other way round.
    student = _login()
    crossed = TestClient(app)
    crossed.cookies.set(s.admin_refresh_cookie_name, student.cookies.get(s.refresh_cookie_name))
    assert crossed.post("/api/admin/auth/refresh").status_code == 401
    crossed = TestClient(app)
    crossed.cookies.set(s.refresh_cookie_name, admin.cookies.get(s.admin_refresh_cookie_name))
    assert _refresh(crossed).status_code == 401


@pytest.mark.parametrize("kind", ["student", "admin"])
def test_no_token_in_web_storage_shape_answers(kind, admin_client):
    """Log-in and refresh answers carry no token in the body: only HttpOnly cookies hold them."""
    if kind == "student":
        c = TestClient(app)
        body = c.post("/api/auth/login", json={"phone": PHONES[LEAD], "password": PASSWORD}).text
    else:
        c = admin_client()
        body = c.get("/api/admin/auth/me").text
    for name in (get_settings().cookie_name, get_settings().refresh_cookie_name, get_settings().admin_cookie_name,
                 get_settings().admin_refresh_cookie_name):
        value = c.cookies.get(name)
        if value:
            assert value not in body
    assert "eyJ" not in body


def test_tokens_in_the_query_string_are_never_read():
    """A4/B6: a token in a URL (logged by every proxy) is ignored, for access and refresh alike."""
    c = _login()
    access = c.cookies.get(get_settings().cookie_name)
    refresh = c.cookies.get(get_settings().refresh_cookie_name)
    anon = TestClient(app)
    for name in ("access_token", "token", "session", "cc_session", "jwt"):
        assert anon.get(f"/api/auth/me?{name}={access}").status_code == 401, name
    for name in ("refresh_token", "refresh", "cc_refresh"):
        assert anon.post(f"/api/auth/refresh?{name}={refresh}", headers=SITE).status_code == 401, name
