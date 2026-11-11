"""Server-side sessions for students and admins, and single-use password-reset grants.

The cookie (or Bearer token) is a signed JWT that names one `auth_sessions` row. A request is
signed in only while that row exists, is of the right kind, belongs to the same subject, has not
expired and has not been revoked. So:

- log out revokes this row: a copied cookie stops working at once;
- "sign out everywhere", a password change or reset, a suspension, a blocked number, a deleted
  account and a deactivated admin revoke every row of that person;
- logging in always makes a new row (and revokes the one the browser came with), so a session
  id planted before sign-in is never promoted (no session fixation);
- a reset grant is spent with one atomic UPDATE, so it works once even if two requests race.
"""

import hashlib
import random
import secrets
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

from fastapi import Request
from sqlalchemy import delete, select, text, update
from sqlalchemy.orm import Session

from app import realtime
from app.config import get_settings
from app.db import SessionLocal
from app.models import AuthSession, RefreshToken, SocketTicket
from app.security import decode_token, encode_token

KINDS = ("student", "admin", "reset", "ws")
# Sign-ins (not reset grants or socket tickets) also end when idle or too old; see resolve().
SIGN_INS = ("student", "admin")
# last_used_at is written at most this often per session (not on every request).
TOUCH_EVERY = timedelta(minutes=5)


def _now() -> datetime:
    return datetime.now(UTC)


def start(db: Session, kind: str, subject_id: str, lifetime: timedelta, request: Request | None = None) -> str:
    """A new session row and the signed token naming it (living as long as the row). The caller
    commits. Sign-ins use sign_in() instead (short access token + refresh token)."""
    assert kind in KINDS
    sid = _new_row(db, kind, subject_id, lifetime, request)
    return encode_token(kind, subject_id, sid, lifetime)


def _new_row(db: Session, kind: str, subject_id: str, lifetime: timedelta, request: Request | None) -> str:
    sid = f"ses_{secrets.token_hex(16)}"
    agent = (request.headers.get("user-agent") or "")[:200] if request is not None else None
    db.add(AuthSession(id=sid, kind=kind, subject_id=subject_id, expires_at=_now() + lifetime, user_agent=agent or None))
    if random.random() < 0.01:
        # Expired rows are useless: drop them (and their refresh tokens) now and then.
        old = select(AuthSession.id).where(AuthSession.expires_at < _now() - timedelta(days=1))
        db.execute(delete(RefreshToken).where(RefreshToken.session_id.in_(old)))
        db.execute(delete(AuthSession).where(AuthSession.expires_at < _now() - timedelta(days=1)))
    return sid


def access_lifetime() -> timedelta:
    return timedelta(minutes=get_settings().access_token_minutes)


def _refresh_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()


def _new_refresh(db: Session, session_id: str) -> str:
    token = secrets.token_urlsafe(32)  # opaque, random: not a JWT, nothing to decode
    db.add(RefreshToken(token_hash=_refresh_hash(token), session_id=session_id))
    return token


def sign_in(db: Session, kind: str, subject_id: str, lifetime: timedelta, request: Request | None = None) -> tuple[str, str, str]:
    """(access token, refresh token, session id) of a brand-new sign-in. The session row is the
    token family and lasts `lifetime` (absolute); the access token lives ACCESS_TOKEN_MINUTES."""
    assert kind in SIGN_INS
    sid = _new_row(db, kind, subject_id, lifetime, request)
    return encode_token(kind, subject_id, sid, access_lifetime()), _new_refresh(db, sid), sid


# A refresh token spent this recently is still accepted once more (two tabs refreshing at the same
# moment both send the old cookie): the second gets a fresh access token but no new refresh token.
# Older than this, a spent token is a replay and ends the session.
def reuse_grace() -> timedelta:
    return timedelta(seconds=get_settings().refresh_reuse_grace_seconds)


class Refreshed(NamedTuple):
    access: str
    refresh: str | None  # None in the grace window: keep the refresh cookie the browser already got
    session_id: str
    subject_id: str
    expires_at: datetime


def refresh(db: Session, token: str | None, kind: str) -> Refreshed | None:
    """Rotates a refresh token. None (and nothing issued) for an unknown token, a session that
    ended, expired or went idle, or a token of another kind. A replayed spent token revokes the
    whole session, closes its sockets and returns None. The caller commits."""
    if not token or len(token) > 200:
        return None
    row = db.execute(select(RefreshToken).where(RefreshToken.token_hash == _refresh_hash(token)).with_for_update()).scalar_one_or_none()
    if row is None:
        return None
    session = db.get(AuthSession, row.session_id, with_for_update=True)
    if session is None or session.kind != kind or session.revoked_at is not None or _aware(session.expires_at) <= _now():
        return None
    if row.used_at is not None:
        if _now() - _aware(row.used_at) > reuse_grace():
            end_family(db, session)  # a stolen, replayed token: nobody keeps this session
            return None
        new_refresh = None
    else:
        row.used_at = _now()
        new_refresh = _new_refresh(db, session.id)
    if not _still_fresh(session):
        return None
    access = encode_token(kind, session.subject_id, session.id, access_lifetime())
    return Refreshed(access, new_refresh, session.id, session.subject_id, _aware(session.expires_at))


def end_family(db: Session, session: AuthSession) -> None:
    revoke(db, session.id)
    if session.kind == "student":
        realtime.publish(db, [session.subject_id], {"type": "session.revoked", "sid": session.id})


def session_of_refresh(db: Session, token: str | None) -> AuthSession | None:
    if not token or len(token) > 200:
        return None
    row = db.get(RefreshToken, _refresh_hash(token))
    return db.get(AuthSession, row.session_id) if row else None


def resolve(db: Session, token: str | None, kind: str) -> tuple[str, str] | None:
    """(subject id, session id) for a valid access token of a live session, else None."""
    claims = decode_token(token or "", kind)
    if claims is None:
        return None
    subject = live(db, claims["sid"], kind)
    return (subject, claims["sid"]) if subject == claims["sub"] else None


def live(db: Session, session_id: str | None, kind: str) -> str | None:
    """The subject of a session row that is still live (not revoked, not expired, not idle, not
    past its absolute lifetime), else None. The socket checks this, not the short access token."""
    row = db.get(AuthSession, session_id) if session_id else None
    if row is None or row.kind != kind or row.revoked_at is not None or _aware(row.expires_at) <= _now():
        return None
    if kind in SIGN_INS and not _still_fresh(row):
        return None
    return row.subject_id


def claimed_subject(token: str | None, kind: str) -> str | None:
    """Who a validly signed token was issued to, even if its session has ended (used only to tell
    a suspended student why they were signed out)."""
    claims = decode_token(token or "", kind)
    return claims["sub"] if claims else None


def revoke(db: Session, session_id: str | None) -> None:
    """Ends one session and deletes its refresh tokens."""
    if session_id:
        db.execute(update(AuthSession).where(AuthSession.id == session_id, AuthSession.revoked_at.is_(None)).values(revoked_at=_now()))
        db.execute(delete(RefreshToken).where(RefreshToken.session_id == session_id))


def revoke_token(db: Session, token: str | None, kind: str) -> None:
    """Revokes the session a (still validly signed) token names, whoever presents it. A student's
    live socket on that session is closed as soon as `db` commits."""
    claims = decode_token(token or "", kind)
    if claims is not None:
        revoke(db, claims["sid"])
        if kind == "student":
            realtime.publish(db, [claims["sub"]], {"type": "session.revoked", "sid": claims["sid"]})


def revoke_all(db: Session, kind: str, subject_ids, except_session: str | None = None) -> None:
    """Every live session (or reset grant) of these people, and their refresh tokens."""
    ids = list(subject_ids)
    if not ids:
        return
    rows = select(AuthSession.id).where(AuthSession.kind == kind, AuthSession.subject_id.in_(ids))
    stmt = update(AuthSession).where(AuthSession.kind == kind, AuthSession.subject_id.in_(ids), AuthSession.revoked_at.is_(None))
    if except_session:
        stmt = stmt.where(AuthSession.id != except_session)
        rows = rows.where(AuthSession.id != except_session)
    db.execute(stmt.values(revoked_at=_now()))
    db.execute(delete(RefreshToken).where(RefreshToken.session_id.in_(rows)))


def end_everything(db: Session, kind: str, subject_ids, close_code: int = 4401) -> None:
    """Sessions and, for students, outstanding reset grants (a password change, a suspension...).
    Their live sockets are closed as soon as `db` commits."""
    ids = list(subject_ids)
    revoke_all(db, kind, ids)
    if kind == "student":
        revoke_all(db, "reset", ids)
        # 4401: signed out (suspended, deleted, password changed); 1008: a policy (number blocked).
        realtime.publish(db, ids, {"type": "session.ended", "code": close_code})


_SPEND = text(
    "UPDATE auth_sessions SET revoked_at = now() "
    "WHERE id = :sid AND kind = 'reset' AND subject_id = :sub AND revoked_at IS NULL AND expires_at > now() "
    "RETURNING subject_id"
)


def spend_reset(db: Session, token: str) -> str | None:
    """The user id if this reset grant was live, and marks it used, atomically."""
    claims = decode_token(token, "reset")
    if claims is None:
        return None
    row = db.execute(_SPEND, {"sid": claims["sid"], "sub": claims["sub"]}).first()
    return claims["sub"] if row else None


# ---------------------------------------------------------------------------------------------
# Socket tickets: what a page sends as the first frame of the live socket, besides its cookie.
# A cookie alone is what a cross-site page could also make the browser send; a ticket comes
# from POST /realtime/ticket, whose answer only this site's pages can read (CORS) and which the
# request guard refuses from other origins. A ticket lives seconds, works once, and only for the
# session (and student) it was issued to.
# ---------------------------------------------------------------------------------------------

_SPEND_TICKET = text(
    "UPDATE socket_tickets SET used_at = now() "
    "WHERE token_hash = :hash AND user_id = :user AND session_id = :session AND used_at IS NULL AND expires_at > now() "
    "RETURNING token_hash"
)


def _ticket_hash(ticket: str) -> str:
    # A plain SHA-256 is enough: the ticket is 256 random bits, nothing to guess or brute-force.
    return hashlib.sha256(ticket.encode("utf-8", "surrogatepass")).hexdigest()


def issue_ticket(db: Session, user_id: str, session_id: str, lifetime: timedelta) -> str:
    """A fresh random ticket; only its hash is stored. The caller commits."""
    ticket = secrets.token_urlsafe(32)
    db.add(SocketTicket(token_hash=_ticket_hash(ticket), user_id=user_id, session_id=session_id, expires_at=_now() + lifetime))
    if random.random() < 0.01:
        db.execute(delete(SocketTicket).where(SocketTicket.expires_at < _now() - timedelta(hours=1)))
    return ticket


def spend_ticket(db: Session, ticket: str, user_id: str, session_id: str) -> bool:
    """True once for a live ticket of this student and this session (spent atomically)."""
    if not ticket or len(ticket) > 200:
        return False
    params = {"hash": _ticket_hash(ticket), "user": user_id, "session": session_id}
    return db.execute(_SPEND_TICKET, params).first() is not None


def _aware(at: datetime) -> datetime:
    return at if at.tzinfo else at.replace(tzinfo=UTC)


def _still_fresh(row: AuthSession) -> bool:
    """Absolute lifetime (SESSION_MAX_DAYS from sign-in) and sliding idle expiry
    (SESSION_IDLE_DAYS since last use). Refreshes last_used_at, on its own connection so a
    read-only request still counts as use."""
    settings, now = get_settings(), _now()
    created = _aware(row.created_at)
    last = _aware(row.last_used_at or row.created_at)
    if now - created > timedelta(days=settings.session_max_days) or now - last > timedelta(days=settings.session_idle_days):
        return False
    if now - last > TOUCH_EVERY:
        with SessionLocal() as own:
            own.execute(update(AuthSession).where(AuthSession.id == row.id).values(last_used_at=now))
            own.commit()
    return True
