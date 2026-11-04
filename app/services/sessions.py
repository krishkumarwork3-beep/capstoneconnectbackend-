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

import random
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import delete, text, update
from sqlalchemy.orm import Session

from app import realtime
from app.models import AuthSession
from app.security import decode_token, encode_token, token_matches_password

KINDS = ("student", "admin", "reset")


def _now() -> datetime:
    return datetime.now(UTC)


def start(db: Session, kind: str, subject_id: str, password_hash: str, lifetime: timedelta,
          request: Request | None = None) -> str:
    """A new session row and the signed token naming it. The caller commits."""
    assert kind in KINDS
    sid = f"ses_{secrets.token_hex(16)}"
    agent = (request.headers.get("user-agent") or "")[:200] if request is not None else None
    db.add(AuthSession(id=sid, kind=kind, subject_id=subject_id, expires_at=_now() + lifetime, user_agent=agent or None))
    if random.random() < 0.01:
        # Expired rows are useless: drop them now and then.
        db.execute(delete(AuthSession).where(AuthSession.expires_at < _now() - timedelta(days=1)))
    return encode_token(kind, subject_id, sid, password_hash, lifetime)


def resolve(db: Session, token: str | None, kind: str) -> tuple[str, str, str] | None:
    """(subject id, session id, password fingerprint) for a live session, else None."""
    claims = decode_token(token or "", kind)
    if claims is None:
        return None
    row = db.get(AuthSession, claims["sid"])
    if row is None or row.kind != kind or row.subject_id != claims["sub"] or row.revoked_at is not None:
        return None
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    if expires <= _now():
        return None
    return claims["sub"], claims["sid"], str(claims.get("pv", ""))


def claimed_subject(token: str | None, kind: str) -> str | None:
    """Who a validly signed token was issued to, even if its session has ended (used only to tell
    a suspended student why they were signed out)."""
    claims = decode_token(token or "", kind)
    return claims["sub"] if claims else None


def check_password(fingerprint: str, password_hash: str) -> bool:
    return token_matches_password(fingerprint, password_hash)


def revoke(db: Session, session_id: str | None) -> None:
    if session_id:
        db.execute(update(AuthSession).where(AuthSession.id == session_id, AuthSession.revoked_at.is_(None)).values(revoked_at=_now()))


def revoke_token(db: Session, token: str | None, kind: str) -> None:
    """Revokes the session a (still validly signed) token names, whoever presents it. A student's
    live socket on that session is closed as soon as `db` commits."""
    claims = decode_token(token or "", kind)
    if claims is not None:
        revoke(db, claims["sid"])
        if kind == "student":
            realtime.publish(db, [claims["sub"]], {"type": "session.revoked", "sid": claims["sid"]})


def revoke_all(db: Session, kind: str, subject_ids, except_session: str | None = None) -> None:
    """Every live session (or reset grant) of these people."""
    ids = list(subject_ids)
    if not ids:
        return
    stmt = update(AuthSession).where(AuthSession.kind == kind, AuthSession.subject_id.in_(ids), AuthSession.revoked_at.is_(None))
    if except_session:
        stmt = stmt.where(AuthSession.id != except_session)
    db.execute(stmt.values(revoked_at=_now()))


def end_everything(db: Session, kind: str, subject_ids) -> None:
    """Sessions and, for students, outstanding reset grants (a password change, a suspension...).
    Their live sockets are closed as soon as `db` commits."""
    ids = list(subject_ids)
    revoke_all(db, kind, ids)
    if kind == "student":
        revoke_all(db, "reset", ids)
        realtime.publish(db, ids, {"type": "session.ended"})


_SPEND = text(
    "UPDATE auth_sessions SET revoked_at = now() "
    "WHERE id = :sid AND kind = 'reset' AND subject_id = :sub AND revoked_at IS NULL AND expires_at > now() "
    "RETURNING subject_id"
)


def spend_reset(db: Session, token: str) -> tuple[str, str] | None:
    """(user id, password fingerprint) if this reset grant was live, and marks it used, atomically."""
    claims = decode_token(token, "reset")
    if claims is None:
        return None
    row = db.execute(_SPEND, {"sid": claims["sid"], "sub": claims["sub"]}).first()
    return (claims["sub"], str(claims.get("pv", ""))) if row else None
