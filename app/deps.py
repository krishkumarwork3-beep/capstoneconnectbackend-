"""Who is signed in: the session cookie (browsers) or an `Authorization: Bearer` token (API clients)."""

from typing import Annotated

from fastapi import Depends, Path, Request
from sqlalchemy.orm import Session

from app.cookies import admin_cookie, student_cookie
from app.db import get_db
from app.errors import AppError
from app.models import AdminUser, User
from app.services import bans, sessions

DB = Annotated[Session, Depends(get_db)]
# Every id in a URL: bounded (our ids are "usr_" + 16 hex characters).
PathId = Annotated[str, Path(min_length=1, max_length=64)]


def _token_from(request: Request) -> str | None:
    cookie = request.cookies.get(student_cookie())
    if cookie:
        return cookie
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


def optional_user(request: Request, db: DB) -> User | None:
    token = _token_from(request)
    found = sessions.resolve(db, token, "student")
    if not found:
        # Ended because of a suspension: say so (403) rather than a bare "sign in" (401).
        subject = sessions.claimed_subject(token, "student") if token else None
        user = db.get(User, subject) if subject else None
        if user is not None:
            bans.ensure_can_sign_in(db, user)
        return None
    user_id, session_id = found
    user = db.get(User, user_id)
    # A password change ends every session (the rows are revoked), so no token outlives it.
    if not user:
        return None
    # Suspended (or on a blocked number) in the admin portal: signed out at once.
    bans.ensure_can_sign_in(db, user)
    request.state.session_id = session_id
    return user


def current_user(user: Annotated[User | None, Depends(optional_user)]) -> User:
    if user is None:
        raise AppError("Sign in to continue", 401)
    return user


CurrentUser = Annotated[User, Depends(current_user)]
OptionalUser = Annotated[User | None, Depends(optional_user)]


# ---------------------------------------------------------------------------------------------
# Admin portal: its own cookie (ADMIN_COOKIE_NAME), never a student session.
# ---------------------------------------------------------------------------------------------


def current_admin(request: Request, db: DB) -> AdminUser:
    found = sessions.resolve(db, request.cookies.get(admin_cookie()), "admin")
    admin = db.get(AdminUser, found[0]) if found else None
    # A password change, deactivation or log-out ends the admin's sessions (rows revoked).
    if admin is None or not admin.active:
        raise AppError("Sign in to the admin portal", 401)
    request.state.admin_session_id = found[1]
    return admin


def admin_writer(admin: Annotated[AdminUser, Depends(current_admin)]) -> AdminUser:
    if admin.role != "admin":
        raise AppError("This admin account is read-only", 403)
    return admin


CurrentAdmin = Annotated[AdminUser, Depends(current_admin)]


def student_or_admin(request: Request, db: DB) -> str:
    """The signed-in student's id, else the signed-in admin's ("admin:<id>"); 401 for visitors."""
    user = optional_user(request, db)
    if user is not None:
        return user.id
    return f"admin:{current_admin(request, db).id}"


StudentOrAdmin = Annotated[str, Depends(student_or_admin)]
AdminWriter = Annotated[AdminUser, Depends(admin_writer)]
