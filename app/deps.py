"""Who is signed in: the session cookie (browsers) or an `Authorization: Bearer` token (API clients)."""

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.errors import AppError
from app.models import AdminUser, User
from app.security import read_token, token_matches_password
from app.services import bans

DB = Annotated[Session, Depends(get_db)]


def _token_from(request: Request) -> str | None:
    cookie = request.cookies.get(get_settings().cookie_name)
    if cookie:
        return cookie
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


def optional_user(request: Request, db: DB) -> User | None:
    token = _token_from(request)
    if not token:
        return None
    read = read_token(token, "session")
    if not read:
        return None
    user_id, fingerprint = read
    user = db.get(User, user_id)
    # A password change (reset) invalidates every session issued before it.
    if not user or not token_matches_password(fingerprint, user.password_hash):
        return None
    # Suspended (or on a blocked number) in the admin portal: signed out at once.
    bans.ensure_can_sign_in(db, user)
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
    token = request.cookies.get(get_settings().admin_cookie_name)
    read = read_token(token, "admin") if token else None
    admin = db.get(AdminUser, read[0]) if read else None
    # A password change or deactivation ends the admin's sessions.
    if admin is None or not admin.active or not token_matches_password(read[1], admin.password_hash):
        raise AppError("Sign in to the admin portal", 401)
    return admin


def admin_writer(admin: Annotated[AdminUser, Depends(current_admin)]) -> AdminUser:
    if admin.role != "admin":
        raise AppError("This admin account is read-only", 403)
    return admin


CurrentAdmin = Annotated[AdminUser, Depends(current_admin)]
AdminWriter = Annotated[AdminUser, Depends(admin_writer)]
