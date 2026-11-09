"""Bans set in the admin portal: a suspended account, or a blocked phone number.

A blocked number can't be used to sign up, sign in or reset a password, and an account on it
counts as suspended. A suspended account can't sign in, and its sessions stop working at once
(they are checked on every request and on the live socket).
"""

from sqlalchemy.orm import Session

from app import crypto
from app.errors import AppError
from app.models import BannedPhone, User

SUSPENDED = "This account has been suspended. Contact the site admin if you think this is a mistake."
NUMBER_BLOCKED = "This phone number can't be used on CapstoneConnect."


def phone_banned(db: Session, phone_normalized: str) -> bool:
    return db.get(BannedPhone, crypto.phone_hash(phone_normalized)) is not None


def is_blocked(db: Session, user: User) -> bool:
    """Suspended, or on a blocked number."""
    return user.banned_at is not None or phone_banned(db, user.phone_normalized)


def ensure_can_sign_in(db: Session, user: User) -> None:
    if is_blocked(db, user):
        raise AppError(SUSPENDED, 403)


def ensure_number_allowed(db: Session, phone_normalized: str) -> None:
    if phone_banned(db, phone_normalized):
        raise AppError(NUMBER_BLOCKED, 403)
