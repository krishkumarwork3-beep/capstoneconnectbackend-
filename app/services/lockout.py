"""Per-account lock-out with exponential back-off, for students (by phone number, so every way of
writing the number shares one counter) and admins (by email). Kept in PostgreSQL so every worker
and server agrees, and applied whether or not the account exists, so a lock-out never tells
anyone which numbers or emails are registered.

After the 5th consecutive failure the account is locked for 15 minutes, then 30, 60, 120... up
to a day; each failure while unlocked doubles the next wait. A successful sign-in clears it.
The per-IP limits (app.services.limits) still apply on top.
"""

import math
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, text
from sqlalchemy.orm import Session

from app.errors import AppError
from app.models import LoginLockout
from app.security import normalize_phone

FREE_FAILURES = 5
BASE_LOCK = timedelta(minutes=15)
MAX_LOCK = timedelta(days=1)

_FAIL = text(
    """
    INSERT INTO login_lockouts (key, failures, updated_at) VALUES (:key, 1, now())
    ON CONFLICT (key) DO UPDATE SET failures = login_lockouts.failures + 1, updated_at = now()
    RETURNING failures
    """
)


def student_key(phone: str) -> str:
    return f"student:{normalize_phone(phone)}"


def admin_key(email: str) -> str:
    return f"admin:{email.strip().lower()}"


def lock_for(failures: int) -> timedelta | None:
    if failures < FREE_FAILURES:
        return None
    seconds = BASE_LOCK.total_seconds() * 2 ** min(failures - FREE_FAILURES, 20)
    return timedelta(seconds=min(seconds, MAX_LOCK.total_seconds()))


def _refuse(wait: timedelta) -> AppError:
    seconds = max(1, math.ceil(wait.total_seconds()))
    when = f"{seconds} seconds" if seconds < 90 else f"{math.ceil(seconds / 60)} minutes"
    return AppError(f"Too many attempts. Try again in {when}.", 429, {"Retry-After": str(seconds)})


def check(db: Session, key: str) -> None:
    """429 while the account is locked. Counts nothing."""
    row = db.get(LoginLockout, key)
    if row is not None and row.locked_until is not None:
        until = row.locked_until if row.locked_until.tzinfo else row.locked_until.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        if until > now:
            raise _refuse(until - now)


def fail(db: Session, key: str) -> None:
    """One more failure (atomic, committed at once so it counts even though the request fails)."""
    failures = db.execute(_FAIL, {"key": key}).scalar_one()
    wait = lock_for(failures)
    if wait is not None:
        db.execute(text("UPDATE login_lockouts SET locked_until = now() + :wait WHERE key = :key"), {"wait": wait, "key": key})
    db.commit()


def succeed(db: Session, key: str) -> None:
    db.execute(delete(LoginLockout).where(LoginLockout.key == key))
