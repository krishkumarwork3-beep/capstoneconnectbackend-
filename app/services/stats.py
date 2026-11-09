"""Site-wide aggregates shared by the public site and the admin portal (one query, one answer)."""

import threading
import time

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import User

# The public figure is cached this long per process (it is a headline number, not a live one).
CACHE_SECONDS = 60.0
_cache: tuple[float, int] | None = None
_lock = threading.Lock()


def signup_total(db: Session) -> int:
    """Registered student accounts. Deleted accounts are gone (rows removed) and so not counted;
    suspended ones still count: they signed up, and the admin can still restore them."""
    return db.scalar(select(func.count()).select_from(User)) or 0


def cached_signup_total(db: Session) -> int:
    global _cache
    now = time.monotonic()
    with _lock:
        if _cache is not None and now - _cache[0] < CACHE_SECONDS:
            return _cache[1]
    value = signup_total(db)
    with _lock:
        _cache = (now, value)
    return value


def clear_cache() -> None:
    global _cache
    with _lock:
        _cache = None
