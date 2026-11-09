"""Reads, not only writes, have a budget: anti-scraping for the people, group and chat data.

- Page sizes are capped (PAGE_DEFAULT, PAGE_MAX) and the cursor is opaque: signed, bound to the
  account and the list it came from, and short-lived, so a scraper can't jump to any offset, share
  cursors between accounts or replay them later.
- Every list page, search, profile view and chat-history page counts against a per-account read
  budget (READ_*, app.config), shared across devices; over it: 429.
- Suspicious access (many distinct profiles in a short window, or paging very deep into a list)
  writes one audit-log entry per window, visible on the admin portal's Audit page, and throttles
  the account's reads for a while.
"""

import base64
import hashlib
import hmac
import time
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.errors import AppError
from app.models import AuditLog
from app.services import limits

PAGE_DEFAULT = 20
PAGE_MAX = 50
CURSOR_SECONDS = 30 * 60
SEARCH_MIN = 2

THROTTLED = "Too many pages viewed in a short time. Try again in a few minutes."


# --- Cursors ---------------------------------------------------------------------------------

def _mac(payload: str) -> str:
    key = hashlib.sha256(b"capconnect-cursor:" + get_settings().secret_key.encode()).digest()
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()[:24]


def make_cursor(scope: str, user_id: str, offset: int) -> str:
    payload = f"{scope}|{user_id}|{offset}|{int(time.time()) + CURSOR_SECONDS}"
    return base64.urlsafe_b64encode(f"{payload}|{_mac(payload)}".encode()).decode().rstrip("=")


def read_cursor(cursor: str | None, scope: str, user_id: str) -> int:
    """The offset a cursor stands for; 0 for none. 400 for a forged, foreign or expired one."""
    if not cursor:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        payload, mac = raw.rsplit("|", 1)
        c_scope, c_user, offset, expires = payload.split("|")
        valid = (hmac.compare_digest(mac, _mac(payload)) and c_scope == scope and c_user == user_id
                 and int(expires) >= time.time() and 0 <= int(offset) < 100_000)
    except (ValueError, UnicodeDecodeError):
        valid = False
    if not valid:
        raise AppError("This list has changed or the link expired. Reload the page.", 400)
    return int(offset)


# --- Budgets and detection -------------------------------------------------------------------

def _budget(action: str) -> int:
    s = get_settings()
    return {"profile_view": s.read_limit_profiles, "list_page": s.read_limit_pages,
            "search": s.read_limit_searches, "chat_history": s.read_limit_chat_pages}[action]


_THROTTLE_KEY = "read_throttle:who:{}"


def _throttled(db: Session, user_id: str) -> bool:
    minutes = get_settings().read_throttle_minutes
    row = db.execute(text("SELECT 1 FROM rate_limits WHERE key = :k AND window_start > now() - make_interval(mins => :m)"),
                     {"k": _THROTTLE_KEY.format(user_id), "m": minutes}).first()
    return row is not None


def _flag(db: Session, user_id: str, why: str, detail: dict) -> None:
    """Throttle the account and leave one audit entry (the throttle row makes it once per window)."""
    db.execute(text(
        "INSERT INTO rate_limits (key, count, window_start) VALUES (:k, 1, now()) "
        "ON CONFLICT (key) DO UPDATE SET count = 1, window_start = now()"), {"k": _THROTTLE_KEY.format(user_id)})
    db.add(AuditLog(id=f"aud_{uuid.uuid4().hex[:16]}", admin_id=None, admin_email="system", action="security.suspicious_read",
                    target_type="user", target_id=user_id, summary=f"Suspicious reading by {user_id}: {why}", detail=detail))
    db.commit()


def count(db: Session, action: str, user_id: str) -> None:
    """One read on the account's budget for `action`; 429 when throttled or over it."""
    if _throttled(db, user_id):
        raise AppError(THROTTLED, 429)
    limits.per_account(db, f"read_{action}", user_id, _budget(action))


def profile_viewed(db: Session, user_id: str, profile_id: str) -> None:
    """Counts the view, and the number of DISTINCT profiles seen in the window."""
    count(db, "profile_view", user_id)
    if profile_id == user_id:
        return
    window = limits.WRITE_LIMITS["read_distinct"][1]
    first = db.execute(text(
        "INSERT INTO rate_limits (key, count, window_start) VALUES (:k, 1, now()) "
        "ON CONFLICT (key) DO UPDATE SET "
        "count = CASE WHEN rate_limits.window_start <= now() - :w THEN 1 ELSE rate_limits.count + 1 END, "
        "window_start = CASE WHEN rate_limits.window_start <= now() - :w THEN now() ELSE rate_limits.window_start END "
        "RETURNING count"), {"k": f"read_seen:{user_id}:{profile_id}", "w": window}).scalar()
    db.commit()
    if first != 1:
        return
    try:
        limits.per_account(db, "read_distinct", user_id, get_settings().suspicious_distinct_profiles)
    except AppError:
        _flag(db, user_id, "many different profiles in a short time",
              {"distinct_profiles_over": get_settings().suspicious_distinct_profiles})
        raise AppError(THROTTLED, 429) from None


def page_read(db: Session, user_id: str, scope: str, offset: int, search: bool) -> None:
    count(db, "search" if search else "list_page", user_id)
    if offset >= get_settings().suspicious_list_depth:
        _flag(db, user_id, f"paging deep into the {scope} list", {"list": scope, "offset": offset})
        raise AppError(THROTTLED, 429)
