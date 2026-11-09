"""Throttling for sign-in, sign-up and password reset, per phone number and per IP address.

Each key ("login:phone:919876543210", "login:ip:203.0.113.7") is a fixed-window counter in the
`rate_limits` table, updated with one atomic upsert, so every worker (`--workers 2`) and every
server shares the same counts. When a key is over its limit the request is refused with 429, a
message saying when to try again, and a `Retry-After` header.
"""

import math
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import delete, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.errors import AppError
from app.models import RateLimit
from app.security import normalize_phone

_HIT = text(
    """
    INSERT INTO rate_limits (key, count, window_start) VALUES (:key, 1, now())
    ON CONFLICT (key) DO UPDATE SET
        count = CASE WHEN rate_limits.window_start <= now() - :window THEN 1 ELSE rate_limits.count + 1 END,
        window_start = CASE WHEN rate_limits.window_start <= now() - :window THEN now() ELSE rate_limits.window_start END
    RETURNING count, window_start
    """
)


@dataclass(frozen=True)
class Rule:
    action: str
    per_phone: int
    per_ip: int
    window: timedelta


def rule(action: str) -> Rule:
    s = get_settings()
    limits = {
        "login": (s.login_limit_per_phone, s.login_limit_per_ip, s.login_window_minutes),
        "signup": (s.signup_limit_per_phone, s.signup_limit_per_ip, s.signup_window_minutes),
        "reset": (s.reset_limit_per_phone, s.reset_limit_per_ip, s.reset_window_minutes),
        "verify": (s.verify_limit_per_phone, s.verify_limit_per_ip, s.verify_window_minutes),
    }[action]
    return Rule(action, limits[0], limits[1], timedelta(minutes=limits[2]))


def client_ip(request: Request) -> str:
    # Behind a reverse proxy, run uvicorn with --proxy-headers (and --forwarded-allow-ips) so this
    # is the visitor's address, not the proxy's.
    return request.client.host if request.client else "unknown"


def _keys(rule_: Rule, phone: str | None, ip: str) -> list[tuple[str, int]]:
    keys = [(f"{rule_.action}:ip:{ip}", rule_.per_ip)]
    digits = normalize_phone(phone) if phone else ""
    if digits:
        keys.append((f"{rule_.action}:phone:{digits}", rule_.per_phone))
    return keys


def _refuse(wait: timedelta) -> AppError:
    seconds = max(1, math.ceil(wait.total_seconds()))
    when = f"{seconds} seconds" if seconds < 90 else f"{math.ceil(seconds / 60)} minutes"
    return AppError(f"Too many attempts. Try again in {when}.", 429, {"Retry-After": str(seconds)})


def check(db: Session, rule_: Rule, phone: str | None, ip: str) -> None:
    """Refuses (429) if the phone number or the IP address has used up its attempts. Counts nothing."""
    now = datetime.now(UTC)
    for key, limit in _keys(rule_, phone, ip):
        row = db.get(RateLimit, key)
        if row and row.count >= limit and row.window_start > now - rule_.window:
            raise _refuse(row.window_start + rule_.window - now)


def hit(db: Session, rule_: Rule, phone: str | None, ip: str) -> None:
    """Counts one attempt for the phone number and the IP address (committed at once, so it is
    kept even when the request then fails). Refuses (429) once either is over its limit."""
    now = datetime.now(UTC)
    over: timedelta | None = None
    for key, limit in _keys(rule_, phone, ip):
        count, start = db.execute(_HIT, {"key": key, "window": rule_.window}).one()
        if count > limit:
            wait = start + rule_.window - now
            over = max(over, wait) if over else wait
    if random.random() < 0.01:
        # Old counters are useless; drop them now and then.
        db.execute(delete(RateLimit).where(RateLimit.window_start < now - timedelta(days=1)))
    db.commit()
    if over is not None:
        raise _refuse(over)


def reset(db: Session, rule_: Rule, phone: str) -> None:
    """A successful sign-in clears the phone number's count (the IP's count of failures stays)."""
    db.execute(delete(RateLimit).where(RateLimit.key == f"{rule_.action}:phone:{normalize_phone(phone)}"))
    db.commit()



# ---------------------------------------------------------------------------------------------
# Per-account write limits: generous for a person, a wall for a script. Counted in the same
# table, so every worker shares them. (Reports also have their own per-day cap.)
# ---------------------------------------------------------------------------------------------

WRITE_LIMITS: dict[str, tuple[int, timedelta]] = {
    "message": (60, timedelta(minutes=1)),
    "join_request": (20, timedelta(hours=1)),
    "invitation": (30, timedelta(hours=1)),
    "recommendation": (30, timedelta(hours=1)),
    "group_create": (5, timedelta(days=1)),
    "group_edit": (60, timedelta(hours=1)),
    "profile_edit": (30, timedelta(hours=1)),
    "upload": (30, timedelta(hours=1)),
    "report": (20, timedelta(hours=1)),
    "github_lookup": (30, timedelta(minutes=10)),  # per account or, signed out, per IP address
    # Shared by HTTP (POST /conversations/{id}/read) and the socket's read/delivered frames.
    "receipt": (120, timedelta(minutes=1)),
    # Socket only, but per account: ten sockets don't get ten times the budget.
    "typing": (60, timedelta(minutes=1)),
    "ws_ticket": (60, timedelta(minutes=10)),
    "refresh": (60, timedelta(minutes=10)),  # POST /api/auth/refresh and the admin one, per IP address
    "stats_read": (60, timedelta(minutes=1)),  # GET /api/stats/signups, per signed-in account
    # Reads (app.services.reads): the counts come from the READ_* settings; these are the windows.
    "read_profile_view": (300, timedelta(minutes=10)),
    "read_list_page": (200, timedelta(minutes=10)),
    "read_search": (120, timedelta(minutes=10)),
    "read_chat_history": (600, timedelta(minutes=10)),
    "read_distinct": (80, timedelta(minutes=10)),
}


def per_account(db: Session, action: str, who: str, limit: int | None = None) -> None:
    """Counts one write for this account (or address) and refuses (429) once over the limit."""
    default, window = WRITE_LIMITS[action]
    limit = default if limit is None else limit
    count, start = db.execute(_HIT, {"key": f"{action}:who:{who}", "window": window}).one()
    if random.random() < 0.01:
        # Old windows are useless: drop them now and then (every window here is under a day).
        db.execute(text("DELETE FROM rate_limits WHERE window_start < now() - interval '2 days'"))
    db.commit()
    if count > limit:
        raise _refuse(start + window - datetime.now(UTC))
