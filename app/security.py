"""Passwords, ids, phone numbers and signed tokens (sessions and password resets)."""

import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt

from app.config import get_settings

MIN_PASSWORD_LENGTH = 8


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def hash_password(password: str) -> str:
    # bcrypt reads at most 72 bytes; longer passwords are pre-hashed so nothing is silently cut.
    return bcrypt.hashpw(_bcrypt_input(password), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_bcrypt_input(password), hashed.encode())
    except ValueError:
        return False


def _bcrypt_input(password: str) -> bytes:
    raw = password.encode()
    return hashlib.sha256(raw).hexdigest().encode() if len(raw) > 72 else raw


def normalize_phone(phone: str) -> str:
    """Digits only, with the country code: "+91 98765 43210" and "9876543210" are the same number."""
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) == 10:
        digits = "91" + digits
    if len(digits) == 11 and digits.startswith("0"):
        digits = "91" + digits[1:]
    return digits


def e164(phone_normalized: str) -> str:
    return f"+{phone_normalized}"


# ---------------------------------------------------------------------------------------------
# Signed tokens. Each carries a short fingerprint of the password hash, so changing the password
# (a reset) signs out every existing session and voids older reset tokens.
# ---------------------------------------------------------------------------------------------


def _fingerprint(password_hash: str) -> str:
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def _encode(claims: dict, lifetime: timedelta) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    return jwt.encode({**claims, "iat": now, "exp": now + lifetime}, settings.secret_key, algorithm="HS256")


def _decode(token: str, kind: str) -> dict | None:
    try:
        claims = jwt.decode(token, get_settings().secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return claims if claims.get("kind") == kind else None


def create_session_token(user_id: str, password_hash: str) -> str:
    days = get_settings().session_days
    return _encode({"kind": "session", "sub": user_id, "pv": _fingerprint(password_hash)}, timedelta(days=days))


def create_reset_token(user_id: str, password_hash: str) -> str:
    minutes = get_settings().reset_token_minutes
    return _encode({"kind": "reset", "sub": user_id, "pv": _fingerprint(password_hash)}, timedelta(minutes=minutes))


def read_token(token: str, kind: str) -> tuple[str, str] | None:
    """(user id, password fingerprint) from a valid token of this kind, else None."""
    claims = _decode(token, kind)
    if not claims or "sub" not in claims:
        return None
    return claims["sub"], claims.get("pv", "")


def token_matches_password(fingerprint: str, password_hash: str) -> bool:
    return secrets.compare_digest(fingerprint, _fingerprint(password_hash))


def hash_code(code: str) -> str:
    """One-time codes are short, so they are hashed with the secret key (an HMAC), not bare SHA."""
    key = get_settings().secret_key.encode()
    return hashlib.blake2b(code.encode(), key=key[:64], digest_size=32).hexdigest()


def new_code(length: int) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))
