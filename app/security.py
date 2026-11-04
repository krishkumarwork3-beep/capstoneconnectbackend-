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
# Signed tokens: HS256 only, with a fixed issuer and one audience per kind, so a student cookie is
# never accepted as an admin one, nor a reset grant as a session. Each names a server-side row
# (`sid`, app.services.sessions) that can be revoked, and carries a fingerprint of the password
# hash as a second check.
# ---------------------------------------------------------------------------------------------

ALGORITHM = "HS256"
AUDIENCES = {"student": "capstoneconnect:student", "admin": "capstoneconnect:admin", "reset": "capstoneconnect:reset",
             "ws": "capstoneconnect:ws"}
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub", "sid", "kind"]
LEEWAY_SECONDS = 30


def fingerprint(password_hash: str) -> str:
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def encode_token(kind: str, subject_id: str, session_id: str, password_hash: str, lifetime: timedelta,
                 extra: dict | None = None) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    claims = {
        **(extra or {}),
        "iss": settings.jwt_issuer, "aud": AUDIENCES[kind], "sub": subject_id, "sid": session_id,
        "kind": kind, "pv": fingerprint(password_hash), "iat": now, "exp": now + lifetime,
    }
    return jwt.encode(claims, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str, kind: str) -> dict | None:
    """The claims of a valid token of this kind, else None: wrong algorithm (or "none"), bad
    signature, wrong issuer or audience, missing or past `exp`, `iat` in the future, wrong kind."""
    if not token or len(token) > 2000:
        return None
    settings = get_settings()
    try:
        if jwt.get_unverified_header(token).get("alg") != ALGORITHM:
            return None
        claims = jwt.decode(
            token, settings.secret_key, algorithms=[ALGORITHM], audience=AUDIENCES[kind], issuer=settings.jwt_issuer,
            leeway=LEEWAY_SECONDS, options={"require": REQUIRED_CLAIMS, "verify_signature": True, "verify_exp": True,
                                            "verify_iat": True, "verify_aud": True, "verify_iss": True},
        )
    except (jwt.PyJWTError, ValueError, TypeError):
        return None
    now = datetime.now(UTC).timestamp()
    if claims.get("kind") != kind or not isinstance(claims.get("iat"), (int, float)) or claims["iat"] > now + LEEWAY_SECONDS:
        return None
    if not all(isinstance(claims.get(k), str) and claims[k] for k in ("sub", "sid")):
        return None
    return claims


def token_matches_password(token_fingerprint: str, password_hash: str) -> bool:
    return secrets.compare_digest(str(token_fingerprint or ""), fingerprint(password_hash))


def hash_code(code: str) -> str:
    """One-time codes are short, so they are hashed with the secret key (an HMAC), not bare SHA."""
    key = get_settings().secret_key.encode()
    return hashlib.blake2b(code.encode(), key=key[:64], digest_size=32).hexdigest()


def new_code(length: int) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))
