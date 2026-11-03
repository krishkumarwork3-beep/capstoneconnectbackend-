"""Forgot password: a one-time code by SMS, then a short-lived token to set a new password.

1. request_code: if the phone number has an account, a 6-digit code is sent (only its hash is
   stored; it expires in OTP_TTL_MINUTES; asking again replaces it, at most once a minute).
   The answer is the same whether or not the number is registered.
2. verify_code: a correct code (OTP_MAX_ATTEMPTS tries) is used up and returns a reset token.
3. reset_password: the token sets the new password. Changing the password voids the token and
   signs out every existing session.
"""

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.errors import AppError
from app.models import PasswordResetCode, User
from app.services import bans
from app.security import (
    create_reset_token,
    e164,
    hash_code,
    hash_password,
    new_code,
    new_id,
    normalize_phone,
    read_token,
    token_matches_password,
)
from app.services.sms import SmsError, send_sms

GENERIC = "If an account uses that number, a code is on its way."


def _user_by_phone(db: Session, phone: str) -> User | None:
    return db.scalar(select(User).where(User.phone_normalized == normalize_phone(phone)))


def _latest_code(db: Session, user_id: str) -> PasswordResetCode | None:
    return db.scalar(
        select(PasswordResetCode)
        .where(PasswordResetCode.user_id == user_id)
        .order_by(PasswordResetCode.created_at.desc())
        .limit(1)
    )


def request_code(db: Session, phone: str) -> dict:
    settings = get_settings()
    user = _user_by_phone(db, phone)
    reply = {"message": GENERIC, "resend_after": settings.otp_resend_seconds, "dev_code": None}
    # Same answer for a blocked number or suspended account: no code is sent.
    if user is None or bans.is_blocked(db, user):
        return reply

    now = datetime.now(UTC)
    latest = _latest_code(db, user.id)
    if latest and (now - latest.created_at).total_seconds() < settings.otp_resend_seconds:
        wait = settings.otp_resend_seconds - int((now - latest.created_at).total_seconds())
        raise AppError(f"Wait {wait} seconds before asking for another code", 429)

    # A new code replaces any earlier one.
    db.execute(
        update(PasswordResetCode)
        .where(PasswordResetCode.user_id == user.id, PasswordResetCode.used_at.is_(None))
        .values(used_at=now)
    )
    code = new_code(settings.otp_length)
    db.add(
        PasswordResetCode(
            id=new_id("otp"),
            user_id=user.id,
            code_hash=hash_code(code),
            expires_at=now + timedelta(minutes=settings.otp_ttl_minutes),
            created_at=now,
        )
    )
    db.flush()
    try:
        send_sms(
            e164(user.phone_normalized),
            f"{code} is your CapstoneConnect code to reset your password. "
            f"It expires in {settings.otp_ttl_minutes} minutes. Don't share it.",
        )
    except SmsError as exc:
        db.rollback()
        raise AppError("We could not send the SMS. Try again in a minute.", 502) from exc
    db.commit()
    if settings.sms_provider == "console":
        reply["dev_code"] = code
    return reply


def verify_code(db: Session, phone: str, code: str) -> str:
    settings = get_settings()
    user = _user_by_phone(db, phone)
    record = _latest_code(db, user.id) if user else None
    now = datetime.now(UTC)
    if user is None or record is None or record.used_at is not None or record.expires_at <= now:
        raise AppError("That code has expired or was replaced. Ask for a new one.", 400)

    record.attempts += 1
    if record.attempts > settings.otp_max_attempts:
        record.used_at = now
        db.commit()
        raise AppError("Too many wrong codes. Ask for a new one.", 429)
    if not secrets.compare_digest(record.code_hash, hash_code(code.strip())):
        left = settings.otp_max_attempts - record.attempts
        db.commit()
        if left <= 0:
            raise AppError("That code is not right, and it is now used up. Ask for a new one.", 400)
        raise AppError(f"That code is not right. {left} {'try' if left == 1 else 'tries'} left.", 400)

    record.used_at = now
    db.commit()
    return create_reset_token(user.id, user.password_hash)


def reset_password(db: Session, token: str, password: str) -> User:
    read = read_token(token, "reset")
    user = db.get(User, read[0]) if read else None
    # The token carries the old password's fingerprint, so it works once and only until a change.
    if not read or user is None or not token_matches_password(read[1], user.password_hash):
        raise AppError("This reset link has expired. Start again.", 400)
    bans.ensure_can_sign_in(db, user)
    user.password_hash = hash_password(password)
    db.commit()
    return user
