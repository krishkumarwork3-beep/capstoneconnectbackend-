"""Sign up, log in, log out, who am I, and forgot password (SMS code).

Sign-in, sign-up and every password-reset step are throttled per phone number and per IP
address (app.services.limits).
"""

from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app import schemas
from app.config import get_settings
from app.cookies import (
    clear_sign_in_cookies,
    refresh_cookie,
    set_sign_in_cookies,
    student_cookie,
)
from app.deps import DB, CurrentUser, OptionalUser, PathId
from app.errors import AppError
from app.models import User, utcnow
from app.passwords import ensure_good_password
from app.security import hash_password, new_id, normalize_phone, verify_password
from app.serializers import user_out
from app.services import admin as admin_ops
from app.services import bans, github, limits, lockout, password_reset, sessions

router = APIRouter(prefix="/auth", tags=["auth"])

# Checked against when the number has no account, so a wrong number takes as long as a wrong
# password and timing does not tell which numbers are registered.
_DUMMY_HASH = hash_password("not-a-real-password-for-timing")


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    return header[7:].strip() or None if header.lower().startswith("bearer ") else None


def _end_current(request: Request, db) -> None:
    """Revokes the sign-in this browser came with, by its access or its refresh token."""
    sessions.revoke_token(db, request.cookies.get(student_cookie()) or _bearer(request), "student")
    row = sessions.session_of_refresh(db, request.cookies.get(refresh_cookie()))
    if row is not None and row.kind == "student":
        sessions.end_family(db, row)


def _start_session(request: Request, response: Response, db, user: User) -> None:
    """Always a brand-new session (whatever the browser came with is revoked, so a session planted
    before sign-in is never promoted), committed before the cookies are sent: a 15-minute access
    token and a refresh token that rotates on every use."""
    settings = get_settings()
    _end_current(request, db)
    access, refresh, _ = sessions.sign_in(db, "student", user.id, timedelta(days=settings.session_days), request)
    db.commit()
    # SameSite, Secure and Domain come from the settings (see app.cookies for the layouts).
    set_sign_in_cookies(response, "student", access, refresh, settings.session_days * 86400)


def _signed_out(message: str = "Sign in to continue", status: int = 401) -> JSONResponse:
    reply = JSONResponse({"message": message}, status_code=status)
    clear_sign_in_cookies(reply, "student")
    return reply


@router.post("/refresh", status_code=204, responses={401: {"description": "No live session: sign in again"}})
def refresh(request: Request, response: Response, db: DB):
    """A new access token (and the next refresh token) from the refresh cookie. CSRF-checked like
    every cookie write (app.guard), rate limited per address. A refresh token works once: a
    replayed one ends the session everywhere it is used."""
    limits.per_account(db, "refresh", f"ip:{limits.client_ip(request)}")
    renewed = sessions.refresh(db, request.cookies.get(refresh_cookie()), "student")
    db.commit()
    if renewed is None:
        return _signed_out()
    user = db.get(User, renewed.subject_id)
    if user is None or bans.is_blocked(db, user):
        sessions.revoke(db, renewed.session_id)
        db.commit()
        return _signed_out()
    remaining = int((renewed.expires_at - utcnow()).total_seconds())
    set_sign_in_cookies(response, "student", renewed.access, renewed.refresh, remaining)


@router.post("/signup", response_model=schemas.UserOut, status_code=201)
def signup(payload: schemas.SignupIn, request: Request, response: Response, background: BackgroundTasks, db: DB):
    limits.hit(db, limits.rule("signup"), payload.phone, limits.client_ip(request))
    phone = normalize_phone(payload.phone)
    if len(phone) < 10:
        raise AppError("Enter a valid phone number", 422)
    ensure_good_password(payload.password, payload.phone)
    bans.ensure_number_allowed(db, phone)
    if db.scalar(select(User.id).where(User.phone_normalized == phone)):
        raise AppError("An account already exists for this phone number", 409)

    github_username = github.username_from(payload.github_url)
    user = User(
        id=new_id("usr"),
        name=payload.name.strip(),
        college=payload.college.strip(),
        department=(payload.department or "").strip() or None,
        passing_year=payload.passing_year,
        phone=payload.phone.strip(),
        phone_normalized=phone,
        password_hash=hash_password(payload.password),
        bio=payload.bio.strip(),
        skills=payload.skills,
        github_url=f"https://github.com/{github_username}" if github_username else None,
        last_seen=utcnow(),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise AppError("An account already exists for this phone number", 409) from exc

    if github_username:
        background.add_task(github.sync_user, user.id)
    _start_session(request, response, db, user)
    return user_out(user)


@router.post("/login", response_model=schemas.UserOut)
def login(payload: schemas.LoginIn, request: Request, response: Response, db: DB):
    """Five wrong passwords for a number (or 20 from one address) in 15 minutes: 429 until the
    window ends; after that the number's lock-out doubles with each further failure (up to a day,
    app.services.lockout). Every way of writing the number counts together. Signing in clears it."""
    rule, ip = limits.rule("login"), limits.client_ip(request)
    account = lockout.student_key(payload.phone)
    limits.check(db, rule, payload.phone, ip)
    lockout.check(db, account)
    user = db.scalar(select(User).where(User.phone_normalized == normalize_phone(payload.phone)))
    password_ok = verify_password(payload.password, user.password_hash if user else _DUMMY_HASH)
    if user is None or not password_ok:
        lockout.fail(db, account)
        limits.hit(db, rule, payload.phone, ip)
        raise AppError("Invalid phone number or password", 401)
    bans.ensure_can_sign_in(db, user)
    limits.reset(db, rule, payload.phone)
    lockout.succeed(db, account)
    user.last_seen = utcnow()
    _start_session(request, response, db, user)
    return user_out(user)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: DB):
    """Ends this session on the server and deletes its refresh tokens (a copy of either cookie
    stops working too)."""
    _end_current(request, db)
    db.commit()
    clear_sign_in_cookies(response, "student")


@router.post("/logout-all", status_code=204)
def logout_everywhere(response: Response, user: CurrentUser, db: DB):
    """Sign out everywhere: every session of this account, on every device, ends now."""
    admin_ops.end_sessions(db, [user.id])  # every session and reset grant; open tabs are told at once
    db.commit()
    clear_sign_in_cookies(response, "student")


@router.get("/me", response_model=schemas.UserOut)
def me(user: CurrentUser, background: BackgroundTasks):
    if user.github_verified and github.is_stale(user.github_synced_at):
        background.add_task(github.sync_user, user.id, True)  # the next load shows the fresh total
    return user_out(user)


@router.post("/demo-login/{user_id}", response_model=schemas.UserOut)
def demo_login(user_id: PathId, request: Request, response: Response, db: DB, _: OptionalUser):
    """Persona switcher for demos (DEMO_LOGIN=true only): signs in as a seeded student."""
    if not get_settings().demo_login:
        raise AppError("Not found", 404)
    user = db.get(User, user_id)
    if user is None:
        raise AppError("User not found", 404)
    bans.ensure_can_sign_in(db, user)
    _start_session(request, response, db, user)
    return user_out(user)


# --------------------------------------------------------------------------------------------
# Forgot password
# --------------------------------------------------------------------------------------------


@router.post("/password/forgot", response_model=schemas.ForgotOut)
def forgot_password(payload: schemas.ForgotIn, request: Request, db: DB):
    limits.hit(db, limits.rule("reset"), payload.phone, limits.client_ip(request))
    return password_reset.request_code(db, payload.phone)


@router.post("/password/verify", response_model=schemas.VerifyCodeOut)
def verify_reset_code(payload: schemas.VerifyCodeIn, request: Request, db: DB):
    limits.hit(db, limits.rule("verify"), payload.phone, limits.client_ip(request))
    return {"reset_token": password_reset.verify_code(db, payload.phone, payload.code)}


@router.post("/password/reset", response_model=schemas.UserOut)
def reset_password(payload: schemas.ResetIn, request: Request, response: Response, db: DB):
    """Sets the new password and signs in with it (older sessions stop working)."""
    limits.hit(db, limits.rule("verify"), None, limits.client_ip(request))
    user = password_reset.reset_password(db, payload.reset_token, payload.password)
    _start_session(request, response, db, user)
    return user_out(user)
