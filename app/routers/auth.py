"""Sign up, log in, log out, who am I, and forgot password (SMS code).

Sign-in, sign-up and every password-reset step are throttled per phone number and per IP
address (app.services.limits).
"""

from fastapi import APIRouter, BackgroundTasks, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app import schemas
from app.config import get_settings
from app.deps import DB, CurrentUser, OptionalUser
from app.errors import AppError
from app.models import User, utcnow
from app.passwords import ensure_good_password
from app.security import create_session_token, hash_password, new_id, normalize_phone, verify_password

# Checked against when the number has no account, so a wrong number takes as long as a wrong
# password and timing does not tell which numbers are registered.
_DUMMY_HASH = hash_password("not-a-real-password-for-timing")
from app.serializers import user_out
from app.services import bans, github, limits, password_reset

router = APIRouter(prefix="/auth", tags=["auth"])


def _start_session(response: Response, user: User) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.cookie_name,
        create_session_token(user.id, user.password_hash),
        max_age=settings.session_days * 86400,
        httponly=True,
        secure=settings.cookie_secure,
        # Lax: sent on same-site requests (the frontend and API on one site), never cross-site POSTs.
        samesite="lax",
        path="/",
    )


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
    _start_session(response, user)
    return user_out(user)


@router.post("/login", response_model=schemas.UserOut)
def login(payload: schemas.LoginIn, request: Request, response: Response, db: DB):
    """Five wrong passwords for a number (or 20 from one address) in 15 minutes: 429 until the
    window ends. Signing in clears the number's count."""
    rule, ip = limits.rule("login"), limits.client_ip(request)
    limits.check(db, rule, payload.phone, ip)
    user = db.scalar(select(User).where(User.phone_normalized == normalize_phone(payload.phone)))
    password_ok = verify_password(payload.password, user.password_hash if user else _DUMMY_HASH)
    if user is None or not password_ok:
        limits.hit(db, rule, payload.phone, ip)
        raise AppError("Invalid phone number or password", 401)
    bans.ensure_can_sign_in(db, user)
    limits.reset(db, rule, payload.phone)
    user.last_seen = utcnow()
    db.commit()
    _start_session(response, user)
    return user_out(user)


@router.post("/logout", status_code=204)
def logout(response: Response):
    response.delete_cookie(get_settings().cookie_name, path="/")


@router.get("/me", response_model=schemas.UserOut)
def me(user: CurrentUser):
    return user_out(user)


@router.post("/demo-login/{user_id}", response_model=schemas.UserOut)
def demo_login(user_id: str, response: Response, db: DB, _: OptionalUser):
    """Persona switcher for demos (DEMO_LOGIN=true only): signs in as a seeded student."""
    if not get_settings().demo_login:
        raise AppError("Not found", 404)
    user = db.get(User, user_id)
    if user is None:
        raise AppError("User not found", 404)
    bans.ensure_can_sign_in(db, user)
    _start_session(response, user)
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
    _start_session(response, user)
    return user_out(user)
