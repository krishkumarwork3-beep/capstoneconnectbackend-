"""Admin portal: admin accounts and sign-in, the audit log, and operations on site data.

Admin sessions are a signed cookie (ADMIN_COOKIE_NAME, kind "admin"), separate from students'
cookie. Like students' sessions they carry a fingerprint of the password, so changing an admin's
password signs that admin out everywhere; deactivating an admin does the same on the next request.
"""

import logging
from collections.abc import Iterable

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import admin_schemas as s
from app import realtime
from app.services import uploads
from app.config import get_settings
from app.db import SessionLocal
from app.errors import AppError
from app.passwords import ensure_good_password
from app.models import (
    AdminUser,
    AuditLog,
    BannedPhone,
    Conversation,
    ConversationParticipant,
    Group,
    JoinRequest,
    Message,
    User,
    utcnow,
)
from app.security import hash_password, new_id, normalize_phone, verify_password
from app.services import chat, lockout, sessions
from app.services import groups as rules

log = logging.getLogger("app.admin")

# ---------------------------------------------------------------------------------------------
# Sign-in, with the per-account lock-out and back-off shared with students (app.services.lockout).
# ---------------------------------------------------------------------------------------------

_DUMMY_HASH = hash_password("not-a-real-admin-password-for-timing")


def authenticate(db: Session, email: str, password: str) -> AdminUser:
    email = email.strip().lower()
    account = lockout.admin_key(email)
    lockout.check(db, account)
    admin = db.scalar(select(AdminUser).where(AdminUser.email == email))
    # A missing account takes as long as a wrong password (no timing hint about which emails exist).
    password_ok = verify_password(password, admin.password_hash if admin else _DUMMY_HASH)
    if admin is None or not admin.active or not password_ok:
        lockout.fail(db, account)
        raise AppError("Wrong email or password", 401)
    lockout.succeed(db, account)
    admin.last_login_at = utcnow()
    return admin


def reset_lockouts() -> None:
    """Kept for callers from before lock-outs moved to the database (the table is cleared instead)."""


def create_admin(db: Session, email: str, name: str, password: str, role: str = "admin") -> AdminUser:
    email = email.strip().lower()
    if db.scalar(select(AdminUser.id).where(AdminUser.email == email)):
        raise AppError("An admin with this email already exists", 409)
    ensure_good_password(password)
    admin = AdminUser(id=new_id("adm"), email=email, name=name.strip(), password_hash=hash_password(password), role=role)
    db.add(admin)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise AppError("An admin with this email already exists", 409) from exc
    return admin


def ensure_first_admin() -> None:
    """At startup: create ADMIN_EMAIL / ADMIN_PASSWORD as an admin if that email has no account."""
    settings = get_settings()
    if not settings.admin_email or not settings.admin_password:
        return
    with SessionLocal() as db:
        email = settings.admin_email.strip().lower()
        if db.scalar(select(AdminUser.id).where(AdminUser.email == email)):
            return
        create_admin(db, email, settings.admin_name, settings.admin_password)
        db.add(AuditLog(id=new_id("aud"), admin_email="system", action="admin.create", target_type="admin",
                        summary=f"First admin {email} created from ADMIN_EMAIL"))
        db.commit()
        log.info("created the first admin %s", email)


def active_admin_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.active, AdminUser.role == "admin")) or 0


# ---------------------------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------------------------


def record(
    db: Session,
    admin: AdminUser,
    action: str,
    summary: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            id=new_id("aud"),
            admin_id=admin.id,
            admin_email=admin.email,
            action=action,
            target_type=target_type,
            target_id=target_id,
            summary=summary,
            detail=detail,
        )
    )


# ---------------------------------------------------------------------------------------------
# Students
# ---------------------------------------------------------------------------------------------


def blocked_numbers(db: Session, phones: Iterable[str]) -> set[str]:
    phones = list(set(phones))
    if not phones:
        return set()
    return set(db.scalars(select(BannedPhone.phone_normalized).where(BannedPhone.phone_normalized.in_(phones))))


def student_row(user: User, blocked: set[str]) -> s.StudentRow:
    membership = user.membership
    return s.StudentRow(
        id=user.id,
        name=user.name,
        phone=user.phone,
        college=user.college,
        department=user.department,
        passing_year=user.passing_year,
        group_id=membership.group_id if membership else None,
        group_name=membership.group.name if membership else None,
        group_role=membership.role if membership else None,
        github_url=user.github_url,
        github_contribution_count=user.github_contribution_count,
        banned=user.banned_at is not None,
        ban_reason=user.ban_reason,
        banned_at=user.banned_at,
        number_blocked=user.phone_normalized in blocked,
        last_seen=user.last_seen,
        created_at=user.created_at,
    )


def student_detail(db: Session, user: User) -> s.StudentDetail:
    row = student_row(user, blocked_numbers(db, [user.phone_normalized]))
    count = lambda stmt: db.scalar(stmt) or 0  # noqa: E731
    return s.StudentDetail(
        **row.model_dump(),
        bio=user.bio or "",
        skills=list(user.skills or []),
        avatar_url=uploads.public_url(user.avatar_url),
        resume_url=uploads.public_url(user.resume_url),
        github_verified=bool(user.github_verified),
        requests_sent=count(select(func.count()).select_from(JoinRequest).where(JoinRequest.sender_id == user.id)),
        requests_received=count(select(func.count()).select_from(JoinRequest).where(JoinRequest.receiver_id == user.id)),
        messages_sent=count(select(func.count()).select_from(Message).where(Message.sender_id == user.id)),
        conversations=count(
            select(func.count()).select_from(ConversationParticipant).where(ConversationParticipant.user_id == user.id)
        ),
    )


def check_phone_free(db: Session, phone_normalized: str, except_user: str | None = None) -> None:
    if len(phone_normalized) < 10:
        raise AppError("Enter a valid phone number", 422)
    other = db.scalar(select(User.id).where(User.phone_normalized == phone_normalized))
    if other and other != except_user:
        raise AppError("Another account already uses this phone number", 409)


def end_sessions(db: Session, user_ids: Iterable[str]) -> None:
    """Revokes every session (and reset grant) of these students, and tells their open tabs at
    once (when `db` commits) that they are signed out."""
    sessions.end_everything(db, "student", list(user_ids))  # also tells their open sockets


def ban(db: Session, user: User, reason: str) -> None:
    user.banned_at = utcnow()
    user.ban_reason = reason.strip() or None
    end_sessions(db, [user.id])


def unban(user: User) -> None:
    user.banned_at = None
    user.ban_reason = None


def block_numbers(db: Session, admin: AdminUser, phones: Iterable[str], reason: str) -> s.BannedPhoneAdded:
    added, already, invalid = [], [], []
    for raw in phones:
        raw = raw.strip()
        if not raw:
            continue
        normalized = normalize_phone(raw)
        if len(normalized) < 10:
            invalid.append(raw)
        elif db.get(BannedPhone, normalized) or normalized in added:
            already.append(raw)
        else:
            db.add(BannedPhone(phone_normalized=normalized, phone=raw, reason=reason.strip() or None, created_by=admin.email))
            added.append(normalized)
    db.flush()
    if added:
        end_sessions(db, db.scalars(select(User.id).where(User.phone_normalized.in_(added))))
    return s.BannedPhoneAdded(added=added, already=already, invalid=invalid)


def delete_student(db: Session, user: User) -> None:
    """Leaves their group first (a Group Lead hands over to the longest-serving member, a last
    member closes the group), then deletes the account. Their requests, recommendations and chat
    memberships go with it; messages they sent stay in group chats, without a sender id. A direct
    chat that has nobody left in it is deleted too."""
    end_sessions(db, [user.id])
    membership = user.membership
    if membership is not None:
        rules.leave_group(db, membership.group, user)
        db.flush()
        db.expire(user, ["membership"])  # the membership row is gone; don't let delete touch it
    direct = list(db.scalars(
        select(Conversation.id)
        .join(ConversationParticipant, ConversationParticipant.conversation_id == Conversation.id)
        .where(ConversationParticipant.user_id == user.id, Conversation.type == "direct")
    ))
    db.delete(user)
    db.flush()
    if direct:
        empty = select(ConversationParticipant.conversation_id).where(ConversationParticipant.conversation_id.in_(direct))
        for conv in db.scalars(select(Conversation).where(Conversation.id.in_(direct), Conversation.id.not_in(empty))):
            db.delete(conv)


# ---------------------------------------------------------------------------------------------
# Groups and chat
# ---------------------------------------------------------------------------------------------


def group_row(group: Group) -> s.GroupRow:
    lead = next((m for m in group.members if m.role == "admin"), None)
    return s.GroupRow(
        id=group.id,
        name=group.name,
        domain=group.domain,
        description=group.description,
        max_members=group.max_members,
        member_count=len(group.members),
        lead_id=lead.user_id if lead else None,
        lead_name=lead.user.name if lead else None,
        requirements=list(group.requirements or []),
        created_at=group.created_at,
    )


def delete_group(db: Session, group: Group) -> None:
    rules.cancel_group_items(db, group.id)
    chat.conversations_changed(db, (m.user_id for m in group.members))
    db.delete(group)


def conversation_title(conv: Conversation) -> str:
    if conv.type == "group" and conv.group is not None:
        return conv.group.name
    names = [p.user.name for p in conv.participants]
    return " & ".join(names) or "Conversation"


def delete_message(db: Session, message: Message) -> None:
    conv = db.get(Conversation, message.conversation_id)
    db.delete(message)
    db.flush()
    if conv is None:
        return
    # Keep the conversation list's preview honest.
    latest = db.scalar(select(Message).where(Message.conversation_id == conv.id).order_by(Message.created_at.desc()).limit(1))
    conv.last_message_text = (latest.text or latest.attachment_name or "Attachment") if latest else None
    conv.last_message_sender = latest.sender_name if latest else None
    conv.last_message_at = latest.created_at if latest else None
    chat.conversations_changed(db, (p.user_id for p in conv.participants))
