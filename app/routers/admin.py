"""Admin API (/api/admin), used by the admin portal (../adminportal).

Signed in with the admin cookie (POST /admin/auth/login). Every admin can read; only the
"admin" role can change things ("viewer" accounts are read-only). Every change is written to
the audit log (GET /admin/audit).
"""

import csv
import io
from datetime import timedelta
from typing import Literal

from typing import Annotated

from fastapi import APIRouter, Path as PathParam, Query, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import Date, cast, func, or_, select
from sqlalchemy.exc import IntegrityError

from app import search as like_text
from app.links import csv_cell
from app import admin_schemas as s
from app.config import get_settings
from app.cookies import admin_cookie, clear_session_cookie, set_session_cookie
from app.deps import PathId, DB, AdminWriter, CurrentAdmin
from app.errors import AppError, not_found
from app.models import (
    AdminUser,
    AuditLog,
    BannedPhone,
    Conversation,
    Group,
    GroupMember,
    JoinRequest,
    Announcement,
    Message,
    Recommendation,
    Report,
    User,
    utcnow,
)
from app.security import hash_password, new_id, normalize_phone, verify_password
from app.services import sessions
from app.passwords import ensure_good_password
from app.services import admin as ops
from app.services import github, uploads
from app.services import groups as rules

router = APIRouter(prefix="/admin")


def _paged(page: int, page_size: int) -> tuple[int, int]:
    return (page - 1) * page_size, page_size


# =============================================================================================
# Sign-in and admin accounts
# =============================================================================================

auth = APIRouter(tags=["admin: sign-in"])


def _start_admin_session(request: Request, response: Response, db, admin: AdminUser) -> None:
    """A new session row every time (the cookie the browser came with is revoked first)."""
    settings = get_settings()
    sessions.revoke_token(db, request.cookies.get(admin_cookie()), "admin")
    token = sessions.start(db, "admin", admin.id, admin.password_hash, timedelta(hours=settings.admin_session_hours), request)
    db.commit()
    set_session_cookie(response, admin_cookie(), token, settings.admin_session_hours * 3600)


@auth.post("/auth/login", response_model=s.AdminOut)
def admin_login(payload: s.AdminLoginIn, request: Request, response: Response, db: DB):
    admin = ops.authenticate(db, payload.email, payload.password)
    _start_admin_session(request, response, db, admin)
    return admin


@auth.post("/auth/logout", status_code=204)
def admin_logout(request: Request, response: Response, db: DB):
    """Ends this session on the server: a copy of the cookie stops working too."""
    sessions.revoke_token(db, request.cookies.get(admin_cookie()), "admin")
    db.commit()
    clear_session_cookie(response, admin_cookie())


@auth.post("/auth/logout-all", status_code=204)
def admin_logout_everywhere(response: Response, admin: CurrentAdmin, db: DB):
    """Sign out everywhere: every session of this admin account ends now."""
    sessions.revoke_all(db, "admin", [admin.id])
    ops.record(db, admin, "admin.logout_all", "Signed out of every session", "admin", admin.id)
    db.commit()
    clear_session_cookie(response, admin_cookie())


@auth.get("/auth/me", response_model=s.AdminOut)
def admin_me(admin: CurrentAdmin):
    return admin


@auth.post("/auth/password", status_code=204)
def change_own_password(payload: s.AdminPasswordIn, request: Request, response: Response, admin: CurrentAdmin, db: DB):
    """Changes your own password. Your other sessions end; this one gets a new cookie."""
    if not verify_password(payload.current_password, admin.password_hash):
        raise AppError("Your current password is wrong", 400)
    ensure_good_password(payload.new_password)
    admin.password_hash = hash_password(payload.new_password)
    ops.record(db, admin, "admin.password", "Changed their own password", "admin", admin.id)
    sessions.revoke_all(db, "admin", [admin.id])
    _start_admin_session(request, response, db, admin)


admins = APIRouter(tags=["admin: admin accounts"])


@admins.get("/admins", response_model=list[s.AdminOut])
def list_admins(_: CurrentAdmin, db: DB):
    return list(db.scalars(select(AdminUser).order_by(AdminUser.created_at)))


@admins.post("/admins", response_model=s.AdminOut, status_code=201)
def add_admin(payload: s.AdminCreateIn, admin: AdminWriter, db: DB):
    created = ops.create_admin(db, payload.email, payload.name, payload.password, payload.role)
    ops.record(db, admin, "admin.create", f"Added {payload.role} {created.email}", "admin", created.id)
    db.commit()
    return created


@admins.patch("/admins/{admin_id}", response_model=s.AdminOut)
def update_admin(admin_id: PathId, payload: s.AdminUpdateIn, admin: AdminWriter, db: DB):
    target = db.get(AdminUser, admin_id)
    if target is None:
        raise not_found("Admin")
    removing_power = (payload.role == "viewer" or payload.active is False) and target.role == "admin" and target.active
    if removing_power and ops.active_admin_count(db) <= 1:
        raise AppError("Keep at least one active admin", 409)
    changes = payload.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(target, key, value)
    if payload.active is False:
        sessions.revoke_all(db, "admin", [target.id])  # deactivated: signed out everywhere now
    ops.record(db, admin, "admin.update", f"Updated admin {target.email}", "admin", target.id, changes)
    db.commit()
    return target


@admins.delete("/admins/{admin_id}", status_code=204)
def remove_admin(admin_id: PathId, admin: AdminWriter, db: DB):
    target = db.get(AdminUser, admin_id)
    if target is None:
        raise not_found("Admin")
    if target.id == admin.id:
        raise AppError("You can't remove your own admin account", 409)
    if target.role == "admin" and target.active and ops.active_admin_count(db) <= 1:
        raise AppError("Keep at least one active admin", 409)
    ops.record(db, admin, "admin.delete", f"Removed admin {target.email}", "admin", target.id)
    sessions.revoke_all(db, "admin", [target.id])
    db.delete(target)
    db.commit()


# =============================================================================================
# Dashboard
# =============================================================================================

dashboard = APIRouter(tags=["admin: dashboard"])


@dashboard.get("/stats")
def stats(_: CurrentAdmin, db: DB):
    """Totals for the dashboard, sign-ups per day for the last 30 days, and the latest activity."""
    count = lambda model, *where: db.scalar(select(func.count()).select_from(model).where(*where)) or 0  # noqa: E731
    now = utcnow()
    day_ago, week_ago = now - timedelta(days=1), now - timedelta(days=7)
    since = (now - timedelta(days=29)).date()
    day = cast(User.created_at, Date)
    per_day = dict(db.execute(select(day, func.count()).where(day >= since).group_by(day)).all())
    signups = [{"date": (since + timedelta(days=i)).isoformat(), "count": per_day.get(since + timedelta(days=i), 0)} for i in range(30)]
    in_group = count(GroupMember)
    total_users = count(User)
    groups = list(db.scalars(select(Group)))
    return {
        "users": {
            "total": total_users,
            "in_group": in_group,
            "looking": total_users - in_group,
            "banned": count(User, User.banned_at.is_not(None)),
            "new_this_week": count(User, User.created_at >= week_ago),
            "active_today": count(User, User.last_seen >= day_ago),
        },
        "groups": {
            "total": len(groups),
            "full": sum(1 for g in groups if len(g.members) >= g.max_members),
            "open": sum(1 for g in groups if len(g.members) < g.max_members),
        },
        "requests": {
            "pending": count(JoinRequest, JoinRequest.status == "pending"),
            "accepted": count(JoinRequest, JoinRequest.status == "accepted"),
            "declined": count(JoinRequest, JoinRequest.status == "declined"),
        },
        "chat": {
            "conversations": count(Conversation),
            "messages": count(Message),
            "messages_today": count(Message, Message.created_at >= day_ago),
        },
        "blocked_numbers": count(BannedPhone),
        "reports": {"open": count(Report, Report.status == "open")},
        "signups": signups,
        "recent_users": [
            {"id": u.id, "name": u.name, "college": u.college, "created_at": u.created_at}
            for u in db.scalars(select(User).order_by(User.created_at.desc()).limit(6))
        ],
        "recent_actions": [
            s.AuditRow.model_validate(a).model_dump(mode="json")
            for a in db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(8))
        ],
    }


# =============================================================================================
# Students
# =============================================================================================

students = APIRouter(tags=["admin: students"])

StudentStatus = Literal["all", "active", "banned", "in_group", "looking"]
StudentSort = Literal["newest", "oldest", "name", "last_seen"]


def _student_query(q: str | None, status: StudentStatus, college: str | None):
    stmt = select(User)
    if q:
        like = like_text.contains(q.strip().lower())
        digits = normalize_phone(q) if any(c.isdigit() for c in q) else ""
        conditions = [func.lower(User.name).like(like, escape=like_text.ESCAPE), func.lower(User.college).like(like, escape=like_text.ESCAPE), User.id == q.strip()]
        if digits:
            conditions.append(User.phone_normalized.like(f"%{digits[-10:]}%"))
        stmt = stmt.where(or_(*conditions))
    if college:
        stmt = stmt.where(User.college == college)
    member = select(GroupMember.user_id)
    if status == "active":
        stmt = stmt.where(User.banned_at.is_(None))
    elif status == "banned":
        stmt = stmt.where(User.banned_at.is_not(None))
    elif status == "in_group":
        stmt = stmt.where(User.id.in_(member))
    elif status == "looking":
        stmt = stmt.where(User.id.not_in(member))
    return stmt


@students.get("/users", response_model=s.Page[s.StudentRow])
def list_students(
    _: CurrentAdmin,
    db: DB,
    q: str | None = Query(None, max_length=100, description="Name, college, phone (any format) or id"),
    status: StudentStatus = "all",
    college: str | None = Query(None, max_length=160),
    sort: StudentSort = "newest",
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(25, ge=1, le=200),
):
    stmt = _student_query(q, status, college)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    order = {
        "newest": User.created_at.desc(),
        "oldest": User.created_at.asc(),
        "name": func.lower(User.name).asc(),
        "last_seen": User.last_seen.desc().nulls_last(),
    }[sort]
    offset, limit = _paged(page, page_size)
    users = list(db.scalars(stmt.order_by(order, User.id).offset(offset).limit(limit)).unique())
    blocked = ops.blocked_numbers(db, (u.phone_normalized for u in users))
    return {"items": [ops.student_row(u, blocked) for u in users], "total": total, "page": page, "page_size": page_size}


@students.get("/users/ids", response_model=list[str])
def student_ids(_: CurrentAdmin, db: DB, q: str | None = Query(None, max_length=100), status: StudentStatus = "all", college: str | None = Query(None, max_length=160)):
    """Ids of every student matching the filters (for "select all"), newest first."""
    stmt = _student_query(q, status, college).with_only_columns(User.id).order_by(User.created_at.desc())
    return list(db.scalars(stmt.limit(s.BULK_LIMIT)))


@students.get("/users/colleges", response_model=list[str])
def colleges(_: CurrentAdmin, db: DB):
    return list(db.scalars(select(User.college).distinct().order_by(User.college)))


# One export is built in memory: bounded, so a huge table can't exhaust the server.
EXPORT_LIMIT = 50_000


@students.get("/users/export.csv", response_class=StreamingResponse,
               responses={200: {"content": {"text/csv": {}}, "description": "A CSV file"}})
def export_students(_: CurrentAdmin, db: DB, q: str | None = Query(None, max_length=100), status: StudentStatus = "all", college: str | None = Query(None, max_length=160)):
    """Every matching student as a CSV file (opens in Excel or Google Sheets)."""
    users = list(db.scalars(_student_query(q, status, college).order_by(User.created_at).limit(EXPORT_LIMIT + 1)).unique())
    if len(users) > EXPORT_LIMIT:
        raise AppError(f"More than {EXPORT_LIMIT:,} students match: filter by college or status and export in parts", 422)
    blocked = ops.blocked_numbers(db, (u.phone_normalized for u in users))
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "name", "phone", "college", "department", "passing_year", "group", "role", "github", "contributions", "suspended", "number_blocked", "last_seen", "joined"])
    for u in users:
        row = ops.student_row(u, blocked)
        writer.writerow([csv_cell(v) for v in [row.id, row.name, row.phone, row.college, row.department or "", row.passing_year, row.group_name or "", row.group_role or "",
                         row.github_url or "", row.github_contribution_count if row.github_contribution_count is not None else "",
                         "yes" if row.banned else "", "yes" if row.number_blocked else "",
                         row.last_seen.isoformat() if row.last_seen else "", row.created_at.isoformat()]])
    stamp = utcnow().strftime("%Y%m%d-%H%M")
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="capstoneconnect-students-{stamp}.csv"'})


def _checked_hash(password: str, phone: str) -> str:
    ensure_good_password(password, phone)
    return hash_password(password)


def _student(db, user_id: PathId) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise not_found("Student")
    return user


@students.get("/users/{user_id}", response_model=s.StudentDetail)
def get_student(user_id: PathId, _: CurrentAdmin, db: DB):
    return ops.student_detail(db, _student(db, user_id))


@students.post("/users", response_model=s.StudentDetail, status_code=201)
def create_student(payload: s.StudentCreateIn, admin: AdminWriter, db: DB):
    phone = normalize_phone(payload.phone)
    ops.check_phone_free(db, phone)
    username = github.username_from(payload.github_url)
    user = User(
        id=new_id("usr"),
        name=payload.name.strip(),
        college=payload.college.strip(),
        department=(payload.department or "").strip() or None,
        passing_year=payload.passing_year,
        phone=payload.phone.strip(),
        phone_normalized=phone,
        password_hash=_checked_hash(payload.password, payload.phone),
        bio=payload.bio.strip(),
        skills=[x.strip() for x in payload.skills if x.strip()],
        github_url=f"https://github.com/{username}" if username else None,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise AppError("Another account already uses this phone number", 409) from exc
    ops.record(db, admin, "user.create", f"Created student {user.name} ({user.phone})", "user", user.id)
    db.commit()
    return ops.student_detail(db, user)


@students.patch("/users/{user_id}", response_model=s.StudentDetail)
def update_student(user_id: PathId, payload: s.StudentUpdateIn, admin: AdminWriter, db: DB):
    user = _student(db, user_id)
    changes = payload.model_dump(exclude_unset=True)
    before = {key: getattr(user, key) for key in changes if hasattr(user, key)}
    if "phone" in changes and changes["phone"] is not None:
        phone = normalize_phone(changes["phone"])
        ops.check_phone_free(db, phone, except_user=user.id)
        user.phone = changes["phone"].strip()
        user.phone_normalized = phone
    for key in ("name", "college", "passing_year", "bio"):
        if changes.get(key) is not None:
            setattr(user, key, changes[key].strip() if isinstance(changes[key], str) else changes[key])
    if "department" in changes:
        user.department = (changes["department"] or "").strip() or None
    if changes.get("skills") is not None:
        user.skills = [x.strip() for x in changes["skills"] if x.strip()]
    if "github_url" in changes:
        username = github.username_from(changes["github_url"])
        new_url = f"https://github.com/{username}" if username else None
        if new_url != user.github_url:
            user.github_url, user.github_verified, user.github_contribution_count = new_url, False, None
    ops.record(db, admin, "user.update", f"Edited {user.name}: {', '.join(changes) or 'nothing'}", "user", user.id,
               {"fields": list(changes), "before": {k: str(v) for k, v in before.items()}})
    db.commit()
    return ops.student_detail(db, user)


@students.post("/users/{user_id}/password", status_code=204)
def set_student_password(user_id: PathId, payload: s.PasswordSetIn, admin: AdminWriter, db: DB):
    """Sets a new password. Every session of that student ends (they sign in with the new one)."""
    user = _student(db, user_id)
    ensure_good_password(payload.password, user.phone)
    user.password_hash = hash_password(payload.password)
    ops.end_sessions(db, [user.id])
    ops.record(db, admin, "user.password", f"Set a new password for {user.name}", "user", user.id)
    db.commit()


@students.post("/users/{user_id}/ban", response_model=s.StudentDetail)
def ban_student(user_id: PathId, payload: s.BanIn, admin: AdminWriter, db: DB):
    """Suspends the account (signed out at once, can't sign in). Optionally blocks its number too."""
    user = _student(db, user_id)
    ops.ban(db, user, payload.reason)
    summary = f"Suspended {user.name}" + (f": {payload.reason.strip()}" if payload.reason.strip() else "")
    if payload.block_number:
        ops.block_numbers(db, admin, [user.phone], payload.reason or f"Suspended account {user.name}")
        summary += " (number blocked)"
    ops.record(db, admin, "user.ban", summary, "user", user.id, {"reason": payload.reason, "block_number": payload.block_number})
    db.commit()
    return ops.student_detail(db, user)


@students.post("/users/{user_id}/unban", response_model=s.StudentDetail)
def unban_student(user_id: PathId, admin: AdminWriter, db: DB):
    """Lifts the suspension. A blocked number stays blocked until removed under Blocked numbers."""
    user = _student(db, user_id)
    ops.unban(user)
    ops.record(db, admin, "user.unban", f"Lifted the suspension of {user.name}", "user", user.id)
    db.commit()
    return ops.student_detail(db, user)


@students.delete("/users/{user_id}", status_code=204)
def delete_student(user_id: PathId, admin: AdminWriter, db: DB):
    user = _student(db, user_id)
    ops.record(db, admin, "user.delete", f"Deleted student {user.name} ({user.phone})", "user", user.id,
               {"name": user.name, "phone": user.phone, "college": user.college})
    ops.delete_student(db, user)
    db.commit()


@students.delete("/users/{user_id}/{kind}", response_model=s.StudentDetail)
def remove_student_file(user_id: PathId, kind: Literal["avatar", "resume"], admin: AdminWriter, db: DB):
    """Removes a student's photo or résumé, and deletes the file from disk."""
    user = _student(db, user_id)
    url = user.avatar_url if kind == "avatar" else user.resume_url
    if not url:
        raise AppError(f"{user.name} has no {'photo' if kind == 'avatar' else 'résumé'}", 409)
    deleted = uploads.remove(url)
    if kind == "avatar":
        user.avatar_url = None
    else:
        user.resume_url = None
    what = "photo" if kind == "avatar" else "résumé"
    ops.record(db, admin, f"user.remove_{kind}", f"Removed {user.name}'s {what}", "user", user.id,
               {"url": url, "file_deleted": deleted})
    db.commit()
    return ops.student_detail(db, user)


@students.post("/users/bulk", response_model=s.BulkOut)
def bulk_students(payload: s.BulkIn, admin: AdminWriter, db: DB):
    """Suspend, lift suspension or delete many students at once."""
    done, skipped = 0, []
    for user_id in dict.fromkeys(payload.ids):
        user = db.get(User, user_id)
        if user is None:
            skipped.append(user_id)
            continue
        if payload.action == "ban":
            ops.ban(db, user, payload.reason)
        elif payload.action == "unban":
            ops.unban(user)
        else:
            ops.delete_student(db, user)
        done += 1
    ops.record(db, admin, f"user.bulk_{payload.action}", f"Bulk {payload.action}: {done} student(s)", "user", None,
               {"ids": payload.ids, "reason": payload.reason})
    db.commit()
    return {"done": done, "skipped": skipped}


# =============================================================================================
# Blocked numbers
# =============================================================================================

numbers = APIRouter(tags=["admin: blocked numbers"])


@numbers.get("/banned-phones", response_model=list[s.BannedPhoneOut])
def list_blocked(_: CurrentAdmin, db: DB, q: str | None = Query(None, max_length=100)):
    stmt = select(BannedPhone).order_by(BannedPhone.created_at.desc())
    if q and any(c.isdigit() for c in q):
        stmt = stmt.where(BannedPhone.phone_normalized.like(f"%{normalize_phone(q)[-10:]}%"))
    rows = list(db.scalars(stmt))
    accounts = {u.phone_normalized: u for u in db.scalars(select(User).where(User.phone_normalized.in_([r.phone_normalized for r in rows])))}
    return [
        s.BannedPhoneOut(
            phone_normalized=r.phone_normalized, phone=r.phone, reason=r.reason, created_by=r.created_by, created_at=r.created_at,
            account_id=accounts[r.phone_normalized].id if r.phone_normalized in accounts else None,
            account_name=accounts[r.phone_normalized].name if r.phone_normalized in accounts else None,
        )
        for r in rows
    ]


@numbers.post("/banned-phones", response_model=s.BannedPhoneAdded, status_code=201)
def block_numbers(payload: s.BannedPhoneIn, admin: AdminWriter, db: DB):
    """Blocks numbers from signing up, signing in and resetting a password (an existing account on
    a blocked number is suspended for as long as the number stays blocked)."""
    result = ops.block_numbers(db, admin, payload.phones, payload.reason)
    if result.added:
        ops.record(db, admin, "phone.block", f"Blocked {len(result.added)} number(s)", "phone", ",".join(result.added)[:60],
                   {"numbers": result.added, "reason": payload.reason})
    db.commit()
    return result


@numbers.post("/banned-phones/bulk-delete", response_model=s.BulkOut)
def unblock_numbers(payload: s.IdsIn, admin: AdminWriter, db: DB):
    """Unblocks several numbers (any format) at once."""
    done, skipped = [], []
    for phone in dict.fromkeys(payload.ids):
        row = db.get(BannedPhone, normalize_phone(phone))
        if row is None:
            skipped.append(phone)
            continue
        done.append(row.phone_normalized)
        db.delete(row)
    if done:
        ops.record(db, admin, "phone.bulk_unblock", f"Unblocked {len(done)} number(s)", "phone", ",".join(done)[:60], {"numbers": done})
    db.commit()
    return {"done": len(done), "skipped": skipped}


@numbers.delete("/banned-phones/{phone}", status_code=204)
def unblock_number(phone: Annotated[str, PathParam(max_length=32)], admin: AdminWriter, db: DB):
    row = db.get(BannedPhone, normalize_phone(phone))
    if row is None:
        raise not_found("Blocked number")
    ops.record(db, admin, "phone.unblock", f"Unblocked {row.phone}", "phone", row.phone_normalized)
    db.delete(row)
    db.commit()


# =============================================================================================
# Groups and requests
# =============================================================================================

groups_router = APIRouter(tags=["admin: groups"])


GroupStatus = Literal["all", "open", "full"]


@groups_router.get("/groups", response_model=s.Page[s.GroupRow])
def list_groups(
    _: CurrentAdmin,
    db: DB,
    q: str | None = Query(None, max_length=100),
    status: GroupStatus = "all",
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(25, ge=1, le=200),
):
    groups = _matching_groups(db, q, status)
    offset, limit = _paged(page, page_size)
    return {"items": [ops.group_row(g) for g in groups[offset : offset + limit]], "total": len(groups), "page": page, "page_size": page_size}


def _matching_groups(db, q: str | None, status: GroupStatus) -> list[Group]:
    stmt = select(Group).order_by(Group.created_at.desc())
    if q:
        like = like_text.contains(q.strip().lower())
        stmt = stmt.where(or_(func.lower(Group.name).like(like, escape=like_text.ESCAPE), func.lower(Group.domain).like(like, escape=like_text.ESCAPE), Group.id == q.strip()))
    groups = list(db.scalars(stmt).unique())
    if status == "open":
        groups = [g for g in groups if len(g.members) < g.max_members]
    elif status == "full":
        groups = [g for g in groups if len(g.members) >= g.max_members]
    return groups


@groups_router.get("/groups/ids", response_model=list[str])
def group_ids(_: CurrentAdmin, db: DB, q: str | None = Query(None, max_length=100), status: GroupStatus = "all"):
    """Ids of every group matching the filters (for "select all")."""
    return [g.id for g in _matching_groups(db, q, status)[: s.BULK_LIMIT]]


@groups_router.post("/groups/bulk-delete", response_model=s.BulkOut)
def delete_groups(payload: s.IdsIn, admin: AdminWriter, db: DB):
    """Deletes several groups and their chats; their members become free to join another group."""
    done, skipped = [], []
    for group_id in dict.fromkeys(payload.ids):
        group = db.get(Group, group_id)
        if group is None:
            skipped.append(group_id)
            continue
        done.append(group.name)
        ops.delete_group(db, group)
        db.flush()
    if done:
        ops.record(db, admin, "group.bulk_delete", f"Deleted {len(done)} group(s)", "group", None, {"ids": payload.ids, "names": done})
    db.commit()
    return {"done": len(done), "skipped": skipped}


def _group(db, group_id: PathId) -> Group:
    group = db.get(Group, group_id)
    if group is None:
        raise not_found("Group")
    return group


@groups_router.get("/groups/{group_id}", response_model=s.GroupDetail)
def get_group(group_id: PathId, _: CurrentAdmin, db: DB):
    group = _group(db, group_id)
    members = sorted(group.members, key=lambda m: m.joined_at)
    pending = db.scalar(select(func.count()).select_from(JoinRequest).where(JoinRequest.group_id == group.id, JoinRequest.status == "pending")) or 0
    return s.GroupDetail(
        **ops.group_row(group).model_dump(),
        members=[s.GroupMemberRow(user_id=m.user_id, name=m.user.name, phone=m.user.phone, role=m.role, joined_at=m.joined_at) for m in members],
        pending_requests=pending,
    )


@groups_router.patch("/groups/{group_id}", response_model=s.GroupDetail)
def edit_group(group_id: PathId, payload: s.GroupEditIn, admin: AdminWriter, db: DB):
    """Name, description, domain and requirements (the size can't change)."""
    group = _group(db, group_id)
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise AppError("Nothing to change", 422)
    before = {key: getattr(group, key) for key in changes}
    rules.apply_group_changes(db, group, changes)
    ops.record(db, admin, "group.edit", f"Edited group {group.name} ({', '.join(changes)})", "group", group.id,
               {"before": {k: list(v) if isinstance(v, list) else v for k, v in before.items()}, "after": changes})
    db.commit()
    return get_group(group.id, admin, db)


@groups_router.post("/groups/{group_id}/lead", response_model=s.GroupDetail)
def make_lead(group_id: PathId, payload: s.LeadIn, admin: AdminWriter, db: DB):
    """Makes another member the Group Lead (the old lead stays as a member)."""
    group = _group(db, group_id)
    old = next((m.user.name for m in group.members if m.role == "admin"), None)
    new = rules.transfer_lead(db, group, payload.user_id)
    ops.record(db, admin, "group.transfer_lead", f"Made {new.user.name} Group Lead of {group.name}", "group", group.id,
               {"from": old, "to": new.user_id})
    db.commit()
    return get_group(group.id, admin, db)


@groups_router.delete("/groups/{group_id}", status_code=204)
def delete_group(group_id: PathId, admin: AdminWriter, db: DB):
    """Deletes the group and its chat; members become free to join another group."""
    group = _group(db, group_id)
    ops.record(db, admin, "group.delete", f"Deleted group {group.name} ({len(group.members)} members)", "group", group.id)
    ops.delete_group(db, group)
    db.commit()


@groups_router.delete("/groups/{group_id}/members/{user_id}", status_code=204)
def remove_member(group_id: PathId, user_id: PathId, admin: AdminWriter, db: DB):
    """Removes a student from a group (a Group Lead hands over to the longest-serving member)."""
    group = _group(db, group_id)
    user = _student(db, user_id)
    if user.membership is None or user.membership.group_id != group.id:
        raise AppError("That student is not in this group", 409)
    ops.record(db, admin, "group.remove_member", f"Removed {user.name} from {group.name}", "group", group.id, {"user_id": user.id})
    rules.leave_group(db, group, user)
    db.commit()


@groups_router.get("/requests", response_model=s.Page[s.RequestRow])
def list_requests(
    _: CurrentAdmin,
    db: DB,
    status: Literal["all", "pending", "accepted", "declined", "withdrawn", "cancelled"] = "all",
    type: Literal["all", "join_request", "invitation"] = "all",
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(25, ge=1, le=200),
):
    stmt = select(JoinRequest)
    if status != "all":
        stmt = stmt.where(JoinRequest.status == status)
    if type != "all":
        stmt = stmt.where(JoinRequest.type == type)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    offset, limit = _paged(page, page_size)
    rows = db.scalars(stmt.order_by(JoinRequest.updated_at.desc()).offset(offset).limit(limit)).unique()
    items = [
        s.RequestRow(id=r.id, type=r.type, status=r.status, group_id=r.group_id, group_name=r.group_name, sender_id=r.sender_id,
                     sender_name=r.sender.name, receiver_id=r.receiver_id, receiver_name=r.receiver.name, note=r.note,
                     created_at=r.created_at, updated_at=r.updated_at)
        for r in rows
    ]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@groups_router.get("/requests/ids", response_model=list[str])
def pending_request_ids(_: CurrentAdmin, db: DB, type: Literal["all", "join_request", "invitation"] = "all"):
    """Ids of every pending request (only pending ones can be cancelled), for "select all"."""
    stmt = select(JoinRequest.id).where(JoinRequest.status == "pending").order_by(JoinRequest.updated_at.desc())
    if type != "all":
        stmt = stmt.where(JoinRequest.type == type)
    return list(db.scalars(stmt.limit(s.BULK_LIMIT)))


@groups_router.post("/requests/bulk-cancel", response_model=s.BulkOut)
def cancel_requests(payload: s.IdsIn, admin: AdminWriter, db: DB):
    """Cancels several pending requests; ones that are no longer pending are skipped."""
    done, skipped = 0, []
    for request_id in dict.fromkeys(payload.ids):
        req = db.get(JoinRequest, request_id)
        if req is None or req.status != "pending":
            skipped.append(request_id)
            continue
        req.status = "cancelled"
        done += 1
    if done:
        ops.record(db, admin, "request.bulk_cancel", f"Cancelled {done} request(s)", "request", None, {"ids": payload.ids})
    db.commit()
    return {"done": done, "skipped": skipped}


@groups_router.get("/recommendations", response_model=s.Page[s.RecommendationRow])
def list_recommendations(
    _: CurrentAdmin,
    db: DB,
    status: Literal["all", "pending", "invited", "dismissed", "closed"] = "all",
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(25, ge=1, le=200),
):
    """Members vouching for Looking students (read-only here)."""
    stmt = select(Recommendation)
    if status != "all":
        stmt = stmt.where(Recommendation.status == status)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    offset, limit = _paged(page, page_size)
    rows = list(db.scalars(stmt.order_by(Recommendation.updated_at.desc()).offset(offset).limit(limit)).unique())
    names = dict(db.execute(select(Group.id, Group.name).where(Group.id.in_({r.group_id for r in rows if r.group_id}))).all())
    items = [
        s.RecommendationRow(id=r.id, group_id=r.group_id, group_name=names.get(r.group_id), recommender_id=r.recommender_id,
                            recommender_name=r.recommender.name, student_id=r.student_id, student_name=r.student.name,
                            note=r.note, status=r.status, created_at=r.created_at, updated_at=r.updated_at)
        for r in rows
    ]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@groups_router.post("/requests/{request_id}/cancel", status_code=204)
def cancel_request(request_id: PathId, admin: AdminWriter, db: DB):
    req = db.get(JoinRequest, request_id)
    if req is None:
        raise not_found("Request")
    if req.status != "pending":
        raise AppError("Only pending requests can be cancelled", 409)
    req.status = "cancelled"
    ops.record(db, admin, "request.cancel", f"Cancelled a {req.type.replace('_', ' ')} for {req.group_name}", "request", req.id)
    db.commit()


# =============================================================================================
# Chat moderation
# =============================================================================================

chat_router = APIRouter(tags=["admin: chat"])


@chat_router.get("/conversations", response_model=s.Page[s.ConversationRow])
def list_conversations(
    _: CurrentAdmin,
    db: DB,
    q: str | None = Query(None, max_length=100, description="A participant's name, or a group name"),
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(25, ge=1, le=200),
):
    convs = list(db.scalars(select(Conversation).order_by(Conversation.updated_at.desc())).unique())
    if q:
        needle = q.strip().lower()
        convs = [c for c in convs if needle in ops.conversation_title(c).lower()]
    counts = dict(db.execute(select(Message.conversation_id, func.count()).group_by(Message.conversation_id)).all())
    offset, limit = _paged(page, page_size)
    items = [
        s.ConversationRow(id=c.id, type=c.type, title=ops.conversation_title(c), participants=[p.user.name for p in c.participants],
                          message_count=counts.get(c.id, 0), last_message_text=c.last_message_text, last_message_at=c.last_message_at)
        for c in convs[offset : offset + limit]
    ]
    return {"items": items, "total": len(convs), "page": page, "page_size": page_size}


@chat_router.get("/conversations/{conversation_id}/messages", response_model=list[s.MessageRow])
def conversation_messages(conversation_id: PathId, _: CurrentAdmin, db: DB, limit: int = Query(200, ge=1, le=1000)):
    if db.get(Conversation, conversation_id) is None:
        raise not_found("Conversation")
    latest = list(db.scalars(select(Message).where(Message.conversation_id == conversation_id).order_by(Message.created_at.desc()).limit(limit)))
    return list(reversed(latest))


@chat_router.post("/messages/bulk-delete", response_model=s.BulkOut)
def delete_messages(payload: s.IdsIn, admin: AdminWriter, db: DB):
    """Deletes several messages; each conversation's preview updates."""
    done, skipped = [], []
    for message_id in dict.fromkeys(payload.ids):
        message = db.get(Message, message_id)
        if message is None:
            skipped.append(message_id)
            continue
        done.append({"id": message.id, "conversation_id": message.conversation_id, "by": message.sender_name, "text": message.text[:200]})
        ops.delete_message(db, message)
    if done:
        ops.record(db, admin, "message.bulk_delete", f"Deleted {len(done)} message(s)", "message", None, {"messages": done})
    db.commit()
    return {"done": len(done), "skipped": skipped}


@chat_router.delete("/messages/{message_id}", status_code=204)
def delete_message(message_id: PathId, admin: AdminWriter, db: DB):
    message = db.get(Message, message_id)
    if message is None:
        raise not_found("Message")
    ops.record(db, admin, "message.delete", f"Deleted a message by {message.sender_name}", "message", message.id,
               {"conversation_id": message.conversation_id, "text": message.text[:500]})
    ops.delete_message(db, message)
    db.commit()


# =============================================================================================
# Audit log
# =============================================================================================

audit = APIRouter(tags=["admin: audit log"])


@audit.get("/audit", response_model=s.Page[s.AuditRow])
def audit_log(
    _: CurrentAdmin,
    db: DB,
    q: str | None = Query(None, max_length=100, description="Text in the summary, or an admin's email"),
    action: str | None = Query(None, max_length=60, description='e.g. "user.ban", or a prefix like "user."'),
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(50, ge=1, le=200),
):
    stmt = select(AuditLog)
    if q:
        like = like_text.contains(q.strip().lower())
        stmt = stmt.where(or_(func.lower(AuditLog.summary).like(like, escape=like_text.ESCAPE), func.lower(AuditLog.admin_email).like(like, escape=like_text.ESCAPE)))
    if action:
        stmt = stmt.where(AuditLog.action.like(like_text.starts_with(action), escape=like_text.ESCAPE))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    offset, limit = _paged(page, page_size)
    items = list(db.scalars(stmt.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)))
    return {"items": items, "total": total, "page": page, "page_size": page_size}


# =============================================================================================
# Reports (from students) and announcements (the site banner)
# =============================================================================================

community = APIRouter(tags=["admin: reports and announcements"])


def _report_row(db, r: Report) -> s.ReportRow:
    from app.routers.community import REASONS

    exists = {
        "user": lambda: db.get(User, r.target_id) is not None,
        "group": lambda: db.get(Group, r.target_id) is not None,
        "message": lambda: db.get(Message, r.target_id) is not None,
    }[r.target_type]()
    return s.ReportRow(
        id=r.id, reporter_id=r.reporter_id, reporter_name=r.reporter.name, target_type=r.target_type,
        target_id=r.target_id, target_user_id=r.target_user_id,
        target_user_name=r.target_user.name if r.target_user else None,
        target_user_banned=bool(r.target_user and r.target_user.banned_at), target_exists=exists,
        conversation_id=r.conversation_id, reason=r.reason, reason_label=REASONS.get(r.reason, r.reason),
        details=r.details or "", snapshot=r.snapshot or "", status=r.status, handled_by=r.handled_by,
        handled_at=r.handled_at, created_at=r.created_at,
    )


def _report(db, report_id: PathId) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise not_found("Report")
    return report


def _handled(report: Report, admin, status: str) -> None:
    report.status = status
    report.handled_by = admin.email
    report.handled_at = utcnow()


@community.get("/reports", response_model=s.Page[s.ReportRow])
def list_reports(
    _: CurrentAdmin,
    db: DB,
    status: Literal["all", "open", "reviewed", "dismissed", "actioned"] = "open",
    target_type: Literal["all", "user", "group", "message"] = "all",
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(25, ge=1, le=200),
):
    stmt = select(Report)
    if status != "all":
        stmt = stmt.where(Report.status == status)
    if target_type != "all":
        stmt = stmt.where(Report.target_type == target_type)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    offset, limit = _paged(page, page_size)
    rows = list(db.scalars(stmt.order_by(Report.created_at.desc()).offset(offset).limit(limit)).unique())
    return {"items": [_report_row(db, r) for r in rows], "total": total, "page": page, "page_size": page_size}


@community.post("/reports/{report_id}/status", response_model=s.ReportRow)
def set_report_status(report_id: PathId, payload: s.ReportStatusIn, admin: AdminWriter, db: DB):
    """Mark reviewed, dismiss, or reopen."""
    report = _report(db, report_id)
    if payload.status == "open":
        report.status, report.handled_by, report.handled_at = "open", None, None
    else:
        _handled(report, admin, payload.status)
    ops.record(db, admin, f"report.{payload.status}", f"Marked a report on {report.snapshot[:60]} as {payload.status}", "report", report.id)
    db.commit()
    return _report_row(db, report)


@community.post("/reports/{report_id}/suspend", response_model=s.ReportRow)
def suspend_from_report(report_id: PathId, payload: s.ReportSuspendIn, admin: AdminWriter, db: DB):
    """Suspends the student behind the report (they are signed out at once)."""
    report = _report(db, report_id)
    user = db.get(User, report.target_user_id) if report.target_user_id else None
    if user is None:
        raise AppError("There is no student to suspend for this report", 409)
    reason = payload.reason.strip() or f"Report: {report.reason}"
    ops.ban(db, user, reason)
    _handled(report, admin, "actioned")
    ops.record(db, admin, "report.suspend", f"Suspended {user.name} after a report", "user", user.id,
               {"report_id": report.id, "reason": reason})
    db.commit()
    return _report_row(db, report)


@community.post("/reports/{report_id}/delete-message", response_model=s.ReportRow)
def delete_reported_message(report_id: PathId, admin: AdminWriter, db: DB):
    report = _report(db, report_id)
    if report.target_type != "message":
        raise AppError("This report is not about a message", 409)
    message = db.get(Message, report.target_id)
    if message is None:
        raise AppError("That message was already deleted", 409)
    ops.record(db, admin, "report.delete_message", f"Deleted a reported message by {message.sender_name}", "message",
               message.id, {"report_id": report.id, "text": (message.text or "")[:500]})
    ops.delete_message(db, message)
    _handled(report, admin, "actioned")
    db.commit()
    return _report_row(db, report)


def _announcement_row(a: Announcement) -> s.AnnouncementRow:
    now = utcnow()
    return s.AnnouncementRow.model_validate(a).model_copy(update={"active": a.starts_at <= now and (a.ends_at is None or a.ends_at > now)})


def _check_window(starts_at, ends_at) -> None:
    if ends_at is not None and starts_at is not None and ends_at <= starts_at:
        raise AppError("The end must be after the start", 422)


@community.get("/announcements", response_model=list[s.AnnouncementRow])
def list_announcements(_: CurrentAdmin, db: DB):
    return [_announcement_row(a) for a in db.scalars(select(Announcement).order_by(Announcement.starts_at.desc()).limit(200))]


@community.post("/announcements", response_model=s.AnnouncementRow, status_code=201)
def create_announcement(payload: s.AnnouncementIn, admin: AdminWriter, db: DB):
    starts = payload.starts_at or utcnow()
    _check_window(starts, payload.ends_at)
    a = Announcement(id=new_id("ann"), text=payload.text.strip(), link_url=payload.link_url,
                     link_label=(payload.link_label or "").strip() or None, level=payload.level,
                     starts_at=starts, ends_at=payload.ends_at, created_by=admin.email)
    db.add(a)
    ops.record(db, admin, "announcement.create", f"Posted an announcement: {a.text[:60]}", "announcement", a.id)
    db.commit()
    return _announcement_row(a)


@community.patch("/announcements/{announcement_id}", response_model=s.AnnouncementRow)
def update_announcement(announcement_id: PathId, payload: s.AnnouncementPatch, admin: AdminWriter, db: DB):
    a = db.get(Announcement, announcement_id)
    if a is None:
        raise not_found("Announcement")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if key in ("text", "link_label") and isinstance(value, str):
            value = value.strip() or (None if key == "link_label" else value)
        setattr(a, key, value)
    if a.starts_at is None:
        a.starts_at = utcnow()
    _check_window(a.starts_at, a.ends_at)
    ops.record(db, admin, "announcement.edit", f"Edited an announcement: {a.text[:60]}", "announcement", a.id,
               {"fields": sorted(changes)})
    db.commit()
    return _announcement_row(a)


@community.delete("/announcements/{announcement_id}", status_code=204)
def delete_announcement(announcement_id: PathId, admin: AdminWriter, db: DB):
    a = db.get(Announcement, announcement_id)
    if a is None:
        raise not_found("Announcement")
    ops.record(db, admin, "announcement.delete", f"Deleted an announcement: {a.text[:60]}", "announcement", a.id)
    db.delete(a)
    db.commit()


for part in (auth, admins, dashboard, students, numbers, groups_router, chat_router, community, audit):
    router.include_router(part)
