"""Students: the Discover board, profiles, profile edits, uploads and GitHub activity."""

import asyncio
import logging
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, File, Query, UploadFile
from sqlalchemy import String, cast, exists, func, or_, select
from sqlalchemy.orm import Session

from app import schemas
from app import search as like_text
from app.deps import DB, CurrentUser, PathId
from app.errors import AppError, not_found
from app.models import GroupMember, User
from app.serializers import request_out, user_out
from app.services import chat, github, groups, reads, uploads
from app.services import limits as write_limits

log = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["users"])

IN_GROUP_WORDS = "in a group grouped"
LOOKING_WORDS = "looking for group open"


def _get_user(db: Session, user_id: PathId) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise not_found("User")
    return user


@router.get("", response_model=schemas.UserPage)
def list_users(
    db: DB,
    me: CurrentUser,
    search: str | None = Query(default=None, min_length=reads.SEARCH_MIN, max_length=100),
    college: str | None = Query(default=None, max_length=160),
    passing_year: int | None = Query(default=None, ge=1900, le=2200),
    hasGroup: bool | None = None,
    sort: Literal["relevance", "contributions", "name"] = "relevance",
    cursor: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=reads.PAGE_DEFAULT, ge=1, le=reads.PAGE_MAX),
):
    """Search covers name, college, graduation year, skills and group status (never bios)."""
    in_group = exists().where(GroupMember.user_id == User.id)
    stmt = select(User)
    if search and search.strip():
        q = search.strip().lower()
        like = like_text.contains(q)
        conditions = [
            func.lower(User.name).like(like, escape=like_text.ESCAPE),
            func.lower(User.college).like(like, escape=like_text.ESCAPE),
            cast(User.passing_year, String).like(like, escape=like_text.ESCAPE),
            func.lower(func.array_to_string(User.skills, "\x1f")).like(like, escape=like_text.ESCAPE),
        ]
        if q in IN_GROUP_WORDS:
            conditions.append(in_group)
        if q in LOOKING_WORDS:
            conditions.append(~in_group)
        stmt = stmt.where(or_(*conditions))
    if college and college != "all":
        stmt = stmt.where(User.college == college)
    if passing_year:
        stmt = stmt.where(User.passing_year == passing_year)
    if hasGroup is not None:
        stmt = stmt.where(in_group if hasGroup else ~in_group)

    start = reads.read_cursor(cursor, "users", me.id)
    reads.page_read(db, me.id, "users", start, bool(search and search.strip()))
    if sort == "contributions":
        # Ranked students first; students with no total yet stay unranked rather than showing 0.
        stmt = stmt.order_by(User.github_contribution_count.desc().nulls_last(), User.created_at, User.id)
    elif sort == "name":
        stmt = stmt.order_by(func.lower(User.name), User.id)
    else:
        stmt = stmt.order_by(User.created_at, User.id)

    # One extra row tells whether there is a next page, without counting the whole table.
    rows = db.scalars(stmt.offset(start).limit(limit + 1)).unique().all()
    items, more = rows[:limit], len(rows) > limit
    visible = groups.phone_visible_ids(db, me, [u.id for u in items])
    known = chat.contacts(db, me.id)
    return {
        "items": [user_out(u, u.id in visible, viewer=me.id, contacts=known) for u in items],
        "nextCursor": reads.make_cursor("users", me.id, start + limit) if more else None,
        "hasMore": more,
    }


@router.get("/{user_id}", response_model=schemas.UserOut)
def get_user(user_id: PathId, db: DB, me: CurrentUser, background: BackgroundTasks):
    reads.profile_viewed(db, me.id, user_id)
    user = _get_user(db, user_id)
    if user.github_verified and github.is_stale(user.github_synced_at):
        background.add_task(github.sync_user, user.id, True)  # the next view shows the fresh total
    return user_out(user, user.id in groups.phone_visible_ids(db, me, [user.id]), viewer=me.id, contacts=chat.contacts(db, me.id))


@router.patch("/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: PathId, payload: schemas.UserUpdateIn, db: DB, me: CurrentUser):
    """Your own profile only. Name, college and graduation year are fixed at sign-up."""
    write_limits.per_account(db, "profile_edit", me.id)
    if user_id != me.id:
        raise AppError("You can only edit your own profile", 403)
    changes = payload.model_dump(exclude_unset=True)
    for field in ("department", "bio", "skills"):
        if field in changes and changes[field] is not None:
            setattr(me, field, changes[field].strip() if isinstance(changes[field], str) else changes[field])
    for field in ("avatar_url", "resume_url"):
        if field in changes:  # only ever "" or null: remove the file
            uploads.remove(getattr(me, field))
            setattr(me, field, None)

    if "github_url" in changes:
        _apply_github(me, changes.get("github_url"), bool(changes.get("github_verified")))
    db.commit()
    return user_out(me)


def _apply_github(user: User, url: str | None, wants_verified: bool) -> None:
    """Editing the username resets verification. "Verified" is never taken from the client: the
    server checks the username itself and stores the real all-time total."""
    username = github.username_from(url)
    if username is None:
        user.github_url = None
        user.github_verified = False
        user.github_contribution_count = None
        user.github_synced_at = None
        return
    canonical = f"https://github.com/{username}"
    changed = (user.github_url or "").lower() != canonical.lower()
    user.github_url = canonical
    if changed:
        user.github_verified = False
        user.github_contribution_count = None
        user.github_synced_at = None
    if not wants_verified:
        return
    try:
        result = asyncio.run(github.lookup(username))
    except github.GitHubUnavailable:
        return  # stays unverified; the profile can be checked again later
    if result is None:
        user.github_verified = False
        return
    profile, total = result
    user.github_url = f"https://github.com/{github._login(profile, username)}"
    user.github_verified = True
    github.apply_total(user, total)


@router.post("/{user_id}/avatar", response_model=schemas.AvatarOut)
async def upload_avatar(user_id: PathId, db: DB, me: CurrentUser, avatar: UploadFile = File(...)):
    write_limits.per_account(db, "upload", me.id)
    if user_id != me.id:
        raise AppError("You can only change your own photo", 403)
    path, _, _ = await uploads.save(avatar, "avatar")
    uploads.remove(me.avatar_url)  # the previous photo is no longer used
    me.avatar_url = path
    db.commit()
    return {"avatar_url": uploads.public_url(path)}


@router.post("/{user_id}/resume", response_model=schemas.ResumeOut)
async def upload_resume(user_id: PathId, db: DB, me: CurrentUser, resume: UploadFile = File(...)):
    write_limits.per_account(db, "upload", me.id)
    if user_id != me.id:
        raise AppError("You can only change your own resume", 403)
    path, _, _ = await uploads.save(resume, "resume")
    uploads.remove(me.resume_url)
    me.resume_url = path
    db.commit()
    return {"resume_url": uploads.public_url(path)}


@router.get("/{user_id}/github", response_model=schemas.GitHubActivityOut)
def github_activity(user_id: PathId, db: DB, _: CurrentUser, background: BackgroundTasks):
    """Live from GitHub. A stale all-time total is refreshed in the background."""
    user = _get_user(db, user_id)
    username = github.username_from(user.github_url)
    if username is None:
        raise AppError("This student has not added a GitHub username", 404)
    if github.is_stale(user.github_synced_at):
        if user.github_verified:
            # One calendar request (not the rate-limited API): this answer already has the fresh total.
            try:
                github.apply_total(user, asyncio.run(github.refresh_count(username)))
                db.commit()
            except github.GitHubUnavailable as exc:
                log.warning("GitHub total for %s not refreshed: %s", user.id, exc)
        else:
            background.add_task(github.sync_user, user.id, True)
    try:
        return asyncio.run(github.activity(username, user.github_contribution_count or 0))
    except github.GitHubUnavailable as exc:
        raise AppError("GitHub is not answering right now", 502) from exc


@router.post("/{user_id}/invitations", response_model=schemas.JoinRequestOut, status_code=201)
def invite(user_id: PathId, payload: schemas.InvitationIn, db: DB, me: CurrentUser):
    write_limits.per_account(db, "invitation", me.id)
    req = groups.send_invitation(db, user_id, payload.group_id, me, payload.note)
    db.commit()
    return request_out(req)

