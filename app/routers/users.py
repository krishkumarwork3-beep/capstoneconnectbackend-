"""Students: the Discover board, profiles, profile edits, uploads and GitHub activity."""

import asyncio
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, File, Query, UploadFile
from sqlalchemy import String, cast, exists, func, or_, select
from sqlalchemy.orm import Session

from app import schemas
from app.deps import DB, CurrentUser
from app.errors import AppError, not_found
from app.models import GroupMember, User
from app.serializers import request_out, user_out
from app.services import github, groups, uploads

router = APIRouter(prefix="/users", tags=["users"])

IN_GROUP_WORDS = "in a group grouped"
LOOKING_WORDS = "looking for group open"


def _get_user(db: Session, user_id: str) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise not_found("User")
    return user


@router.get("", response_model=schemas.UserPage)
def list_users(
    db: DB,
    me: CurrentUser,
    search: str | None = None,
    college: str | None = None,
    passing_year: int | None = None,
    hasGroup: bool | None = None,
    sort: Literal["relevance", "contributions", "name"] = "relevance",
    cursor: str | None = None,
    limit: int = Query(default=10, ge=1, le=200),
):
    """Search covers name, college, graduation year, skills and group status (never bios)."""
    in_group = exists().where(GroupMember.user_id == User.id)
    stmt = select(User)
    if search and search.strip():
        q = search.strip().lower()
        like = f"%{q}%"
        conditions = [
            func.lower(User.name).like(like),
            func.lower(User.college).like(like),
            cast(User.passing_year, String).like(like),
            func.lower(func.array_to_string(User.skills, "\x1f")).like(like),
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

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    if sort == "contributions":
        # Ranked students first; students with no total yet stay unranked rather than showing 0.
        stmt = stmt.order_by(User.github_contribution_count.desc().nulls_last(), User.created_at, User.id)
    elif sort == "name":
        stmt = stmt.order_by(func.lower(User.name), User.id)
    else:
        stmt = stmt.order_by(User.created_at, User.id)

    start = int(cursor) if cursor and cursor.isdigit() else 0
    items = db.scalars(stmt.offset(start).limit(limit)).unique().all()
    next_index = start + limit
    visible = groups.phone_visible_ids(db, me, [u.id for u in items])
    return {
        "items": [user_out(u, u.id in visible) for u in items],
        "nextCursor": str(next_index) if next_index < total else None,
        "hasMore": next_index < total,
        "total": total,
    }


@router.get("/{user_id}", response_model=schemas.UserOut)
def get_user(user_id: str, db: DB, me: CurrentUser):
    user = _get_user(db, user_id)
    return user_out(user, user.id in groups.phone_visible_ids(db, me, [user.id]))


@router.patch("/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: str, payload: schemas.UserUpdateIn, db: DB, me: CurrentUser):
    """Your own profile only. Name, college and graduation year are fixed at sign-up."""
    if user_id != me.id:
        raise AppError("You can only edit your own profile", 403)
    changes = payload.model_dump(exclude_unset=True)
    for field in ("department", "bio", "skills", "avatar_url", "resume_url"):
        if field in changes and changes[field] is not None:
            setattr(me, field, changes[field].strip() if isinstance(changes[field], str) else changes[field])

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
    user.github_url = f"https://github.com/{profile['login']}"
    user.github_verified = True
    user.github_contribution_count = total
    user.github_synced_at = datetime.now(UTC)


@router.post("/{user_id}/avatar")
async def upload_avatar(user_id: str, db: DB, me: CurrentUser, avatar: UploadFile = File(...)):
    if user_id != me.id:
        raise AppError("You can only change your own photo", 403)
    url, _, _ = await uploads.save(avatar, "avatar")
    me.avatar_url = url
    db.commit()
    return {"avatar_url": url}


@router.post("/{user_id}/resume")
async def upload_resume(user_id: str, db: DB, me: CurrentUser, resume: UploadFile = File(...)):
    if user_id != me.id:
        raise AppError("You can only change your own resume", 403)
    url, _, _ = await uploads.save(resume, "resume")
    me.resume_url = url
    db.commit()
    return {"resume_url": url}


@router.get("/{user_id}/github", response_model=schemas.GitHubActivityOut)
def github_activity(user_id: str, db: DB, _: CurrentUser, background: BackgroundTasks):
    """Live from GitHub. A stale all-time total is refreshed in the background."""
    user = _get_user(db, user_id)
    username = github.username_from(user.github_url)
    if username is None:
        raise AppError("This student has not added a GitHub username", 404)
    if github.is_stale(user.github_synced_at):
        background.add_task(github.sync_user, user.id, True)
    try:
        return asyncio.run(github.activity(username, user.github_contribution_count or 0))
    except github.GitHubUnavailable as exc:
        raise AppError("GitHub is not answering right now", 502) from exc


@router.post("/{user_id}/invitations", response_model=schemas.JoinRequestOut, status_code=201)
def invite(user_id: str, payload: schemas.InvitationIn, db: DB, me: CurrentUser):
    req = groups.send_invitation(db, user_id, payload.group_id, me, payload.note)
    db.commit()
    return request_out(req)

