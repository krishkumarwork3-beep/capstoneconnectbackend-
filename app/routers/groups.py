"""Capstone groups: the board, details, create/edit/delete, leave, remove members, join requests."""

from fastapi import APIRouter, Query
from sqlalchemy import func, or_, select

from app import schemas
from app import search as like_text
from app.deps import DB, CurrentUser, PathId
from app.models import Group, GroupMember
from app.serializers import group_out, request_out
from app.services import groups as rules
from app.services import limits as write_limits
from app.services import reads

router = APIRouter(prefix="/groups", tags=["groups"])

OPEN_WORDS = "open slot open slots vacancy vacancies"


@router.get("", response_model=schemas.GroupPage)
def list_groups(
    db: DB,
    me: CurrentUser,
    search: str | None = Query(default=None, min_length=reads.SEARCH_MIN, max_length=100),
    domain: str | None = Query(default=None, max_length=160),
    openOnly: bool = False,
    cursor: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=reads.PAGE_DEFAULT, ge=1, le=reads.PAGE_MAX),
):
    """Signed-in students only (group pages name their members). Search covers title, skills,
    domain and open seats only."""
    seats = select(func.count()).where(GroupMember.group_id == Group.id).correlate(Group).scalar_subquery()
    stmt = select(Group)
    if search and search.strip():
        q = search.strip().lower()
        like = like_text.contains(q)
        conditions = [
            func.lower(Group.name).like(like, escape=like_text.ESCAPE),
            func.lower(Group.domain).like(like, escape=like_text.ESCAPE),
            func.lower(func.array_to_string(Group.requirements, "\x1f")).like(like, escape=like_text.ESCAPE),
        ]
        if q in OPEN_WORDS:
            conditions.append(seats < Group.max_members)
        if q in "full":
            conditions.append(seats >= Group.max_members)
        stmt = stmt.where(or_(*conditions))
    if domain and domain != "all":
        stmt = stmt.where(Group.domain == domain)
    if openOnly:
        stmt = stmt.where(seats < Group.max_members)

    start = reads.read_cursor(cursor, "groups", me.id)
    reads.page_read(db, me.id, "groups", start, bool(search and search.strip()))
    rows = db.scalars(stmt.order_by(Group.created_at.desc(), Group.id).offset(start).limit(limit + 1)).unique().all()
    items, more = rows[:limit], len(rows) > limit
    return {
        "items": [group_out(g) for g in items],
        "nextCursor": reads.make_cursor("groups", me.id, start + limit) if more else None,
        "hasMore": more,
    }


@router.get("/mine", response_model=list[schemas.GroupOut])
def my_groups(user: CurrentUser):
    return [group_out(user.membership.group)] if user.membership else []


@router.get("/{group_id}", response_model=schemas.GroupOut)
def get_group(group_id: PathId, db: DB, _: CurrentUser):
    return group_out(rules.get_group(db, group_id))


@router.post("", response_model=schemas.GroupOut, status_code=201)
def create_group(payload: schemas.GroupCreateIn, db: DB, user: CurrentUser):
    write_limits.per_account(db, "group_create", user.id)
    group = rules.create_group(db, user, **payload.model_dump())
    db.commit()
    return group_out(group)


@router.patch("/{group_id}", response_model=schemas.GroupOut)
def update_group(group_id: PathId, payload: schemas.GroupUpdateIn, db: DB, user: CurrentUser):
    write_limits.per_account(db, "group_edit", user.id)
    group = rules.update_group(db, rules.get_group(db, group_id), user, payload.model_dump(exclude_unset=True))
    db.commit()
    return group_out(group)


@router.delete("/{group_id}", status_code=204)
def delete_group(group_id: PathId, db: DB, user: CurrentUser):
    rules.delete_group(db, rules.get_group(db, group_id, lock=True), user)
    db.commit()


@router.post("/{group_id}/leave", response_model=schemas.GroupOut | None)
def leave_group(group_id: PathId, db: DB, user: CurrentUser):
    group = rules.leave_group(db, rules.get_group(db, group_id, lock=True), user)
    db.commit()
    return group_out(group) if group else None


@router.delete("/{group_id}/members/{member_id}", response_model=schemas.GroupOut)
def remove_member(group_id: PathId, member_id: PathId, db: DB, user: CurrentUser):
    group = rules.remove_member(db, rules.get_group(db, group_id, lock=True), user, member_id)
    db.commit()
    return group_out(group)


@router.post("/{group_id}/join-requests", response_model=schemas.JoinRequestOut, status_code=201)
def join_request(group_id: PathId, payload: schemas.NoteIn, db: DB, user: CurrentUser):
    write_limits.per_account(db, "join_request", user.id)
    req = rules.send_join_request(db, group_id, user, payload.note)
    db.commit()
    return request_out(req)
