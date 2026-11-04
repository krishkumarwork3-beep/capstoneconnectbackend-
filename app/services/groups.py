"""Group, request and recommendation rules (the SRS rules the frontend's mock store also follows).

- A student is in at most one group. Only a Looking student can create a group or ask to join.
- Only the Group Lead invites, accepts join requests, edits, removes members or deletes the group.
- Pending invites never exceed the group's free seats.
- Accepting adds the student to the group and its chat, cancels the student's other pending items
  and closes recommendations for them. A group that fills declines its remaining pending items.
- If the Lead leaves, the earliest-joined member takes over; the last member leaving deletes the
  group (and its chat).

Seat-changing steps lock the group row (SELECT … FOR UPDATE), so two simultaneous accepts cannot
overfill a group.
"""

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.errors import AppError, not_found, rule
from app.models import Group, GroupMember, JoinRequest, Recommendation, User, utcnow
from app.security import new_id
from app.services import chat


# --------------------------------------------------------------------------------------------
# Lookups
# --------------------------------------------------------------------------------------------


def get_group(db: Session, group_id: str, *, lock: bool = False) -> Group:
    # FOR UPDATE OF the group row only (eager-loaded relations are outer-joined, which can't be locked).
    group = db.get(Group, group_id, with_for_update={"of": Group} if lock else None)
    if group is None:
        raise not_found("Group")
    return group


def is_lead(group: Group | None, user_id: str) -> bool:
    return bool(group) and any(m.user_id == user_id and m.role == "admin" for m in group.members)


def lead_group_ids(user: User) -> list[str]:
    membership = user.membership
    return [membership.group_id] if membership and membership.role == "admin" else []


def phone_visible_ids(db: Session, viewer: User, user_ids: list[str]) -> set[str]:
    """Whose full phone number the viewer may see among user_ids: their own, their group's
    members', and anyone they had a request or invitation accepted with."""
    visible = {viewer.id}
    if viewer.membership:
        visible |= set(db.scalars(select(GroupMember.user_id).where(GroupMember.group_id == viewer.membership.group_id)))
    others = [uid for uid in user_ids if uid not in visible]
    if others:
        rows = db.execute(
            select(JoinRequest.sender_id, JoinRequest.receiver_id).where(
                JoinRequest.status == "accepted",
                or_(
                    (JoinRequest.sender_id == viewer.id) & JoinRequest.receiver_id.in_(others),
                    (JoinRequest.receiver_id == viewer.id) & JoinRequest.sender_id.in_(others),
                ),
            )
        )
        for sender_id, receiver_id in rows:
            visible.add(receiver_id if sender_id == viewer.id else sender_id)
    return visible


def _seats_taken(group: Group) -> int:
    return len(group.members)


def _is_full(group: Group) -> bool:
    return _seats_taken(group) >= group.max_members


# --------------------------------------------------------------------------------------------
# Cascades
# --------------------------------------------------------------------------------------------


def _notify_outcome(db: Session, user_id: str) -> None:
    user = db.get(User, user_id)
    if user:
        user.outcome_updates = (user.outcome_updates or 0) + 1


def _close_recommendations(db: Session, *, group_id: str | None = None, student_id: str | None = None) -> None:
    stmt = select(Recommendation).where(Recommendation.status == "pending")
    if group_id:
        stmt = stmt.where(Recommendation.group_id == group_id)
    if student_id:
        stmt = stmt.where(Recommendation.student_id == student_id)
    for rec in db.scalars(stmt):
        rec.status = "closed"


def _pending_for_group(db: Session, group_id: str) -> list[JoinRequest]:
    return list(db.scalars(select(JoinRequest).where(JoinRequest.group_id == group_id, JoinRequest.status == "pending")))


def _settle_full_group(db: Session, group: Group) -> None:
    """A full group declines what is still pending for it and closes its recommendations."""
    if not _is_full(group):
        return
    for req in _pending_for_group(db, group.id):
        req.status = "declined"
        _notify_outcome(db, req.sender_id)
    _close_recommendations(db, group_id=group.id)


def cancel_group_items(db: Session, group_id: str) -> None:
    """The group is closing: its pending requests are cancelled and its recommendations closed."""
    for req in _pending_for_group(db, group_id):
        req.status = "cancelled"
    _close_recommendations(db, group_id=group_id)


def _cancel_other_pending_items(db: Session, student_id: str, except_request_id: str) -> None:
    """The student joined a group: their other pending requests and invites are cancelled."""
    stmt = select(JoinRequest).where(JoinRequest.status == "pending", JoinRequest.id != except_request_id)
    for req in db.scalars(stmt):
        subject = req.sender_id if req.type == "join_request" else req.receiver_id
        if subject == student_id:
            req.status = "cancelled"
    _close_recommendations(db, student_id=student_id)


def _add_member(db: Session, group: Group, student: User, joined_request_id: str) -> None:
    group.members.append(GroupMember(user=student, role="member", joined_at=utcnow()))
    db.flush()
    _cancel_other_pending_items(db, student.id, joined_request_id)
    chat.sync_group_chat(db, group)
    _settle_full_group(db, group)


# --------------------------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------------------------


def create_group(db: Session, creator: User, *, name: str, description: str, max_members: int,
                 requirements: list[str], domain: str) -> Group:
    if creator.membership:
        raise rule("already_in_group")
    group = Group(
        id=new_id("grp"),
        name=name.strip(),
        description=description.strip(),
        max_members=max_members,
        requirements=requirements,
        domain=domain.strip(),
        created_by=creator.id,
    )
    group.members.append(GroupMember(user=creator, role="admin", joined_at=utcnow()))
    db.add(group)
    db.flush()
    chat.create_group_chat(db, group)
    return group


def update_group(db: Session, group: Group, actor: User, changes: dict) -> Group:
    if not is_lead(group, actor.id):
        raise rule("lead_only", 403)
    if "max_members" in changes:
        raise AppError("Group size cannot be changed")
    return apply_group_changes(db, group, changes)


def apply_group_changes(db: Session, group: Group, changes: dict) -> Group:
    """Name, description, domain and requirements (the Group Lead, or an admin)."""
    if changes.get("name") is not None:
        group.name = changes["name"].strip()
        # Requests keep the group's name for their history; keep pending ones in step.
        for req in db.scalars(select(JoinRequest).where(JoinRequest.group_id == group.id)):
            req.group_name = group.name
    if changes.get("description") is not None:
        group.description = changes["description"].strip()
    if changes.get("domain") is not None:
        group.domain = changes["domain"].strip()
    if changes.get("requirements") is not None:
        group.requirements = changes["requirements"]
    return group


def transfer_lead(db: Session, group: Group, new_lead_id: str) -> GroupMember:
    """Makes another member the Group Lead; the old lead stays as a member."""
    target = next((m for m in group.members if m.user_id == new_lead_id), None)
    if target is None:
        raise AppError("That student is not in this group", 409)
    if target.role == "admin":
        raise AppError("They are already the Group Lead", 409)
    for member in group.members:
        if member.role == "admin":
            member.role = "member"
    target.role = "admin"
    group.created_by = target.user_id
    # The new lead's and old lead's apps reload their group (and the lead-only pages).
    chat.conversations_changed(db, (m.user_id for m in group.members))
    return target


def delete_group(db: Session, group: Group, actor: User) -> None:
    if not is_lead(group, actor.id):
        raise AppError("Only the Group Lead can delete the group", 403)
    cancel_group_items(db, group.id)
    chat.conversations_changed(db, (m.user_id for m in group.members))
    db.delete(group)  # members and the group chat go with it


def leave_group(db: Session, group: Group, user: User) -> Group | None:
    membership = next((m for m in group.members if m.user_id == user.id), None)
    if membership is None:
        raise AppError("You are not in this group")
    group.members.remove(membership)
    db.flush()

    if not group.members:
        cancel_group_items(db, group.id)
        chat.conversations_changed(db, [user.id])
        db.delete(group)
        return None

    if membership.role == "admin":
        successor = min(group.members, key=lambda m: m.joined_at)
        successor.role = "admin"
        group.created_by = successor.user_id
    chat.sync_group_chat(db, group)
    return group


def remove_member(db: Session, group: Group, actor: User, member_id: str) -> Group:
    if not is_lead(group, actor.id):
        raise AppError("Only the Group Lead can remove members", 403)
    membership = next((m for m in group.members if m.user_id == member_id), None)
    if membership is None:
        raise AppError("That student is not in this group")
    if membership.role == "admin":
        raise AppError("You cannot remove the Group Lead")
    group.members.remove(membership)
    db.flush()
    chat.sync_group_chat(db, group)
    return group


# --------------------------------------------------------------------------------------------
# Requests and invitations
# --------------------------------------------------------------------------------------------


def list_requests(db: Session, user: User, direction: str) -> list[JoinRequest]:
    leads = lead_group_ids(user)
    stmt = select(JoinRequest).order_by(JoinRequest.created_at.desc())
    if direction == "received":
        if leads:
            return list(db.scalars(stmt.where(JoinRequest.type == "join_request", JoinRequest.group_id.in_(leads))))
        if not user.membership:
            return list(db.scalars(stmt.where(JoinRequest.type == "invitation", JoinRequest.receiver_id == user.id)))
        return []  # a plain Member has no request lists
    if leads:
        return list(db.scalars(stmt.where(JoinRequest.type == "invitation", JoinRequest.sender_id == user.id)))
    if not user.membership:
        return list(db.scalars(stmt.where(JoinRequest.type == "join_request", JoinRequest.sender_id == user.id)))
    return []


def send_join_request(db: Session, group_id: str, sender: User, note: str) -> JoinRequest:
    group = get_group(db, group_id, lock=True)
    if sender.membership:
        raise rule("already_in_group")
    if _is_full(group):
        raise rule("group_full")
    existing = db.scalar(
        select(JoinRequest).where(JoinRequest.status == "pending", JoinRequest.group_id == group.id).where(
            ((JoinRequest.type == "join_request") & (JoinRequest.sender_id == sender.id))
            | ((JoinRequest.type == "invitation") & (JoinRequest.receiver_id == sender.id))
        )
    )
    if existing:
        raise AppError("You already have a pending request for this group", 409)
    req = JoinRequest(
        id=new_id("req"),
        group_id=group.id,
        group_name=group.name,
        sender_id=sender.id,
        receiver_id=group.created_by,
        type="join_request",
        status="pending",
        note=note.strip(),
    )
    db.add(req)
    return req


def send_invitation(db: Session, target_id: str, group_id: str, sender: User, note: str) -> JoinRequest:
    group = get_group(db, group_id, lock=True)
    target = db.get(User, target_id)
    if target is None:
        raise not_found("User")
    if not sender.membership:
        raise rule("no_group")
    if not is_lead(group, sender.id):
        raise rule("lead_only", 403)
    if target.membership:
        raise rule("in_group")
    if _is_full(group):
        raise rule("group_full")
    duplicate = db.scalar(
        select(JoinRequest).where(
            JoinRequest.status == "pending",
            JoinRequest.group_id == group.id,
            JoinRequest.type == "invitation",
            JoinRequest.receiver_id == target.id,
        )
    )
    if duplicate:
        raise AppError("You already have a pending invite for this group", 409)
    pending_invites = db.scalars(
        select(JoinRequest).where(
            JoinRequest.status == "pending", JoinRequest.group_id == group.id, JoinRequest.type == "invitation"
        )
    ).all()
    if len(pending_invites) >= group.max_members - _seats_taken(group):
        raise rule("max_invites")
    req = JoinRequest(
        id=new_id("req"),
        group_id=group.id,
        group_name=group.name,
        sender_id=sender.id,
        receiver_id=target.id,
        type="invitation",
        status="pending",
        note=note.strip(),
    )
    db.add(req)
    return req


def _get_request(db: Session, request_id: str) -> JoinRequest:
    req = db.get(JoinRequest, request_id, with_for_update={"of": JoinRequest}, populate_existing=True)
    if req is None:
        raise not_found("Request")
    return req


def respond_request(db: Session, request_id: str, status: str, actor: User) -> JoinRequest:
    """Locks in one fixed order, everywhere: the group, then the student, then the request. (Two
    accepts that each locked their request first and then the group deadlocked: found by the
    race tests.) Each row is re-read under its lock."""
    if status not in ("accepted", "declined", "withdrawn", "cancelled"):
        raise AppError("Choose accept or decline")
    peek = db.get(JoinRequest, request_id)
    if peek is None:
        raise not_found("Request")
    group = get_group(db, peek.group_id, lock=True) if peek.group_id else None
    student_id = peek.sender_id if peek.type == "join_request" else peek.receiver_id
    if student_id:
        db.get(User, student_id, with_for_update={"of": User}, populate_existing=True)
    req = _get_request(db, request_id)
    if status == "withdrawn":
        return withdraw_request(db, req, actor)
    if status == "cancelled":
        return cancel_invitation(db, req, actor)
    if req.group_id is None or group is None:
        raise not_found("Group")
    if req.status != "pending":
        raise AppError("Only pending items can be updated", 409)
    if req.type == "invitation":
        if req.receiver_id != actor.id:
            raise rule("lead_only", 403)
    elif not is_lead(group, actor.id):
        raise rule("lead_only", 403)

    student = db.get(User, req.sender_id if req.type == "join_request" else req.receiver_id)
    if student is None:
        raise not_found("User")
    db.refresh(student, ["membership"])  # another group may have taken them a moment ago

    if status == "declined":
        req.status = "declined"
        _notify_outcome(db, req.sender_id)
        return req

    if student.membership:
        raise rule("already_in_group")
    if _is_full(group):
        # The group filled while this item was waiting.
        req.status = "declined"
        _notify_outcome(db, req.sender_id)
        db.commit()
        raise rule("group_full")

    req.status = "accepted"
    _notify_outcome(db, req.sender_id)
    _add_member(db, group, student, req.id)
    return req


def withdraw_request(db: Session, req: JoinRequest, actor: User) -> JoinRequest:
    if req.type != "join_request" or req.sender_id != actor.id:
        raise AppError("Only a join request you sent can be withdrawn", 403)
    if req.status != "pending":
        raise AppError("Only pending items can be updated", 409)
    req.status = "withdrawn"
    return req


def cancel_invitation(db: Session, req: JoinRequest, actor: User) -> JoinRequest:
    group = db.get(Group, req.group_id) if req.group_id else None
    if req.type != "invitation" or req.sender_id != actor.id or not is_lead(group, actor.id):
        raise AppError("Only an invite you sent can be cancelled", 403)
    if req.status != "pending":
        raise AppError("Only pending items can be updated", 409)
    req.status = "cancelled"
    return req


# --------------------------------------------------------------------------------------------
# Recommendations (Member → Group Lead)
# --------------------------------------------------------------------------------------------


def list_recommendations(db: Session, user: User, status: str | None) -> list[Recommendation]:
    leads = lead_group_ids(user)
    if not leads:
        return []
    stmt = select(Recommendation).where(Recommendation.group_id.in_(leads)).order_by(Recommendation.created_at.desc())
    if status and status != "all":
        stmt = stmt.where(Recommendation.status == status)
    return list(db.scalars(stmt))


def create_recommendation(db: Session, recommender: User, group_id: str, student_id: str, note: str | None) -> Recommendation:
    group = get_group(db, group_id)
    student = db.get(User, student_id)
    if student is None:
        raise not_found("User")
    if not recommender.membership:
        raise rule("no_group")
    if is_lead(group, recommender.id):
        raise AppError("Group Leads invite students directly")
    if not any(m.user_id == recommender.id for m in group.members):
        raise rule("no_group", 403)
    if student.membership:
        raise rule("in_group")
    if _is_full(group):
        raise rule("group_full")
    duplicate = db.scalar(
        select(Recommendation).where(
            Recommendation.status == "pending",
            Recommendation.group_id == group.id,
            Recommendation.student_id == student.id,
            Recommendation.recommender_id == recommender.id,
        )
    )
    if duplicate:
        raise AppError("You have already recommended this student", 409)
    rec = Recommendation(
        id=new_id("rec"),
        group_id=group.id,
        recommender_id=recommender.id,
        student_id=student.id,
        note=(note or "").strip() or None,
        status="pending",
    )
    db.add(rec)  # the recommended student is intentionally not notified
    return rec


def _open_recommendation_for_lead(db: Session, recommendation_id: str, actor: User) -> Recommendation:
    rec = db.get(Recommendation, recommendation_id, with_for_update={"of": Recommendation})
    if rec is None:
        raise not_found("Recommendation")
    group = db.get(Group, rec.group_id) if rec.group_id else None
    if not is_lead(group, actor.id):
        raise rule("lead_only", 403)
    if rec.status != "pending":
        raise AppError("This recommendation is no longer open", 409)
    return rec


def dismiss_recommendation(db: Session, recommendation_id: str, actor: User) -> Recommendation:
    rec = _open_recommendation_for_lead(db, recommendation_id, actor)
    rec.status = "dismissed"
    return rec


def invite_from_recommendation(db: Session, recommendation_id: str, actor: User, note: str) -> JoinRequest:
    rec = _open_recommendation_for_lead(db, recommendation_id, actor)
    invitation = send_invitation(db, rec.student_id, rec.group_id or "", actor, note)
    rec.status = "invited"
    return invitation


# --------------------------------------------------------------------------------------------
# Badges
# --------------------------------------------------------------------------------------------


def pending_received(db: Session, user: User) -> int:
    """Join requests plus recommendations for a Lead; invitations for a Looking student."""
    leads = lead_group_ids(user)
    if leads:
        joins = db.scalars(
            select(JoinRequest.id).where(
                JoinRequest.status == "pending", JoinRequest.type == "join_request", JoinRequest.group_id.in_(leads)
            )
        ).all()
        recs = db.scalars(
            select(Recommendation.id).where(Recommendation.status == "pending", Recommendation.group_id.in_(leads))
        ).all()
        return len(joins) + len(recs)
    if not user.membership:
        return len(
            db.scalars(
                select(JoinRequest.id).where(
                    JoinRequest.status == "pending", JoinRequest.type == "invitation", JoinRequest.receiver_id == user.id
                )
            ).all()
        )
    return 0
