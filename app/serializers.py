"""Rows to the frontend's JSON shapes (see `schemas.py`)."""

from app import schemas
from app.models import Conversation, Group, JoinRequest, Message, Recommendation, User


def user_out(user: User) -> schemas.UserOut:
    membership = user.membership
    return schemas.UserOut(
        id=user.id,
        name=user.name,
        college=user.college,
        department=user.department,
        passing_year=user.passing_year,
        phone=user.phone,
        bio=user.bio or "",
        skills=list(user.skills or []),
        resume_url=user.resume_url,
        github_url=user.github_url,
        avatar_url=user.avatar_url,
        group_id=membership.group_id if membership else None,
        group_name=membership.group.name if membership else None,
        group_role=membership.role if membership else None,  # type: ignore[arg-type]
        github_verified=bool(user.github_verified),
        github_contribution_count=user.github_contribution_count,
        last_seen=user.last_seen,
        created_at=user.created_at,
    )


def group_out(group: Group) -> schemas.GroupOut:
    members = sorted(group.members, key=lambda m: m.joined_at)
    return schemas.GroupOut(
        id=group.id,
        name=group.name,
        description=group.description,
        max_members=group.max_members,
        requirements=list(group.requirements or []),
        domain=group.domain,
        created_by=group.created_by,
        created_at=group.created_at,
        members=[
            schemas.GroupMemberOut(
                user_id=m.user_id,
                name=m.user.name,
                college=m.user.college,
                department=m.user.department,
                passing_year=m.user.passing_year,
                role=m.role,  # type: ignore[arg-type]
                joined_at=m.joined_at,
                avatar_url=m.user.avatar_url,
                github_url=m.user.github_url,
            )
            for m in members
        ],
        is_full=len(members) >= group.max_members,
    )


def request_out(req: JoinRequest) -> schemas.JoinRequestOut:
    return schemas.JoinRequestOut(
        id=req.id,
        group_id=req.group_id or "",
        group_name=req.group_name,
        sender_id=req.sender_id,
        sender_name=req.sender.name,
        sender_college=req.sender.college,
        sender_passing_year=req.sender.passing_year,
        receiver_id=req.receiver_id,
        receiver_name=req.receiver.name,
        receiver_college=req.receiver.college,
        receiver_passing_year=req.receiver.passing_year,
        type=req.type,  # type: ignore[arg-type]
        status=req.status,  # type: ignore[arg-type]
        note=req.note or None,
        created_at=req.created_at,
        updated_at=req.updated_at,
    )


def recommendation_out(rec: Recommendation) -> schemas.RecommendationOut:
    return schemas.RecommendationOut(
        id=rec.id,
        group_id=rec.group_id or "",
        recommender_id=rec.recommender_id,
        recommender_name=rec.recommender.name,
        student_id=rec.student_id,
        student_name=rec.student.name,
        note=rec.note or None,
        status=rec.status,  # type: ignore[arg-type]
        created_at=rec.created_at,
        updated_at=rec.updated_at,
    )


def _plural_members(count: int) -> str:
    return f"{count} member{'' if count == 1 else 's'}"


def conversation_out(conv: Conversation, viewer_id: str) -> schemas.ConversationOut:
    people = [p.user for p in conv.participants]
    receipts = {p.user_id: p for p in conv.participants}
    if conv.type == "group" and conv.group is not None:
        title = conv.group.name
        subtitle = _plural_members(len(conv.group.members))
    else:
        other = next((u for u in people if u.id != viewer_id), people[0] if people else None)
        title = other.name if other else "Conversation"
        subtitle = f"{other.college}{f' · {other.department}' if other and other.department else ''}" if other else None
    last = (
        schemas.LastMessageOut(
            text=conv.last_message_text or "",
            sender_name=conv.last_message_sender or "",
            created_at=conv.last_message_at,
        )
        if conv.last_message_at
        else None
    )
    # Only the viewer's own unread count is shared.
    mine = next((p.unread for p in conv.participants if p.user_id == viewer_id), 0)
    return schemas.ConversationOut(
        id=conv.id,
        type=conv.type,  # type: ignore[arg-type]
        title=title,
        subtitle=subtitle,
        group_id=conv.group_id,
        participant_ids=[u.id for u in people],
        participants=[
            schemas.ParticipantOut(
                id=u.id,
                name=u.name,
                college=u.college,
                avatar_url=u.avatar_url,
                last_seen=u.last_seen,
                last_delivered_at=receipts[u.id].last_delivered_at,
                last_read_at=receipts[u.id].last_read_at,
            )
            for u in people
        ],
        last_message=last,
        unread={viewer_id: mine},
        updated_at=conv.updated_at,
    )


def message_out(message: Message, client_id: str | None = None) -> schemas.ChatMessageOut:
    attachment = (
        schemas.AttachmentIO(name=message.attachment_name, url=message.attachment_url or "", size=message.attachment_size or 0)
        if message.attachment_name
        else None
    )
    return schemas.ChatMessageOut(
        id=message.id,
        conversation_id=message.conversation_id,
        sender_id=message.sender_id or "",
        sender_name=message.sender_name,
        text=message.text or "",
        attachment=attachment,
        created_at=message.created_at,
        client_id=client_id,
    )
