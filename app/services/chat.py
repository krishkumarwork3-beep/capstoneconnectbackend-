"""Conversations: one group chat per group (its members), and direct chats between two students.

Group chats are only ever shown to the group's current members.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.errors import AppError, not_found
from app.models import Conversation, ConversationParticipant, Group, Message, User, utcnow
from app.security import new_id


def create_group_chat(db: Session, group: Group) -> Conversation:
    conv = Conversation(id=new_id("conv"), type="group", group_id=group.id, updated_at=utcnow())
    conv.participants = [ConversationParticipant(user_id=m.user_id, unread=0) for m in group.members]
    db.add(conv)
    db.flush()
    return conv


def sync_group_chat(db: Session, group: Group) -> None:
    """Participants follow the members (unread counts of those who stay are kept)."""
    conv = db.scalar(select(Conversation).where(Conversation.group_id == group.id))
    if conv is None:
        create_group_chat(db, group)
        return
    member_ids = {m.user_id for m in group.members}
    conv.participants = [p for p in conv.participants if p.user_id in member_ids]
    present = {p.user_id for p in conv.participants}
    for user_id in member_ids - present:
        conv.participants.append(ConversationParticipant(user_id=user_id, unread=0))
    db.flush()


def visible_conversations(db: Session, user: User) -> list[Conversation]:
    stmt = (
        select(Conversation)
        .join(ConversationParticipant, ConversationParticipant.conversation_id == Conversation.id)
        .where(ConversationParticipant.user_id == user.id)
        .order_by(Conversation.updated_at.desc())
    )
    return list(db.scalars(stmt).unique())


def get_visible(db: Session, conversation_id: str, user: User) -> Conversation:
    conv = db.get(Conversation, conversation_id)
    if conv is None:
        raise not_found("Conversation")
    if not any(p.user_id == user.id for p in conv.participants):
        raise AppError("You do not have access to this conversation", 403)
    return conv


def get_or_create_direct(db: Session, me: User, other_id: str) -> Conversation:
    if other_id == me.id:
        raise AppError("You cannot message yourself")
    other = db.get(User, other_id)
    if other is None:
        raise not_found("User")
    mine = select(ConversationParticipant.conversation_id).where(ConversationParticipant.user_id == me.id)
    theirs = select(ConversationParticipant.conversation_id).where(ConversationParticipant.user_id == other.id)
    existing = db.scalar(
        select(Conversation).where(Conversation.type == "direct", Conversation.id.in_(mine), Conversation.id.in_(theirs))
    )
    if existing:
        return existing
    conv = Conversation(id=new_id("conv"), type="direct", updated_at=utcnow())
    conv.participants = [ConversationParticipant(user_id=me.id), ConversationParticipant(user_id=other.id)]
    db.add(conv)
    db.flush()
    return conv


def list_messages(db: Session, conv: Conversation) -> list[Message]:
    return list(db.scalars(select(Message).where(Message.conversation_id == conv.id).order_by(Message.created_at)))


def send_message(db: Session, conv: Conversation, sender: User, text: str, attachment: dict | None) -> Message:
    body = (text or "").strip()
    if not body and not attachment:
        raise AppError("Message cannot be empty")
    now = utcnow()
    message = Message(
        id=new_id("msg"),
        conversation_id=conv.id,
        sender_id=sender.id,
        sender_name=sender.name,
        text=body,
        attachment_name=attachment["name"] if attachment else None,
        attachment_url=attachment["url"] if attachment else None,
        attachment_size=attachment["size"] if attachment else None,
        created_at=now,
    )
    db.add(message)
    conv.last_message_text = body or (attachment["name"] if attachment else "Attachment")
    conv.last_message_sender = sender.name
    conv.last_message_at = now
    conv.updated_at = now
    for participant in conv.participants:
        if participant.user_id != sender.id:
            participant.unread = (participant.unread or 0) + 1
    sender.last_seen = now
    return message


def mark_read(db: Session, conv: Conversation, user: User) -> None:
    for participant in conv.participants:
        if participant.user_id == user.id:
            participant.unread = 0


def unread_total(db: Session, user: User) -> int:
    rows = db.scalars(select(ConversationParticipant.unread).where(ConversationParticipant.user_id == user.id)).all()
    return sum(rows)
