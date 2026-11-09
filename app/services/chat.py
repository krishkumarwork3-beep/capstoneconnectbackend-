"""Conversations: one group chat per group (its members), and direct chats between two students.

Group chats are only ever shown to the group's current members. Every change here also goes out
live to the participants' open sockets (see `app.realtime`) when the transaction commits.
"""

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.errors import AppError, not_found
from app.models import Conversation, ConversationParticipant, Group, Message, User, utcnow
from app.realtime import publish
from app.security import new_id
from app.serializers import message_out


def conversations_changed(db: Session, user_ids: Iterable[str]) -> None:
    """Their conversation list changed (a group chat appeared or went): they reload it."""
    publish(db, user_ids, {"type": "conversations.changed"})


def create_group_chat(db: Session, group: Group) -> Conversation:
    conv = Conversation(id=new_id("conv"), type="group", group_id=group.id, updated_at=utcnow())
    conv.participants = [ConversationParticipant(user_id=m.user_id, unread=0) for m in group.members]
    db.add(conv)
    db.flush()
    conversations_changed(db, (m.user_id for m in group.members))
    return conv


def sync_group_chat(db: Session, group: Group) -> None:
    """Participants follow the members (unread counts of those who stay are kept)."""
    conv = db.scalar(select(Conversation).where(Conversation.group_id == group.id))
    if conv is None:
        create_group_chat(db, group)
        return
    member_ids = {m.user_id for m in group.members}
    before = {p.user_id for p in conv.participants}
    conv.participants = [p for p in conv.participants if p.user_id in member_ids]
    present = {p.user_id for p in conv.participants}
    for user_id in member_ids - present:
        # A new member gets the history as delivered and read: it was before their time.
        conv.participants.append(
            ConversationParticipant(user_id=user_id, unread=0, last_delivered_at=utcnow(), last_read_at=utcnow())
        )
    db.flush()
    if before != member_ids:
        conversations_changed(db, before | member_ids)


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
        raise not_found("Conversation")  # ids can't be probed: the same answer as a missing one
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


MESSAGE_PAGE = 50


def list_messages(db: Session, conv: Conversation, before: datetime | None = None) -> list[Message]:
    """The latest MESSAGE_PAGE messages (before `before`, for older history), oldest first."""
    stmt = select(Message).where(Message.conversation_id == conv.id)
    if before is not None:
        stmt = stmt.where(Message.created_at < before)
    latest = db.scalars(stmt.order_by(Message.created_at.desc()).limit(MESSAGE_PAGE))
    return list(reversed(list(latest)))


def send_message(
    db: Session, conv: Conversation, sender: User, text: str, attachment: dict | None, client_id: str | None = None
) -> Message:
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
        client_id=client_id or None,
        created_at=now,
    )
    db.add(message)
    conv.last_message_text = body or (attachment["name"] if attachment else "Attachment")
    conv.last_message_sender = sender.name
    conv.last_message_at = now
    conv.updated_at = now
    for participant in conv.participants:
        if participant.user_id == sender.id:
            # Sending means the sender has seen everything before it.
            participant.unread = 0
            participant.last_delivered_at = participant.last_read_at = now
        else:
            participant.unread = (participant.unread or 0) + 1
    sender.last_seen = now
    # To every participant, the sender too: their other tabs show it at once.
    publish(
        db,
        (p.user_id for p in conv.participants),
        {"type": "message.new", "message": message_out(message, client_id).model_dump(mode="json")},
    )
    return message


def _participant(conv: Conversation, user_id: str) -> ConversationParticipant:
    participant = next((p for p in conv.participants if p.user_id == user_id), None)
    if participant is None:
        raise not_found("Conversation")
    return participant


def mark_read(db: Session, conv: Conversation, user: User) -> None:
    """Blue ticks: everything in the conversation up to now has been read by `user`."""
    me = _participant(conv, user.id)
    latest = conv.last_message_at
    if not me.unread and (latest is None or (me.last_read_at and me.last_read_at >= latest)):
        return  # nothing new, so nobody needs to hear about it
    now = utcnow()
    me.unread = 0
    me.last_read_at = me.last_delivered_at = now
    # Their own other tabs clear the badge; everyone else's ticks turn blue.
    publish(db, (p.user_id for p in conv.participants), {"type": "read", "conversation_id": conv.id, "user_id": user.id, "at": now})


def mark_delivered(db: Session, conv: Conversation, user_id: str) -> None:
    """Two grey ticks: `user_id` has received everything up to now."""
    me = _participant(conv, user_id)
    latest = conv.last_message_at
    if latest is None or (me.last_delivered_at and me.last_delivered_at >= latest):
        return
    now = utcnow()
    me.last_delivered_at = now
    others = [p.user_id for p in conv.participants if p.user_id != user_id]
    publish(db, others, {"type": "delivered", "conversation_id": conv.id, "user_id": user_id, "at": now})


def mark_all_delivered(db: Session, user_id: str) -> None:
    """On connect: whatever arrived while they were away has now reached them."""
    convs = db.scalars(
        select(Conversation)
        .join(ConversationParticipant, ConversationParticipant.conversation_id == Conversation.id)
        .where(ConversationParticipant.user_id == user_id)
    ).unique()
    for conv in convs:
        mark_delivered(db, conv, user_id)


def contacts(db: Session, user_id: str) -> set[str]:
    """Everyone who shares a conversation with `user_id` (they see when they are online)."""
    mine = select(ConversationParticipant.conversation_id).where(ConversationParticipant.user_id == user_id)
    rows = db.scalars(
        select(ConversationParticipant.user_id).where(ConversationParticipant.conversation_id.in_(mine)).distinct()
    )
    return set(rows) - {user_id}


def unread_total(db: Session, user: User) -> int:
    rows = db.scalars(select(ConversationParticipant.unread).where(ConversationParticipant.user_id == user.id)).all()
    return sum(rows)
