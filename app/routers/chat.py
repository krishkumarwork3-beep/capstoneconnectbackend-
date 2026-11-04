"""Conversations and messages."""

from datetime import datetime

from fastapi import APIRouter, File, Response, UploadFile
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from app.services import limits as write_limits
from app import schemas
from app.deps import PathId, DB, CurrentUser
from app.serializers import conversation_out, message_out
from app.errors import AppError
from app.models import Message
from app.services import chat, uploads

router = APIRouter(tags=["chat"])


@router.get("/conversations", response_model=list[schemas.ConversationOut])
def list_conversations(db: DB, user: CurrentUser):
    return [conversation_out(c, user.id) for c in chat.visible_conversations(db, user)]


@router.post("/conversations/direct", response_model=schemas.ConversationOut)
def direct(payload: schemas.DirectIn, db: DB, user: CurrentUser):
    conv = chat.get_or_create_direct(db, user, payload.user_id)
    db.commit()
    return conversation_out(conv, user.id)


@router.get("/conversations/{conversation_id}", response_model=schemas.ConversationOut)
def get_conversation(conversation_id: PathId, db: DB, user: CurrentUser):
    return conversation_out(chat.get_visible(db, conversation_id, user), user.id)


@router.get("/conversations/{conversation_id}/messages", response_model=list[schemas.ChatMessageOut])
def messages(conversation_id: PathId, db: DB, user: CurrentUser, before: datetime | None = None):
    """The latest 500 messages; pass `before` (the oldest one's created_at) for older ones."""
    conv = chat.get_visible(db, conversation_id, user)
    return [message_out(m) for m in chat.list_messages(db, conv, before)]


def _already_sent(db, user, conversation_id: str, client_id: str | None) -> Message | None:
    if not client_id:
        return None
    return db.scalar(select(Message).where(Message.sender_id == user.id, Message.client_id == client_id,
                                           Message.conversation_id == conversation_id))


@router.post("/conversations/{conversation_id}/messages", response_model=schemas.ChatMessageOut, status_code=201)
def send(conversation_id: PathId, payload: schemas.SendMessageIn, response: Response, db: DB, user: CurrentUser):
    """Idempotent per `client_id`: sending the same one again (a retry) returns the first message (200)."""
    write_limits.per_account(db, "message", user.id)
    conv = chat.get_visible(db, conversation_id, user)
    earlier = _already_sent(db, user, conv.id, payload.client_id)
    if earlier is not None:
        response.status_code = 200
        return message_out(earlier, payload.client_id)
    attachment = payload.attachment.model_dump() if payload.attachment else None
    if attachment:
        # Only a file just uploaded here, and not one already shared elsewhere: attachments are
        # readable by the conversation they were sent in, so a link can't be re-shared to gain access.
        parsed = uploads.parse_url(attachment["url"])
        if parsed is None or parsed[0] != "attachment" or not uploads.exists(*parsed):
            raise AppError("Upload the file first, then send it", 422)
        path = uploads.path_of(*parsed)
        if db.scalar(select(Message.id).where(or_(Message.attachment_url == path, Message.attachment_url.endswith(path))).limit(1)):
            raise AppError("That file was already sent. Upload it again to share it here.", 409)
        attachment["url"] = path  # stored as a path (see app.services.uploads)
        attachment["size"] = uploads.size(*parsed)  # the real size, not the client's
    try:
        message = chat.send_message(db, conv, user, payload.text, attachment, payload.client_id)
        db.commit()
    except IntegrityError:
        # The same send arrived twice at the same moment (or the same file in two messages): the
        # unique indexes let exactly one through.
        db.rollback()
        earlier = _already_sent(db, user, conv.id, payload.client_id)
        if earlier is not None:
            response.status_code = 200
            return message_out(earlier, payload.client_id)
        raise AppError("That file was already sent. Upload it again to share it here.", 409) from None
    return message_out(message, payload.client_id)


@router.post("/conversations/{conversation_id}/read", status_code=204)
def mark_read(conversation_id: PathId, db: DB, user: CurrentUser):
    write_limits.per_account(db, "receipt", user.id)  # one budget with the socket's receipts
    chat.mark_read(db, chat.get_visible(db, conversation_id, user), user)
    db.commit()


@router.post("/uploads/attachments", response_model=schemas.AttachmentIO, status_code=201)
async def upload_attachment(db: DB, user: CurrentUser, file: UploadFile = File(...)):
    """Upload first, then send the message with the returned {name, url, size}."""
    write_limits.per_account(db, "upload", user.id)
    path, name, size = await uploads.save(file, "attachment")
    return {"name": name, "url": uploads.public_url(path), "size": size}
