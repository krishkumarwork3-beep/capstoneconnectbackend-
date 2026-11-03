"""Conversations and messages."""

from fastapi import APIRouter, File, UploadFile

from app import schemas
from app.deps import DB, CurrentUser
from app.serializers import conversation_out, message_out
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
def get_conversation(conversation_id: str, db: DB, user: CurrentUser):
    return conversation_out(chat.get_visible(db, conversation_id, user), user.id)


@router.get("/conversations/{conversation_id}/messages", response_model=list[schemas.ChatMessageOut])
def messages(conversation_id: str, db: DB, user: CurrentUser):
    conv = chat.get_visible(db, conversation_id, user)
    return [message_out(m) for m in chat.list_messages(db, conv)]


@router.post("/conversations/{conversation_id}/messages", response_model=schemas.ChatMessageOut, status_code=201)
def send(conversation_id: str, payload: schemas.SendMessageIn, db: DB, user: CurrentUser):
    conv = chat.get_visible(db, conversation_id, user)
    attachment = payload.attachment.model_dump() if payload.attachment else None
    message = chat.send_message(db, conv, user, payload.text, attachment, payload.client_id)
    db.commit()
    return message_out(message, payload.client_id)


@router.post("/conversations/{conversation_id}/read", status_code=204)
def mark_read(conversation_id: str, db: DB, user: CurrentUser):
    chat.mark_read(db, chat.get_visible(db, conversation_id, user), user)
    db.commit()


@router.post("/uploads/attachments", response_model=schemas.AttachmentIO, status_code=201)
async def upload_attachment(_: CurrentUser, file: UploadFile = File(...)):
    """Upload first, then send the message with the returned {name, url, size}."""
    url, name, size = await uploads.save(file, "attachment")
    return {"name": name, "url": url, "size": size}
