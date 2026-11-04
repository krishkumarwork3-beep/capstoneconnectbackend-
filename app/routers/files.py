"""Uploaded files, under /uploads (outside /api, so links stored before this change keep working).

- /uploads/avatar/…      public (profile photos are shown to guests too)
- /uploads/resume/…      any signed-in student, or an admin
- /uploads/attachment/…  the participants of the conversation the file was sent in, or an admin

Names are checked against the stored-name pattern before the disk is touched, so `..` and other
paths are refused (404).
"""

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.config import get_settings
from app.deps import DB, OptionalUser, current_admin
from app.errors import AppError, not_found
from app.models import ConversationParticipant, Message
from app.services import uploads

router = APIRouter(prefix="/uploads", tags=["files"])

MEDIA = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


def _is_admin(request: Request, db) -> bool:
    try:
        current_admin(request, db)
        return True
    except AppError:
        return False


@router.get("/{purpose}/{name}")
def get_file(purpose: Literal["avatar", "resume", "attachment"], name: str, request: Request, db: DB, user: OptionalUser):
    path = uploads.stored_path(purpose, name)
    if path is None:
        raise not_found("File")

    filename = name
    if purpose == "resume" and user is None and not _is_admin(request, db):
        raise AppError("Sign in to see résumés", 401)
    if purpose == "attachment":
        url = f"{get_settings().public_base_url}/uploads/attachment/{name}"
        message = db.scalar(select(Message).where(Message.attachment_url == url).limit(1))
        if not _is_admin(request, db):
            if user is None:
                raise AppError("Sign in to see this file", 401)
            participant = message and db.scalar(
                select(ConversationParticipant.user_id).where(
                    ConversationParticipant.conversation_id == message.conversation_id,
                    ConversationParticipant.user_id == user.id,
                )
            )
            if not participant:
                raise AppError("This file was sent in a conversation you are not part of", 403)
        if message and message.attachment_name:
            filename = message.attachment_name

    ext = name.rsplit(".", 1)[1]
    # Chat attachments download under their original name (the chat's link asks for a download,
    # which browsers only honour from the server for a link to another origin); photos and
    # résumés open in the browser.
    inline = purpose != "attachment" and ext in ("png", "jpg", "pdf")
    return FileResponse(
        path,
        media_type=MEDIA[ext],
        filename=filename,
        content_disposition_type="inline" if inline else "attachment",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "public, max-age=86400" if purpose == "avatar" else "private, no-store",
        },
    )
