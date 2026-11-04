"""Uploaded files, under /uploads (outside /api, so links stored before the API kept paths still work).

- /uploads/avatar/…      public (profile photos are shown to guests too)
- /uploads/resume/…      any signed-in student, or an admin
- /uploads/attachment/…  the participants of the conversation the file was sent in, or an admin

The bytes come from the configured storage (local disk or S3-compatible). Names are checked
against the stored-name pattern before storage is touched, so `..` and other paths are refused.
"""

from typing import Annotated, Literal
from urllib.parse import quote

from fastapi import APIRouter, Request, Response
from fastapi import Path as PathParam
from sqlalchemy import or_, select

from app.deps import DB, OptionalUser, current_admin
from app.errors import AppError, not_found
from app.models import ConversationParticipant, Message
from app.services import uploads

router = APIRouter(prefix="/uploads", tags=["files"])


def _is_admin(request: Request, db) -> bool:
    try:
        current_admin(request, db)
        return True
    except AppError:
        return False


def _disposition(inline: bool, filename: str, fallback: str) -> str:
    safe = "".join(c for c in filename if c not in '"\\\r\n')
    ascii_name = safe.encode("ascii", "ignore").decode().strip() or fallback
    value = f'{"inline" if inline else "attachment"}; filename="{ascii_name}"'
    if ascii_name != safe:
        value += f"; filename*=UTF-8''{quote(safe)}"
    return value


@router.get("/{purpose}/{name}")
def get_file(purpose: Literal["avatar", "resume", "attachment"], name: Annotated[str, PathParam(max_length=64)], request: Request,
             db: DB, user: OptionalUser):
    if not uploads.is_ours(purpose, name):
        raise not_found("File")

    filename = name
    if purpose == "resume" and user is None and not _is_admin(request, db):
        raise AppError("Sign in to see résumés", 401)
    if purpose == "attachment":
        path = uploads.path_of(purpose, name)
        # Stored as a path; a full link from before the migration also matches.
        message = db.scalar(
            select(Message).where(or_(Message.attachment_url == path, Message.attachment_url.endswith(path))).limit(1)
        )
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

    data = uploads.read(purpose, name)
    if data is None:
        raise not_found("File")
    ext = name.rsplit(".", 1)[1]
    # Always a download (never rendered as a page of this origin), with a fixed type from the
    # stored extension, nosniff, and a sandbox that would neuter any script even if a browser did
    # render it. <img> tags still show avatars: Content-Disposition does not affect embedding.
    return Response(
        content=data,
        media_type=uploads.MEDIA[ext],
        headers={
            "Content-Disposition": _disposition(False, filename, name),
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "public, max-age=86400" if purpose == "avatar" else "private, no-store",
        },
    )
