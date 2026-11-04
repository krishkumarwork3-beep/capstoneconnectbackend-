"""Uploaded files: checks, storage (app.services.storage) and their links.

Types are checked by content (the file's first bytes), not only by name, and sizes are capped.
Avatars are public; résumés need a sign-in, and chat attachments are only for the conversation's
participants (and admins); app.routers.files serves them all under /uploads.

The database keeps a file's path ("/uploads/resume/res_….pdf"), not a full URL: the API adds
PUBLIC_BASE_URL when it answers (`public_url`), so moving the API to another domain keeps every
link working. Older rows with full URLs are converted by a migration, and `parse_url` still
understands them.
"""

import re

from fastapi import UploadFile

from app.config import get_settings
from app.errors import AppError
from app.security import new_id
from app.services.storage import get_storage

MB = 1024 * 1024

# (signature, extension) pairs: PNG, JPEG, PDF, ZIP (also .docx).
SIGNATURES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "pdf": b"%PDF",
    "zip": b"PK\x03\x04",
}

RULES = {
    "avatar": ({"png", "jpg"}, 2 * MB, "a PNG or JPG image", "up to 2 MB"),
    "resume": ({"pdf"}, 5 * MB, "a PDF", "up to 5 MB"),
    "attachment": ({"png", "jpg", "pdf", "zip"}, 5 * MB, "a PDF, PNG, JPG, DOCX or ZIP", "up to 5 MB"),
}

MEDIA = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

# The only names files are stored under (new_id + extension): anything else is not one of ours.
STORED_NAME = re.compile(r"^[a-z]{3}_[0-9a-f]{16}\.(png|jpg|pdf|zip|docx)$")
PURPOSES = ("avatar", "resume", "attachment")
PREFIX = "/uploads/"


def is_ours(purpose: str, name: str) -> bool:
    """A name we could have stored (which also rules out path traversal)."""
    return purpose in PURPOSES and bool(STORED_NAME.match(name))


def path_of(purpose: str, name: str) -> str:
    return f"{PREFIX}{purpose}/{name}"


def exists(purpose: str, name: str) -> bool:
    return is_ours(purpose, name) and get_storage().exists(f"{purpose}/{name}")


def read(purpose: str, name: str) -> bytes | None:
    return get_storage().get(f"{purpose}/{name}") if is_ours(purpose, name) else None


def size(purpose: str, name: str) -> int | None:
    return get_storage().size(f"{purpose}/{name}") if is_ours(purpose, name) else None


def parse_url(url: str | None) -> tuple[str, str] | None:
    """(purpose, name) of one of our files, from its path or a full link (any host: links made
    before a domain change still count), else None."""
    if not url or PREFIX not in url:
        return None
    parts = url.split(PREFIX, 1)[1].split("?", 1)[0].split("/")
    if len(parts) != 2 or not is_ours(parts[0], parts[1]):
        return None
    return parts[0], parts[1]


def public_url(stored: str | None) -> str | None:
    """The link the browser uses: PUBLIC_BASE_URL + the file's path. A full link to one of our
    files from an older row (any host) is pointed at the current one too; other values pass through."""
    parsed = parse_url(stored)
    if parsed:
        return f"{get_settings().public_base_url}{path_of(*parsed)}"
    return stored


def remove(stored: str | None) -> bool:
    """Deletes the file behind a stored path (or a link to one of ours). True if one was deleted."""
    parsed = parse_url(stored)
    return bool(parsed) and get_storage().delete(f"{parsed[0]}/{parsed[1]}")


def _kind_of(head: bytes) -> str | None:
    return next((ext for ext, sig in SIGNATURES.items() if head.startswith(sig)), None)


async def save(upload: UploadFile, purpose: str) -> tuple[str, str, int]:
    """Stores the file and returns (stored path, original name, size)."""
    allowed, limit, what, size_text = RULES[purpose]
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise AppError(f"That file is too large. Upload {what}, {size_text}.", 413)
    kind = _kind_of(data[:8])
    if kind not in allowed:
        raise AppError(f"That file type is not supported. Upload {what}.", 415)
    name = upload.filename or f"file.{kind}"
    # A .docx is a ZIP inside; keep its own extension so it opens in Word.
    ext = "docx" if kind == "zip" and name.lower().endswith(".docx") else kind
    stored = f"{new_id(purpose[:3])}.{ext}"
    get_storage().put(f"{purpose}/{stored}", data, MEDIA[ext])
    return path_of(purpose, stored), name, len(data)
