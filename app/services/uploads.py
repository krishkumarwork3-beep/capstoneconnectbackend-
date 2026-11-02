"""Stores uploaded files on disk (UPLOAD_DIR) and serves them under /uploads.

Types are checked by content (the file's first bytes), not only by name, and sizes are capped.
"""

from fastapi import UploadFile

from app.config import get_settings
from app.errors import AppError
from app.security import new_id

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


def _kind_of(head: bytes) -> str | None:
    return next((ext for ext, sig in SIGNATURES.items() if head.startswith(sig)), None)


async def save(upload: UploadFile, purpose: str) -> tuple[str, str, int]:
    """Saves the file and returns (public URL, original name, size)."""
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

    settings = get_settings()
    folder = settings.upload_dir / purpose
    folder.mkdir(parents=True, exist_ok=True)
    stored = f"{new_id(purpose[:3])}.{ext}"
    (folder / stored).write_bytes(data)
    return f"{settings.public_base_url}/uploads/{purpose}/{stored}", name, len(data)
