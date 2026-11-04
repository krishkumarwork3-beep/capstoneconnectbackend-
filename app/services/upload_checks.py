"""Content checks for uploaded files, after the type is known from the first bytes.

- Images (PNG, JPEG) are decoded and re-encoded with Pillow: what is stored is a fresh image with
  no metadata, no trailing data and nothing else glued on (a PNG that is also an HTML page, a ZIP
  or a script is no longer either). Decompression bombs are refused by pixel count first.
- PDFs are never rendered here; ones carrying JavaScript, launch actions, embedded files, forms
  that run scripts, or HTML are refused.
- ZIP and DOCX files are never extracted (nothing in the app unpacks an archive). Only the central
  directory is read, to refuse zip bombs (too many entries, too much unpacked size, extreme
  compression ratios), nested archives and entries with path tricks ("../", "/etc", "C:\\").

zipfile is used in this module only, and only for `infolist()` (tests/attacks/test_injection.py
checks that nothing calls extract, extractall, open or read).
"""

import io
import zipfile

from PIL import Image, UnidentifiedImageError

from app.errors import AppError

MAX_PIXELS = 24_000_000          # about 6000 x 4000
MAX_SIDE = 10_000
ZIP_MAX_ENTRIES = 1_000
ZIP_MAX_UNPACKED = 50 * 1024 * 1024
ZIP_MAX_RATIO = 100
PDF_ACTIVE = (b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile", b"/RichMedia", b"/XFA", b"/SubmitForm", b"/ImportData")
HTML_MARKERS = (b"<html", b"<script", b"<svg", b"<iframe", b"<!doctype html", b"<body", b"javascript:")

Image.MAX_IMAGE_PIXELS = MAX_PIXELS  # Pillow's own bomb check, as a second line


def _refuse(why: str) -> AppError:
    return AppError(f"That file can't be uploaded: {why}.", 415)


def reencode_image(data: bytes, kind: str) -> bytes:
    """A clean copy of a PNG or JPEG (same format), or AppError."""
    try:
        with Image.open(io.BytesIO(data)) as probe:
            width, height = probe.size
            if width * height > MAX_PIXELS or max(width, height) > MAX_SIDE:
                raise _refuse("the image is too large")
            if (probe.format or "").upper() not in ("PNG", "JPEG"):
                raise _refuse("it is not a PNG or JPEG image")
            probe.load()
            image = probe.copy()
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError, Image.DecompressionBombError) as exc:
        raise _refuse("it is not a valid image") from exc
    out = io.BytesIO()
    if kind == "png":
        if image.mode not in ("RGB", "RGBA", "L", "LA", "P"):
            image = image.convert("RGBA")
        image.save(out, format="PNG", optimize=False)
    else:
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
        image.save(out, format="JPEG", quality=90)
    return out.getvalue()


def check_pdf(data: bytes) -> None:
    if b"%%EOF" not in data[-2048:]:
        raise _refuse("it is not a complete PDF")
    head = data[:4096].lower()
    if any(marker in head for marker in HTML_MARKERS):
        raise _refuse("it looks like a web page, not a PDF")
    for marker in PDF_ACTIVE:
        start = 0
        while (i := data.find(marker, start)) != -1:
            after = data[i + len(marker): i + len(marker) + 1]
            # "/JS" must be the whole name ("/JSON" is something else); the others are refused as
            # prefixes too ("/EmbeddedFiles", "/JavaScriptAction"...).
            if marker != b"/JS" or not after or not (after.isalnum() or after == b"_"):
                raise _refuse("PDFs with scripts, actions or embedded files are not accepted")
            start = i + 1


def _bad_name(name: str) -> bool:
    n = name.replace("\\", "/")
    return (not n or n.startswith("/") or "\x00" in n or ":" in n.split("/")[0]
            or any(part == ".." for part in n.split("/")))


def check_zip(data: bytes, docx: bool) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError) as exc:
        raise _refuse("it is not a valid ZIP file") from exc
    if len(entries) > ZIP_MAX_ENTRIES:
        raise _refuse("the archive has too many files in it")
    unpacked = 0
    for entry in entries:
        if _bad_name(entry.filename):
            raise _refuse("the archive has a file with an unsafe name")
        unpacked += entry.file_size
        if unpacked > ZIP_MAX_UNPACKED:
            raise _refuse("the archive unpacks to too much data")
        if entry.compress_size and entry.file_size / entry.compress_size > ZIP_MAX_RATIO:
            raise _refuse("the archive is compressed suspiciously well (a zip bomb?)")
        if entry.filename.lower().endswith((".zip", ".rar", ".7z", ".gz", ".tar")):
            raise _refuse("archives inside archives are not accepted")
    if docx:
        names = {e.filename for e in entries}
        if "[Content_Types].xml" not in names or "word/document.xml" not in names:
            raise _refuse("it is not a Word document")


def clean_filename(name: str | None, fallback: str) -> str:
    """The name shown and offered for download: no folders, control or direction-changing
    characters, at most 120 characters, keeping the extension."""
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    base = "".join(ch for ch in base if ch.isprintable() and ch not in '"<>|*?:' and not 0x202A <= ord(ch) <= 0x202E
                   and not 0x2066 <= ord(ch) <= 0x2069 and ord(ch) not in (0x200E, 0x200F))
    base = base.strip(" .")
    if not base:
        return fallback
    if len(base) > 120:
        stem, dot, ext = base.rpartition(".")
        base = (stem[: 120 - len(ext) - 1] + "." + ext) if dot and len(ext) <= 10 else base[:120]
    return base
