"""Part 5: malicious uploads and path traversal. Each sends the hostile file or path."""

import io
import zipfile

import pytest
from PIL import Image

from app.services import upload_checks

LEAD = "usr_1"


def _png(size=(8, 8), extra: bytes = b"") -> bytes:
    out = io.BytesIO()
    Image.new("RGB", size, (200, 30, 30)).save(out, format="PNG")
    return out.getvalue() + extra


def _jpg(exif: bool = False) -> bytes:
    out = io.BytesIO()
    image = Image.new("RGB", (8, 8), (10, 200, 30))
    if exif:
        data = Image.Exif()
        data[0x8825] = {2: (37.0, 25.0, 12.0)}  # GPS latitude: personal data a photo can leak
        image.save(out, format="JPEG", exif=data)
    else:
        image.save(out, format="JPEG")
    return out.getvalue()


def _zip(entries: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return out.getvalue()


def _upload(client, kind: str, filename: str, data: bytes, mime: str = "application/octet-stream"):
    if kind == "avatar":
        return client.post(f"/api/users/{LEAD}/avatar", files={"avatar": (filename, data, mime)})
    if kind == "resume":
        return client.post(f"/api/users/{LEAD}/resume", files={"resume": (filename, data, mime)})
    return client.post("/api/uploads/attachments", files={"file": (filename, data, mime)})


HOSTILE = {
    "renamed exe": ("avatar", "photo.png", b"MZ\x90\x00" + b"\x00" * 200),
    "renamed exe as pdf": ("resume", "cv.pdf", b"MZ\x90\x00" + b"\x00" * 200),
    "html with a png header": ("avatar", "x.png", b"\x89PNG\r\n\x1a\n<html><script>alert(1)</script></html>"),
    "svg with a script": ("avatar", "x.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
    "svg renamed png": ("attachment", "x.png", b'<svg onload="alert(1)"/>'),
    "html file": ("attachment", "page.html", b"<!doctype html><script>alert(1)</script>"),
    "pdf with javascript": ("resume", "cv.pdf", b"%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n%%EOF"),
    "pdf with a launch action": ("attachment", "a.pdf", b"%PDF-1.4\n1 0 obj << /S /Launch /F (cmd.exe) >>\n%%EOF"),
    "pdf with an embedded file": ("attachment", "b.pdf", b"%PDF-1.4\n<< /EmbeddedFiles 2 0 R >>\n%%EOF"),
    "pdf that is a web page": ("resume", "cv.pdf", b"%PDF-1.4\n<html><script>alert(1)</script></html>\n%%EOF"),
    "truncated pdf": ("resume", "cv.pdf", b"%PDF-1.4\n" + b"x" * 100),
    "broken png": ("avatar", "x.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100),
    "zip bomb (ratio)": ("attachment", "bomb.zip", _zip({"zeros.txt": b"\x00" * (20 * 1024 * 1024)})),
    "zip bomb (entries)": ("attachment", "many.zip", _zip({f"f{i}.txt": b"x" for i in range(1500)}, zipfile.ZIP_STORED)),
    "zip slip": ("attachment", "slip.zip", _zip({"../../etc/cron.d/evil": b"* * * * * root id"})),
    "zip absolute path": ("attachment", "abs.zip", _zip({"/etc/passwd": b"x"})),
    "zip windows drive": ("attachment", "win.zip", _zip({"C:/Windows/evil.dll": b"x"})),
    "zip backslash slip": ("attachment", "bs.zip", _zip({"..\\..\\evil.bat": b"x"})),
    "nested archive": ("attachment", "nest.zip", _zip({"inner.zip": _zip({"a": b"b"})})),
    "fake docx": ("attachment", "cv.docx", _zip({"hello.txt": b"not word"})),
    "not a zip": ("attachment", "x.zip", b"PK\x03\x04" + b"\x00" * 50),
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_files_are_refused(as_user, name):
    kind, filename, data = HOSTILE[name]
    r = _upload(as_user(LEAD), kind, filename, data)
    assert r.status_code in (413, 415, 422), (name, r.status_code, r.text[:200])


def test_image_bomb_is_refused_before_decoding(as_user):
    """A small PNG that claims 100,000 x 100,000 pixels."""
    out = io.BytesIO()
    Image.new("1", (1, 1)).save(out, format="PNG")
    data = bytearray(out.getvalue())
    data[16:24] = (100_000).to_bytes(4, "big") + (100_000).to_bytes(4, "big")  # IHDR width, height
    assert _upload(as_user(LEAD), "avatar", "bomb.png", bytes(data)).status_code == 415


def test_polyglot_png_is_reencoded_clean(as_user):
    """A real PNG with a ZIP and a script glued on the end: stored as a fresh image without them."""
    tail = _zip({"evil.js": b"alert(1)"}) + b"<script>alert(1)</script>"
    c = as_user(LEAD)
    r = _upload(c, "avatar", "me.png", _png(extra=tail), "image/png")
    assert r.status_code == 200, r.text
    stored = c.get(r.json()["avatar_url"].split("8000", 1)[-1] if "8000" in r.json()["avatar_url"] else r.json()["avatar_url"])
    assert stored.status_code == 200
    assert b"<script>" not in stored.content and b"PK\x03\x04" not in stored.content
    Image.open(io.BytesIO(stored.content)).verify()


def test_photo_metadata_is_stripped():
    clean = upload_checks.reencode_image(_jpg(exif=True), "jpg")
    assert Image.open(io.BytesIO(clean)).getexif().get(0x8825) is None


def test_good_files_still_work(as_user):
    c = as_user(LEAD)
    assert _upload(c, "avatar", "me.png", _png(), "image/png").status_code == 200
    assert _upload(c, "avatar", "me.jpg", _jpg(), "image/jpeg").status_code == 200
    assert _upload(c, "resume", "cv.pdf", b"%PDF-1.4\n1 0 obj << /Type /Catalog >>\nendobj\n%%EOF", "application/pdf").status_code == 200
    docx = _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"})
    assert _upload(c, "attachment", "cv.docx", docx).status_code == 201
    assert _upload(c, "attachment", "code.zip", _zip({"src/main.py": b"print('hi')\n" * 20})).status_code == 201


@pytest.mark.parametrize("filename,expected", [
    ("../../etc/passwd", "passwd"), ("..\\..\\boot.ini", "boot.ini"), ("C:\\Users\\me\\cv.pdf", "cv.pdf"),
    ("cv\x00.exe.pdf", "cv.exe.pdf"), ("\u202egnp.exe", "gnp.exe"), ("a\r\nSet-Cookie: x.pdf", "aSet-Cookie x.pdf"),
    ('quote".pdf', "quote.pdf"), ("   ", "file.pdf"), ("....", "file.pdf"), ("x" * 300 + ".pdf", "x" * 116 + ".pdf"),
])
def test_file_names_are_cleaned(filename, expected):
    assert upload_checks.clean_filename(filename, "file.pdf") == expected


def test_attachment_names_are_cleaned_end_to_end(as_user):
    c = as_user(LEAD)
    r = _upload(c, "attachment", "../../\u202eevil\r\n.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")
    assert r.status_code == 201
    name = r.json()["name"]  # (the client percent-encodes CR/LF in multipart names; either way they are gone)
    assert name.startswith("evil") and name.endswith(".pdf")
    assert not any(ch in name for ch in ("\r", "\n", "/", "\\", "\u202e")), name


def test_downloads_are_always_attachments_with_fixed_types(as_user):
    c = as_user(LEAD)
    avatar = _upload(c, "avatar", "me.png", _png(), "image/png").json()["avatar_url"]
    resume = _upload(c, "resume", "cv.pdf", b"%PDF-1.4\n%%EOF", "text/html").json()["resume_url"]
    for url, media in ((avatar, "image/png"), (resume, "application/pdf")):
        path = url[url.index("/uploads/"):]
        r = c.get(path)
        assert r.headers["content-type"] == media
        assert r.headers["content-disposition"].startswith("attachment;")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "sandbox" in r.headers["content-security-policy"]


@pytest.mark.parametrize("path", [
    "/uploads/avatar/../../app/config.py", "/uploads/avatar/..%2F..%2Fapp%2Fconfig.py", "/uploads/avatar/%2e%2e%2f%2e%2e%2f.env",
    "/uploads/avatar/..\\..\\.env", "/uploads/avatar/ava_0123456789abcdef.png%00.html", "/uploads/../.env", "/uploads/%2e%2e/.env",
    "/uploads/avatar/ava_0123456789abcdef.png/..", "/uploads/avatar/....//....//.env", "/uploads/resume/C:%5Cwindows%5Cwin.ini",
    "/uploads/x/ava_0123456789abcdef.png", "/uploads/avatar/AVA_0123456789ABCDEF.PNG", "/uploads/avatar/ava_0123456789abcdef.php",
])
def test_path_traversal_finds_nothing(client, path):
    r = client.get(path)
    assert r.status_code in (400, 404, 422), (path, r.status_code)
    assert b"SECRET" not in r.content and b"DATABASE_URL" not in r.content


def test_uploads_over_the_cap_are_cut_off_while_streaming(as_user):
    """A body bigger than MAX_UPLOAD_BODY_BYTES is refused without being read whole (chunked, no length)."""
    c = as_user(LEAD)

    def chunks():
        boundary = b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF"
        yield boundary
        for _ in range(8):
            yield b"0" * (1024 * 1024)

    r = c.post("/api/uploads/attachments", content=chunks(), headers={"Content-Type": "multipart/form-data; boundary=b"})
    assert r.status_code == 413
