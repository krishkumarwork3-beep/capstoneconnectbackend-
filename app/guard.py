"""Request guard: rules every HTTP request must pass before any route sees it (plain ASGI, so it
also covers routes added later).

- NUL bytes are refused anywhere in the path, query string or a JSON body (PostgreSQL text can't
  hold them, and they are a classic way to cut strings short).
- Repeated query parameters are refused (one rule for parameter pollution: no "which one wins").
- Body size is capped while it streams in (JSON 1 MB, uploads 6 MB by default), not after.
- JSON bodies: nesting depth and array length are capped, and duplicate keys are refused.
- Writes (POST/PUT/PATCH/DELETE) with a body must be JSON or multipart: HTML forms and text/plain
  posts, the two kinds a foreign page can send without asking, never reach a route.
- CSRF: a write that carries one of our session cookies must come from an allowed origin (Origin,
  or Referer when the browser sent no Origin). Requests with neither header come from non-browser
  clients, which can't be made to send a victim's cookie.
"""

import json
from urllib.parse import parse_qsl, urlsplit

from app.config import get_settings

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _reply(send, status: int, message: str):
    body = json.dumps({"message": message}).encode()

    async def respond():
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    return respond()


def json_shape_problem(raw: bytes, max_depth: int, max_items: int) -> str | None:
    """A cheap scan (no parsing) for nesting deeper than max_depth or arrays longer than max_items."""
    depth = 0
    in_string = escaped = False
    counts: list[int] = []  # items so far in each open array (-1 for objects)
    for byte in raw:
        c = chr(byte)
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            if depth > max_depth:
                return f"JSON nested deeper than {max_depth} levels"
            counts.append(0 if c == "[" else -1)
        elif c in "]}":
            depth -= 1
            if counts:
                counts.pop()
        elif c == "," and counts and counts[-1] >= 0:
            counts[-1] += 1
            if counts[-1] >= max_items:
                return f"JSON array longer than {max_items} items"
    return None


def _no_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def allowed_origins() -> set[str]:
    s = get_settings()
    origins = {o.rstrip("/") for o in s.cors_origins}
    base = urlsplit(s.public_base_url)
    if base.scheme and base.netloc:
        origins.add(f"{base.scheme}://{base.netloc}")  # the API's own docs page
    return origins


def _origin_of(value: str) -> str | None:
    parts = urlsplit(value)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None


class RequestGuardMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        s = get_settings()
        method = scope.get("method", "GET")
        raw_path = scope.get("raw_path") or scope.get("path", "").encode()
        query = scope.get("query_string", b"")
        if b"\x00" in raw_path or b"%00" in raw_path.lower() or b"%00" in query.lower() or b"\x00" in query:
            await _reply(send, 400, "The request contains a character that is not allowed")
            return
        names = [k for k, _ in parse_qsl(query.decode("latin-1"), keep_blank_values=True)]
        if len(names) != len(set(names)):
            await _reply(send, 400, "Each query parameter may appear only once")
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        ctype = headers.get("content-type", "").split(";")[0].strip().lower()

        if method not in SAFE_METHODS:
            cookie = headers.get("cookie", "")
            names_in_cookie = {part.split("=", 1)[0].strip() for part in cookie.split(";") if "=" in part}
            ours = {s.cookie_name, s.admin_cookie_name, f"__Host-{s.cookie_name}", f"__Host-{s.admin_cookie_name}"}
            if names_in_cookie & ours:
                origin = headers.get("origin") or (_origin_of(headers["referer"]) if headers.get("referer") else None)
                if origin is not None and origin.rstrip("/") not in allowed_origins():
                    await _reply(send, 403, "This request came from a page that is not allowed to make it")
                    return

        multipart = ctype == "multipart/form-data"
        limit = s.max_upload_body_bytes if multipart else s.max_json_body_bytes
        declared = headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await _reply(send, 413, f"The request is too large (at most {limit // 1_000_000 or 1} MB)")
            return
        has_body = (declared not in (None, "0")) or "transfer-encoding" in headers
        if method not in SAFE_METHODS and has_body and ctype not in ("application/json", "multipart/form-data"):
            await _reply(send, 415, "Send JSON (or a file upload)")
            return

        # Read the body (up to the limit) so JSON can be checked, then hand it on unchanged.
        body = b""
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            more = message.get("more_body", False)
            if len(body) > limit:
                await _reply(send, 413, f"The request is too large (at most {limit // 1_000_000 or 1} MB)")
                return

        if body and ctype == "application/json":
            if b"\x00" in body or b"\\u0000" in body.lower():
                await _reply(send, 400, "The request contains a character that is not allowed")
                return
            problem = json_shape_problem(body, s.max_json_depth, s.max_json_array)
            if problem is None:
                try:
                    json.loads(body, object_pairs_hook=_no_duplicate_keys)
                except ValueError as exc:
                    problem = "Each JSON key may appear only once" if "duplicate key" in str(exc) else None
            if problem:
                await _reply(send, 400, problem)
                return

        sent = False

        async def replay():
            nonlocal sent
            if sent:
                return await receive()
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)
