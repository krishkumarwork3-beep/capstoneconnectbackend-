"""Request logging, request IDs and security headers (plain ASGI middleware, so streaming and the
WebSocket pass through untouched).

Every HTTP request is logged as one JSON line: request id, method, path (no query string, which
could carry a username or token), status, duration and client address. Bodies are never logged,
so passwords, reset codes and tokens never reach the logs. The id is echoed in `X-Request-ID`
(an incoming one from a proxy is kept if it looks sane) and in error answers.
"""

import json
import logging
import re
import time
import uuid
from contextvars import ContextVar

from app.config import get_settings

log = logging.getLogger("app.requests")
request_id: ContextVar[str] = ContextVar("request_id", default="-")
_SANE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# API answers are JSON: nothing to load, nothing to frame.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"


def _docs_csp() -> str:
    # Swagger UI / ReDoc load their own scripts from a CDN; they may only be framed by the admin
    # portal (its API page embeds them).
    origins = " ".join(o for o in get_settings().cors_origins if o.startswith("http"))
    return f"frame-ancestors 'self' {origins}".strip()


class RequestContextMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        incoming = headers.get(b"x-request-id", b"").decode("latin-1")
        rid = incoming if _SANE_ID.match(incoming) else uuid.uuid4().hex
        token = request_id.set(rid)
        path = scope.get("path", "")
        started = time.perf_counter()
        status = 500
        secure = get_settings().cookie_secure

        async def send_with_headers(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                extra = [
                    (b"x-request-id", rid.encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                ]
                if path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
                    extra.append((b"content-security-policy", _docs_csp().encode()))
                elif path.startswith("/uploads/"):
                    extra.append((b"x-frame-options", b"DENY"))
                else:
                    extra += [(b"content-security-policy", API_CSP.encode()), (b"x-frame-options", b"DENY")]
                if secure:
                    extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                present = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [(k, v) for k, v in extra if k not in present]
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            client = scope.get("client")
            log.info(json.dumps({
                "event": "request",
                "request_id": rid,
                "method": scope.get("method"),
                "path": path,
                "status": status,
                "ms": round((time.perf_counter() - started) * 1000, 1),
                "client": client[0] if client else None,
            }))
            request_id.reset(token)


def trusted_proxies() -> list[str] | str | None:
    """TRUSTED_PROXY_IPS as uvicorn's ProxyHeadersMiddleware wants it (None: no proxy trusted)."""
    raw = get_settings().trusted_proxy_ips.strip()
    if not raw:
        return None
    return "*" if raw == "*" else [part.strip() for part in raw.split(",") if part.strip()]
