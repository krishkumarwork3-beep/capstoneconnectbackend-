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
log_errors = logging.getLogger("app.errors")
request_id: ContextVar[str] = ContextVar("request_id", default="-")
_SANE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# API answers are JSON: nothing to load, nothing to frame.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"


def _docs_csp() -> str:
    # Swagger UI and ReDoc run on files this API serves (/docs-assets), plus FastAPI's short inline
    # start-up script; nothing from another site. Only the admin portal may frame them (its API
    # page embeds them).
    origins = " ".join(o for o in get_settings().cors_origins if o.startswith("http"))
    return ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self' data:; worker-src 'self' blob:; connect-src 'self'; "
            f"object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self' {origins}").strip()


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
                    # Nothing the API serves belongs in a search engine.
                    (b"x-robots-tag", b"noindex, nofollow, noarchive"),
                ]
                if path in ("/docs", "/redoc", "/openapi.json") or path.startswith("/docs-assets/"):
                    extra.append((b"content-security-policy", _docs_csp().encode()))
                elif path.startswith("/uploads/"):
                    extra.append((b"x-frame-options", b"DENY"))
                else:
                    extra += [(b"content-security-policy", API_CSP.encode()), (b"x-frame-options", b"DENY")]
                if path.startswith("/api/"):
                    # Answers carry personal data: never kept by a browser or a shared cache.
                    extra.append((b"cache-control", b"no-store"))
                if secure:
                    extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                present = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [(k, v) for k, v in extra if k not in present]
            await send(message)

        started_response = False

        async def tracking_send(message):
            nonlocal started_response
            if message["type"] == "http.response.start":
                started_response = True
            await send_with_headers(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            # Anything a route didn't handle: logged in full here, a plain answer for the visitor
            # (with the request id to quote, and the usual security headers).
            log_errors.exception("Unhandled error (request %s)", rid)
            if not started_response:
                body = json.dumps({"message": "Something went wrong on our side. Try again in a moment.", "request_id": rid}).encode()
                await tracking_send({"type": "http.response.start", "status": 500,
                                     "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
                await tracking_send({"type": "http.response.body", "body": body})
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
