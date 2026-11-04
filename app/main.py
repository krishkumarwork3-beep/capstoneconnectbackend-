"""FastAPI application: CORS for the frontend, the API under /api (with the live socket at /api/ws),
uploads under /uploads (app.routers.files)."""

import logging
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from starlette.concurrency import run_in_threadpool

from app import realtime
from app.check_config import startup_check
from app.services.admin import ensure_first_admin
from app.config import get_settings
from app.errors import install_error_handlers
from app import log_safety
from app.guard import RequestGuardMiddleware
from app.observability import RequestContextMiddleware, trusted_proxies
from app.routers import admin, auth, chat, community, files, groups, requests, system, users
from app.routers import realtime as realtime_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log_safety.install()  # one line per entry, no control characters, secrets masked

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Refuses to run a secure (HTTPS) deployment with development settings (app.check_config).
    startup_check(settings)
    # The thread that LISTENs for events from every worker (see app.realtime).
    await run_in_threadpool(realtime.start)
    # The first admin from ADMIN_EMAIL / ADMIN_PASSWORD, if set and not created yet.
    await run_in_threadpool(ensure_first_admin)
    yield
    await run_in_threadpool(realtime.stop)


app = FastAPI(title="CapstoneConnect API", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)

# The API docs (/docs, /redoc) run on files this API serves itself (app/static/docs, see
# VERSIONS.txt there): no script, style or font is loaded from a third-party CDN.
DOCS_ASSETS = Path(__file__).with_name("static") / "docs"
app.mount("/docs-assets", StaticFiles(directory=DOCS_ASSETS), name="docs-assets")


@app.get("/docs", include_in_schema=False)
def swagger_ui():
    return get_swagger_ui_html(openapi_url=app.openapi_url, title=f"{app.title} - Swagger UI",
                               swagger_js_url="/docs-assets/swagger-ui-bundle.js", swagger_css_url="/docs-assets/swagger-ui.css",
                               swagger_favicon_url="data:,")


@app.get("/redoc", include_in_schema=False)
def redoc():
    return get_redoc_html(openapi_url=app.openapi_url, title=f"{app.title} - ReDoc",
                          redoc_js_url="/docs-assets/redoc.standalone.js", redoc_favicon_url="data:,", with_google_fonts=False)


install_error_handlers(app)
# Middleware, innermost first (each add_middleware wraps the ones before it):
# 1. the request guard (body limits, JSON shape, content types, CSRF origin check, NUL bytes);
# 2. CORS outside it, so even a refused request carries CORS headers and the site can show why;
# 3. request ids, logs, security headers and clean 500s;
# 4. allowed Host headers;
# 5. outermost, the proxy's X-Forwarded-For (only from TRUSTED_PROXY_IPS), so the log and the
#    per-IP limits see the visitor's address.
app.add_middleware(RequestGuardMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    # The session is an httpOnly cookie, so the browser must send credentials.
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
if trusted_proxies() is not None:
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=trusted_proxies())

for router in (auth.router, users.router, groups.router, requests.router, chat.router, community.router, system.router, realtime_router.router, admin.router):
    app.include_router(router, prefix=settings.api_prefix)

settings.upload_dir.mkdir(parents=True, exist_ok=True)
# Avatars are public; résumés and chat attachments are checked (app.routers.files).
app.include_router(files.router)
