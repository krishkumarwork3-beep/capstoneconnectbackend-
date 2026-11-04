"""FastAPI application: CORS for the frontend, the API under /api (with the live socket at /api/ws),
uploads under /uploads (app.routers.files)."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from starlette.concurrency import run_in_threadpool

from app import realtime
from app.check_config import startup_check
from app.services.admin import ensure_first_admin
from app.config import get_settings
from app.errors import install_error_handlers
from app.observability import RequestContextMiddleware, trusted_proxies
from app.routers import admin, auth, chat, files, groups, requests, system, users
from app.routers import realtime as realtime_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

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


app = FastAPI(title="CapstoneConnect API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    # The session is an httpOnly cookie, so the browser must send credentials.
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
install_error_handlers(app)
# Outermost last: the proxy's X-Forwarded-For is applied first (only from TRUSTED_PROXY_IPS), so
# the request log and the per-IP limits see the visitor's address.
app.add_middleware(RequestContextMiddleware)
if trusted_proxies() is not None:
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=trusted_proxies())

for router in (auth.router, users.router, groups.router, requests.router, chat.router, system.router, realtime_router.router, admin.router):
    app.include_router(router, prefix=settings.api_prefix)

settings.upload_dir.mkdir(parents=True, exist_ok=True)
# Avatars are public; résumés and chat attachments are checked (app.routers.files).
app.include_router(files.router)
