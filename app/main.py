"""FastAPI application: CORS for the frontend, the API under /api (with the live socket at /api/ws),
uploads under /uploads."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app import realtime
from app.config import get_settings
from app.errors import install_error_handlers
from app.routers import auth, chat, groups, requests, system, users
from app.routers import realtime as realtime_router

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # The thread that LISTENs for events from every worker (see app.realtime).
    await run_in_threadpool(realtime.start)
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

for router in (auth.router, users.router, groups.router, requests.router, chat.router, system.router, realtime_router.router):
    app.include_router(router, prefix=settings.api_prefix)

settings.upload_dir.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=settings.upload_dir), name="uploads")
