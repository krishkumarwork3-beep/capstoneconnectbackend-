"""FastAPI application: CORS for the frontend, the API under /api, uploads under /uploads."""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.errors import install_error_handlers
from app.routers import auth, chat, groups, requests, system, users

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

settings = get_settings()
app = FastAPI(title="CapstoneConnect API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    # The session is an httpOnly cookie, so the browser must send credentials.
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
install_error_handlers(app)

for router in (auth.router, users.router, groups.router, requests.router, chat.router, system.router):
    app.include_router(router, prefix=settings.api_prefix)

settings.upload_dir.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=settings.upload_dir), name="uploads")
