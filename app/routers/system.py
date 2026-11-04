"""Navbar badges, presence, GitHub username checks and a health check."""

import logging
import os

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app import schemas
from app.deps import DB, CurrentUser
from app.config import get_settings
from app.errors import AppError
from app.models import utcnow
from app.services import chat, github
from app.services import groups as rules

router = APIRouter(tags=["system"])


@router.get("/counts", response_model=schemas.CountsOut)
def counts(db: DB, user: CurrentUser):
    return {
        "unreadChat": chat.unread_total(db, user),
        "pendingReceived": rules.pending_received(db, user),
        "outcomeUpdates": user.outcome_updates or 0,
    }


@router.post("/counts/outcomes", status_code=204)
def ack_outcomes(db: DB, user: CurrentUser):
    user.outcome_updates = 0
    db.commit()


@router.post("/presence", status_code=204)
def presence(db: DB, user: CurrentUser):
    user.last_seen = utcnow()
    db.commit()


@router.get("/github/verify", response_model=schemas.GitHubLookupOut)
async def verify_github(username: str = Query(min_length=1, max_length=100)):
    """Public (used during sign-up): does this GitHub user exist, and their all-time contributions."""
    name = github.username_from(username)
    if name is None:
        return {"valid": False, "username": username.strip()}
    try:
        result = await github.lookup(name)
    except github.GitHubUnavailable as exc:
        raise AppError("GitHub is not answering right now. Try again in a minute.", 502) from exc
    if result is None:
        return {"valid": False, "username": name}
    profile, total = result
    return {"valid": True, "username": profile["login"], "contribution_count": total}


@router.get("/health")
def health(db: DB):
    """For load balancers and uptime checks: 200 when the database answers, 503 when it doesn't."""
    try:
        db.execute(text("select 1"))
    except Exception:
        logging.getLogger("app.health").exception("Health check: the database is not answering")
        return JSONResponse({"status": "unavailable", "database": "down"}, status_code=503)
    if get_settings().expose_worker_pid:
        return {"status": "ok", "database": "ok", "worker": os.getpid()}
    return {"status": "ok", "database": "ok"}
