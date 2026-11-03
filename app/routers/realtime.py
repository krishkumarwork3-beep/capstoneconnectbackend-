"""The live connection: `GET /api/ws` (WebSocket).

Signed in by the same session cookie as the rest of the API (or `Authorization: Bearer`).
Messages are still sent with `POST /conversations/{id}/messages`; this socket carries what
happens next.

Server → client (JSON, each with a `type`):
  hello {user_id}                       once connected
  message.new {message}                 a message in one of your conversations (yours too)
  typing {conversation_id, user_id, name, typing}
  delivered / read {conversation_id, user_id, at}   receipts: the ticks
  presence {user_id, online, last_seen}             someone you chat with came online or left
  conversations.changed                 a group chat appeared or went; reload the list
  pong

Client → server:
  ping                                  every ~25 s; keeps the connection and "online" fresh
  typing {conversation_id, typing}
  delivered {conversation_id}           a message.new arrived here
  read {conversation_id}                you are looking at the conversation

Close codes: 4401 not signed in (or the session ended), 4403 origin not allowed.
"""

import asyncio
import json
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from app import realtime
from app.config import get_settings
from app.db import SessionLocal
from app.errors import AppError
from app.models import Conversation, User, utcnow
from app.security import read_token, token_matches_password
from app.services import bans, chat

log = logging.getLogger("app.realtime")
router = APIRouter(tags=["realtime"])

MAX_CLIENT_MESSAGE = 2048
# How often a held connection re-checks its session and refreshes "last seen".
HEARTBEAT_SECONDS = 20
# A typing state is passed on at most this often per conversation (unless it changes).
TYPING_REPEAT_SECONDS = 2.5


def _token(ws: WebSocket) -> str | None:
    cookie = ws.cookies.get(get_settings().cookie_name)
    if cookie:
        return cookie
    header = ws.headers.get("authorization", "")
    return header[7:].strip() or None if header.lower().startswith("bearer ") else None


def _session_user(token: str | None) -> tuple[str, str] | None:
    """(user id, name) while the session is valid. A password reset ends every session."""
    read = read_token(token, "session") if token else None
    if not read:
        return None
    user_id, fingerprint = read
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if not user or not token_matches_password(fingerprint, user.password_hash):
            return None
        if bans.is_blocked(db, user):  # suspended in the admin portal: the socket closes (4401)
            return None
        return user.id, user.name


def _presence(user_id: str, online: bool) -> None:
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if user is None:
            return
        user.last_seen = utcnow()
        if online:
            chat.mark_all_delivered(db, user_id)
        realtime.publish(
            db, chat.contacts(db, user_id), {"type": "presence", "user_id": user_id, "online": online, "last_seen": user.last_seen}
        )
        db.commit()


def _heartbeat(token: str | None, user_id: str) -> bool:
    if _session_user(token) is None:
        return False
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if user:
            user.last_seen = utcnow()
            db.commit()
    return True


def _receipt(user_id: str, conversation_id: str, kind: str) -> None:
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if user is None:
            return
        try:
            conv = chat.get_visible(db, conversation_id, user)
        except AppError:
            return
        if kind == "read":
            chat.mark_read(db, conv, user)
        else:
            chat.mark_delivered(db, conv, user.id)
        db.commit()


def _typing(user_id: str, name: str, conversation_id: str, typing: bool) -> None:
    with SessionLocal() as db:
        conv = db.get(Conversation, conversation_id)
        if conv is None:
            return
        people = [p.user_id for p in conv.participants]
    if user_id not in people:
        return
    realtime.publish_now(
        (p for p in people if p != user_id),
        {"type": "typing", "conversation_id": conversation_id, "user_id": user_id, "name": name, "typing": typing},
    )


def _origin_allowed(ws: WebSocket) -> bool:
    # Browsers always send Origin on a WebSocket; refusing others stops a foreign site from
    # opening a socket with the visitor's cookie. Clients without a browser send none.
    origin = ws.headers.get("origin")
    return origin is None or origin in get_settings().cors_origins


@router.websocket("/ws")
async def socket(ws: WebSocket):
    if not _origin_allowed(ws):
        await ws.close(code=4403)
        return
    token = _token(ws)
    who = await run_in_threadpool(_session_user, token)
    await ws.accept()
    if who is None:
        await ws.close(code=4401, reason="Sign in to continue")
        return
    user_id, name = who
    await run_in_threadpool(realtime.ensure_listener)

    conn = realtime.Connection(ws, user_id, name)
    first = realtime.hub.add(conn)
    conn.push({"type": "hello", "user_id": user_id})
    pump = asyncio.create_task(conn.pump())
    if first:
        await run_in_threadpool(_presence, user_id, True)

    last_heartbeat = time.monotonic()
    typing_sent: dict[str, tuple[bool, float]] = {}
    try:
        while True:
            raw = await ws.receive_text()
            if len(raw) > MAX_CLIENT_MESSAGE:
                continue
            try:
                data = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            kind = data.get("type")
            conversation_id = data.get("conversation_id")
            if kind == "ping":
                conn.push({"type": "pong"})
                if time.monotonic() - last_heartbeat >= HEARTBEAT_SECONDS:
                    last_heartbeat = time.monotonic()
                    if not await run_in_threadpool(_heartbeat, token, user_id):
                        await ws.close(code=4401, reason="Your session ended")
                        break
            elif not isinstance(conversation_id, str) or len(conversation_id) > 40:
                continue
            elif kind in ("read", "delivered"):
                await run_in_threadpool(_receipt, user_id, conversation_id, kind)
            elif kind == "typing":
                typing = bool(data.get("typing"))
                previous = typing_sent.get(conversation_id)
                now = time.monotonic()
                if previous and previous[0] == typing and now - previous[1] < TYPING_REPEAT_SECONDS:
                    continue
                typing_sent[conversation_id] = (typing, now)
                await run_in_threadpool(_typing, user_id, name, conversation_id, typing)
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("realtime socket of %s failed", user_id)
    finally:
        pump.cancel()
        if realtime.hub.remove(conn):
            # Whoever they were typing to should not see "typing…" linger.
            for conversation_id, (typing, _) in typing_sent.items():
                if typing:
                    await run_in_threadpool(_typing, user_id, name, conversation_id, False)
            await run_in_threadpool(_presence, user_id, False)
