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

Close codes: 4401 not signed in (or the session ended), 4403 origin not allowed, 1003 a binary
frame, 1009 a frame over 2 KB, 1008 five frames that aren't one of the above (strict schema), too many
frames (over 30 in 10 seconds) or too many sockets (10 per account, WS_MAX_SOCKETS in all),
4408 nothing heard for 90 seconds (the client pings every 25).
"""

import asyncio
import json
import logging
import time

from typing import Literal

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocketState

from app import realtime
from app.config import get_settings
from app.db import SessionLocal
from app.errors import AppError
from app.models import Conversation, User, utcnow
from app.cookies import student_cookie
from app.guard import allowed_origins
from app.services import bans, chat, sessions

log = logging.getLogger("app.realtime")
router = APIRouter(tags=["realtime"])

MAX_CLIENT_MESSAGE = 2048
# Per connection: at most this many frames in RATE_WINDOW seconds (the app sends a few a minute).
RATE_FRAMES = 30
RATE_WINDOW = 10.0
# Frames that aren't valid JSON of the schema below are ignored; this many closes the socket.
MAX_BAD_FRAMES = 5
# Closed when nothing at all arrives for this long (a live client pings every ~25 s).
IDLE_SECONDS = 90
MAX_SOCKETS_PER_USER = 10


class Frame(BaseModel):
    """The only frames a client may send. Anything else closes the socket (1008)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["ping", "typing", "delivered", "read"]
    conversation_id: str | None = Field(default=None, min_length=1, max_length=64)
    typing: StrictBool | None = None
# How often a held connection re-checks its session and refreshes "last seen".
HEARTBEAT_SECONDS = 20
# A typing state is passed on at most this often per conversation (unless it changes).
TYPING_REPEAT_SECONDS = 2.5


def _token(ws: WebSocket) -> str | None:
    cookie = ws.cookies.get(student_cookie())
    if cookie:
        return cookie
    header = ws.headers.get("authorization", "")
    return header[7:].strip() or None if header.lower().startswith("bearer ") else None


def _session_user(token: str | None) -> tuple[str, str] | None:
    """(user id, name) while the session row is live: log-out, "sign out everywhere", a password
    change or a suspension ends it, and the next heartbeat closes the socket (4401)."""
    with SessionLocal() as db:
        found = sessions.resolve(db, token, "student")
        if not found:
            return None
        user = db.get(User, found[0])
        if not user or not sessions.check_password(found[2], user.password_hash):
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
    # Browsers always send Origin on a WebSocket; refusing others (exact match: no "null", no
    # look-alikes) stops a foreign site from opening a socket with the visitor's cookie. Clients
    # without a browser send none.
    origin = ws.headers.get("origin")
    return origin is None or origin.rstrip("/") in allowed_origins()


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
    first = realtime.hub.try_add(conn, MAX_SOCKETS_PER_USER, get_settings().ws_max_sockets)
    if first is None:
        await ws.close(code=1008, reason="Too many open connections")
        return
    conn.push({"type": "hello", "user_id": user_id})
    pump = asyncio.create_task(conn.pump())
    if first:
        await run_in_threadpool(_presence, user_id, True)

    last_heartbeat = time.monotonic()
    typing_sent: dict[str, tuple[bool, float]] = {}
    recent: list[float] = []
    bad_frames = 0
    try:
        while True:
            try:
                message = await asyncio.wait_for(ws.receive(), timeout=IDLE_SECONDS)
            except TimeoutError:
                await ws.close(code=4408, reason="Idle")
                break
            if message["type"] == "websocket.disconnect":
                break
            now = time.monotonic()
            recent = [t for t in recent if now - t < RATE_WINDOW]
            recent.append(now)
            if len(recent) > RATE_FRAMES:
                await ws.close(code=1008, reason="Too many messages")
                break
            raw = message.get("text")
            if raw is None:
                await ws.close(code=1003, reason="Text frames only")
                break
            if len(raw) > MAX_CLIENT_MESSAGE:
                await ws.close(code=1009, reason="Message too big")
                break
            try:
                frame = Frame.model_validate(json.loads(raw))
            except (ValueError, ValidationError):
                bad_frames += 1
                if bad_frames >= MAX_BAD_FRAMES:
                    await ws.close(code=1008, reason="Unknown messages")
                    break
                continue
            kind, conversation_id = frame.type, frame.conversation_id
            if kind == "ping":
                conn.push({"type": "pong"})
                if time.monotonic() - last_heartbeat >= HEARTBEAT_SECONDS:
                    last_heartbeat = time.monotonic()
                    if not await run_in_threadpool(_heartbeat, token, user_id):
                        await ws.close(code=4401, reason="Your session ended")
                        break
            elif conversation_id is None:
                bad_frames += 1
                if bad_frames >= MAX_BAD_FRAMES:
                    await ws.close(code=1008, reason="Unknown messages")
                    break
            elif kind in ("read", "delivered"):
                await run_in_threadpool(_receipt, user_id, conversation_id, kind)
            elif kind == "typing":
                typing = bool(frame.typing)
                previous = typing_sent.get(conversation_id)
                now = time.monotonic()
                if previous and previous[0] == typing and now - previous[1] < TYPING_REPEAT_SECONDS:
                    continue
                typing_sent[conversation_id] = (typing, now)
                await run_in_threadpool(_typing, user_id, name, conversation_id, typing)
    except WebSocketDisconnect:
        pass
    except RuntimeError:
        # Starlette raises this when the socket is already closing (a close we sent, such as the
        # 4401 after "session.ended", or the other side dropped mid-read): not a failure.
        if ws.client_state == WebSocketState.CONNECTED and ws.application_state == WebSocketState.CONNECTED:
            log.exception("realtime socket of %s failed", user_id)
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
