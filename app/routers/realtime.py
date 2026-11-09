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
frames (over 30 in 10 seconds on one socket, 60 across the account's sockets) or too many sockets (10 per account, WS_MAX_SOCKETS in all),
4408 nothing heard for 90 seconds (the client pings every 25).
"""

import asyncio
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field

from typing import Annotated, Literal

from datetime import timedelta

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocketState

from app import realtime
from app.config import get_settings
from app.db import SessionLocal
from app.errors import AppError
from app.models import Conversation, User, utcnow
from app.cookies import student_cookie
from app.guard import allowed_origins
from app.deps import DB, CurrentUser
from app.services import bans, chat, limits, sessions

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
# Per account, across all its sockets in this process: at most this many frames in RATE_WINDOW
# (10 sockets x 30 would otherwise allow 300). Over it, the socket that sent the frame closes (1008).
ACCOUNT_RATE_FRAMES = 60
# The session row is re-read this often even on a silent socket (and on every acting frame), so a
# session that expired or went idle closes the socket (4401) without waiting for a push.
SESSION_RECHECK_SECONDS = 60.0
# The first frame must be {"type": "auth", "ticket": ...} within this long (see POST /realtime/ticket).
AUTH_SECONDS = 5
# How long a ticket from POST /realtime/ticket can be used (once).
TICKET_SECONDS = 30
# The server's own heartbeat: every HEARTBEAT_EVERY seconds it sends {"type": "heartbeat", "n"};
# a client that hasn't answered {"type": "heartbeat.ack", "n"} within HEARTBEAT_GRACE is closed
# (4408) even if it keeps sending other frames. Separate from the idle timeout, which only
# notices silence.
HEARTBEAT_EVERY = 30.0
HEARTBEAT_GRACE = 20.0


ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
# A frame is a flat object: anything nested deeper than this is refused before it is parsed
# (Python's parser would otherwise recurse ~1000 levels deep on a 2 KB frame).
MAX_DEPTH = 4


def _too_deep(raw: str) -> bool:
    depth, in_string, escaped = 0, False, False
    for ch in raw:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    """Same rule as HTTP bodies: a key given twice means different things to different parsers."""
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_constants(name: str) -> float:
    raise ValueError(f"{name} is not JSON")


# --- The frames a client may send: one strict schema each (unknown fields refused, exact JSON
# types, every field required, ids that can only be ids). Nothing else reaches a handler. ------

_STRICT = ConfigDict(extra="forbid", strict=True)
ConversationId = Annotated[str, Field(min_length=1, max_length=64, pattern=ID_PATTERN)]


class PingFrame(BaseModel):
    model_config = _STRICT
    type: Literal["ping"]


class TypingFrame(BaseModel):
    model_config = _STRICT
    type: Literal["typing"]
    conversation_id: ConversationId
    typing: bool


class ReadFrame(BaseModel):
    model_config = _STRICT
    type: Literal["read"]
    conversation_id: ConversationId


class DeliveredFrame(BaseModel):
    model_config = _STRICT
    type: Literal["delivered"]
    conversation_id: ConversationId


class HeartbeatAckFrame(BaseModel):
    model_config = _STRICT
    type: Literal["heartbeat.ack"]
    n: int = Field(ge=0, le=2**31)


class AuthFrame(BaseModel):
    """Only as the very first frame (the handshake); not accepted after it."""

    model_config = _STRICT
    type: Literal["auth"]
    ticket: str = Field(min_length=1, max_length=2000)


FRAME_MODELS: dict[str, type[BaseModel]] = {"ping": PingFrame, "typing": TypingFrame, "read": ReadFrame,
                                            "delivered": DeliveredFrame, "heartbeat.ack": HeartbeatAckFrame}
Frame = PingFrame | TypingFrame | ReadFrame | DeliveredFrame | HeartbeatAckFrame


def parse_frame(raw: str) -> Frame:
    """The frame, or ValueError for anything that isn't exactly one of FRAME_MODELS."""
    if _too_deep(raw):
        raise ValueError("nested too deeply")
    data = json.loads(raw, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    if not isinstance(data, dict) or not isinstance(data.get("type"), str) or data["type"] not in FRAME_MODELS:
        raise ValueError("not a known frame")
    return FRAME_MODELS[data["type"]].model_validate(data)


# Every frame type a client may send: who may send it and what it is authorized against, checked
# from the database on every frame. tests/attacks/test_ws_messages.py fails on a type missing here.
FRAME_POLICY: dict[str, dict] = {
    "ping": {"roles": {"student"}, "object": None, "writes": None},
    "typing": {"roles": {"student"}, "object": "conversation: a participant", "writes": None},
    "read": {"roles": {"student"}, "object": "conversation: a participant", "writes": "own read receipt"},
    "delivered": {"roles": {"student"}, "object": "conversation: a participant", "writes": "own delivery receipt"},
    "heartbeat.ack": {"roles": {"student"}, "object": None, "writes": None},
}


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


def _session_user(token: str | None) -> tuple[str, str, str] | None:
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
        return user.id, user.name, found[1]


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


def _counted(db, action: str, user_id: str) -> bool:
    """One more write on the account's budget (the same counter the HTTP side uses). False when
    over it."""
    try:
        limits.per_account(db, action, user_id)
    except AppError as exc:
        if exc.status == 429:
            return False
        raise
    return True


def _receipt(user_id: str, conversation_id: str, kind: str) -> str:
    """Marks the conversation read/delivered for this user: "ok", "limited" (over the account's
    receipt budget, shared with HTTP) or "forbidden" (not a participant right now, checked in the
    database on every frame)."""
    with SessionLocal() as db:
        if not _counted(db, "receipt", user_id):
            return "limited"
        user = db.get(User, user_id)
        if user is None:
            return "forbidden"
        try:
            conv = chat.get_visible(db, conversation_id, user)
        except AppError:
            return "forbidden"
        if kind == "read":
            chat.mark_read(db, conv, user)
        else:
            chat.mark_delivered(db, conv, user.id)
        db.commit()
        return "ok"


def _typing(user_id: str, conversation_id: str, typing: bool, send: bool = True) -> str:
    """Tells the other participants: "ok", "limited" (the account's typing budget, across all its
    sockets) or "forbidden" (not a participant right now). The name shown is the one in the
    database now, not one remembered from the handshake."""
    with SessionLocal() as db:
        if not _counted(db, "typing", user_id):
            return "limited"
        conv = db.get(Conversation, conversation_id)
        user = db.get(User, user_id)
        if conv is None or user is None:
            return "forbidden"
        people = [p.user_id for p in conv.participants]
        name = user.name
    if user_id not in people:
        return "forbidden"
    if not send:
        return "ok"  # allowed, but the others already know this state
    realtime.publish_now(
        (p for p in people if p != user_id),
        {"type": "typing", "conversation_id": conversation_id, "user_id": user_id, "name": name, "typing": typing},
    )
    return "ok"


_account_lock = threading.Lock()
_account_frames: dict[str, list[float]] = {}


def _account_over(user_id: str, now: float) -> bool:
    """One more frame on the account's budget across all its sockets; True when over it."""
    with _account_lock:
        recent = [t for t in _account_frames.get(user_id, ()) if now - t < RATE_WINDOW]
        recent.append(now)
        _account_frames[user_id] = recent
        return len(recent) > ACCOUNT_RATE_FRAMES


def _request_id(ws: WebSocket) -> str:
    """For the log lines about this socket: the proxy's X-Request-ID if it is sane, else a new one.
    Never the cookie, the ticket or a frame's body."""
    rid = ws.headers.get("x-request-id", "")
    return rid if rid.isalnum() and len(rid) <= 64 else secrets.token_hex(8)


def _origin_allowed(ws: WebSocket) -> bool:
    # Browsers always send Origin on a WebSocket; refusing others (exact match: no "null", no
    # look-alikes) stops a foreign site from opening a socket with the visitor's cookie. Clients
    # without a browser send none.
    origin = ws.headers.get("origin")
    return origin is None or origin.rstrip("/") in allowed_origins()


@dataclass
class _State:
    """What one connection remembers between frames (never who may see what: that is re-read
    from the database on every frame)."""

    token: str | None
    user_id: str
    name: str
    last_heartbeat: float = field(default_factory=time.monotonic)
    typing_sent: dict[str, tuple[bool, float]] = field(default_factory=dict)
    bad_frames: int = 0
    # The server's heartbeat: the number last sent and when, until it is acknowledged.
    beat: int = 0
    awaiting: int | None = None
    awaiting_since: float = 0.0


async def _bad_frame(ws: WebSocket, state: _State, conn: "realtime.Connection | None" = None) -> bool:
    """Refuses a frame that matches no schema (an error frame back, nothing else happens); True
    once there have been too many (socket closed)."""
    if conn is not None:
        conn.push({"type": "error", "for": "frame", "code": "invalid"})
    state.bad_frames += 1
    if state.bad_frames >= MAX_BAD_FRAMES:
        await ws.close(code=1008, reason="Unknown messages")
        return True
    return False


async def _handle(ws: WebSocket, conn: "realtime.Connection", frame: "Frame", state: _State) -> bool:
    """Acts on one valid frame. True when the socket was closed."""
    kind = frame.type
    conversation_id = getattr(frame, "conversation_id", None)
    if kind != "ping" and await run_in_threadpool(_session_user, state.token) is None:
        # Checked on every frame that acts, not only at the handshake and the heartbeat: a
        # session ended any way (even if its push was lost) can't act once more.
        await ws.close(code=4401, reason="Your session ended")
        return True
    if kind == "heartbeat.ack":
        if frame.n == state.awaiting:
            state.awaiting = None
            return False
        return await _bad_frame(ws, state, conn)  # not the beat we sent: still unanswered
    if kind == "ping":
        conn.push({"type": "pong"})
        if time.monotonic() - state.last_heartbeat >= HEARTBEAT_SECONDS:
            state.last_heartbeat = time.monotonic()
            if not await run_in_threadpool(_heartbeat, state.token, state.user_id):
                await ws.close(code=4401, reason="Your session ended")
                return True
        return False
    if kind in ("read", "delivered"):
        result = await run_in_threadpool(_receipt, state.user_id, conversation_id, kind)
        if result != "ok":
            _refused(conn, kind, result)
    elif kind == "typing":
        typing = bool(frame.typing)
        previous = state.typing_sent.get(conversation_id)
        now = time.monotonic()
        # The same state again within a moment isn't passed on, but it is still authorized.
        repeat = bool(previous and previous[0] == typing and now - previous[1] < TYPING_REPEAT_SECONDS)
        result = await run_in_threadpool(_typing, state.user_id, conversation_id, typing, not repeat)
        if result != "ok":
            state.typing_sent.pop(conversation_id, None)
            _refused(conn, kind, result)
            return False
        if not repeat:
            state.typing_sent[conversation_id] = (typing, now)
    return False


def _refused(conn: "realtime.Connection", kind: str, why: str) -> None:
    """"forbidden": not a participant (or no such conversation: the same answer, so ids can't be
    probed). "rate_limited": over the account's budget for that action."""
    conn.push({"type": "error", "for": kind, "code": "rate_limited" if why == "limited" else "forbidden"})


async def _heartbeat_loop(ws: WebSocket, conn: "realtime.Connection", state: _State) -> None:
    """Sends a numbered heartbeat every HEARTBEAT_EVERY seconds and closes the socket (4408) if
    one goes unanswered for HEARTBEAT_GRACE: a client that is connected but no longer working
    (frozen tab, stuck reader) is let go, even if it still sends other frames."""
    tick = max(0.05, min(HEARTBEAT_EVERY, HEARTBEAT_GRACE, SESSION_RECHECK_SECONDS) / 3)
    sent_at = checked_at = time.monotonic()
    while True:
        await asyncio.sleep(tick)
        now = time.monotonic()
        if now - checked_at >= SESSION_RECHECK_SECONDS:
            checked_at = now
            if await run_in_threadpool(_session_user, state.token) is None:
                conn.close(4401, "Your session ended")
                return
        if state.awaiting is not None:
            if now - state.awaiting_since > HEARTBEAT_GRACE:
                conn.close(4408, "No answer to the heartbeat")
                return
        elif now - sent_at >= HEARTBEAT_EVERY:
            state.beat += 1
            state.awaiting, state.awaiting_since, sent_at = state.beat, now, now
            conn.push({"type": "heartbeat", "n": state.beat})


def _ticket_ok(ticket: str, user_id: str, session_id: str) -> bool:
    with SessionLocal() as db:
        ok = sessions.spend_ticket(db, ticket, user_id, session_id)
        db.commit()
        return ok


async def _handshake(ws: WebSocket, user_id: str, session_id: str) -> bool:
    """The first frame must be {"type": "auth", "ticket": ...} with a live ticket of this student
    and this session. The cookie alone is not enough: it is the one thing a cross-site page could
    make the browser send."""
    try:
        message = await asyncio.wait_for(ws.receive(), timeout=AUTH_SECONDS)
        raw = message.get("text")
        if raw is None or len(raw) > MAX_CLIENT_MESSAGE or _too_deep(raw):
            return False
        data = json.loads(raw, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
        frame = AuthFrame.model_validate(data)
    except (TimeoutError, ValueError, ValidationError, RecursionError, KeyError):
        return False
    return await run_in_threadpool(_ticket_ok, frame.ticket, user_id, session_id)


class TicketOut(BaseModel):
    ticket: str


@router.post("/realtime/ticket", response_model=TicketOut)
def socket_ticket(request: Request, db: DB, user: CurrentUser):
    """A ticket for opening the live socket: send it as the first frame, within TICKET_SECONDS.
    Single use, only for this session. (Cross-site pages can't get one: this needs the session,
    the request guard refuses other origins, and CORS hides the answer from them.)"""
    limits.per_account(db, "ws_ticket", user.id)
    ticket = sessions.issue_ticket(db, user.id, user.password_hash, request.state.session_id, timedelta(seconds=TICKET_SECONDS))
    db.commit()
    return {"ticket": ticket}


@router.websocket("/ws")
async def socket(ws: WebSocket):
    rid = _request_id(ws)
    if not _origin_allowed(ws):
        log.warning("socket refused (4403 origin not allowed) request_id=%s", rid)
        await ws.close(code=4403)
        return
    token = _token(ws)
    who = await run_in_threadpool(_session_user, token)
    await ws.accept()
    if who is None:
        log.info("socket refused (4401 no session) request_id=%s", rid)
        await ws.close(code=4401, reason="Sign in to continue")
        return
    user_id, name, session_id = who
    if not await _handshake(ws, user_id, session_id):
        log.info("socket refused (4401 no valid ticket first) request_id=%s user=%s", rid, user_id)
        await ws.close(code=4401, reason="Sign in to continue")
        return
    await run_in_threadpool(realtime.ensure_listener)

    conn = realtime.Connection(ws, user_id, name, session_id)
    first = realtime.hub.try_add(conn, MAX_SOCKETS_PER_USER, get_settings().ws_max_sockets)
    if first is None:
        await ws.close(code=1008, reason="Too many open connections")
        return
    conn.push({"type": "hello", "user_id": user_id})
    pump = asyncio.create_task(conn.pump())
    if first:
        await run_in_threadpool(_presence, user_id, True)

    state = _State(token=token, user_id=user_id, name=name)
    beats = asyncio.create_task(_heartbeat_loop(ws, conn, state))
    recent: list[float] = []
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
            if len(recent) > RATE_FRAMES or _account_over(user_id, now):
                log.info("socket closed (1008 rate limit) request_id=%s user=%s", rid, user_id)
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
                frame = parse_frame(raw)
            except (ValueError, ValidationError, RecursionError):
                log.info("frame refused (invalid) request_id=%s user=%s", rid, user_id)
                if await _bad_frame(ws, state, conn):
                    break
                continue
            try:
                if await _handle(ws, conn, frame, state):
                    break
            except Exception:
                # One frame's failure never takes the connection down: the cause is logged here,
                # the client only learns that this frame did nothing.
                log.warning("a %s frame from %s failed", frame.type, user_id, exc_info=True)
                conn.push({"type": "error", "for": frame.type, "code": "failed"})
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
        beats.cancel()
        if realtime.hub.remove(conn):
            with _account_lock:
                _account_frames.pop(user_id, None)
            # Whoever they were typing to should not see "typing…" linger.
            for conversation_id, (typing, _) in state.typing_sent.items():
                if typing:
                    await run_in_threadpool(_typing, user_id, conversation_id, False)
            await run_in_threadpool(_presence, user_id, False)
