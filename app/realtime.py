"""Real-time events over WebSockets: new messages, typing, receipts (the ticks), presence.

Every API process keeps its own sockets. Events travel between processes through PostgreSQL
LISTEN/NOTIFY: `publish` adds a NOTIFY to the caller's transaction, so an event goes out only if
the change it describes is committed, and it reaches the user's sockets whichever process
(worker) holds them. Each process listens on one background thread and hands every event to the
event loop of each socket it is for.
"""

import asyncio
import json
import logging
import threading
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime

import psycopg
from fastapi import WebSocket
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal

log = logging.getLogger("app.realtime")

CHANNEL = "capconnect_events"
# PostgreSQL caps a NOTIFY payload at 8000 bytes; a longer message goes by reference.
MAX_PAYLOAD = 7800
# A socket that falls this far behind is closed; the client reconnects and catches up.
QUEUE_SIZE = 256


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Not JSON serializable: {type(value).__name__}")


def _dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=_json_default)


def publish(db: Session, to: Iterable[str], event: dict) -> None:
    """Send `event` to every open socket of the users in `to` once `db` commits."""
    recipients = sorted(set(to))
    if not recipients:
        return
    payload = _dumps({"to": recipients, "event": event})
    if len(payload.encode()) > MAX_PAYLOAD:
        if event.get("type") != "message.new":
            log.warning("dropped an oversized %s event", event.get("type"))
            return
        message = event["message"]
        payload = _dumps({"to": recipients, "ref": message["id"], "client_id": message.get("client_id")})
    db.execute(text("SELECT pg_notify(:channel, :payload)"), {"channel": CHANNEL, "payload": payload})


def publish_now(to: Iterable[str], event: dict) -> None:
    """For events that change nothing in the database (typing)."""
    with SessionLocal() as db:
        publish(db, to, event)
        db.commit()


class Connection:
    """One open socket. Events are queued and written by one task, so writes never interleave."""

    def __init__(self, ws: WebSocket, user_id: str, name: str):
        self.ws = ws
        self.user_id = user_id
        self.name = name
        self.loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=QUEUE_SIZE)

    def push(self, event: dict) -> None:
        """Called on this socket's own loop."""
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            log.warning("closing a socket of %s that fell behind", self.user_id)
            asyncio.ensure_future(self.ws.close(code=1013))

    async def pump(self) -> None:
        while True:
            event = await self.queue.get()
            await self.ws.send_text(_dumps(event))
            if event.get("type") == "session.ended":
                # Suspended, blocked, password reset or deleted: this socket is done.
                await self.ws.close(code=4401, reason="Your session ended")
                return


class Hub:
    """The sockets open in this process, by user. Safe to use from any thread."""

    def __init__(self):
        self._lock = threading.Lock()
        self._by_user: dict[str, set[Connection]] = defaultdict(set)

    def add(self, conn: Connection) -> bool:
        """True when it is the user's first socket here (they just came online)."""
        with self._lock:
            first = not self._by_user[conn.user_id]
            self._by_user[conn.user_id].add(conn)
            return first

    def remove(self, conn: Connection) -> bool:
        """True when it was the user's last socket here."""
        with self._lock:
            sockets = self._by_user.get(conn.user_id)
            if not sockets:
                return False
            sockets.discard(conn)
            if sockets:
                return False
            del self._by_user[conn.user_id]
            return True

    def deliver(self, to: Iterable[str], event: dict) -> None:
        with self._lock:
            targets = [conn for user_id in to for conn in self._by_user.get(user_id, ())]
        for conn in targets:
            try:
                conn.loop.call_soon_threadsafe(conn.push, event)
            except RuntimeError:  # that socket's loop has shut down
                pass


hub = Hub()


def _listen_dsn() -> str:
    url = make_url(get_settings().database_url).set(drivername="postgresql")
    return url.render_as_string(hide_password=False)


class Listener(threading.Thread):
    """LISTENs on its own connection and passes each event to the hub. Reconnects on failure."""

    def __init__(self):
        super().__init__(name="realtime-listener", daemon=True)
        self.ready = threading.Event()
        self.stopping = threading.Event()

    def run(self) -> None:
        delay = 1.0
        while not self.stopping.is_set():
            try:
                with psycopg.connect(_listen_dsn(), autocommit=True) as conn:
                    conn.execute(f"LISTEN {CHANNEL}")
                    self.ready.set()
                    delay = 1.0
                    while not self.stopping.is_set():
                        for notify in conn.notifies(timeout=1.0):
                            self._handle(notify.payload)
            except Exception:
                self.ready.clear()
                if self.stopping.is_set():
                    break
                log.exception("realtime listener lost its connection; retrying in %.0fs", delay)
                self.stopping.wait(delay)
                delay = min(delay * 2, 30.0)

    def _handle(self, payload: str) -> None:
        try:
            data = json.loads(payload)
            event = data.get("event") or _load_message_event(data["ref"], data.get("client_id"))
            if event:
                hub.deliver(data["to"], event)
        except Exception:
            log.exception("could not deliver a realtime event")


def _load_message_event(message_id: str, client_id: str | None) -> dict | None:
    from app.models import Message
    from app.serializers import message_out

    with SessionLocal() as db:
        message = db.get(Message, message_id)
        if message is None:
            return None
        return {"type": "message.new", "message": message_out(message, client_id).model_dump(mode="json")}


_listener: Listener | None = None
_users = 0
_listener_lock = threading.Lock()


def ensure_listener(wait: float = 5.0) -> None:
    """Starts the listener if it is not running and waits until it is listening."""
    global _listener
    with _listener_lock:
        if _listener is None or not _listener.is_alive():
            _listener = Listener()
            _listener.start()
        listener = _listener
    if not listener.ready.wait(wait):
        log.warning("realtime listener is not connected yet; events will start once it is")


def start() -> None:
    """App startup (each app instance counts; the last one to shut down stops the thread)."""
    global _users
    with _listener_lock:
        _users += 1
    ensure_listener()


def stop() -> None:
    global _listener, _users
    with _listener_lock:
        _users = max(0, _users - 1)
        if _users or _listener is None:
            return
        listener, _listener = _listener, None
    listener.stopping.set()
    listener.join(timeout=3)
