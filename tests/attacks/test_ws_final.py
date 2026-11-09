"""WebSocket final round: fan-out re-checks, per-frame-type mass assignment, the silent-socket
session timer, idle/absolute session expiry, per-account frame cap, send timeout, one write path
for chat, inert payloads, and log lines that carry a request id but never a secret."""

import asyncio
import json
import logging
from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import select, update

from app import realtime
from app.db import SessionLocal
from app.models import AuthSession, Message, User, utcnow
from app.routers import realtime as ws_routes
from tests.attacks.ws_tools import closed_code, drain, frames_until, open_socket

LEAD, MEMBER, GROUP_CHAT = "usr_1", "usr_9", "conv_1"
PRIVILEGED = ["role", "sender_id", "user_id", "is_admin", "status", "read_at"]
VALID = {
    "ping": {"type": "ping"},
    "typing": {"type": "typing", "conversation_id": "conv_2", "typing": True},
    "read": {"type": "read", "conversation_id": "conv_2"},
    "delivered": {"type": "delivered", "conversation_id": "conv_2"},
    "heartbeat.ack": {"type": "heartbeat.ack", "n": 1},
}


def _ping_answers(ws) -> list[dict]:
    ws.send_text('{"type":"ping"}')
    return frames_until(ws, "pong")


# 1. Recipients are re-checked at fan-out, not only when the event was published ------------------

def test_a_removed_member_gets_nothing_even_from_an_event_that_still_names_them(as_user):
    lead = as_user(LEAD)
    with open_socket(lead) as lead_ws, open_socket(as_user(MEMBER)) as ws:
        assert lead.delete(f"/api/groups/grp_1/members/{MEMBER}").status_code in (200, 204)
        drain(ws, 0.5)
        drain(lead_ws, 0.3)
        # A stale recipient list (published before the removal committed) still names them.
        realtime.publish_now([LEAD, MEMBER], {"type": "typing", "conversation_id": GROUP_CHAT, "user_id": "usr_11",
                                              "name": "x", "typing": True})
        assert any(e["type"] == "typing" for e in drain(lead_ws, 1.0))
        assert [e for e in drain(ws, 1.0) if e.get("conversation_id") == GROUP_CHAT] == []


def test_a_suspended_user_is_dropped_at_fan_out(as_user):
    with SessionLocal() as db:
        db.execute(update(User).where(User.id == "usr_2").values(banned_at=utcnow()))
        db.commit()
    assert realtime.current_recipients(["usr_1", "usr_2"], {"type": "read", "conversation_id": "conv_2"}) == ["usr_1"]


# 2. Privileged fields are refused in every frame type -------------------------------------------

@pytest.mark.parametrize("kind", sorted(VALID))
@pytest.mark.parametrize("field", PRIVILEGED)
def test_mass_assignment_fields_are_refused_in_every_frame_type(kind, field):
    with pytest.raises((ValueError, ValidationError)):
        ws_routes.parse_frame(json.dumps({**VALID[kind], field: "admin"}))


@pytest.mark.parametrize("bad", [{"$gt": ""}, ["conv_2"], 7, None, True, "conv_2' OR '1'='1", "a" * 65])
def test_operator_objects_and_wrong_types_are_refused(bad):
    with pytest.raises((ValueError, ValidationError)):
        ws_routes.parse_frame(json.dumps({"type": "read", "conversation_id": bad}))


# 3. No first frame within the time limit -------------------------------------------------------

def test_no_first_frame_is_closed_4401(as_user, monkeypatch):
    monkeypatch.setattr(ws_routes, "AUTH_SECONDS", 0.3)
    with as_user(LEAD).websocket_connect("/api/ws") as ws:
        assert closed_code(ws, 3) == 4401


# 4. A silent socket still notices its session ending; idle and absolute expiry -----------------

def _age_session(user_id: str, **values) -> None:
    with SessionLocal() as db:
        db.execute(update(AuthSession).where(AuthSession.kind == "student", AuthSession.subject_id == user_id).values(**values))
        db.commit()


def test_a_session_that_expires_closes_a_silent_socket(as_user, monkeypatch):
    monkeypatch.setattr(ws_routes, "SESSION_RECHECK_SECONDS", 0.2)
    with open_socket(as_user(LEAD)) as ws:
        _age_session(LEAD, expires_at=utcnow() - timedelta(seconds=1))  # no push: only the timer can see it
        assert closed_code(ws, 3) == 4401


def test_an_idle_session_ends_for_http_and_the_socket(as_user, monkeypatch):
    monkeypatch.setattr(ws_routes, "SESSION_RECHECK_SECONDS", 0.2)
    c = as_user(LEAD)
    with open_socket(c) as ws:
        _age_session(LEAD, last_used_at=utcnow() - timedelta(days=8))
        assert closed_code(ws, 3) == 4401
    assert c.get("/api/auth/me").status_code == 401


def test_no_session_outlives_the_absolute_lifetime(as_user):
    c = as_user(LEAD)
    assert c.get("/api/auth/me").status_code == 200
    _age_session(LEAD, created_at=utcnow() - timedelta(days=31), last_used_at=utcnow(),
                 expires_at=utcnow() + timedelta(days=30))
    assert c.get("/api/auth/me").status_code == 401


def test_use_keeps_a_session_alive(as_user):
    c = as_user(LEAD)
    _age_session(LEAD, last_used_at=utcnow() - timedelta(days=6))
    assert c.get("/api/auth/me").status_code == 200
    with SessionLocal() as db:
        last = db.scalar(select(AuthSession.last_used_at).where(AuthSession.kind == "student", AuthSession.subject_id == LEAD))
    assert utcnow() - last < timedelta(minutes=1)


# 5. One frame budget per account across all its sockets ----------------------------------------

def test_ten_sockets_share_one_frame_budget(as_user):
    c = as_user(LEAD)
    from tests.conftest import ws_connect

    managers = [ws_connect(c) for _ in range(10)]
    sockets = [m.__enter__() for m in managers]
    try:
        for ws in sockets:
            frames_until(ws, "hello")
        # 7 frames each: under the 30-per-socket limit, over the account's 60 in all.
        for _ in range(7):
            for ws in sockets:
                try:
                    ws.send_text('{"type":"ping"}')
                except Exception:
                    pass
        codes = [closed_code(ws, 0.5) for ws in sockets]
    finally:
        for m in managers:
            try:
                m.__exit__(None, None, None)
            except Exception:
                pass
    assert 1008 in codes
    assert ws_routes.ACCOUNT_RATE_FRAMES < 10 * ws_routes.RATE_FRAMES


# 6. A client that never reads is closed --------------------------------------------------------

class _NeverReads:
    def __init__(self):
        self.closed = []

    async def send_text(self, text):
        await asyncio.Event().wait()  # the client's receive window is full: the write never finishes

    async def close(self, code=1000, reason=""):
        self.closed.append(code)


def test_a_client_that_never_reads_is_closed_by_the_send_timeout(monkeypatch):
    monkeypatch.setattr(realtime, "SEND_TIMEOUT", 0.1)

    async def run():
        sock = _NeverReads()
        conn = realtime.Connection(sock, LEAD, "x", "ses_x")
        pump = asyncio.create_task(conn.pump())
        conn.push({"type": "pong"})  # far below the queue size: only the timeout can catch it
        await asyncio.sleep(0.4)
        pump.cancel()
        return sock.closed

    assert asyncio.run(run()) == [1013]


# 8. Chat goes through one write path (HTTP, idempotent on client_id) ---------------------------

def test_the_same_client_id_over_two_sockets_writes_nothing_and_http_writes_once(as_user):
    c = as_user(LEAD)
    frame = {"type": "message.send", "conversation_id": "conv_2", "client_id": "c-dup", "text": "dup"}
    with open_socket(c) as one, open_socket(c) as two:
        for ws in (one, two):
            ws.send_text(json.dumps(frame))
            assert {"type": "error", "for": "frame", "code": "invalid"} in _ping_answers(ws)
    for _ in range(2):
        assert c.post("/api/conversations/conv_2/messages", json={"text": "dup", "client_id": "c-dup"}).status_code in (200, 201)
    with SessionLocal() as db:
        assert len(db.scalars(select(Message).where(Message.client_id == "c-dup")).all()) == 1


# 10/11. Payloads stay inert text; hostile encodings are refused without a crash ----------------

PAYLOADS = ["<script>alert(1)</script>", "{{7*7}}${7*7}", "'; DROP TABLE users; --", "$(rm -rf /)", '{"$ne": null}']


def test_hostile_text_is_broadcast_verbatim_as_json_strings(as_user):
    sender, reader = as_user("usr_2"), as_user(LEAD)
    with open_socket(reader) as ws:
        for text in PAYLOADS:
            assert sender.post("/api/conversations/conv_2/messages", json={"text": text}).status_code == 201
            got = frames_until(ws, "message.new")[-1]["message"]["text"]
            assert got == text and isinstance(got, str)


@pytest.mark.parametrize("raw", [
    '{"type":"heartbeat.ack","n":' + "9" * 400 + "}",
    '{"type":"heartbeat.ack","n":NaN}', '{"type":"heartbeat.ack","n":Infinity}',
    '{"type":"read","conversation_id":"conv_2","conversation_id":"conv_1"}',
    "[" * 50 + "]" * 50, "\x80\x04\x95cos\nsystem\n", '{"type":"typing","conversation_id":"<script>","typing":true}',
])
def test_hostile_encodings_are_refused_cleanly(as_user, raw):
    with open_socket(as_user(LEAD)) as ws:
        ws.send_text(raw)
        assert {"type": "error", "for": "frame", "code": "invalid"} in _ping_answers(ws)


# 12. Refusals are logged with a request id, never a ticket or cookie ---------------------------

class _Lines(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.INFO)
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def test_refused_handshakes_and_frames_are_logged_without_secrets(as_user):
    c = as_user(LEAD)
    cookie = next(iter(c.cookies.values()))
    handler, logger = _Lines(), logging.getLogger("app.realtime")
    old = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        with c.websocket_connect("/api/ws", headers={"x-request-id": "req42abc"}) as ws:
            ws.send_text(json.dumps({"type": "auth", "ticket": "SECRET-TICKET-VALUE"}))
            assert closed_code(ws) == 4401
        with open_socket(c, headers={"x-request-id": "req43abc"}) as ws:
            ws.send_text('{"type":"nope","body":"SECRET-BODY"}')
            _ping_answers(ws)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old)
    text = "\n".join(handler.lines)
    assert "request_id=req42abc" in text and "request_id=req43abc" in text
    for secret in ("SECRET-TICKET-VALUE", "SECRET-BODY", cookie):
        assert secret not in text
