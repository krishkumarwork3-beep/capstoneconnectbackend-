"""WebSocket message layer, Part 5b: a handshake that needs more than a cookie, an app-level
heartbeat, bounded outbound queues, and per-account limits shared with the HTTP side."""

import asyncio
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import realtime
from app.config import get_settings
from app.main import app
from app.routers import realtime as ws_routes
from app.services import limits
from tests.attacks.ws_tools import closed_code, frames_until, open_socket, receive
from tests.conftest import PASSWORD, PHONES

LEAD = "usr_1"


def _login(phone=PHONES[LEAD]) -> TestClient:
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"phone": phone, "password": PASSWORD}).status_code == 200
    return c


def _ticket(client) -> str:
    r = client.post("/api/realtime/ticket")
    assert r.status_code == 200, r.text
    return r.json()["ticket"]


# --- The handshake: a valid cookie alone is not enough -------------------------------------------


def test_a_valid_cookie_without_a_ticket_is_refused():
    """What a cross-site page could do: open the socket with the visitor's cookie. It has no ticket."""
    with _login().websocket_connect("/api/ws") as ws:
        assert closed_code(ws, timeout=ws_routes.AUTH_SECONDS + 3) == 4401


@pytest.mark.parametrize("frame", [
    {"type": "ping"}, {"type": "read", "conversation_id": "conv_2"}, {"type": "auth"}, {"type": "auth", "ticket": ""},
    {"type": "auth", "ticket": "x" * 300}, {"type": "auth", "ticket": None}, {"type": "auth", "ticket": {"$ne": None}},
])
def test_anything_but_a_valid_ticket_first_is_refused(frame):
    with _login().websocket_connect("/api/ws") as ws:
        ws.send_text(json.dumps(frame))
        assert closed_code(ws) == 4401


def test_a_ticket_works_once():
    client = _login()
    ticket = _ticket(client)
    with client.websocket_connect("/api/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
        assert receive(ws)["type"] == "hello"
    with client.websocket_connect("/api/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
        assert closed_code(ws) == 4401


def test_a_ticket_is_bound_to_its_session():
    """A ticket obtained on one session can't open a socket with another session's cookie."""
    one, other = _login(), _login()
    ticket = _ticket(one)
    with other.websocket_connect("/api/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
        assert closed_code(ws) == 4401


def test_a_ticket_is_bound_to_its_student():
    ticket = _ticket(_login())
    with _login(PHONES["usr_8"]).websocket_connect("/api/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
        assert closed_code(ws) == 4401


def test_a_ticket_dies_with_its_session():
    client = _login()
    ticket = _ticket(client)
    cookie = client.cookies.get(get_settings().cookie_name)
    client.post("/api/auth/logout")
    thief = TestClient(app)
    thief.cookies.set(get_settings().cookie_name, cookie)
    with thief.websocket_connect("/api/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
        assert closed_code(ws) == 4401


def test_an_expired_ticket_is_refused(monkeypatch):
    client = _login()
    monkeypatch.setattr(ws_routes, "TICKET_SECONDS", -5)
    ticket = _ticket(client)
    with client.websocket_connect("/api/ws") as ws:
        ws.send_text(json.dumps({"type": "auth", "ticket": ticket}))
        assert closed_code(ws) == 4401


def test_a_ticket_in_the_url_is_not_read():
    client = _login()
    with client.websocket_connect(f"/api/ws?ticket={_ticket(client)}") as ws:
        assert closed_code(ws, timeout=ws_routes.AUTH_SECONDS + 3) == 4401


def test_tickets_can_not_be_had_cross_site_or_signed_out():
    assert TestClient(app).post("/api/realtime/ticket").status_code == 401
    r = _login().post("/api/realtime/ticket", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert "ticket" not in r.text


def test_a_ticket_is_not_a_session_token():
    ticket = _ticket(_login())
    assert TestClient(app).get("/api/auth/me", headers={"Authorization": f"Bearer {ticket}"}).status_code == 401


# --- Heartbeat: an app that stops answering is closed, even if it keeps sending ------------------


def test_a_client_that_never_answers_the_heartbeat_is_closed(as_user, monkeypatch):
    monkeypatch.setattr(ws_routes, "HEARTBEAT_EVERY", 0.3)
    monkeypatch.setattr(ws_routes, "HEARTBEAT_GRACE", 0.6)
    with open_socket(as_user(LEAD)) as ws:
        started = time.monotonic()
        code = None
        # Keeps the connection busy (so the idle timeout never fires) but never acknowledges.
        while time.monotonic() - started < 5:
            ws.send_text('{"type":"ping"}')
            code = closed_code(ws, timeout=0.2)
            if code is not None:
                break
        assert code == 4408


def test_a_client_that_answers_stays(as_user, monkeypatch):
    monkeypatch.setattr(ws_routes, "HEARTBEAT_EVERY", 0.3)
    monkeypatch.setattr(ws_routes, "HEARTBEAT_GRACE", 0.6)
    with open_socket(as_user(LEAD)) as ws:
        answered = 0
        started = time.monotonic()
        while time.monotonic() - started < 2.5:
            try:
                event = receive(ws, timeout=0.5)
            except TimeoutError:
                continue
            if event["type"] == "heartbeat":
                ws.send_text(json.dumps({"type": "heartbeat.ack", "n": event["n"]}))
                answered += 1
        assert answered >= 3
        ws.send_text('{"type":"ping"}')
        assert frames_until(ws, "pong")


def test_a_wrong_acknowledgement_does_not_count(as_user, monkeypatch):
    monkeypatch.setattr(ws_routes, "HEARTBEAT_EVERY", 0.3)
    monkeypatch.setattr(ws_routes, "HEARTBEAT_GRACE", 0.6)
    with open_socket(as_user(LEAD)) as ws:
        event = frames_until(ws, "heartbeat")[-1]
        ws.send_text(json.dumps({"type": "heartbeat.ack", "n": event["n"] + 1000}))
        assert closed_code(ws, timeout=4) in (4408, 1008)


# --- Backpressure: a client that doesn't read can't make the server hold more and more ---------


class _StuckSocket:
    """A peer that never drains: every send waits forever."""

    def __init__(self):
        self.closed: list[int] = []

    async def send_text(self, _text):
        await asyncio.Event().wait()

    async def close(self, code=1000, reason=""):
        self.closed.append(code)


def test_a_slow_consumer_has_a_bounded_queue_and_is_cut_off():
    async def run():
        stuck = _StuckSocket()
        conn = realtime.Connection(stuck, "usr_1", "x", "ses_x")
        pump = asyncio.create_task(conn.pump())
        for i in range(realtime.QUEUE_SIZE * 20):
            conn.push({"type": "typing", "conversation_id": "conv_2", "user_id": "usr_2", "name": "n", "typing": i % 2 == 0})
            assert conn.queue.qsize() <= realtime.QUEUE_SIZE
        await asyncio.sleep(0.05)
        pump.cancel()
        return stuck.closed, conn.queue.qsize()

    closed, size = asyncio.run(run())
    assert closed == [1013]  # closed once, as "try again later"
    assert size <= realtime.QUEUE_SIZE


def test_a_slow_consumer_does_not_slow_the_others():
    async def run():
        stuck, fine = _StuckSocket(), []

        class Fine:
            async def send_text(self, text):
                fine.append(text)

            async def close(self, code=1000, reason=""):
                pass

        slow, fast = realtime.Connection(stuck, "usr_1", "x"), realtime.Connection(Fine(), "usr_2", "y")
        tasks = [asyncio.create_task(slow.pump()), asyncio.create_task(fast.pump())]
        for _ in range(realtime.QUEUE_SIZE * 2):
            slow.push({"type": "pong"})
            fast.push({"type": "pong"})
            await asyncio.sleep(0)  # the healthy client reads as events come
        await asyncio.sleep(0.1)
        for t in tasks:
            t.cancel()
        return len(fine)

    assert asyncio.run(run()) == realtime.QUEUE_SIZE * 2


# --- Per-action limits, shared with the HTTP side ---------------------------------------------


def _limit(monkeypatch, action, count):
    monkeypatch.setitem(limits.WRITE_LIMITS, action, (count, limits.WRITE_LIMITS[action][1]))


def test_receipts_share_one_limit_between_http_and_the_socket(as_user, monkeypatch):
    _limit(monkeypatch, "receipt", 3)
    c = as_user(LEAD)
    for _ in range(3):
        assert c.post("/api/conversations/conv_2/read").status_code == 204
    with open_socket(c) as ws:
        ws.send_text(json.dumps({"type": "read", "conversation_id": "conv_2"}))
        ws.send_text('{"type":"ping"}')
        assert {"type": "error", "for": "read", "code": "rate_limited"} in frames_until(ws, "pong")
    assert c.post("/api/conversations/conv_2/read").status_code == 429


def test_socket_receipts_count_against_the_http_limit(as_user, monkeypatch):
    _limit(monkeypatch, "receipt", 2)
    c = as_user(LEAD)
    with open_socket(c) as ws:
        for _ in range(2):
            ws.send_text(json.dumps({"type": "delivered", "conversation_id": "conv_2"}))
        ws.send_text('{"type":"ping"}')
        frames_until(ws, "pong")
    assert c.post("/api/conversations/conv_2/read").status_code == 429


def test_typing_is_limited_per_account_across_all_its_sockets(as_user, monkeypatch):
    _limit(monkeypatch, "typing", 4)
    monkeypatch.setattr(ws_routes, "TYPING_REPEAT_SECONDS", 0)
    c = as_user(LEAD)
    with open_socket(c) as one, open_socket(c) as two:
        answers = []
        for i in range(4):
            for ws in (one, two):
                ws.send_text(json.dumps({"type": "typing", "conversation_id": "conv_2", "typing": i % 2 == 0}))
                ws.send_text('{"type":"ping"}')
                answers += frames_until(ws, "pong")
    assert sum(1 for a in answers if a == {"type": "error", "for": "typing", "code": "rate_limited"}) >= 4
