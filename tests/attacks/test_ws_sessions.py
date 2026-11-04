"""WebSocket message layer, Part 5: tokens only from the cookie/header (never the URL), open
sockets closed as soon as their session ends (however it ends), races reachable only through
frames, and the classes that don't exist on this socket (login/OTP frames, GraphQL)."""

import importlib.util
import json
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.config import get_settings
from app.db import SessionLocal
from app.main import app
from app.models import ConversationParticipant
from app.routers import realtime as ws_routes
from tests.attacks.ws_tools import ErrorRecorder, closed_code, drain, frames_until, open_socket
from tests.conftest import PASSWORD, PHONES

LEAD = "usr_1"


# --- Tokens never come from the URL --------------------------------------------------------------


@pytest.mark.parametrize("param", ["token", "access_token", "session", "cc_session", "auth", "jwt", "ticket", "sid"])
def test_a_token_in_the_query_string_is_never_read(as_user, param):
    token = as_user(LEAD).cookies.get(get_settings().cookie_name)
    with TestClient(app).websocket_connect(f"/api/ws?{param}={token}") as ws:
        assert closed_code(ws) == 4401


def test_the_socket_code_never_looks_at_the_query_string():
    source = (ws_routes.__file__ and open(ws_routes.__file__, encoding="utf-8").read())
    assert "query_params" not in source and ".url.query" not in source and "scope[\"query_string\"]" not in source


# --- Open sockets end with their session -----------------------------------------------------------


def _student(phone=PHONES[LEAD]) -> TestClient:
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"phone": phone, "password": PASSWORD}).status_code == 200
    return c


def _assert_closed_soon(ws):
    # Promptly: well inside the 20-second heartbeat that used to be the only check.
    assert closed_code(ws, timeout=4) == 4401


def test_logout_closes_that_sessions_socket_now(as_user):
    victim = _student()
    with open_socket(victim) as ws:
        assert victim.post("/api/auth/logout").status_code == 204
        _assert_closed_soon(ws)


def test_logout_closes_only_that_session(as_user):
    laptop, phone = _student(), _student()
    with open_socket(laptop) as laptop_ws, open_socket(phone) as phone_ws:
        assert laptop.post("/api/auth/logout").status_code == 204
        _assert_closed_soon(laptop_ws)
        phone_ws.send_text('{"type":"ping"}')
        assert frames_until(phone_ws, "pong")


def test_sign_out_everywhere_closes_every_socket(as_user):
    laptop, phone = _student(), _student()
    with open_socket(laptop) as laptop_ws, open_socket(phone) as phone_ws:
        assert laptop.post("/api/auth/logout-all").status_code == 204
        _assert_closed_soon(laptop_ws)
        _assert_closed_soon(phone_ws)


def test_a_password_reset_closes_open_sockets(client):
    victim = _student()
    with open_socket(victim) as ws:
        code = client.post("/api/auth/password/forgot", json={"phone": PHONES[LEAD]}).json()["dev_code"]
        grant = client.post("/api/auth/password/verify", json={"phone": PHONES[LEAD], "code": code}).json()["reset_token"]
        assert client.post("/api/auth/password/reset", json={"reset_token": grant, "password": "fresh-pass-for-ws-1"}).status_code == 200
        _assert_closed_soon(ws)


@pytest.mark.parametrize("action", ["password", "ban", "block", "delete"])
def test_admin_actions_close_open_sockets(admin_client, action):
    victim, admin = _student(), admin_client()
    with open_socket(victim) as ws:
        if action == "password":
            admin.post(f"/api/admin/users/{LEAD}/password", json={"password": "an-admin-set-pass-1"})
        elif action == "ban":
            admin.post(f"/api/admin/users/{LEAD}/ban", json={"reason": "x"})
        elif action == "block":
            admin.post("/api/admin/banned-phones", json={"phones": [PHONES[LEAD]], "reason": "x"})
        else:
            admin.delete(f"/api/admin/users/{LEAD}")
        _assert_closed_soon(ws)


def test_a_revoked_session_is_refused_on_the_next_frame_even_without_the_push(as_user, monkeypatch):
    """If the push is lost (the listener reconnecting), the next frame still checks the session."""
    from app import realtime

    victim = _student()
    with open_socket(victim) as ws:
        monkeypatch.setattr(realtime.hub, "deliver", lambda *a, **k: None)  # no push reaches anyone
        assert victim.post("/api/auth/logout").status_code == 204
        ws.send_text(json.dumps({"type": "read", "conversation_id": "conv_2"}))
        _assert_closed_soon(ws)


# --- Races reachable only through frames --------------------------------------------------------


def test_receipts_racing_from_many_sockets_settle_once(as_user):
    other = as_user("usr_2")
    assert other.post("/api/conversations/conv_2/messages", json={"text": "race me"}).status_code == 201
    lead = as_user(LEAD)
    with ErrorRecorder() as errors:
        sockets = [lead.websocket_connect("/api/ws").__enter__() for _ in range(6)]
        try:
            for ws in sockets:
                frames_until(ws, "hello")
            barrier = threading.Barrier(len(sockets))

            def fire(ws):
                barrier.wait()
                for kind in ("read", "delivered", "read"):
                    ws.send_text(json.dumps({"type": kind, "conversation_id": "conv_2"}))

            threads = [threading.Thread(target=fire, args=(ws,)) for ws in sockets]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            for ws in sockets:
                ws.send_text('{"type":"ping"}')
                seen = frames_until(ws, "pong", timeout=10)
                assert not [e for e in seen if e["type"] == "error"], seen
        finally:
            for ws in sockets:
                ws.__exit__(None, None, None)
    assert errors.records == []
    with SessionLocal() as db:
        row = db.scalar(select(ConversationParticipant).where(ConversationParticipant.conversation_id == "conv_2",
                                                              ConversationParticipant.user_id == LEAD))
        assert row.unread == 0 and row.last_read_at is not None


def test_no_seat_join_or_request_action_exists_on_the_socket():
    """Accepts, joins, invitations and messages are HTTP only (with their own row locks and unique
    indexes, tests/attacks/test_races.py); the socket can only touch its own receipts."""
    assert set(ws_routes.FRAME_MODELS) == {"ping", "typing", "read", "delivered"}


# --- Not on this socket: sign-in, OTP, GraphQL ---------------------------------------------------


@pytest.mark.parametrize("frame", [
    {"type": "login", "phone": PHONES[LEAD], "password": "wrong-pass-1"},
    {"type": "verify", "phone": PHONES[LEAD], "code": "000000"},
    {"type": "password.forgot", "phone": PHONES[LEAD]},
    {"type": "auth", "token": "x"},
])
def test_sign_in_and_otp_can_not_be_driven_over_the_socket(as_user, frame):
    with open_socket(as_user(LEAD)) as ws:
        ws.send_text(json.dumps(frame))
        ws.send_text('{"type":"ping"}')
        seen = frames_until(ws, "pong")
    assert {"type": "error", "for": "frame", "code": "invalid"} in seen


@pytest.mark.parametrize("path", ["/graphql", "/api/graphql", "/subscriptions", "/api/graphql/ws", "/api/subscriptions", "/ws"])
def test_no_graphql_subscription_endpoint_exists(as_user, path):
    with pytest.raises(WebSocketDisconnect):
        with as_user(LEAD).websocket_connect(path, subprotocols=["graphql-transport-ws", "graphql-ws"]) as ws:
            ws.receive_text()


def test_no_graphql_server_exists():
    """No GraphQL server library, nothing in app/ imports graphql, none among the runtime
    dependencies (graphql-core is only a dev dependency of the Schemathesis test tool)."""
    import ast
    import tomllib
    from pathlib import Path

    for name in ("strawberry", "ariadne", "graphene", "tartiflette"):
        assert importlib.util.find_spec(name) is None, name
    root = Path(__file__).resolve().parents[2]
    for path in (root / "app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        modules = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        modules |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert not any("graphql" in m for m in modules), path.name
    runtime = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    assert not [d for d in runtime if "graph" in d.lower()]
