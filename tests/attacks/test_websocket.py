"""Part 4: the live socket under abuse: oversized, binary, malformed and flooding frames, foreign
origins, too many sockets, idle connections."""

from contextlib import ExitStack

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app
from app.routers import realtime as ws_routes
from tests.conftest import ws_connect


def _closed_with(ws) -> int:
    with pytest.raises(WebSocketDisconnect) as closed:
        for _ in range(100):
            ws.receive_json()
    return closed.value.code


def _hello(ws):
    assert ws.receive_json()["type"] == "hello"


def test_oversized_frame_closes_the_socket(as_user):
    with ws_connect(as_user("usr_8")) as ws:
        _hello(ws)
        ws.send_text('{"type":"ping","pad":"' + "x" * 5000 + '"}')
        assert _closed_with(ws) == 1009


def test_binary_frame_closes_the_socket(as_user):
    with ws_connect(as_user("usr_8")) as ws:
        _hello(ws)
        ws.send_bytes(b"\x00\x01\x02 binary")
        assert _closed_with(ws) == 1003


@pytest.mark.parametrize("frame", ["not json", "[]", "null", '"ping"', '{"type":"ping","extra":1}', '{"type":"admin"}',
                                   '{"type":"typing","conversation_id":{"$ne":null}}', '{"type":"typing","conversation_id":"conv_1","typing":"yes"}',
                                   '{"type":"read"}', '{"type":"read","conversation_id":"' + "c" * 100 + '"}', '{"__proto__":{"x":1},"type":"ping"}'])
def test_malformed_frames_are_ignored_then_close_the_socket(as_user, frame):
    with ws_connect(as_user("usr_8")) as ws:
        _hello(ws)
        ws.send_text(frame)
        ws.send_json({"type": "ping"})
        # One bad frame: refused with an error frame, and the socket keeps working.
        assert ws.receive_json() == {"type": "error", "for": "frame", "code": "invalid"}
        assert ws.receive_json()["type"] == "pong"
        for _ in range(ws_routes.MAX_BAD_FRAMES):
            ws.send_text(frame)
        assert _closed_with(ws) == 1008


def test_flooding_closes_the_socket(as_user):
    with ws_connect(as_user("usr_8")) as ws:
        _hello(ws)
        for _ in range(ws_routes.RATE_FRAMES + 5):
            ws.send_json({"type": "ping"})
        assert _closed_with(ws) == 1008


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://localhost:3000.evil.example", "http://localhost:3001",
                                    "https://localhost:3000", "http://evil.localhost:3000"])
def test_cross_origin_sockets_are_refused(as_user, origin):
    # Refused before the handshake completes: the connection itself fails with 4403.
    with pytest.raises(WebSocketDisconnect) as closed:
        with as_user("usr_8").websocket_connect("/api/ws", headers={"Origin": origin}) as ws:
            ws.receive_json()
    assert closed.value.code == 4403


def test_the_site_origin_is_accepted(as_user):
    with ws_connect(as_user("usr_8"), headers={"Origin": "http://localhost:3000"}) as ws:
        _hello(ws)


def test_too_many_sockets_for_one_account(as_user, monkeypatch):
    monkeypatch.setattr(ws_routes, "MAX_SOCKETS_PER_USER", 3)
    c = as_user("usr_8")
    with ExitStack() as stack:
        for _ in range(3):
            _hello(stack.enter_context(ws_connect(c)))
        with ws_connect(c) as extra:
            assert _closed_with(extra) == 1008
    # Once they close, a new one is fine again.
    with ws_connect(c) as ws:
        _hello(ws)


def test_total_socket_cap(as_user, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "ws_max_sockets", 1)
    with ws_connect(as_user("usr_8")) as first:
        _hello(first)
        with ws_connect(as_user("usr_1")) as second:
            assert _closed_with(second) == 1008


def test_idle_sockets_are_closed(as_user, monkeypatch):
    monkeypatch.setattr(ws_routes, "IDLE_SECONDS", 0.3)
    with ws_connect(as_user("usr_8")) as ws:
        _hello(ws)
        assert _closed_with(ws) == 4408


def test_no_cookie_no_socket():
    with ws_connect(TestClient(app)) as ws:
        assert _closed_with(ws) == 4401
