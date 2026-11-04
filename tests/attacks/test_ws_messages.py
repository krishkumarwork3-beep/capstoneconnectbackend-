"""WebSocket message layer, Part 1: every frame type the socket accepts, every payload family in
every field position, sent over a real socket as each kind of caller. Asserts the connection is
never killed by an unhandled error, nothing internal ever reaches a client, and no payload is
broadcast to another participant."""

import json
import typing

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import realtime as ws_routes
from tests.attacks import payloads
from tests.attacks.ws_tools import ErrorRecorder, closed_code, drain, frames_until, open_socket, receive

ATTACKER, VICTIM, CONV = "usr_1", "usr_2", "conv_2"  # conv_2: the direct chat of usr_1 and usr_2

# --- Corpus ------------------------------------------------------------------------------------

PRIVILEGED = {"role": "admin", "user_id": "usr_2", "sender_id": "usr_2", "group_id": "grp_1", "is_admin": True,
              "verified": True, "name": "Someone Else", "to": ["usr_8"], "event": {"type": "session.ended"}}
VALUES = [
    *payloads.SQL, *payloads.LDAP_XPATH, *payloads.SHELL, *payloads.TEMPLATE, *payloads.XSS, *payloads.CRLF,
    *payloads.UNICODE, *payloads.NOSQL, "A" * 1500, "", None, True, 0, -1, 2**63, 1.5, [], {}, ["conv_2"] * 50,
    {"$ne": None}, {"__proto__": {"isAdmin": True}}, "conv_2\u0000", " conv_2", "CONV_2", "conv_1", "conv_does_not_exist",
]
# Whole frames that aren't a JSON object of the schema at all.
RAW = [
    "", " ", "null", "true", "[]", "{}", '"ping"', "not json", "{'type': 'ping'}", '{"type":"ping"', "\u0000",
    '{"type":"ping","type":"typing"}', '{"type":"typing","conversation_id":"conv_2","typing":NaN}',
    '{"type":"ping","n":Infinity}', "[" * 900 + "]" * 900, '{"a":' * 300 + "1" + "}" * 300,
    json.dumps({"type": "ping", "pad": ["x"] * 300}), '{"type":"read","conversation_id":"conv_2"}\n{"type":"ping"}',
    "﻿" + '{"type":"ping"}', '{"type":"\\u0070ing"}',
]


def _base(kind: str) -> dict:
    return {"type": kind} if kind == "ping" else {"type": kind, "conversation_id": CONV, **({"typing": True} if kind == "typing" else {})}


def _fields(kind: str) -> list[str]:
    return ["type", *[f for f in _base(kind) if f != "type"]]


def _frames():
    for kind in sorted(ws_routes.FRAME_POLICY):
        for field in _fields(kind):
            for value in VALUES:
                yield json.dumps({**_base(kind), field: value})
        for extra, value in PRIVILEGED.items():
            yield json.dumps({**_base(kind), extra: value})
    yield from RAW


def _leaks(frame: dict) -> list[str]:
    text = json.dumps(frame)
    return [m for m in payloads.LEAK_MARKERS if m in text]


def _alive(ws) -> list[dict]:
    """Proves the connection still works: a ping is answered. Returns the frames on the way."""
    ws.send_text('{"type":"ping"}')
    return frames_until(ws, "pong", timeout=5)


# --- Fuzz --------------------------------------------------------------------------------------


def test_fuzz_every_frame_type_and_field_as_a_student(as_user, monkeypatch):
    # The per-connection limits would (rightly) close the socket long before the corpus is through.
    monkeypatch.setattr(ws_routes, "RATE_FRAMES", 100_000)
    monkeypatch.setattr(ws_routes, "MAX_BAD_FRAMES", 100_000)
    attacker, victim = as_user(ATTACKER), as_user(VICTIM)
    corpus = list(_frames())
    assert len(corpus) > 500
    with ErrorRecorder() as errors, open_socket(victim) as watcher, open_socket(attacker) as ws:
        for frame in corpus:
            ws.send_text(frame)
            for answer in _alive(ws):
                assert not _leaks(answer), (frame[:80], answer)
        received = drain(watcher, timeout=1.0)
    assert errors.records == [], errors.records[:3]
    for event in received:
        assert not _leaks(event), event
        text = json.dumps(event)
        for value in VALUES:
            if isinstance(value, str) and len(value) > 3 and value not in ("conv_2", "conv_1"):
                assert value not in text and json.dumps(value)[1:-1] not in text, (value, event)
        # Only what the attacker may legitimately cause in their own chat with the victim.
        assert event["type"] in ("typing", "read", "delivered", "presence"), event
        if event["type"] == "typing":
            assert event == {"type": "typing", "conversation_id": CONV, "user_id": ATTACKER, "name": event["name"],
                             "typing": event["typing"]} and isinstance(event["typing"], bool)


def test_anonymous_sockets_never_get_to_send_anything():
    with ErrorRecorder() as errors:
        for frame in [_base("typing"), _base("read"), {"type": "ping"}]:
            with TestClient(app).websocket_connect("/api/ws") as ws:
                ws.send_text(json.dumps(frame))
                assert closed_code(ws) == 4401
    assert errors.records == []


def test_an_admin_session_is_not_a_socket_session(admin_client):
    """Admins have no socket: their cookie opens nothing (and can't be used to send frames)."""
    with admin_client().websocket_connect("/api/ws") as ws:
        ws.send_text(json.dumps(_base("typing")))
        assert closed_code(ws) == 4401


# --- Inventory -----------------------------------------------------------------------------------


def test_every_frame_type_is_classified():
    accepted = set(typing.get_args(ws_routes.Frame.model_fields["type"].annotation))
    assert accepted == set(ws_routes.FRAME_POLICY), f"classify these in FRAME_POLICY: {accepted ^ set(ws_routes.FRAME_POLICY)}"
    for kind, policy in ws_routes.FRAME_POLICY.items():
        assert policy["roles"] and policy["roles"] <= {"student"}, kind
        assert policy["object"] in (None, "conversation: a participant"), kind
        assert set(policy) == {"roles", "object", "writes"}, kind


@pytest.mark.parametrize("kind", ["send", "message", "join", "subscribe", "login", "verify_otp", "admin", "delete", "accept",
                                  "session.ended", "hello", "pong", "presence", "auth.refresh", "graphql", "connection_init"])
def test_unknown_frame_types_do_nothing(as_user, kind):
    attacker, victim = as_user(ATTACKER), as_user(VICTIM)
    with open_socket(victim) as watcher, open_socket(attacker) as ws:
        ws.send_text(json.dumps({"type": kind, "conversation_id": CONV, "text": "x", "user_id": VICTIM}))
        _alive(ws)
        assert [e for e in drain(watcher) if e["type"] not in ("presence",)] == []


def test_a_single_frame_never_kills_the_connection(as_user):
    """Each raw frame on its own (normal limits): answered or ignored, the socket stays usable."""
    attacker = as_user(ATTACKER)
    with ErrorRecorder() as errors:
        for frame in RAW:
            with open_socket(attacker) as ws:
                ws.send_text(frame)
                _alive(ws)
                receive_none = drain(ws, timeout=0.2)
                assert all(not _leaks(e) for e in receive_none)
    assert errors.records == [], errors.records[:3]
