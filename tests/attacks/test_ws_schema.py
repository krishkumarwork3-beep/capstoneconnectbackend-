"""WebSocket message layer, Part 2: every frame is validated against a strict schema for its type
before anything reaches a query or a broadcast; privileged fields are refused, never applied;
JSON is parsed one strict way only."""

import ast
import json
from pathlib import Path

import pytest

from app.routers import realtime as ws_routes
from tests.attacks.ws_tools import drain, frames_until, open_socket

ATTACKER, VICTIM, CONV = "usr_1", "usr_2", "conv_2"
APP = Path(__file__).resolve().parents[2] / "app"


def _answer(ws, frame) -> dict:
    """The server's answer to one frame: an error frame, or (if it was accepted) the pong after it."""
    ws.send_text(frame if isinstance(frame, str) else json.dumps(frame))
    ws.send_text('{"type":"ping"}')
    seen = frames_until(ws, "pong")
    errors = [e for e in seen if e["type"] == "error"]
    return errors[0] if errors else seen[-1]


INVALID = {
    # missing what the type needs
    "typing without conversation": {"type": "typing", "typing": True},
    "typing without state": {"type": "typing", "conversation_id": CONV},
    "read without conversation": {"type": "read"},
    # fields another type has
    "read with typing": {"type": "read", "conversation_id": CONV, "typing": True},
    "ping with conversation": {"type": "ping", "conversation_id": CONV},
    # wrong JSON types (never coerced)
    "typing as a string": {"type": "typing", "conversation_id": CONV, "typing": "true"},
    "typing as a number": {"type": "typing", "conversation_id": CONV, "typing": 1},
    "conversation as a number": {"type": "read", "conversation_id": 2},
    "conversation as a list": {"type": "read", "conversation_id": [CONV]},
    "conversation as an operator": {"type": "read", "conversation_id": {"$ne": None}},
    "type as a list": {"type": ["read"], "conversation_id": CONV},
    # not an id
    "conversation with a quote": {"type": "read", "conversation_id": "conv_2' OR '1'='1"},
    "conversation with a wildcard": {"type": "read", "conversation_id": "conv_%"},
    "conversation too long": {"type": "read", "conversation_id": "c" * 65},
}


@pytest.mark.parametrize("name", sorted(INVALID))
def test_frames_must_match_their_type_exactly(as_user, name):
    with open_socket(as_user(ATTACKER)) as ws:
        answer = _answer(ws, INVALID[name])
    assert answer == {"type": "error", "for": "frame", "code": "invalid"}, (name, answer)


PRIVILEGED = ["user_id", "sender_id", "role", "group_id", "is_admin", "verified", "name", "to", "at", "unread", "id"]


@pytest.mark.parametrize("field", PRIVILEGED)
def test_privileged_fields_are_refused_and_never_applied(as_user, field):
    attacker, victim = as_user(ATTACKER), as_user(VICTIM)
    with open_socket(victim) as watcher, open_socket(attacker) as ws:
        for kind in ("typing", "read", "delivered"):
            frame = {"type": kind, "conversation_id": CONV, field: VICTIM if field != "is_admin" else True}
            if kind == "typing":
                frame["typing"] = True
            assert _answer(ws, frame)["code"] == "invalid", (kind, field)
        events = drain(watcher, timeout=0.8)
    # Nothing at all was broadcast for those frames (and certainly nothing in the victim's name).
    assert [e for e in events if e["type"] in ("typing", "read", "delivered")] == []


def test_the_real_sender_is_always_the_connection(as_user):
    """A valid typing frame is attributed to whoever is signed in on the socket, from the server."""
    attacker, victim = as_user(ATTACKER), as_user(VICTIM)
    with open_socket(victim) as watcher, open_socket(attacker) as ws:
        ws.send_text(json.dumps({"type": "typing", "conversation_id": CONV, "typing": True}))
        typing = frames_until(watcher, "typing")[-1]
    assert typing["user_id"] == ATTACKER and typing["conversation_id"] == CONV and typing["typing"] is True


@pytest.mark.parametrize("raw", [
    '{"type":"read","conversation_id":"conv_2","conversation_id":"conv_1"}',
    '{"type":"ping","type":"typing","conversation_id":"conv_2","typing":true}',
    '{"type":"typing","conversation_id":"conv_2","typing":NaN}',
    '{"type":"typing","conversation_id":"conv_2","typing":Infinity}',
    '{"type":"typing","conversation_id":"conv_2","typing":-Infinity}',
])
def test_duplicate_keys_and_non_json_numbers_are_refused(as_user, raw):
    """Same rule as HTTP bodies: a key twice is ambiguous between parsers, so it is refused."""
    with open_socket(as_user(ATTACKER)) as ws:
        assert _answer(ws, raw)["code"] == "invalid"


def test_valid_frames_still_work(as_user):
    attacker = as_user(ATTACKER)
    with open_socket(attacker) as ws:
        for frame in ({"type": "ping"}, {"type": "read", "conversation_id": CONV}, {"type": "delivered", "conversation_id": CONV},
                      {"type": "typing", "conversation_id": CONV, "typing": False}):
            assert _answer(ws, frame)["type"] != "error", frame


def test_each_type_has_its_own_strict_schema():
    for kind, model in ws_routes.FRAME_MODELS.items():
        assert model.model_config.get("extra") == "forbid", kind
        assert model.model_config.get("strict") is True, kind
        for name, info in model.model_fields.items():
            if name != "type":
                assert info.is_required(), (kind, name)  # nothing optional: no field means two things


# --- Only strict JSON, only parameterized queries -----------------------------------------------

SOCKET_CODE = [APP / "routers" / "realtime.py", APP / "realtime.py"]


def test_frames_are_parsed_one_strict_way_only():
    banned_modules = {"pickle", "marshal", "shelve", "yaml", "jsonpickle", "dill", "xml", "ast", "jinja2", "string"}
    banned_calls = {"eval", "exec", "compile", "__import__", "literal_eval"}
    for path in SOCKET_CODE:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imports |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        assert not imports & banned_modules, (path.name, imports & banned_modules)
        names = {getattr(n.func, "id", getattr(n.func, "attr", "")) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        assert not names & banned_calls, (path.name, names & banned_calls)
    # The client's text goes through json.loads with the duplicate-key and number guards, nowhere else.
    router = ast.parse(SOCKET_CODE[0].read_text(encoding="utf-8"))
    loads = [n for n in ast.walk(router) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "loads"]
    assert loads and all({k.arg for k in n.keywords} >= {"object_pairs_hook", "parse_constant"} for n in loads)


def test_database_calls_reachable_from_a_frame_are_parameterized():
    """Raw SQL only as constants with bound parameters; no LIKE patterns; ids looked up by key."""
    for path in [*SOCKET_CODE, APP / "services" / "chat.py"]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in ("text", "execute"):
                for arg in node.args[:1]:
                    assert not isinstance(arg, (ast.JoinedStr, ast.BinOp)), f"{path.name}:{node.lineno}"
            if isinstance(node, ast.Attribute) and node.attr in ("like", "ilike", "contains"):
                raise AssertionError(f"{path.name}:{node.lineno} uses {node.attr}")
