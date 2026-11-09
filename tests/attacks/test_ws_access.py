"""WebSocket message layer, Part 3: every frame that names an object is authorized against that
object, from the database, on every frame (never only at connect time)."""

import json

import pytest
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app.db import SessionLocal
from app.models import ConversationParticipant
from app.routers import realtime as ws_routes
from tests.attacks.ws_tools import drain, frames_until, open_socket, receive

OTHERS_CHAT = "conv_2"   # usr_1 and usr_2 only
GROUP_CHAT = "conv_1"    # grp_1: usr_1 (lead), usr_9, usr_11
FRAMES = {
    "typing": {"type": "typing", "conversation_id": None, "typing": True},
    "read": {"type": "read", "conversation_id": None},
    "delivered": {"type": "delivered", "conversation_id": None},
}


def _send(ws, kind: str, conversation_id: str) -> dict:
    """Sends one frame and returns the server's answer to it (an error frame, or the pong after it)."""
    ws.send_text(json.dumps({**FRAMES[kind], "conversation_id": conversation_id}))
    ws.send_text('{"type":"ping"}')
    seen = frames_until(ws, "pong")
    errors = [e for e in seen if e["type"] == "error"]
    return errors[0] if errors else seen[-1]


def _receipts(conversation_id: str) -> dict:
    with SessionLocal() as db:
        rows = db.scalars(select(ConversationParticipant).where(ConversationParticipant.conversation_id == conversation_id))
        return {r.user_id: (r.unread, r.last_read_at, r.last_delivered_at) for r in rows}


@pytest.mark.parametrize("kind", sorted(FRAMES))
def test_a_frame_naming_someone_elses_conversation_is_refused(as_user, kind):
    before = _receipts(OTHERS_CHAT)
    with open_socket(as_user("usr_1")) as one, open_socket(as_user("usr_2")) as two, open_socket(as_user("usr_8")) as ws:
        assert _send(ws, kind, OTHERS_CHAT) == {"type": "error", "for": kind, "code": "forbidden"}
        heard = drain(one, 0.8) + drain(two, 0.8)
    assert [e for e in heard if e["type"] in ("typing", "read", "delivered")] == []
    assert _receipts(OTHERS_CHAT) == before


@pytest.mark.parametrize("kind", sorted(FRAMES))
def test_unknown_and_existing_conversations_answer_the_same(as_user, kind):
    """No way to probe which conversation ids exist."""
    with open_socket(as_user("usr_8")) as ws:
        assert _send(ws, kind, "conv_doesnotexist") == _send(ws, kind, OTHERS_CHAT)


def test_removed_from_a_group_mid_session_has_its_socket_closed_and_hears_nothing(as_user):
    lead, member = as_user("usr_1"), as_user("usr_9")
    with open_socket(lead) as lead_ws, open_socket(member) as ws:
        # Allowed while a member, on this very connection.
        assert _send(ws, "typing", GROUP_CHAT)["type"] == "pong"
        frames_until(lead_ws, "typing", user_id="usr_9")
        # The lead removes them (HTTP): their socket is closed for policy (1008).
        assert lead.delete("/api/groups/grp_1/members/usr_9").status_code in (200, 204)
        seen = []
        try:
            while True:
                seen.append(receive(ws, 4))
        except WebSocketDisconnect as closed:
            assert closed.code == 1008
        assert not any(e.get("conversation_id") == GROUP_CHAT for e in seen)
        # The group goes on; nothing of it reaches the removed member's account any more.
        assert lead.post(f"/api/conversations/{GROUP_CHAT}/messages", json={"text": "after you left"}).status_code == 201
        frames_until(lead_ws, "message.new")
    with open_socket(member) as again:
        heard = drain(again, 1.0)
    assert not any(e["type"] == "message.new" and e["message"]["text"] == "after you left" for e in heard)


def test_typing_shows_the_current_name_not_one_cached_at_connect(as_user, admin_client):
    sender, watcher_client = as_user("usr_1"), as_user("usr_2")
    with open_socket(watcher_client) as watcher, open_socket(sender) as ws:
        assert admin_client().patch("/api/admin/users/usr_1", json={"name": "Renamed Lead"}).status_code == 200
        ws.send_text(json.dumps({"type": "typing", "conversation_id": OTHERS_CHAT, "typing": True}))
        assert frames_until(watcher, "typing")[-1]["name"] == "Renamed Lead"


def test_no_socket_action_needs_or_grants_a_role():
    """Lead-only actions (accept, remove, invite) are HTTP only and checked there; over the socket
    every frame acts only as the signed-in student on their own receipts and typing."""
    for kind, policy in ws_routes.FRAME_POLICY.items():
        assert policy["roles"] == {"student"}, kind
        assert policy["writes"] in (None, "own read receipt", "own delivery receipt"), kind
