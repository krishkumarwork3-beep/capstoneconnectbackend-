"""The live socket: auth, new messages, receipts, typing, presence and group chat changes.

Events go through PostgreSQL NOTIFY even here, so these also check the cross-worker path.
"""

import json

import anyio
import pytest
from starlette.websockets import WebSocketDisconnect

GROUP_CHAT_MEMBERS = ("usr_1", "usr_9")  # both in grp_1


def receive(ws, timeout: float = 5.0) -> dict:
    """The next event, or a failure instead of a hang when none comes."""

    async def get():
        with anyio.fail_after(timeout):
            return await ws._send_rx.receive()

    message = ws.portal.call(get)
    if message["type"] == "websocket.close":
        raise WebSocketDisconnect(message.get("code", 1000), message.get("reason"))
    return json.loads(message["text"])


def wait_for(ws, kind: str, timeout: float = 5.0, **match) -> dict:
    while True:
        event = receive(ws, timeout)
        if event["type"] == kind and all(event.get(k) == v for k, v in match.items()):
            return event


def nothing_like(ws, kind: str, timeout: float = 0.8) -> None:
    with pytest.raises(TimeoutError):
        wait_for(ws, kind, timeout)


def group_chat(client) -> str:
    return next(c["id"] for c in client.get("/api/conversations").json() if c["type"] == "group")


def test_needs_a_session(client):
    with client.websocket_connect("/api/ws") as ws:
        with pytest.raises(WebSocketDisconnect) as closed:
            receive(ws)
    assert closed.value.code == 4401


def test_refuses_a_foreign_origin(as_user):
    with pytest.raises(WebSocketDisconnect) as closed:
        with as_user("usr_1").websocket_connect("/api/ws", headers={"origin": "https://evil.example"}) as ws:
            receive(ws)
    assert closed.value.code == 4403


def test_message_reaches_every_participant_with_ticks(as_user):
    lead, member = (as_user(u) for u in GROUP_CHAT_MEMBERS)
    conv_id = group_chat(lead)
    with lead.websocket_connect("/api/ws") as lead_ws, member.websocket_connect("/api/ws") as member_ws:
        assert wait_for(lead_ws, "hello")["user_id"] == "usr_1"
        wait_for(member_ws, "hello")

        sent = lead.post(f"/api/conversations/{conv_id}/messages", json={"text": "Stand-up at 6?", "client_id": "c-1"})
        assert sent.status_code == 201 and sent.json()["client_id"] == "c-1"

        got = wait_for(member_ws, "message.new")["message"]
        assert (got["id"], got["text"], got["sender_id"]) == (sent.json()["id"], "Stand-up at 6?", "usr_1")
        # The sender's own tabs get it too, with the id that lets them swap the optimistic copy.
        assert wait_for(lead_ws, "message.new")["message"]["client_id"] == "c-1"

        member_ws.send_json({"type": "delivered", "conversation_id": conv_id})
        assert wait_for(lead_ws, "delivered", conversation_id=conv_id)["user_id"] == "usr_9"

        member_ws.send_json({"type": "read", "conversation_id": conv_id})
        read = wait_for(lead_ws, "read", conversation_id=conv_id)
        assert read["user_id"] == "usr_9"
        # The reader's own other tabs hear it as well (their unread badge clears).
        assert wait_for(member_ws, "read", conversation_id=conv_id)["user_id"] == "usr_9"

    conv = next(c for c in lead.get("/api/conversations").json() if c["id"] == conv_id)
    them = next(p for p in conv["participants"] if p["id"] == "usr_9")
    assert them["last_read_at"] >= got["created_at"] and them["last_delivered_at"] >= got["created_at"]
    mine = next(c for c in member.get("/api/conversations").json() if c["id"] == conv_id)
    assert mine["unread"]["usr_9"] == 0


def test_reading_again_says_nothing(as_user):
    lead, member = (as_user(u) for u in GROUP_CHAT_MEMBERS)
    conv_id = group_chat(lead)
    member.post(f"/api/conversations/{conv_id}/read")
    with lead.websocket_connect("/api/ws") as lead_ws:
        wait_for(lead_ws, "hello")
        member.post(f"/api/conversations/{conv_id}/read")
        nothing_like(lead_ws, "read")


def test_a_long_message_still_arrives(as_user):
    lead, member = (as_user(u) for u in GROUP_CHAT_MEMBERS)
    conv_id = group_chat(lead)
    text = "🚀" * 4000  # far over the 8000-byte NOTIFY limit, so it goes by reference
    with member.websocket_connect("/api/ws") as ws:
        wait_for(ws, "hello")
        lead.post(f"/api/conversations/{conv_id}/messages", json={"text": text, "client_id": "long"})
        got = wait_for(ws, "message.new")["message"]
    assert got["text"] == text and got["client_id"] == "long"


def test_typing_goes_to_the_others_only(as_user):
    lead, member = (as_user(u) for u in GROUP_CHAT_MEMBERS)
    conv_id = group_chat(lead)
    with lead.websocket_connect("/api/ws") as lead_ws:
        wait_for(lead_ws, "hello")
        with member.websocket_connect("/api/ws") as member_ws:
            wait_for(member_ws, "hello")
            member_ws.send_json({"type": "typing", "conversation_id": conv_id, "typing": True})
            event = wait_for(lead_ws, "typing", conversation_id=conv_id)
            assert (event["user_id"], event["typing"]) == ("usr_9", True) and event["name"]
            nothing_like(member_ws, "typing")
        # Leaving while typing clears the indicator for the others.
        assert wait_for(lead_ws, "typing", conversation_id=conv_id)["typing"] is False


def test_typing_into_someone_elses_chat_is_ignored(as_user):
    lead, outsider = as_user("usr_1"), as_user("usr_8")
    conv_id = group_chat(lead)
    with lead.websocket_connect("/api/ws") as lead_ws, outsider.websocket_connect("/api/ws") as outsider_ws:
        wait_for(lead_ws, "hello")
        wait_for(outsider_ws, "hello")
        outsider_ws.send_json({"type": "typing", "conversation_id": conv_id, "typing": True})
        nothing_like(lead_ws, "typing")


def test_presence_online_and_offline(as_user):
    lead, member = (as_user(u) for u in GROUP_CHAT_MEMBERS)
    with lead.websocket_connect("/api/ws") as lead_ws:
        wait_for(lead_ws, "hello")
        with member.websocket_connect("/api/ws") as member_ws:
            wait_for(member_ws, "hello")
            assert wait_for(lead_ws, "presence", user_id="usr_9")["online"] is True
        assert wait_for(lead_ws, "presence", user_id="usr_9")["online"] is False


def test_joining_a_group_shows_its_chat_live(as_user):
    lead, newcomer = as_user("usr_1"), as_user("usr_6")
    request = next(r for r in lead.get("/api/requests?direction=received").json() if r["sender_id"] == "usr_6")
    with newcomer.websocket_connect("/api/ws") as ws:
        wait_for(ws, "hello")
        assert lead.patch(f"/api/requests/{request['id']}", json={"status": "accepted"}).status_code == 200
        wait_for(ws, "conversations.changed")
    assert any(c["type"] == "group" for c in newcomer.get("/api/conversations").json())


def test_ping_pong(as_user):
    with as_user("usr_1").websocket_connect("/api/ws") as ws:
        wait_for(ws, "hello")
        ws.send_json({"type": "ping"})
        wait_for(ws, "pong")
        ws.send_text("not json")
        ws.send_json({"type": "ping"})
        wait_for(ws, "pong")
