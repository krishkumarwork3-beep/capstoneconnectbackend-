"""Loads the demo data (the same students, groups, requests and chats as the frontend's demo mode).

    uv run python -m app.seed            # only into an empty database
    uv run python -m app.seed --reset    # wipe every table first

Every seeded student signs in with their phone number and the password `password123`.
The seeded GitHub usernames are examples: their contribution totals are demo values until a
refresh checks them against GitHub (a username that doesn't exist then shows as unverified).
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import (
    Conversation,
    ConversationParticipant,
    Group,
    GroupMember,
    JoinRequest,
    Message,
    Recommendation,
    User,
)
from app.security import hash_password, normalize_phone

DEMO_PASSWORD = "password123"
DATA = Path(__file__).with_name("seed_data.json")
TABLES = (
    "messages, conversation_participants, conversations, recommendations, join_requests, "
    "group_members, groups, password_reset_codes, users"
)


def when(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def seed(db: Session) -> dict[str, int]:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    password_hash = hash_password(DEMO_PASSWORD)  # one hash for all demo accounts keeps seeding fast
    now = datetime.now(UTC)

    for u in data["users"]:
        db.add(
            User(
                id=u["id"],
                name=u["name"],
                college=u["college"],
                department=u.get("department"),
                passing_year=u["passing_year"],
                phone=u["phone"],
                phone_normalized=normalize_phone(u["phone"]),
                password_hash=password_hash,
                bio=u.get("bio", ""),
                skills=u.get("skills", []),
                resume_url=u.get("resume_url"),
                avatar_url=u.get("avatar_url"),
                github_url=u.get("github_url"),
                github_verified=bool(u.get("github_verified")),
                github_contribution_count=u.get("github_contribution_count"),
                github_synced_at=now if u.get("github_contribution_count") is not None else None,
                created_at=when(u["created_at"]),
            )
        )
    db.flush()

    for g in data["groups"]:
        group = Group(
            id=g["id"],
            name=g["name"],
            description=g["description"],
            max_members=g["max_members"],
            requirements=g.get("requirements", []),
            domain=g["domain"],
            created_by=g["created_by"],
            created_at=when(g["created_at"]),
        )
        group.members = [
            GroupMember(user_id=m["user_id"], role=m["role"], joined_at=when(m["joined_at"])) for m in g["members"]
        ]
        db.add(group)
    db.flush()

    for r in data["requests"]:
        db.add(
            JoinRequest(
                id=r["id"],
                group_id=r["group_id"],
                group_name=r["group_name"],
                sender_id=r["sender_id"],
                receiver_id=r["receiver_id"],
                type=r["type"],
                status=r["status"],
                note=r.get("note"),
                created_at=when(r["created_at"]),
                updated_at=when(r["updated_at"]),
            )
        )

    for r in data["recommendations"]:
        db.add(
            Recommendation(
                id=r["id"],
                group_id=r["group_id"],
                recommender_id=r["recommender_id"],
                student_id=r["student_id"],
                note=r.get("note"),
                status=r["status"],
                created_at=when(r["created_at"]),
                updated_at=when(r["updated_at"]),
            )
        )

    # Every group gets its chat (the demo data only has one); participants follow the members.
    convs = {c.get("group_id"): c for c in data["conversations"] if c["type"] == "group"}
    for g in data["groups"]:
        source = convs.get(g["id"], {})
        conv = Conversation(id=source.get("id", f"conv_{g['id']}"), type="group", group_id=g["id"],
                            updated_at=when(source.get("updated_at")) or when(g["created_at"]))
        unread = source.get("unread", {})
        conv.participants = [ConversationParticipant(user_id=m["user_id"], unread=unread.get(m["user_id"], 0)) for m in g["members"]]
        db.add(conv)
    for c in data["conversations"]:
        if c["type"] != "direct":
            continue
        conv = Conversation(id=c["id"], type="direct", updated_at=when(c["updated_at"]))
        conv.participants = [ConversationParticipant(user_id=uid, unread=c.get("unread", {}).get(uid, 0)) for uid in c["participant_ids"]]
        db.add(conv)
    db.flush()

    count = 0
    for conv_id, messages in data["messages"].items():
        for m in messages:
            db.add(
                Message(
                    id=m["id"],
                    conversation_id=conv_id,
                    sender_id=m["sender_id"],
                    sender_name=m["sender_name"],
                    text=m.get("text", ""),
                    created_at=when(m["created_at"]),
                )
            )
            count += 1
        last = messages[-1] if messages else None
        conv = db.get(Conversation, conv_id)
        if conv and last:
            conv.last_message_text = last.get("text") or "Attachment"
            conv.last_message_sender = last["sender_name"]
            conv.last_message_at = when(last["created_at"])
            conv.updated_at = when(last["created_at"])
    db.commit()
    return {
        "users": len(data["users"]),
        "groups": len(data["groups"]),
        "requests": len(data["requests"]),
        "recommendations": len(data["recommendations"]),
        "messages": count,
    }


def main() -> None:
    with SessionLocal() as db:
        if "--reset" in sys.argv:
            db.execute(text(f"TRUNCATE {TABLES} CASCADE"))
            db.commit()
        elif db.scalar(select(User.id).limit(1)):
            print("The database already has data. Use --reset to replace it with the demo data.")
            return
        print("Seeded:", seed(db))


if __name__ == "__main__":
    main()
