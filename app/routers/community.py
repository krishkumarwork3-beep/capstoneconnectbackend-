"""Reports (a student flags a student, a group or a chat message for the admins) and the site
announcements banner."""

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app.config import get_settings
from app.deps import DB, CurrentUser
from app.errors import AppError, not_found
from app.models import Announcement, ConversationParticipant, Group, Message, Report, User, utcnow
from app.security import new_id

router = APIRouter(tags=["community"])

ReportReason = Literal["spam", "harassment", "inappropriate", "fake_profile", "scam", "other"]
REASONS: dict[str, str] = {
    "spam": "Spam or advertising",
    "harassment": "Harassment or bullying",
    "inappropriate": "Inappropriate content",
    "fake_profile": "Fake profile or impersonation",
    "scam": "Scam or fraud",
    "other": "Something else",
}


class ReportIn(BaseModel):
    target_type: Literal["user", "group", "message"]
    target_id: str = Field(min_length=1, max_length=40)
    reason: ReportReason
    details: str = Field(default="", max_length=1000)


class ReportOut(BaseModel):
    id: str
    status: str


class AnnouncementOut(BaseModel):
    id: str
    text: str
    link_url: str | None = None
    link_label: str | None = None
    level: str
    starts_at: str
    ends_at: str | None = None


def _target(db, me: User, payload: ReportIn) -> tuple[str | None, str, str | None]:
    """(the student behind it, a snapshot of it, its conversation) — or 404/422."""
    if payload.target_type == "user":
        user = db.get(User, payload.target_id)
        if user is None:
            raise not_found("Student")
        if user.id == me.id:
            raise AppError("You can't report yourself", 422)
        return user.id, f"{user.name} · {user.college}", None
    if payload.target_type == "group":
        group = db.get(Group, payload.target_id)
        if group is None:
            raise not_found("Group")
        lead = next((m.user_id for m in group.members if m.role == "admin"), None)
        if lead == me.id:
            raise AppError("You can't report your own group", 422)
        return lead, f"{group.name} · {group.domain}", None
    message = db.get(Message, payload.target_id)
    seen = message and db.scalar(
        select(ConversationParticipant.user_id).where(
            ConversationParticipant.conversation_id == message.conversation_id, ConversationParticipant.user_id == me.id
        )
    )
    if not seen:
        # Not "forbidden": a message you can't see doesn't exist for you.
        raise not_found("Message")
    if message.sender_id == me.id:
        raise AppError("You can't report your own message", 422)
    text = message.text or (f"[file] {message.attachment_name}" if message.attachment_name else "")
    return message.sender_id, f"{message.sender_name}: {text}"[:1000], message.conversation_id


@router.post("/reports", response_model=ReportOut, status_code=201)
def create_report(payload: ReportIn, db: DB, me: CurrentUser):
    """Report a student, a group or a message you can see. Once per thing; a few a day."""
    since = utcnow() - timedelta(days=1)
    today = db.scalar(select(func.count()).select_from(Report).where(Report.reporter_id == me.id, Report.created_at >= since)) or 0
    if today >= get_settings().reports_per_day:
        raise AppError("You have sent the most reports allowed for today. Try again tomorrow.", 429)
    target_user, snapshot, conversation = _target(db, me, payload)
    if db.scalar(select(Report.id).where(Report.reporter_id == me.id, Report.target_type == payload.target_type,
                                         Report.target_id == payload.target_id)):
        raise AppError("You have already reported this. The admins will look at it.", 409)
    report = Report(
        id=new_id("rpt"), reporter_id=me.id, target_type=payload.target_type, target_id=payload.target_id,
        target_user_id=target_user, conversation_id=conversation, reason=payload.reason,
        details=payload.details.strip(), snapshot=snapshot, status="open",
    )
    db.add(report)
    db.commit()
    return {"id": report.id, "status": report.status}


@router.get("/reports/reasons")
def report_reasons() -> dict[str, str]:
    return REASONS


def active_announcements(db) -> list[Announcement]:
    now = utcnow()
    stmt = (
        select(Announcement)
        .where(Announcement.starts_at <= now, or_(Announcement.ends_at.is_(None), Announcement.ends_at > now))
        .order_by(Announcement.level.desc(), Announcement.starts_at.desc())
        .limit(3)
    )
    return list(db.scalars(stmt))


def announcement_out(a: Announcement) -> AnnouncementOut:
    return AnnouncementOut(
        id=a.id, text=a.text, link_url=a.link_url, link_label=a.link_label, level=a.level,
        starts_at=a.starts_at.isoformat(), ends_at=a.ends_at.isoformat() if a.ends_at else None,
    )


@router.get("/announcements", response_model=list[AnnouncementOut])
def announcements(db: DB):
    """Public (guests see it too): the banners showing right now, warnings first."""
    return [announcement_out(a) for a in active_announcements(db)]

