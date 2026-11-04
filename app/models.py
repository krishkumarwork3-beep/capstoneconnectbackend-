"""Database tables.

IDs are short prefixed strings (`usr_…`, `grp_…`) so they read well in URLs and logs and match
the ids the frontend already uses. A student is in at most one group: `group_members.user_id`
is unique. A user's group, group name and role are read from that membership, never stored twice.
"""

from datetime import UTC, datetime

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def _now_column(**kwargs) -> Mapped[datetime]:
    # Set in Python (so a new row has it at once) with a database default as a backstop.
    return mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), **kwargs)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_created_at", "created_at"),
        Index("ix_users_college", "college"),
        Index("ix_users_contributions", "github_contribution_count"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    college: Mapped[str] = mapped_column(String(160))
    department: Mapped[str | None] = mapped_column(String(160))
    passing_year: Mapped[int] = mapped_column(Integer)
    # As typed (shown back to the user) and normalised to digits with the country code (unique,
    # used for login and password reset).
    phone: Mapped[str] = mapped_column(String(32))
    phone_normalized: Mapped[str] = mapped_column(String(20), unique=True)
    password_hash: Mapped[str] = mapped_column(String(100))

    bio: Mapped[str] = mapped_column(Text, default="")
    skills: Mapped[list[str]] = mapped_column(ARRAY(String(60)), default=list)
    resume_url: Mapped[str | None] = mapped_column(String(500))
    avatar_url: Mapped[str | None] = mapped_column(String(500))

    github_url: Mapped[str | None] = mapped_column(String(300))
    github_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    # All-time GitHub contributions, cached; null until the first successful lookup.
    github_contribution_count: Mapped[int | None] = mapped_column(Integer)
    github_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Accepted/declined outcomes of this user's requests that they have not looked at yet.
    outcome_updates: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now_column()
    # Suspended by an admin: cannot sign in, and existing sessions stop working.
    banned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ban_reason: Mapped[str | None] = mapped_column(Text)

    membership: Mapped["GroupMember | None"] = relationship(back_populates="user", uselist=False, lazy="joined")


class Group(Base):
    __tablename__ = "groups"
    __table_args__ = (CheckConstraint("max_members >= 2", name="group_min_seats"), Index("ix_groups_created_at", "created_at"))

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    # Fixed at creation: group size cannot be changed.
    max_members: Mapped[int] = mapped_column(Integer)
    requirements: Mapped[list[str]] = mapped_column(ARRAY(String(60)), default=list)
    domain: Mapped[str] = mapped_column(String(160))
    # The current Group Lead (moves to the earliest member if the lead leaves).
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = _now_column()

    members: Mapped[list["GroupMember"]] = relationship(
        back_populates="group",
        cascade="all, delete-orphan",
        order_by="GroupMember.joined_at",
        lazy="selectin",
    )


class GroupMember(Base):
    __tablename__ = "group_members"

    group_id: Mapped[str] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True)
    # Unique: one group per student.
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, unique=True)
    role: Mapped[str] = mapped_column(String(10))  # "admin" (Group Lead) or "member"
    joined_at: Mapped[datetime] = _now_column()

    group: Mapped[Group] = relationship(back_populates="members", lazy="joined")
    user: Mapped[User] = relationship(back_populates="membership", lazy="joined")


class JoinRequest(Base):
    """A join request (student → group) or an invitation (Group Lead → student)."""

    __tablename__ = "join_requests"
    __table_args__ = (
        Index("ix_requests_group_status", "group_id", "status"),
        Index("ix_requests_sender", "sender_id"),
        Index("ix_requests_receiver", "receiver_id"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    # The group may be deleted later; the request keeps its history with the name it had.
    group_id: Mapped[str | None] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"))
    group_name: Mapped[str] = mapped_column(String(160))
    sender_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    receiver_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(20))  # "join_request" | "invitation"
    status: Mapped[str] = mapped_column(String(20), default="pending")
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now_column()
    updated_at: Mapped[datetime] = _now_column(onupdate=utcnow)

    sender: Mapped[User] = relationship(foreign_keys=[sender_id], lazy="joined")
    receiver: Mapped[User] = relationship(foreign_keys=[receiver_id], lazy="joined")


class Report(Base):
    """A student reporting another student, a group or a chat message to the admins.

    `target_user_id` is the student behind the reported thing (the student, the group's lead, the
    message's sender), so an admin can suspend them in one click; `snapshot` keeps what was
    reported (a name, a group name, the message text) even if it is later edited or deleted.
    """

    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("reporter_id", "target_type", "target_id", name="uq_report_once"),
        Index("ix_reports_status_created", "status", "created_at"),
        Index("ix_reports_reporter_created", "reporter_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    reporter_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    target_type: Mapped[str] = mapped_column(String(10))  # user | group | message
    target_id: Mapped[str] = mapped_column(String(40))
    target_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    conversation_id: Mapped[str | None] = mapped_column(String(40))
    reason: Mapped[str] = mapped_column(String(20))
    details: Mapped[str] = mapped_column(Text, default="")
    snapshot: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(12), default="open")  # open | reviewed | dismissed | actioned
    handled_by: Mapped[str | None] = mapped_column(String(200))
    handled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now_column()
    updated_at: Mapped[datetime] = _now_column(onupdate=utcnow)

    reporter: Mapped[User] = relationship(foreign_keys=[reporter_id], lazy="joined")
    target_user: Mapped[User | None] = relationship(foreign_keys=[target_user_id], lazy="joined")


class Announcement(Base):
    """A site-wide banner: shown to every visitor between `starts_at` and `ends_at` (open-ended
    when empty)."""

    __tablename__ = "announcements"
    __table_args__ = (Index("ix_announcements_window", "starts_at", "ends_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    text: Mapped[str] = mapped_column(String(300))
    link_url: Mapped[str | None] = mapped_column(String(500))
    link_label: Mapped[str | None] = mapped_column(String(60))
    level: Mapped[str] = mapped_column(String(10), default="info")  # info | warning
    starts_at: Mapped[datetime] = _now_column()
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = _now_column()
    updated_at: Mapped[datetime] = _now_column(onupdate=utcnow)


class RateLimit(Base):
    """A fixed-window counter for sign-in, sign-up and password-reset throttling (app.services.limits).
    Kept in PostgreSQL so every worker counts together."""

    __tablename__ = "rate_limits"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    window_start: Mapped[datetime] = _now_column()


class Recommendation(Base):
    """A group Member vouching for a Looking student. Only the Group Lead sees it."""

    __tablename__ = "recommendations"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    group_id: Mapped[str | None] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), index=True)
    recommender_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    student_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    note: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|invited|dismissed|closed
    created_at: Mapped[datetime] = _now_column()
    updated_at: Mapped[datetime] = _now_column(onupdate=utcnow)

    recommender: Mapped[User] = relationship(foreign_keys=[recommender_id], lazy="joined")
    student: Mapped[User] = relationship(foreign_keys=[student_id], lazy="joined")


class Conversation(Base):
    __tablename__ = "conversations"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    type: Mapped[str] = mapped_column(String(10))  # "direct" | "group"
    # Group chats belong to their group and are deleted with it.
    group_id: Mapped[str | None] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), unique=True)
    last_message_text: Mapped[str | None] = mapped_column(Text)
    last_message_sender: Mapped[str | None] = mapped_column(String(120))
    last_message_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = _now_column()

    participants: Mapped[list["ConversationParticipant"]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan", lazy="selectin"
    )
    group: Mapped[Group | None] = relationship(lazy="joined")


class ConversationParticipant(Base):
    __tablename__ = "conversation_participants"

    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    unread: Mapped[int] = mapped_column(Integer, default=0)
    # Receipts (the ticks): this participant has received / read every message up to these times.
    last_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    conversation: Mapped[Conversation] = relationship(back_populates="participants")
    user: Mapped[User] = relationship(lazy="joined")


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        Index("ix_messages_conversation_created", "conversation_id", "created_at"),
        Index("ix_messages_sender", "sender_id"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"))
    sender_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    sender_name: Mapped[str] = mapped_column(String(120))
    text: Mapped[str] = mapped_column(Text, default="")
    attachment_name: Mapped[str | None] = mapped_column(String(255))
    attachment_url: Mapped[str | None] = mapped_column(String(500))
    attachment_size: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = _now_column()


class PasswordResetCode(Base):
    """A one-time code sent by SMS. Only its hash is stored."""

    __tablename__ = "password_reset_codes"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(100))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now_column()


# ---------------------------------------------------------------------------------------------
# Admin portal
# ---------------------------------------------------------------------------------------------


class AdminUser(Base):
    """Someone who runs the site (the admin portal). Separate from students: own login, own cookie."""

    __tablename__ = "admin_users"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    email: Mapped[str] = mapped_column(String(200), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(100))
    # "admin" can change anything; "viewer" can only look.
    role: Mapped[str] = mapped_column(String(10), default="admin")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now_column()


class BannedPhone(Base):
    """A phone number that may not sign up, sign in or reset a password."""

    __tablename__ = "banned_phones"

    phone_normalized: Mapped[str] = mapped_column(String(20), primary_key=True)
    phone: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = _now_column()


class AuditLog(Base):
    """Every change made through the admin portal: who, what, to which record, when."""

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_created", "created_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    admin_id: Mapped[str | None] = mapped_column(String(40))
    admin_email: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(60))
    target_type: Mapped[str | None] = mapped_column(String(30))
    target_id: Mapped[str | None] = mapped_column(String(60))
    summary: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = _now_column()
