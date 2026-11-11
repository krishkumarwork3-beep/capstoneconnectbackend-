"""Request and response shapes of the admin API (/api/admin)."""

from datetime import datetime
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.links import clean_link
from app.security import MIN_PASSWORD_LENGTH

T = TypeVar("T")
AdminRole = Literal["admin", "viewer"]



class In(BaseModel):
    """Admin request bodies: explicit allowlists, unknown fields refused."""

    model_config = ConfigDict(extra="forbid")


Id = Annotated[str, Field(min_length=1, max_length=64)]
Tag = Annotated[str, Field(max_length=100)]
Phone = Annotated[str, Field(min_length=1, max_length=32)]

class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(Out, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


# --------------------------------------------------------------------------------------------
# Admin accounts
# --------------------------------------------------------------------------------------------


class AdminLoginIn(In):
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=1, max_length=200)


class AdminOut(Out):
    id: str
    email: str
    name: str
    role: AdminRole
    active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class AdminCreateIn(In):
    email: str = Field(min_length=3, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)
    role: AdminRole = "admin"

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value:
            raise ValueError("Enter an email address")
        return value


class AdminUpdateIn(In):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    role: AdminRole | None = None
    active: bool | None = None


class ExportIn(In):
    """POST /api/admin/users/export.csv: the admin's own password again, and the list's filters."""

    password: str = Field(min_length=1, max_length=200)
    q: str | None = Field(None, max_length=100)
    status: Literal["all", "active", "banned", "in_group", "looking"] = "all"
    college: str | None = Field(None, max_length=160)


class AdminPasswordIn(In):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


# --------------------------------------------------------------------------------------------
# Students
# --------------------------------------------------------------------------------------------


class StudentRow(Out):
    id: str
    name: str
    phone: str
    college: str
    department: str | None = None
    passing_year: int
    group_id: str | None = None
    group_name: str | None = None
    group_role: str | None = None
    github_url: str | None = None
    github_contribution_count: int | None = None
    banned: bool
    ban_reason: str | None = None
    banned_at: datetime | None = None
    number_blocked: bool = False
    last_seen: datetime | None = None
    created_at: datetime


class StudentDetail(StudentRow):
    bio: str = ""
    skills: list[Tag] = []
    avatar_url: str | None = None
    resume_url: str | None = None
    github_verified: bool = False
    requests_sent: int = 0
    requests_received: int = 0
    messages_sent: int = 0
    conversations: int = 0


class StudentCreateIn(In):
    name: str = Field(min_length=1, max_length=120)
    college: str = Field(min_length=1, max_length=160)
    department: str | None = Field(default=None, max_length=160)
    passing_year: int = Field(ge=2000, le=2100)
    phone: str = Field(min_length=7, max_length=32)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)
    bio: str = Field(default="", max_length=400)
    skills: list[Tag] = Field(default_factory=list, max_length=30)
    github_url: str | None = Field(default=None, max_length=300)


class StudentUpdateIn(In):
    """Every field optional: only those sent are changed."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    college: str | None = Field(default=None, min_length=1, max_length=160)
    department: str | None = Field(default=None, max_length=160)
    passing_year: int | None = Field(default=None, ge=2000, le=2100)
    phone: str | None = Field(default=None, min_length=7, max_length=32)
    bio: str | None = Field(default=None, max_length=400)
    skills: list[Tag] | None = Field(default=None, max_length=30)
    github_url: str | None = Field(default=None, max_length=300)


class PasswordSetIn(In):
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


class BanIn(In):
    reason: str = Field(default="", max_length=500)
    # Also block the account's phone number from signing up again.
    block_number: bool = False


BULK_LIMIT = 5000


class BulkIn(In):
    ids: list[Id] = Field(min_length=1, max_length=BULK_LIMIT)
    action: Literal["ban", "unban", "delete"]
    reason: str = Field(default="", max_length=500)


class BulkOut(BaseModel):
    done: int
    skipped: list[str]


class IdsIn(In):
    """Several records at once (groups, requests, messages; numbers for blocked numbers)."""

    ids: list[Id] = Field(min_length=1, max_length=BULK_LIMIT)


# --------------------------------------------------------------------------------------------
# Blocked numbers
# --------------------------------------------------------------------------------------------


class BannedPhoneIn(In):
    phones: list[Phone] = Field(min_length=1, max_length=500, description="One or more numbers, any format")
    reason: str = Field(default="", max_length=500)


class BannedPhoneOut(Out):
    phone_normalized: str
    phone: str
    reason: str | None = None
    created_by: str | None = None
    created_at: datetime
    account_id: str | None = None
    account_name: str | None = None


class BannedPhoneAdded(BaseModel):
    added: list[str]
    already: list[str]
    invalid: list[str]


# --------------------------------------------------------------------------------------------
# Groups, requests, chat
# --------------------------------------------------------------------------------------------


class GroupMemberRow(Out):
    user_id: str
    name: str
    phone: str
    role: str
    joined_at: datetime


class GroupRow(Out):
    id: str
    name: str
    domain: str
    description: str
    max_members: int
    member_count: int
    lead_id: str | None = None
    lead_name: str | None = None
    requirements: list[str] = []
    created_at: datetime


class GroupDetail(GroupRow):
    members: list[GroupMemberRow]
    pending_requests: int


class GroupEditIn(In):
    """Only the fields sent change. Group size is fixed once a group exists."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    domain: str | None = Field(default=None, min_length=1, max_length=160)
    requirements: list[Tag] | None = Field(default=None, max_length=20)

    @field_validator("requirements")
    @classmethod
    def _requirements(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        seen: list[str] = []
        for item in (v.strip()[:60] for v in value):
            if item and item.lower() not in (v.lower() for v in seen):
                seen.append(item)
        return seen


class LeadIn(In):
    user_id: Id


class RecommendationRow(Out):
    id: str
    group_id: str | None = None
    group_name: str | None = None
    recommender_id: str
    recommender_name: str
    student_id: str
    student_name: str
    note: str | None = None
    status: str
    created_at: datetime
    updated_at: datetime


class RequestRow(Out):
    id: str
    type: str
    status: str
    group_id: str | None = None
    group_name: str
    sender_id: str
    sender_name: str
    receiver_id: str
    receiver_name: str
    note: str | None = None
    created_at: datetime
    updated_at: datetime


class ConversationRow(Out):
    id: str
    type: str
    title: str
    participants: list[str]
    message_count: int
    last_message_text: str | None = None
    last_message_at: datetime | None = None


class MessageRow(Out):
    id: str
    sender_id: str | None = None
    sender_name: str
    text: str
    attachment_name: str | None = None
    attachment_url: str | None = None
    created_at: datetime

    @field_validator("attachment_url")
    @classmethod
    def _link(cls, value: str | None) -> str | None:
        from app.services.uploads import public_url

        return public_url(value)


class ReportRow(Out):
    id: str
    reporter_id: str
    reporter_name: str
    target_type: str
    target_id: str
    target_user_id: str | None = None
    target_user_name: str | None = None
    target_user_banned: bool = False
    target_exists: bool = True
    conversation_id: str | None = None
    reason: str
    reason_label: str
    details: str
    snapshot: str
    status: str
    handled_by: str | None = None
    handled_at: datetime | None = None
    created_at: datetime


class ReportStatusIn(In):
    status: Literal["open", "reviewed", "dismissed"]


class ReportSuspendIn(In):
    reason: str = Field(default="", max_length=500)


def _http_link(value: str | None) -> str | None:
    return clean_link(value)


class AnnouncementIn(In):
    text: str = Field(min_length=1, max_length=300)
    link_url: str | None = Field(default=None, max_length=500)
    link_label: str | None = Field(default=None, max_length=60)
    level: Literal["info", "warning"] = "info"
    starts_at: datetime | None = None
    ends_at: datetime | None = None

    @field_validator("link_url")
    @classmethod
    def _link(cls, value: str | None) -> str | None:
        return _http_link(value)


class AnnouncementPatch(In):
    model_config = ConfigDict(extra="forbid")

    text: str | None = Field(default=None, min_length=1, max_length=300)
    link_url: str | None = Field(default=None, max_length=500)
    link_label: str | None = Field(default=None, max_length=60)
    level: Literal["info", "warning"] | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None

    @field_validator("link_url")
    @classmethod
    def _link(cls, value: str | None) -> str | None:
        return _http_link(value)


class AnnouncementRow(Out):
    id: str
    text: str
    link_url: str | None = None
    link_label: str | None = None
    level: str
    starts_at: datetime
    ends_at: datetime | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    active: bool = False


class AuditRow(Out):
    id: str
    admin_email: str
    action: str
    target_type: str | None = None
    target_id: str | None = None
    summary: str
    detail: dict | None = None
    created_at: datetime
