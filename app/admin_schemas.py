"""Request and response shapes of the admin API (/api/admin)."""

from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security import MIN_PASSWORD_LENGTH

T = TypeVar("T")
AdminRole = Literal["admin", "viewer"]


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


class AdminLoginIn(BaseModel):
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


class AdminCreateIn(BaseModel):
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


class AdminUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    role: AdminRole | None = None
    active: bool | None = None


class AdminPasswordIn(BaseModel):
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
    skills: list[str] = []
    avatar_url: str | None = None
    resume_url: str | None = None
    github_verified: bool = False
    requests_sent: int = 0
    requests_received: int = 0
    messages_sent: int = 0
    conversations: int = 0


class StudentCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    college: str = Field(min_length=1, max_length=160)
    department: str | None = Field(default=None, max_length=160)
    passing_year: int = Field(ge=2000, le=2100)
    phone: str = Field(min_length=7, max_length=32)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)
    bio: str = Field(default="", max_length=400)
    skills: list[str] = Field(default_factory=list, max_length=30)
    github_url: str | None = Field(default=None, max_length=300)


class StudentUpdateIn(BaseModel):
    """Every field optional: only those sent are changed."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    college: str | None = Field(default=None, min_length=1, max_length=160)
    department: str | None = Field(default=None, max_length=160)
    passing_year: int | None = Field(default=None, ge=2000, le=2100)
    phone: str | None = Field(default=None, min_length=7, max_length=32)
    bio: str | None = Field(default=None, max_length=400)
    skills: list[str] | None = Field(default=None, max_length=30)
    github_url: str | None = Field(default=None, max_length=300)


class PasswordSetIn(BaseModel):
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


class BanIn(BaseModel):
    reason: str = Field(default="", max_length=500)
    # Also block the account's phone number from signing up again.
    block_number: bool = False


class BulkIn(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=500)
    action: Literal["ban", "unban", "delete"]
    reason: str = Field(default="", max_length=500)


class BulkOut(BaseModel):
    done: int
    skipped: list[str]


# --------------------------------------------------------------------------------------------
# Blocked numbers
# --------------------------------------------------------------------------------------------


class BannedPhoneIn(BaseModel):
    phones: list[str] = Field(min_length=1, max_length=500, description="One or more numbers, any format")
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


class AuditRow(Out):
    id: str
    admin_email: str
    action: str
    target_type: str | None = None
    target_id: str | None = None
    summary: str
    detail: dict | None = None
    created_at: datetime
