"""Request and response shapes. Responses mirror the frontend's `lib/types` exactly."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security import MIN_PASSWORD_LENGTH

GroupRole = Literal["admin", "member"]
RequestStatus = Literal["pending", "accepted", "declined", "withdrawn", "cancelled"]


class In(BaseModel):
    """Every request body: an explicit allowlist. Unknown fields are refused (no mass assignment:
    nobody can send role, banned_at, password_hash, github_verified… and have it stick)."""

    model_config = ConfigDict(extra="forbid")


# Bounded building blocks for request fields.
Id = Annotated[str, Field(min_length=1, max_length=64)]
Tag = Annotated[str, Field(max_length=100)]  # a skill or a requirement (cleaned to 60 below)


class Out(BaseModel):
    # Optional fields are left out of the JSON when empty, the way the frontend's types expect.
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------------------------


class UserOut(Out):
    id: str
    name: str
    college: str
    department: str | None = None
    passing_year: int
    # The full number only for the student, their group and people they accepted a request with;
    # otherwise masked (+91 98••• ••210) and phone_visible is false.
    phone: str
    phone_visible: bool = True
    bio: str
    skills: list[str]
    resume_url: str | None = None
    github_url: str | None = None
    avatar_url: str | None = None
    group_id: str | None = None
    group_name: str | None = None
    group_role: GroupRole | None = None
    github_verified: bool = False
    github_contribution_count: int | None = Field(default=None, ge=0, le=10**9)  # ignored: the server counts
    last_seen: datetime | None = None
    created_at: datetime


class AvatarOut(Out):
    avatar_url: str


class ResumeOut(Out):
    resume_url: str


class UserPage(Out):
    """No total: a global count of students helps nobody but a scraper."""

    items: list[UserOut]
    nextCursor: str | None = None
    hasMore: bool


def _clean_list(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        value = value.strip()
        if value and value.lower() not in (v.lower() for v in seen):
            seen.append(value[:60])
    return seen


class SignupIn(In):
    name: str = Field(min_length=1, max_length=120)
    college: str = Field(min_length=1, max_length=160)
    department: str | None = Field(default=None, max_length=160)
    passing_year: int = Field(ge=2000, le=2100)
    phone: str = Field(min_length=7, max_length=32)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)
    bio: str = Field(default="", max_length=400)
    skills: list[Tag] = Field(default_factory=list, max_length=30)
    github_url: str | None = Field(default=None, max_length=300)
    # Uploaded after the account exists (avatar/resume endpoints); accepted here for completeness.
    avatar_url: str | None = Field(default=None, max_length=500)
    resume_url: str | None = Field(default=None, max_length=500)

    @field_validator("skills")
    @classmethod
    def _skills(cls, value: list[str]) -> list[str]:
        return _clean_list(value)


class LoginIn(In):
    phone: str = Field(min_length=1, max_length=32)
    password: str = Field(default="", max_length=200)


class UserUpdateIn(In):
    """Name, college and graduation year are fixed at sign-up and ignored if sent. Every other
    unknown field (role, banned_at, password_hash, group_id…) is refused."""

    # Accepted and ignored (locked at sign-up), so older clients that send the whole profile work.
    name: str | None = Field(default=None, max_length=120)
    college: str | None = Field(default=None, max_length=160)
    passing_year: int | None = Field(default=None, ge=1900, le=2200)
    department: str | None = Field(default=None, max_length=160)
    bio: str | None = Field(default=None, max_length=400)
    skills: list[Tag] | None = Field(default=None, max_length=30)
    github_url: str | None = Field(default=None, max_length=300)
    github_verified: bool | None = None
    github_contribution_count: int | None = Field(default=None, ge=0, le=10**9)  # ignored: the server counts
    # Only "" or null (remove it): files are set by the upload endpoints, never from a link, so
    # nobody can point their profile's résumé at another site or at someone else's private file.
    resume_url: str | None = Field(default=None, max_length=500)
    avatar_url: str | None = Field(default=None, max_length=500)

    @field_validator("resume_url", "avatar_url")
    @classmethod
    def _only_clear(cls, value: str | None) -> str | None:
        if value:
            raise ValueError("upload the file instead; this field can only be cleared")
        return value

    @field_validator("skills")
    @classmethod
    def _skills(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _clean_list(value)


# --------------------------------------------------------------------------------------------
# Password reset
# --------------------------------------------------------------------------------------------


class ForgotIn(In):
    phone: str = Field(min_length=7, max_length=32)


class ForgotOut(BaseModel):
    message: str
    resend_after: int
    # Development only (SMS_PROVIDER=console): the code, so the flow can be tried without SMS.
    dev_code: str | None = None


class VerifyCodeIn(In):
    phone: str = Field(min_length=7, max_length=32)
    code: str = Field(min_length=4, max_length=10)


class VerifyCodeOut(BaseModel):
    reset_token: str


class ResetIn(In):
    reset_token: str = Field(min_length=1, max_length=2000)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=200)


# --------------------------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------------------------


class GroupMemberOut(Out):
    user_id: str
    name: str
    college: str
    department: str | None = None
    passing_year: int
    role: GroupRole
    joined_at: datetime
    avatar_url: str | None = None
    github_url: str | None = None


class GroupOut(Out):
    id: str
    name: str
    description: str
    max_members: int
    requirements: list[str]
    domain: str
    created_by: str
    created_at: datetime
    members: list[GroupMemberOut]
    is_full: bool


class GroupPage(Out):
    items: list[GroupOut]
    nextCursor: str | None = None
    hasMore: bool


class GroupCreateIn(In):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=2000)
    max_members: int = Field(ge=2, le=20)
    requirements: list[Tag] = Field(default_factory=list, max_length=20)
    domain: str = Field(min_length=1, max_length=160)

    @field_validator("requirements")
    @classmethod
    def _requirements(cls, value: list[str]) -> list[str]:
        return _clean_list(value)


class GroupUpdateIn(In):
    # Group size is fixed: sending max_members is rejected in the route.

    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    requirements: list[Tag] | None = Field(default=None, max_length=20)
    domain: str | None = Field(default=None, max_length=160)
    # Accepted only so the route can answer "Group size cannot be changed".
    max_members: int | None = Field(default=None, ge=0, le=1000)

    @field_validator("requirements")
    @classmethod
    def _requirements(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _clean_list(value)


# --------------------------------------------------------------------------------------------
# Requests and recommendations
# --------------------------------------------------------------------------------------------


class JoinRequestOut(Out):
    id: str
    group_id: str
    group_name: str
    sender_id: str
    sender_name: str
    sender_college: str
    sender_passing_year: int
    receiver_id: str
    receiver_name: str | None = None
    receiver_college: str | None = None
    receiver_passing_year: int | None = None
    type: Literal["join_request", "invitation"]
    status: RequestStatus
    note: str | None = None
    created_at: datetime
    updated_at: datetime


class NoteIn(In):
    note: str = Field(default="", max_length=1000)


class InvitationIn(NoteIn):
    group_id: Id


class RespondIn(In):
    status: RequestStatus


class RecommendationOut(Out):
    id: str
    group_id: str
    recommender_id: str
    recommender_name: str
    student_id: str
    student_name: str
    note: str | None = None
    status: Literal["pending", "invited", "dismissed", "closed"]
    created_at: datetime
    updated_at: datetime


class RecommendationIn(In):
    groupId: Id
    studentId: Id
    # Ignored: the recommender is always the signed-in user.
    recommenderId: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=1000)


# --------------------------------------------------------------------------------------------
# Chat
# --------------------------------------------------------------------------------------------


class AttachmentIO(In):
    name: str = Field(max_length=255)
    url: str = Field(max_length=500)
    size: int = Field(ge=0)


class ChatMessageOut(Out):
    id: str
    conversation_id: str
    sender_id: str
    sender_name: str
    text: str
    attachment: AttachmentIO | None = None
    created_at: datetime
    # Echoes the sender's own id for an optimistic message, so its tab can swap it for this one.
    client_id: str | None = None


class ParticipantOut(Out):
    id: str
    name: str
    college: str
    avatar_url: str | None = None
    last_seen: datetime | None = None
    last_delivered_at: datetime | None = None
    last_read_at: datetime | None = None


class LastMessageOut(Out):
    text: str
    sender_name: str
    created_at: datetime


class ConversationOut(Out):
    id: str
    type: Literal["direct", "group"]
    title: str
    subtitle: str | None = None
    group_id: str | None = None
    participant_ids: list[str]
    participants: list[ParticipantOut]
    last_message: LastMessageOut | None = None
    unread: dict[str, int]
    updated_at: datetime


class SendMessageIn(In):
    text: str = Field(default="", max_length=4000)
    attachment: AttachmentIO | None = None
    client_id: str | None = Field(default=None, max_length=64)


class DirectIn(In):
    user_id: Id


# --------------------------------------------------------------------------------------------
# System and GitHub
# --------------------------------------------------------------------------------------------


class CountsOut(BaseModel):
    unreadChat: int
    pendingReceived: int
    outcomeUpdates: int


class SignupTotalOut(BaseModel):
    """GET /api/stats/signups: one number, nothing about anyone."""

    total: int


class GitHubLookupOut(BaseModel):
    valid: bool
    username: str
    contribution_count: int | None = None


class GitHubLanguage(BaseModel):
    name: str
    percentage: float
    color: str


class GitHubRepoOut(BaseModel):
    id: int
    name: str
    description: str | None = None
    html_url: str
    language: str | None = None
    stargazers_count: int
    forks_count: int
    updated_at: str


class GitHubActivityOut(BaseModel):
    username: str
    avatar_url: str
    public_repos: int
    contributions: int
    followers: int
    top_languages: list[GitHubLanguage]
    recent_repos: list[GitHubRepoOut]
