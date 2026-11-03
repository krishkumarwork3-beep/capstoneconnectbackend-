"""Settings, read from the environment (and `.env`). See `.env.example` for every variable."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", env_file_encoding="utf-8", extra="ignore")

    # postgresql+psycopg://user:password@host:5432/capstoneconnect
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/capstoneconnect"

    # Signs session cookies and password-reset tokens. Must be long and random in production.
    secret_key: str = Field(default="dev-only-change-me-dev-only-change-me", min_length=32)
    session_days: int = 14
    # Cookies need Secure over HTTPS (production); local http://localhost needs it off.
    cookie_secure: bool = False
    cookie_name: str = "cc_session"

    # The frontend origins allowed to call the API with cookies.
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Public URL prefix the API is served under (the frontend's NEXT_PUBLIC_API_BASE_URL).
    api_prefix: str = "/api"
    # Where uploaded avatars, resumes and chat attachments are stored, and their public base URL.
    upload_dir: Path = ROOT / "uploads"
    public_base_url: str = "http://localhost:8000"

    # Password reset by SMS one-time code.
    otp_length: int = 6
    otp_ttl_minutes: int = 10
    otp_max_attempts: int = 5
    otp_resend_seconds: int = 60
    reset_token_minutes: int = 15
    # "console" logs the code (development); "twilio" sends a real SMS.
    sms_provider: str = "console"
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""

    # GitHub: a token (no scopes needed) lets the GraphQL API return exact all-time totals and
    # raises the rate limit; without one the public contribution pages are read instead.
    github_token: str = ""
    # A cached contribution total older than this is refreshed when a profile is viewed.
    github_refresh_hours: int = 24

    # Lets the demo persona switcher sign in as a seeded student without a password.
    # Never enable in production.
    demo_login: bool = False

    # Admin portal (../adminportal). Its own session cookie, separate from students'.
    admin_cookie_name: str = "cc_admin"
    admin_session_hours: int = 12
    # First admin, created at startup if no admin has this email yet (later admins are added in
    # the portal, or with `uv run python -m app.admin_cli create`). Leave empty to skip.
    admin_email: str = ""
    admin_password: str = ""
    admin_name: str = "Site admin"


@lru_cache
def get_settings() -> Settings:
    return Settings()
