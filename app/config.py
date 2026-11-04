"""Settings, read from the environment (and `.env`). See `.env.example` for every variable."""

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent

# The SECRET_KEY default: fine on a laptop, never on a public server.
DEV_SECRET_KEY = "dev-only-change-me-dev-only-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", env_file_encoding="utf-8", extra="ignore")

    # postgresql+psycopg://user:password@host:5432/capstoneconnect
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/capstoneconnect"

    # Signs session cookies and password-reset tokens. Must be long and random in production.
    secret_key: str = Field(default=DEV_SECRET_KEY, min_length=32)
    session_days: int = 14
    # Cookies need Secure over HTTPS (production); local http://localhost needs it off.
    cookie_secure: bool = False
    cookie_name: str = "cc_session"
    # "lax" (default) when the site and the API share a site (subdomains of one domain, or one
    # origin through a proxy); "none" only when they are on different sites, and then
    # COOKIE_SECURE must be true. See app.cookies for every layout.
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    # Empty: the cookie belongs to the API's host only. "example.com": shared by its subdomains.
    cookie_domain: str = ""
    # Reverse proxies whose X-Forwarded-For / X-Forwarded-Proto are believed (comma-separated IPs
    # or networks, or "*" when only the proxy can reach the API). Empty: those headers are ignored
    # and the connecting address is the visitor's (the per-IP sign-in limits use it).
    trusted_proxy_ips: str = ""
    # How many reports one student may send in 24 hours.
    reports_per_day: int = 10
    # Tests only: /api/health also reports which worker process answered.
    expose_worker_pid: bool = False

    # The frontend origins allowed to call the API with cookies.
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Public URL prefix the API is served under (the frontend's NEXT_PUBLIC_API_BASE_URL).
    api_prefix: str = "/api"
    # Where uploaded avatars, resumes and chat attachments are stored, and their public base URL.
    upload_dir: Path = ROOT / "uploads"
    public_base_url: str = "http://localhost:8000"
    # "local" (UPLOAD_DIR, needs a persistent disk) or "s3" (any S3-compatible object storage:
    # AWS S3, Cloudflare R2, Backblaze B2, MinIO). See app.services.storage.
    storage_backend: Literal["local", "s3"] = "local"
    s3_bucket: str = ""
    s3_endpoint_url: str = ""  # empty for AWS; e.g. https://<account>.r2.cloudflarestorage.com
    s3_region: str = ""
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_prefix: str = ""  # optional folder inside the bucket

    # Password reset by SMS one-time code.
    otp_length: int = 6
    otp_ttl_minutes: int = 10
    otp_max_attempts: int = 5
    otp_resend_seconds: int = 60
    reset_token_minutes: int = 15
    # "console" logs the code (development); "twilio" sends a real SMS.
    sms_provider: str = "console"
    # Return the reset code in the API answer (dev_code) so the flow works without a phone.
    # Only with SMS_PROVIDER=console, and never on a public server: anyone who knows a phone
    # number could reset that account.
    allow_dev_code: bool = False
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

    # Sign-in, sign-up and password-reset throttling, per phone number and per IP address
    # (counters are in PostgreSQL, so every worker shares them). attempts / minutes.
    login_limit_per_phone: int = 5
    login_limit_per_ip: int = 20
    login_window_minutes: int = 15
    signup_limit_per_phone: int = 5
    signup_limit_per_ip: int = 10
    signup_window_minutes: int = 60
    reset_limit_per_phone: int = 5
    reset_limit_per_ip: int = 20
    reset_window_minutes: int = 60
    verify_limit_per_phone: int = 10
    verify_limit_per_ip: int = 30
    verify_window_minutes: int = 15


    @model_validator(mode="after")
    def _cookie_rules(self) -> "Settings":
        if self.cookie_samesite == "none" and not self.cookie_secure:
            raise ValueError("COOKIE_SAMESITE=none needs COOKIE_SECURE=true (browsers drop SameSite=None cookies without Secure)")
        domain = self.cookie_domain.strip()
        if domain and not re.fullmatch(r"\.?([a-z0-9-]+\.)+[a-z]{2,}", domain.lower()):
            raise ValueError("COOKIE_DOMAIN must be a domain like example.com (no scheme, port or path)")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
