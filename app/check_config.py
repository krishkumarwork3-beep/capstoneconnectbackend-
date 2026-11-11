"""Unsafe settings for a public server.

    uv run python -m app.check_config

lists every problem with the current settings (.env and the environment) and exits with 1 if there
is any. The API itself refuses to start with the dangerous ones when COOKIE_SECURE=true (that is, on
HTTPS, a real deployment): see `startup_check`.
"""

import logging
import sys

from app.config import DEV_BLIND_INDEX_KEY, DEV_FIELD_ENCRYPTION_KEYS, DEV_SECRET_KEY, Settings, get_settings

log = logging.getLogger("app.config")

WEAK_ADMIN_PASSWORDS = {"admin", "password", "admin123", "password123", "changeme", "admin-password-1"}


def problems(settings: Settings) -> list[tuple[str, str]]:
    """(severity, text) for every unsafe production setting. Severity "fatal" stops a secure
    deployment from starting; "warning" is listed by check_config only."""
    found: list[tuple[str, str]] = []
    production = settings.app_env == "production"
    if settings.secret_key == DEV_SECRET_KEY:
        found.append(("fatal", "SECRET_KEY is the development default: anyone could forge sessions"))
    elif production and len(settings.secret_key) < 32:
        found.append(("fatal", "SECRET_KEY is shorter than 32 characters"))
    elif len(set(settings.secret_key)) < 10:
        found.append(("warning", "SECRET_KEY looks weak: use 32+ random characters"))
    found += _key_problems(settings)
    if settings.allow_dev_code:
        found.append(("fatal", "ALLOW_DEV_CODE=true returns password-reset codes to whoever asks"))
    if settings.demo_login:
        found.append(("fatal", "DEMO_LOGIN=true lets anyone sign in as any student without a password"))
    if not settings.cookie_secure:
        found.append(("fatal" if production else "warning", "COOKIE_SECURE=false: session cookies are also sent over plain HTTP"))
    if settings.sms_provider == "console":
        found.append(("fatal" if production else "warning",
                      "SMS_PROVIDER=console: password-reset codes are only written to the server log"))
    if settings.admin_password and (
        len(settings.admin_password) < 12 or settings.admin_password.lower() in WEAK_ADMIN_PASSWORDS
    ):
        found.append(("warning", "ADMIN_PASSWORD is short or a common password: use 12+ random characters"))
    if settings.sms_provider == "twilio" and not (settings.twilio_account_sid and settings.twilio_auth_token and settings.twilio_from_number):
        found.append(("fatal", "SMS_PROVIDER=twilio but TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN or TWILIO_FROM_NUMBER is missing"))
    if settings.storage_backend == "s3" and not settings.s3_bucket:
        found.append(("fatal", "STORAGE_BACKEND=s3 but S3_BUCKET is empty"))
    if settings.cookie_secure and settings.public_base_url.startswith("http://"):
        found.append(("warning", "PUBLIC_BASE_URL is http:// while cookies are Secure: file links would be mixed content"))
    if any(o.startswith("http://") and "localhost" not in o and "127.0.0.1" not in o for o in settings.cors_origins):
        found.append(("warning", "CORS_ORIGINS includes a plain-HTTP origin"))
    if production:
        found.extend(_production_url_problems(settings))
    return found


LOCAL_NAMES = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def _is_local_or_http(url: str) -> bool:
    from urllib.parse import urlsplit

    parts = urlsplit(url.strip())
    return parts.scheme != "https" or (parts.hostname or "") in LOCAL_NAMES or (parts.hostname or "").endswith(".localhost")


def _production_url_problems(settings: Settings) -> list[tuple[str, str]]:
    """APP_ENV=production: the public addresses must be real https ones, the host list explicit."""
    found: list[tuple[str, str]] = []
    if not settings.cors_origins or any(_is_local_or_http(o) for o in settings.cors_origins):
        found.append(("fatal", "CORS_ORIGINS must list only the https:// origins of the site and the portal (no localhost, no http://)"))
    if _is_local_or_http(settings.public_base_url):
        found.append(("fatal", "PUBLIC_BASE_URL must be the API's public https:// address (not localhost, not http://)"))
    hosts = [h.strip() for h in settings.allowed_hosts if h.strip()]
    if not hosts or "*" in hosts:
        found.append(("fatal", "ALLOWED_HOSTS must name the API's host names (empty or * accepts any Host header)"))
    if not settings.github_token:
        found.append(("warning", "GITHUB_TOKEN is empty: GitHub lookups are anonymous (60 an hour per server address); "
                                 "stored totals are kept when a lookup is refused"))
    return found


def _key_problems(settings: Settings) -> list[tuple[str, str]]:
    """The field-encryption and blind-index keys: present, well formed, not the development
    defaults, and not the same as each other or the JWT secret."""
    from app import crypto

    found: list[tuple[str, str]] = []
    try:
        _, field_keys = crypto._parse_keys(settings.field_encryption_keys)
    except crypto.FieldCryptoError as exc:
        return [("fatal", f"FIELD_ENCRYPTION_KEYS: {exc}")]
    try:
        blind = crypto._blind_key(settings.blind_index_key)
    except crypto.FieldCryptoError as exc:
        return [("fatal", f"BLIND_INDEX_KEY: {exc}")]
    dev_field = set(crypto._parse_keys(DEV_FIELD_ENCRYPTION_KEYS)[1].values())
    if set(field_keys.values()) & dev_field:
        found.append(("fatal", "FIELD_ENCRYPTION_KEYS includes the development key: phone numbers and messages are readable by anyone with the repo"))
    if settings.blind_index_key.strip() == DEV_BLIND_INDEX_KEY:
        found.append(("fatal", "BLIND_INDEX_KEY is the development default"))
    secret = settings.secret_key.encode()
    if blind in field_keys.values() or any(k == secret or k in secret for k in [blind, *field_keys.values()]):
        found.append(("fatal", "BLIND_INDEX_KEY, FIELD_ENCRYPTION_KEYS and SECRET_KEY must all be different keys"))
    if settings.blind_index_key.strip() in (settings.secret_key, *settings.field_encryption_keys.split(",")):
        found.append(("fatal", "BLIND_INDEX_KEY, FIELD_ENCRYPTION_KEYS and SECRET_KEY must all be different keys"))
    return found


def startup_check(settings: Settings | None = None) -> None:
    """Called when the API starts. With APP_ENV=production (or on HTTPS, COOKIE_SECURE=true) a
    fatal problem stops it; on a developer's laptop the problems are logged as warnings."""
    settings = settings or get_settings()
    found = problems(settings)
    fatal = [text for severity, text in found if severity == "fatal"]
    if (settings.app_env == "production" or settings.cookie_secure) and fatal:
        raise RuntimeError("Unsafe settings for a public server: " + "; ".join(fatal) + ". Run `python -m app.check_config`.")
    if settings.cookie_secure and settings.sms_provider == "console":
        log.warning("!!! SMS_PROVIDER=console with COOKIE_SECURE=true: no password-reset SMS is sent !!!")
    for text in fatal:
        log.warning("Development setting: %s", text)


def main() -> int:
    found = problems(get_settings())
    if not found:
        print("No unsafe production settings found.")
        return 0
    for severity, text in found:
        print(f"{'FATAL  ' if severity == 'fatal' else 'warning'}  {text}")
    print(f"\n{len(found)} problem(s). FATAL ones stop the API from starting when COOKIE_SECURE=true.")
    # Warnings alone (say, no GITHUB_TOKEN) pass; any fatal problem fails (exit 1). The development
    # defaults (SECRET_KEY, field keys) are fatal, so a laptop's settings still exit 1.
    return 1 if any(severity == "fatal" for severity, _ in found) else 0


if __name__ == "__main__":
    sys.exit(main())
