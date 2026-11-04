"""Unsafe settings for a public server.

    uv run python -m app.check_config

lists every problem with the current settings (.env and the environment) and exits with 1 if there
is any. The API itself refuses to start with the dangerous ones when COOKIE_SECURE=true (that is, on
HTTPS, a real deployment): see `startup_check`.
"""

import logging
import sys

from app.config import DEV_SECRET_KEY, Settings, get_settings

log = logging.getLogger("app.config")

WEAK_ADMIN_PASSWORDS = {"admin", "password", "admin123", "password123", "changeme", "admin-password-1"}


def problems(settings: Settings) -> list[tuple[str, str]]:
    """(severity, text) for every unsafe production setting. Severity "fatal" stops a secure
    deployment from starting; "warning" is listed by check_config only."""
    found: list[tuple[str, str]] = []
    if settings.secret_key == DEV_SECRET_KEY:
        found.append(("fatal", "SECRET_KEY is the development default: anyone could forge sessions"))
    elif len(set(settings.secret_key)) < 10:
        found.append(("warning", "SECRET_KEY looks weak: use 32+ random characters"))
    if settings.allow_dev_code:
        found.append(("fatal", "ALLOW_DEV_CODE=true returns password-reset codes to whoever asks"))
    if settings.demo_login:
        found.append(("fatal", "DEMO_LOGIN=true lets anyone sign in as any student without a password"))
    if not settings.cookie_secure:
        found.append(("warning", "COOKIE_SECURE=false: session cookies are also sent over plain HTTP"))
    if settings.sms_provider == "console":
        found.append(("warning", "SMS_PROVIDER=console: password-reset codes are only written to the server log"))
    if settings.admin_password and (
        len(settings.admin_password) < 12 or settings.admin_password.lower() in WEAK_ADMIN_PASSWORDS
    ):
        found.append(("warning", "ADMIN_PASSWORD is short or a common password: use 12+ random characters"))
    if any(o.startswith("http://") and "localhost" not in o and "127.0.0.1" not in o for o in settings.cors_origins):
        found.append(("warning", "CORS_ORIGINS includes a plain-HTTP origin"))
    return found


def startup_check(settings: Settings | None = None) -> None:
    """Called when the API starts. On HTTPS (COOKIE_SECURE=true) a fatal problem stops it; on
    plain HTTP (a laptop) the problems are logged as warnings."""
    settings = settings or get_settings()
    found = problems(settings)
    fatal = [text for severity, text in found if severity == "fatal"]
    if settings.cookie_secure and fatal:
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
    return 1


if __name__ == "__main__":
    sys.exit(main())
