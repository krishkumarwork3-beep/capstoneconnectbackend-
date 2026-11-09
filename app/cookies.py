"""Session cookies (students' and admins'), set the same way everywhere from the settings.

Which settings work for where the site, the admin portal and the API are served:

| Layout | COOKIE_SAMESITE | COOKIE_SECURE | COOKIE_DOMAIN |
| --- | --- | --- | --- |
| One machine, plain http://localhost | lax | false | (empty) |
| Same site, subdomains: app.example.com + admin.example.com + api.example.com | lax | true | (empty, or example.com to share one cookie across subdomains) |
| Same origin through a proxy: example.com/api → the API | lax | true | (empty) |
| Different sites: app.vercel.app + api.onrender.com | none | true | (empty) |

"Same site" means the same registrable domain (example.com); ports and subdomains don't matter.
Browsers send a SameSite=Lax cookie only within the same site, so the last layout needs
SameSite=None, which browsers only accept with Secure (HTTPS). The live chat socket is signed in
by the same cookie, so it works in every layout above. Some browsers (Safari) also block
third-party cookies outright, so the cross-site layout is the least reliable; prefer subdomains.
"""

from fastapi import Response

from app.config import get_settings


def set_session_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    s = get_settings()
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,
        secure=s.cookie_secure,
        samesite=s.cookie_samesite,
        domain=s.cookie_domain or None,
        path="/",
    )


def clear_session_cookie(response: Response, name: str) -> None:
    s = get_settings()
    # A cookie is only removed with the same domain, path and flags it was set with.
    response.delete_cookie(name, path="/", domain=s.cookie_domain or None, secure=s.cookie_secure,
                           httponly=True, samesite=s.cookie_samesite)


def can_use_host_prefix() -> bool:
    """`__Host-` cookies are pinned by the browser to this exact host, over HTTPS, for the whole
    path: no subdomain or plain-http page can set or overwrite them. Possible only when the
    cookie is Secure and has no Domain."""
    s = get_settings()
    return s.cookie_secure and not (s.cookie_domain or "").strip()


def student_cookie() -> str:
    name = get_settings().cookie_name
    return f"__Host-{name}" if can_use_host_prefix() else name


def admin_cookie() -> str:
    name = get_settings().admin_cookie_name
    return f"__Host-{name}" if can_use_host_prefix() else name


def refresh_cookie() -> str:
    name = get_settings().refresh_cookie_name
    return f"__Host-{name}" if can_use_host_prefix() else name


def admin_refresh_cookie() -> str:
    name = get_settings().admin_refresh_cookie_name
    return f"__Host-{name}" if can_use_host_prefix() else name


def set_sign_in_cookies(response: Response, kind: str, access: str, refresh: str | None, refresh_max_age: int) -> None:
    """The short access token (ACCESS_TOKEN_MINUTES) and, when one was issued, the refresh token
    (until the session's absolute end). Both HttpOnly, Secure (in production), SameSite, __Host-."""
    access_name, refresh_name = (student_cookie(), refresh_cookie()) if kind == "student" else (admin_cookie(), admin_refresh_cookie())
    set_session_cookie(response, access_name, access, get_settings().access_token_minutes * 60)
    if refresh:
        set_session_cookie(response, refresh_name, refresh, max(0, refresh_max_age))


def clear_sign_in_cookies(response: Response, kind: str) -> None:
    for name in ((student_cookie(), refresh_cookie()) if kind == "student" else (admin_cookie(), admin_refresh_cookie())):
        clear_session_cookie(response, name)


def all_session_cookie_names() -> set[str]:
    """Every cookie that signs someone in (the CSRF check in app.guard looks for any of them)."""
    s = get_settings()
    names = {s.cookie_name, s.admin_cookie_name, s.refresh_cookie_name, s.admin_refresh_cookie_name}
    return names | {f"__Host-{n}" for n in names}
