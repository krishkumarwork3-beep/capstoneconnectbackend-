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
