"""GitHub: username checks, the contribution total and the profile activity summary.

The total is GitHub's own profile headline: "N contributions in the last year" (the rolling
year ending today, private contributions included when the user shares them).
- With GITHUB_TOKEN: GraphQL `contributionsCollection` with no from/to (GitHub's default window is
  that same rolling year; windows over one year are refused by GitHub, so none is asked for).
- Without a token: the public calendar page (github.com/users/<login>/contributions, no dates),
  whose heading is that headline. Not api.github.com, so the API's 60/hour limit can't starve it.

Results are cached on the user (`github_contribution_count`, `github_synced_at`) and refreshed
when older than GITHUB_REFRESH_HOURS. A failed lookup never touches the cached total, and an
incomplete one (no headline found, only day cells added up) never lowers it.
"""

import asyncio
import ipaddress
import logging
import re
import socket
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

import httpx

from app.config import get_settings

log = logging.getLogger(__name__)

API = "https://api.github.com"
USERNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
# Applied to a page from another host: every repetition is bounded and starts only at the start of
# a number, so the time is linear in the page size (no ReDoS from a hostile or huge response).
YEAR_TOTAL = re.compile(r"(?<![\d,])(\d[\d,]{0,14})\s{1,20}contributions?\s{1,20}in\s{1,20}(\d{4}|the\s{1,20}last\s{1,20}year)")
DAY_COUNT = re.compile(r"(?<!\d)(\d{1,7}) contributions? on")

# Colours for the language bar (GitHub's linguist colours for the common ones).
LANGUAGE_COLORS = {
    "Python": "#3572A5", "TypeScript": "#3178C6", "JavaScript": "#F1E05A", "Java": "#B07219",
    "C++": "#F34B7D", "C": "#555555", "C#": "#178600", "Go": "#00ADD8", "Rust": "#DEA584",
    "Kotlin": "#A97BFF", "Swift": "#F05138", "Ruby": "#701516", "PHP": "#4F5D95", "Dart": "#00B4AB",
    "HTML": "#E34C26", "CSS": "#563D7C", "Jupyter Notebook": "#DA5B0B", "Shell": "#89E051",
    "MATLAB": "#E16737", "Verilog": "#B2B7F8", "VHDL": "#ADB2CB", "Solidity": "#AA6746", "R": "#198CE7",
}


class GitHubUnavailable(Exception):
    """GitHub did not answer (offline, rate limited, error)."""


class GitHubBlocked(GitHubUnavailable):
    """A request the guard refused: another host or scheme, a private address, a redirect, too big."""


# ---------------------------------------------------------------------------------------------
# Outbound requests (SSRF guard). Only the two GitHub hosts, over HTTPS on 443, to public
# addresses (checked when resolving and again on the connected socket, so DNS rebinding to an
# internal address is refused), no redirects, short timeouts, at most MAX_BYTES of uncompressed
# body. Usernames are checked against USERNAME before they reach a URL path.
# ---------------------------------------------------------------------------------------------

ALLOWED_HOSTS = frozenset({"api.github.com", "github.com"})
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def _public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


async def _resolve(host: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


class GuardedTransport(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport | None = None, require_peer: bool = True):
        self.inner = inner or httpx.AsyncHTTPTransport(retries=0)
        self.require_peer = require_peer

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.scheme != "https" or url.host not in ALLOWED_HOSTS or url.port not in (None, 443) or url.userinfo:
            raise GitHubBlocked(f"refused a request to {url.scheme}://{url.host}")
        try:
            addresses = await _resolve(url.host)
        except OSError as exc:
            raise GitHubUnavailable(f"could not resolve {url.host}") from exc
        if not addresses or not all(_public(a) for a in addresses):
            raise GitHubBlocked(f"{url.host} resolves to a non-public address")
        response = await self.inner.handle_async_request(request)
        try:
            stream = response.extensions.get("network_stream")
            peer = stream.get_extra_info("server_addr") if stream is not None else None
            if peer is None:
                if self.require_peer:
                    raise GitHubBlocked("could not confirm the connected address")
            elif not _public(str(peer[0])):
                raise GitHubBlocked("connected to a non-public address")
            if 300 <= response.status_code < 400:
                raise GitHubBlocked("redirects are not followed")
            encoding = response.headers.get("content-encoding", "identity").lower()
            if encoding not in ("", "identity"):
                raise GitHubBlocked(f"refused a {encoding}-encoded body")
            declared = response.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > MAX_BYTES:
                raise GitHubBlocked("response too large")
            body = bytearray()
            async for chunk in response.stream:  # the raw bytes, as they arrive
                body += chunk
                if len(body) > MAX_BYTES:
                    raise GitHubBlocked("response too large")
        finally:
            await response.aclose()
        headers = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in ("content-length", "transfer-encoding")]
        return httpx.Response(response.status_code, headers=headers, content=bytes(body), request=request)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=GuardedTransport(), timeout=TIMEOUT, follow_redirects=False,
                             limits=httpx.Limits(max_connections=8, max_keepalive_connections=4))


def username_from(value: str | None) -> str | None:
    """'https://github.com/foo', 'github.com/foo/', '@foo' or 'foo' -> 'foo' (None if not a valid name)."""
    if not value:
        return None
    text = value.strip().rstrip("/")
    text = re.sub(r"^(https?://)?(www\.)?github\.com/", "", text, flags=re.I).lstrip("@")
    name = text.split("/")[0]
    return name if USERNAME.match(name) else None


def _login(profile: dict, fallback: str) -> str:
    """GitHub's spelling of the username, only if it is a valid one (it goes into URLs and links)."""
    login = profile.get("login")
    return login if isinstance(login, str) and USERNAME.match(login) else fallback


def _headers(json: bool = True) -> dict[str, str]:
    # identity: the size cap counts real bytes (no compressed "zip bomb" to unpack).
    headers = {"User-Agent": "CapstoneConnect", "Accept-Encoding": "identity"}
    if json:
        headers["Accept"] = "application/vnd.github+json"
    token = get_settings().github_token
    if token and json:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def fetch_profile(client: httpx.AsyncClient, username: str) -> dict | None:
    """The public profile, or None if no such user. Raises GitHubUnavailable if GitHub won't say."""
    try:
        response = await client.get(f"{API}/users/{username}", headers=_headers())
    except httpx.HTTPError as exc:
        raise GitHubUnavailable(str(exc)) from exc
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise GitHubUnavailable(f"GitHub answered {response.status_code}")
    try:
        profile = response.json()
    except ValueError as exc:
        raise GitHubUnavailable("GitHub sent something that isn't JSON") from exc
    if not isinstance(profile, dict):
        raise GitHubUnavailable("GitHub sent an unexpected answer")
    return profile


class Total(NamedTuple):
    count: int
    complete: bool  # False: the headline was missing and only the day cells were added up


async def _last_year_graphql(client: httpx.AsyncClient, login: str) -> Total:
    query = "query($login: String!) { user(login: $login) { contributionsCollection { contributionCalendar { totalContributions } } } }"
    try:
        response = await client.post(f"{API}/graphql", json={"query": query, "variables": {"login": login}}, headers=_headers())
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise GitHubUnavailable(str(exc)) from exc
    if not isinstance(data, dict) or not isinstance(data.get("data") or {}, dict):
        raise GitHubUnavailable("GraphQL answered in an unexpected shape")
    user = (data.get("data") or {}).get("user")
    if response.status_code != 200 or not user:
        raise GitHubUnavailable(f"GraphQL: {data.get('errors') or response.status_code}")
    try:
        value = user["contributionsCollection"]["contributionCalendar"]["totalContributions"]
    except (KeyError, TypeError) as exc:
        raise GitHubUnavailable("GraphQL answered in an unexpected shape") from exc
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 10**9:
        raise GitHubUnavailable("GraphQL answered in an unexpected shape")
    return Total(value, True)


def parse_calendar(text: str) -> Total:
    """GitHub's calendar fragment: the headline ("2,299 contributions in the last year", or "in
    2026" on a calendar-year page), else the day cells added up (marked incomplete)."""
    heading = YEAR_TOTAL.search(text)
    if heading:
        return Total(int(heading.group(1).replace(",", "")), True)
    return Total(sum(int(n) for n in DAY_COUNT.findall(text)), False)


async def _last_year_calendar(client: httpx.AsyncClient, login: str) -> Total:
    try:
        response = await client.get(
            f"https://github.com/users/{login}/contributions",
            headers={**_headers(json=False), "X-Requested-With": "XMLHttpRequest"},
        )
    except httpx.HTTPError as exc:
        raise GitHubUnavailable(str(exc)) from exc
    if response.status_code != 200:
        raise GitHubUnavailable(f"Calendar answered {response.status_code}")
    return parse_calendar(response.text)


async def last_year_total(client: httpx.AsyncClient, login: str) -> Total:
    """The profile headline for `login` (already checked against USERNAME)."""
    if get_settings().github_token:
        try:
            return await _last_year_graphql(client, login)
        except GitHubUnavailable as exc:
            log.warning("GitHub GraphQL failed for %s (%s); reading the public calendar", login, exc)
    return await _last_year_calendar(client, login)


async def contributions(username: str, client: httpx.AsyncClient | None = None) -> tuple[dict, Total] | None:
    """(profile, total in the last year), or None if the user does not exist. Raises GitHubUnavailable."""
    if not USERNAME.match(username or ""):
        return None
    own = client is None
    client = client or _client()
    try:
        profile = await fetch_profile(client, username)
        if profile is None:
            return None
        return profile, await last_year_total(client, _login(profile, username))
    finally:
        if own:
            await client.aclose()


def apply_total(user, total: Total) -> None:
    """Stores a fresh total on the user. An incomplete one never lowers a cached figure."""
    cached = user.github_contribution_count
    if total.complete or cached is None or total.count >= cached:
        user.github_contribution_count = total.count
    user.github_synced_at = datetime.now(UTC)


REPO_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
AVATAR_HOST = "https://avatars.githubusercontent.com/"


def _number(value: object) -> int:
    return value if isinstance(value, int) and 0 <= value < 10**9 else 0


def _text(value: object, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def _avatar(value: object) -> str:
    """Only GitHub's own avatar host (the site's CSP allows no other for images)."""
    return value if isinstance(value, str) and value.startswith(AVATAR_HOST) and len(value) < 500 else ""


def repo_row(repo: dict, login: str) -> dict | None:
    """A repository from GitHub's answer, as the site shows it. That answer comes from another
    host, so nothing in it is trusted: the link is rebuilt from the owner and a checked name
    (never taken from html_url), text is cut to size, numbers must be numbers."""
    name = repo.get("name")
    if not isinstance(name, str) or not REPO_NAME.match(name) or name in (".", "..") or not USERNAME.match(login or ""):
        return None
    return {
        "id": _number(repo.get("id")),
        "name": name,
        "description": _text(repo.get("description"), 300),
        "html_url": f"https://github.com/{login}/{name}",
        "language": _text(repo.get("language"), 60),
        "stargazers_count": _number(repo.get("stargazers_count")),
        "forks_count": _number(repo.get("forks_count")),
        "updated_at": _text(repo.get("pushed_at") or repo.get("updated_at"), 40) or "",
    }


async def activity(username: str, contributions: int) -> dict:
    """Profile summary for the Repositories panel: counts, top languages, recently updated repos."""
    if not USERNAME.match(username or ""):
        raise GitHubUnavailable("Not a GitHub username")
    async with _client() as client:
        profile = await fetch_profile(client, username)
        if profile is None:
            raise GitHubUnavailable("No such GitHub user")
        try:
            response = await client.get(
                f"{API}/users/{_login(profile, username)}/repos",
                params={"sort": "updated", "per_page": 100, "type": "owner"},
                headers=_headers(),
            )
        except httpx.HTTPError as exc:
            raise GitHubUnavailable(str(exc)) from exc
        try:
            repos = response.json() if response.status_code == 200 else []
        except ValueError:
            repos = []
    if not isinstance(repos, list):
        repos = []

    own = [r for r in repos[:100] if isinstance(r, dict) and not r.get("fork")]
    languages = Counter(r["language"][:60] for r in own if isinstance(r.get("language"), str) and r["language"])
    total = sum(languages.values()) or 1
    top = [
        {"name": name, "percentage": round(100 * count / total, 1), "color": LANGUAGE_COLORS.get(name, "#8B949E")}
        for name, count in languages.most_common(4)
    ]
    login = _login(profile, username)
    recent = [row for row in (repo_row(r, login) for r in own[:6]) if row]
    return {
        "username": login,
        "avatar_url": _avatar(profile.get("avatar_url")),
        "public_repos": _number(profile.get("public_repos")),
        "contributions": contributions,
        "followers": _number(profile.get("followers")),
        "top_languages": top,
        "recent_repos": recent,
    }


def is_stale(synced_at: datetime | None) -> bool:
    if synced_at is None:
        return True
    hours = get_settings().github_refresh_hours
    return datetime.now(UTC) - synced_at > timedelta(hours=hours)


async def refresh_count(username: str) -> Total:
    """Only the calendar/GraphQL total of an already verified username (no api.github.com call)."""
    if not USERNAME.match(username or ""):
        raise GitHubUnavailable("Not a GitHub username")
    async with _client() as client:
        return await last_year_total(client, username)


async def sync_user(user_id: str, fresh: bool = False) -> None:
    """Refreshes a user's cached total (in the background after sign-up, or when stale). Any
    failure leaves the cached total and its date as they were, so the next view tries again."""
    from app.db import SessionLocal
    from app.models import User

    with SessionLocal() as db:
        user = db.get(User, user_id)
        username = username_from(user.github_url if user else None)
        if user is None or username is None:
            return
        try:
            if fresh and user.github_verified:
                apply_total(user, await refresh_count(username))
            else:
                result = await (contributions(username) if fresh else lookup(username))
                if result is None:
                    user.github_verified = False
                else:
                    profile, total = result
                    user.github_url = f"https://github.com/{_login(profile, username)}"
                    user.github_verified = True
                    apply_total(user, total)
        except GitHubUnavailable as exc:
            log.warning("GitHub sync for %s skipped: %s", user_id, exc)
            return
        db.commit()


# Lookups are cached briefly: the signup and profile forms check a username and then save it,
# so the second request reuses the first answer instead of walking the calendar again.
_LOOKUPS: dict[str, tuple[datetime, tuple[dict, Total] | None]] = {}
_LOOKUP_TTL = timedelta(minutes=10)
_LOOKUP_MAX = 1000  # bounded: a stream of made-up names can't grow it without end


async def lookup(username: str) -> tuple[dict, Total] | None:
    if not USERNAME.match(username or ""):
        return None
    key = username.lower()
    cached = _LOOKUPS.get(key)
    if cached and datetime.now(UTC) - cached[0] < _LOOKUP_TTL:
        return cached[1]
    result = await contributions(username)
    if len(_LOOKUPS) >= _LOOKUP_MAX:
        _LOOKUPS.pop(next(iter(_LOOKUPS)))  # the oldest entry
    _LOOKUPS[key] = (datetime.now(UTC), result)
    return result
