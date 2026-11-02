"""GitHub: username checks, all-time contribution totals and the profile activity summary.

All-time contributions = the contribution calendar's total for every year since the account was
created (GitHub only reports them a year at a time).
- With GITHUB_TOKEN: one GraphQL query, a `contributionsCollection` per year.
- Without a token: the public calendar page for each year ("1,234 contributions in 2023"), which
  is what github.com shows on the profile. Same numbers; slower and rate-limited by IP.

Results are cached on the user (`github_contribution_count`, `github_synced_at`); a GitHub outage
never breaks a page, the cached total is used instead.
"""

import asyncio
import logging
import re
from collections import Counter
from datetime import UTC, datetime, timedelta

import httpx

from app.config import get_settings

log = logging.getLogger(__name__)

API = "https://api.github.com"
USERNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
YEAR_TOTAL = re.compile(r"([\d,]+)\s+contributions?\s+in\s+(\d{4})", re.S)
DAY_COUNT = re.compile(r"(\d+) contributions? on")

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


def username_from(value: str | None) -> str | None:
    """'https://github.com/foo', 'github.com/foo/', '@foo' or 'foo' -> 'foo' (None if not a valid name)."""
    if not value:
        return None
    text = value.strip().rstrip("/")
    text = re.sub(r"^(https?://)?(www\.)?github\.com/", "", text, flags=re.I).lstrip("@")
    name = text.split("/")[0]
    return name if USERNAME.match(name) else None


def _headers(json: bool = True) -> dict[str, str]:
    headers = {"User-Agent": "CapstoneConnect"}
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
    return response.json()


async def _all_time_graphql(client: httpx.AsyncClient, username: str, years: list[int]) -> int:
    parts = [
        f'y{year}: contributionsCollection(from: "{year}-01-01T00:00:00Z", to: "{year}-12-31T23:59:59Z") '
        "{ contributionCalendar { totalContributions } }"
        for year in years
    ]
    query = f"query($login: String!) {{ user(login: $login) {{ {' '.join(parts)} }} }}"
    try:
        response = await client.post(
            f"{API}/graphql", json={"query": query, "variables": {"login": username}}, headers=_headers()
        )
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise GitHubUnavailable(str(exc)) from exc
    user = (data.get("data") or {}).get("user")
    if response.status_code != 200 or not user:
        raise GitHubUnavailable(f"GraphQL: {data.get('errors') or response.status_code}")
    return sum(user[f"y{year}"]["contributionCalendar"]["totalContributions"] for year in years)


async def _year_from_calendar(client: httpx.AsyncClient, username: str, year: int) -> int:
    try:
        response = await client.get(
            f"https://github.com/users/{username}/contributions",
            params={"from": f"{year}-01-01", "to": f"{year}-12-31"},
            headers={**_headers(json=False), "X-Requested-With": "XMLHttpRequest"},
            follow_redirects=True,
        )
    except httpx.HTTPError as exc:
        raise GitHubUnavailable(str(exc)) from exc
    if response.status_code != 200:
        raise GitHubUnavailable(f"Calendar answered {response.status_code}")
    heading = YEAR_TOTAL.search(response.text)
    if heading and int(heading.group(2)) == year:
        return int(heading.group(1).replace(",", ""))
    # No heading (layout change): add up the days.
    return sum(int(n) for n in DAY_COUNT.findall(response.text))


async def _all_time_calendar(client: httpx.AsyncClient, username: str, years: list[int]) -> int:
    gate = asyncio.Semaphore(4)

    async def one(year: int) -> int:
        async with gate:
            return await _year_from_calendar(client, username, year)

    return sum(await asyncio.gather(*(one(year) for year in years)))


def _years_since(created_at: str | None) -> list[int]:
    now = datetime.now(UTC).year
    start = int(created_at[:4]) if created_at else now - 9
    return list(range(max(2008, start), now + 1))


async def all_time_contributions(username: str, client: httpx.AsyncClient | None = None) -> tuple[dict, int] | None:
    """(profile, all-time total), or None if the user does not exist. Raises GitHubUnavailable."""
    own = client is None
    client = client or httpx.AsyncClient(timeout=20)
    try:
        profile = await fetch_profile(client, username)
        if profile is None:
            return None
        years = _years_since(profile.get("created_at"))
        login = profile.get("login") or username
        if get_settings().github_token:
            try:
                return profile, await _all_time_graphql(client, login, years)
            except GitHubUnavailable as exc:
                log.warning("GitHub GraphQL failed for %s (%s); reading the public calendar", login, exc)
        return profile, await _all_time_calendar(client, login, years)
    finally:
        if own:
            await client.aclose()


async def activity(username: str, contributions: int) -> dict:
    """Profile summary for the Repositories panel: counts, top languages, recently updated repos."""
    async with httpx.AsyncClient(timeout=20) as client:
        profile = await fetch_profile(client, username)
        if profile is None:
            raise GitHubUnavailable("No such GitHub user")
        try:
            response = await client.get(
                f"{API}/users/{profile['login']}/repos",
                params={"sort": "updated", "per_page": 100, "type": "owner"},
                headers=_headers(),
            )
        except httpx.HTTPError as exc:
            raise GitHubUnavailable(str(exc)) from exc
        repos = response.json() if response.status_code == 200 else []

    own = [r for r in repos if not r.get("fork")]
    languages = Counter(r["language"] for r in own if r.get("language"))
    total = sum(languages.values()) or 1
    top = [
        {"name": name, "percentage": round(100 * count / total, 1), "color": LANGUAGE_COLORS.get(name, "#8B949E")}
        for name, count in languages.most_common(4)
    ]
    recent = [
        {
            "id": r["id"],
            "name": r["name"],
            "description": r.get("description"),
            "html_url": r["html_url"],
            "language": r.get("language"),
            "stargazers_count": r.get("stargazers_count", 0),
            "forks_count": r.get("forks_count", 0),
            "updated_at": r.get("pushed_at") or r.get("updated_at") or "",
        }
        for r in own[:6]
    ]
    return {
        "username": profile["login"],
        "avatar_url": profile.get("avatar_url") or "",
        "public_repos": profile.get("public_repos", 0),
        "contributions": contributions,
        "followers": profile.get("followers", 0),
        "top_languages": top,
        "recent_repos": recent,
    }


def is_stale(synced_at: datetime | None) -> bool:
    if synced_at is None:
        return True
    hours = get_settings().github_refresh_hours
    return datetime.now(UTC) - synced_at > timedelta(hours=hours)


async def sync_user(user_id: str, fresh: bool = False) -> None:
    """Refreshes a user's cached all-time total (in the background after sign-up, or when stale)."""
    from app.db import SessionLocal
    from app.models import User

    with SessionLocal() as db:
        user = db.get(User, user_id)
        username = username_from(user.github_url if user else None)
        if user is None or username is None:
            return
        try:
            result = await (all_time_contributions(username) if fresh else lookup(username))
        except GitHubUnavailable as exc:
            log.warning("GitHub sync for %s skipped: %s", user_id, exc)
            return
        if result is None:
            user.github_verified = False
        else:
            profile, total = result
            user.github_url = f"https://github.com/{profile['login']}"
            user.github_verified = True
            user.github_contribution_count = total
            user.github_synced_at = datetime.now(UTC)
        db.commit()


# Lookups are cached briefly: the signup and profile forms check a username and then save it,
# so the second request reuses the first answer instead of walking the calendar again.
_LOOKUPS: dict[str, tuple[datetime, tuple[dict, int] | None]] = {}
_LOOKUP_TTL = timedelta(minutes=10)


async def lookup(username: str) -> tuple[dict, int] | None:
    key = username.lower()
    cached = _LOOKUPS.get(key)
    if cached and datetime.now(UTC) - cached[0] < _LOOKUP_TTL:
        return cached[1]
    result = await all_time_contributions(username)
    _LOOKUPS[key] = (datetime.now(UTC), result)
    return result
