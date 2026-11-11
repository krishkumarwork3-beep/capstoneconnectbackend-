"""GitHub contribution totals, from fixtures in GitHub's real formats (the calendar fragment and
GraphQL `contributionsCollection`). The site shows GitHub's own profile headline: "N
contributions in the last year". Regression: a profile showing 2,299 on GitHub showed 210 here."""

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.config import get_settings
from app.db import SessionLocal
from app.models import User
from app.services import github


def _calendar(headline: str | None, days: list[int], years=(2026,)) -> str:
    """Shaped like github.com/users/<login>/contributions: the heading, a year selector, and one
    tool-tip per day ("No contributions" days included)."""
    cells = "".join(
        f'<td class="ContributionCalendar-day" data-date="2026-06-{i % 28 + 1:02d}" id="d{i}"></td>'
        f'<tool-tip for="d{i}">{"No contributions" if n == 0 else f"{n} contribution{"s" if n != 1 else ""}"} on June {i % 28 + 1}th.</tool-tip>'
        for i, n in enumerate(days)
    )
    heading = f'<h2 class="f4 text-normal mb-2">\n      {headline}\n</h2>' if headline else ""
    selector = "".join(f'<a class="js-year-link" href="?tab=overview&from={y}-01-01">{y}</a>' for y in years)
    return f"<div>{heading}<div class='js-calendar-graph'><table>{cells}</table></div>{selector}</div>"


def _github(handler):
    """A client with the real SSRF guard in front of a fake GitHub."""
    return lambda: httpx.AsyncClient(
        transport=github.GuardedTransport(inner=httpx.MockTransport(handler), require_peer=False),
        timeout=github.TIMEOUT, follow_redirects=False)


def _fake(monkeypatch, calendar: str, created="2026-05-31T09:56:45Z", status=200, seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request.url)
        if request.url.host == "api.github.com":
            return httpx.Response(200, json={"login": "krishkumarwork3-beep", "created_at": created})
        return httpx.Response(status, text=calendar)

    monkeypatch.setattr(github, "_client", _github(handler))
    monkeypatch.setattr(github, "_LOOKUPS", {})


# --- The parser --------------------------------------------------------------------------------

def test_regression_the_2299_profile_reads_2299_not_210():
    # 210 public day cells, 2,299 in GitHub's headline (private contributions counted there).
    page = _calendar("2,299 contributions\n        in the last year", [5] * 42)
    assert sum([5] * 42) == 210
    assert github.parse_calendar(page) == github.Total(2299, True)


@pytest.mark.parametrize("headline,expected", [
    ("2,299 contributions in the last year", 2299),
    ("1,234,567 contributions in the last year", 1234567),
    ("1 contribution in the last year", 1),
    ("0 contributions in the last year", 0),
    ("2,299 contributions in 2026", 2299),
])
def test_headlines_with_separators_and_singular(headline, expected):
    assert github.parse_calendar(_calendar(headline, [1, 0, 3])) == github.Total(expected, True)


def test_private_contributions_in_the_headline_win_over_public_day_cells():
    assert github.parse_calendar(_calendar("2,299 contributions in the last year", [0] * 30 + [1])).count == 2299


def test_without_a_headline_the_days_are_added_and_marked_incomplete():
    assert github.parse_calendar(_calendar(None, [3, 0, 1, 10])) == github.Total(14, False)


# --- One request for the rolling year, whatever the account's age ------------------------------

@pytest.mark.parametrize("created,years", [("2026-05-31T09:56:45Z", (2026,)), ("2019-02-01T00:00:00Z", (2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026))])
def test_new_and_old_accounts_get_the_headline_from_one_calendar_request(monkeypatch, created, years):
    seen = []
    _fake(monkeypatch, _calendar("2,299 contributions in the last year", [5] * 42, years), created, seen=seen)
    _profile, total = asyncio.run(github.contributions("krishkumarwork3-beep"))
    assert total == github.Total(2299, True)
    calendar = [u for u in seen if u.host == "github.com"]
    assert len(calendar) == 1 and calendar[0].path == "/users/krishkumarwork3-beep/contributions"
    assert not calendar[0].params  # no from/to: GitHub's own rolling year, never a partial window


def test_graphql_asks_for_the_default_one_year_window(monkeypatch):
    bodies = []

    def handler(request):
        bodies.append(request.content.decode())
        return httpx.Response(200, json={"data": {"user": {"contributionsCollection": {"contributionCalendar": {"totalContributions": 2299}}}}})

    monkeypatch.setattr(get_settings(), "github_token", "test-token-not-real")
    total = asyncio.run(github.last_year_total(_github(handler)(), "krishkumarwork3-beep"))
    assert total == github.Total(2299, True)
    assert "from:" not in bodies[0] and "to:" not in bodies[0]  # windows over a year are refused by GitHub


def test_graphql_failure_falls_back_to_the_calendar(monkeypatch):
    def handler(request):
        if request.url.host == "api.github.com":
            return httpx.Response(502, json={"errors": ["x"]})
        return httpx.Response(200, text=_calendar("2,299 contributions in the last year", [1]))

    monkeypatch.setattr(get_settings(), "github_token", "test-token-not-real")
    assert asyncio.run(github.last_year_total(_github(handler)(), "someone")).count == 2299


# --- The cached total: refreshed, never lowered by a failure or a partial answer ---------------

@pytest.fixture
def linked_user():
    old = datetime.now(UTC) - timedelta(days=3)
    with SessionLocal() as db:
        user = db.get(User, "usr_8")
        user.github_url, user.github_verified = "https://github.com/krishkumarwork3-beep", True
        user.github_contribution_count, user.github_synced_at = 210, old
        db.commit()
    return "usr_8", old


def _stored(user_id):
    with SessionLocal() as db:
        user = db.get(User, user_id)
        return user.github_contribution_count, user.github_synced_at


def test_a_stale_210_is_refreshed_to_2299(monkeypatch, linked_user):
    _fake(monkeypatch, _calendar("2,299 contributions in the last year", [5] * 42))
    asyncio.run(github.sync_user(linked_user[0], True))
    count, synced = _stored(linked_user[0])
    assert count == 2299 and synced > linked_user[1]


def test_opening_the_repositories_panel_returns_the_fresh_total(monkeypatch, linked_user, as_user):
    def handler(request):
        if request.url.path.endswith("/repos"):
            return httpx.Response(200, json=[])
        if request.url.host == "api.github.com":
            return httpx.Response(200, json={"login": "krishkumarwork3-beep"})
        return httpx.Response(200, text=_calendar("2,299 contributions in the last year", [5] * 42))

    monkeypatch.setattr(github, "_client", _github(handler))
    answer = as_user("usr_1").get(f"/api/users/{linked_user[0]}/github")
    assert answer.status_code == 200 and answer.json()["contributions"] == 2299


@pytest.mark.parametrize("status", [403, 429, 500])
def test_a_failed_lookup_keeps_the_old_total_and_date(monkeypatch, linked_user, as_user, status):
    """No GITHUB_TOKEN: GitHub answers 403/429 when the anonymous limit is used up. The stored
    total is never lowered and the profile still answers 200 (never a 500)."""
    with SessionLocal() as db:
        db.get(User, linked_user[0]).github_contribution_count = 2299
        db.commit()
    _fake(monkeypatch, "rate limited", status=status)
    asyncio.run(github.sync_user(linked_user[0], True))
    assert _stored(linked_user[0]) == (2299, linked_user[1])
    answer = as_user("usr_1").get(f"/api/users/{linked_user[0]}/github")
    assert answer.status_code == 200 and answer.json()["contributions"] == 2299
    assert _stored(linked_user[0])[0] == 2299


def test_a_partial_lookup_never_lowers_a_good_total(monkeypatch, linked_user):
    with SessionLocal() as db:
        db.get(User, linked_user[0]).github_contribution_count = 2299
        db.commit()
    _fake(monkeypatch, _calendar(None, [5] * 42))  # layout change: only 210 in day cells
    asyncio.run(github.sync_user(linked_user[0], True))
    assert _stored(linked_user[0])[0] == 2299


def test_a_complete_smaller_total_is_stored(monkeypatch, linked_user):
    """The rolling year can go down; a full answer is the truth."""
    with SessionLocal() as db:
        db.get(User, linked_user[0]).github_contribution_count = 2299
        db.commit()
    _fake(monkeypatch, _calendar("2,100 contributions in the last year", [1]))
    asyncio.run(github.sync_user(linked_user[0], True))
    assert _stored(linked_user[0])[0] == 2100


def test_an_oversized_calendar_is_refused(monkeypatch):
    _fake(monkeypatch, "9 contributions in the last year" + " " * (github.MAX_BYTES + 10))
    with pytest.raises(github.GitHubUnavailable):
        asyncio.run(github.refresh_count("someone"))
