"""Part 3 (server side): links people can click, CSV formula injection, XSS payloads stay inert
text in every JSON answer, and the export is bounded."""

import csv
import io

import pytest

from app.services import github
from tests.attacks import payloads
from tests.conftest import ADMIN_PASSWORD

BAD_LINKS = [
    "javascript:alert(1)", "JAVASCRIPT:alert(1)", " javascript:alert(1)", "java\tscript:alert(1)",
    "data:text/html,<script>alert(1)</script>", "vbscript:msgbox(1)", "file:///etc/passwd",
    "//evil.example", "///evil.example", "/\\evil.example", "\\\\evil.example", "/\t/evil.example",
    "/\r\n/evil.example", "https://github.com@evil.example", "https://user:pw@evil.example", "https:evil.example",
    "http://", "https://", "https://evil.example/\u2028x", "https://evil .example", "/ok\x00",
]
GOOD_LINKS = ["https://example.org/news", "http://example.org/a?b=1#c", "/groups", "/groups/grp_1?tab=chat"]


@pytest.mark.parametrize("link", BAD_LINKS)
def test_announcement_links_refuse_scripts_and_redirect_tricks(admin_client, link):
    r = admin_client().post("/api/admin/announcements", json={"text": "Hello", "link_url": link})
    assert r.status_code in (400, 422), (link, r.text)


@pytest.mark.parametrize("link", GOOD_LINKS)
def test_announcement_links_keep_ordinary_links(admin_client, link):
    r = admin_client().post("/api/admin/announcements", json={"text": "Hello", "link_url": link})
    assert r.status_code == 201, r.text
    assert r.json()["link_url"] == link


def test_github_repo_links_are_rebuilt_not_trusted():
    """The repo list comes from another host: its html_url never reaches an href unchecked."""
    hostile = {"id": 1, "name": "repo", "html_url": "javascript:alert(1)", "language": "Go", "description": "<img src=x onerror=alert(1)>"}
    row = github.repo_row(hostile, "octocat")
    assert row["html_url"] == "https://github.com/octocat/repo"
    assert github.repo_row({**hostile, "name": "../../evil"}, "octocat") is None
    assert github.repo_row({**hostile, "name": "a" * 200}, "octocat") is None
    assert github.repo_row(hostile, "octo cat") is None
    # Text stays text (React escapes it); only its length is bounded.
    assert github.repo_row({**hostile, "description": "x" * 5000}, "octocat")["description"] == "x" * 300


def _export(admin) -> list[list[str]]:
    r = admin.post("/api/admin/users/export.csv", json={"password": ADMIN_PASSWORD})  # was a GET (needs the password now)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"].startswith("attachment;")
    return list(csv.reader(io.StringIO(r.text)))


@pytest.mark.parametrize("formula", ["=HYPERLINK(\"https://evil.example\",\"x\")", "+1+cmd|' /C calc'!A0", "-2+3", "@SUM(A1:A2)", "\t=1+1", "\r=1+1"])
def test_csv_export_neutralises_formulas(as_user, admin_client, formula):
    c = as_user("usr_8")
    assert c.patch("/api/users/usr_8", json={"department": formula}).status_code == 200
    rows = _export(admin_client())
    header = rows[0]
    row = next(r for r in rows if r[0] == "usr_8")
    cell = row[header.index("department")]
    assert cell.startswith("'"), cell
    assert cell[1:] == formula.strip() or cell[1:] == formula
    for r in rows[1:]:
        for value in r:
            assert not value or value[0] not in "=+-@\t\r", (r, value)


def test_csv_export_is_bounded(admin_client, monkeypatch):
    from app.routers import admin as admin_routes

    monkeypatch.setattr(admin_routes, "EXPORT_LIMIT", 3)
    r = admin_client().post("/api/admin/users/export.csv", json={"password": ADMIN_PASSWORD})
    assert r.status_code == 422
    assert "filter" in r.json()["message"].lower()


@pytest.mark.parametrize("value", payloads.XSS)
def test_xss_payloads_come_back_as_json_text(as_user, value):
    """Stored as typed, returned as a JSON string, never as HTML."""
    c = as_user("usr_8")
    r = c.patch("/api/users/usr_8", json={"bio": value})
    assert r.status_code in (200, 422)
    page = c.get("/api/users/usr_8")
    assert page.headers["content-type"].startswith("application/json")
    assert page.headers["x-content-type-options"] == "nosniff"
    if r.status_code == 200:
        assert page.json()["bio"] == value.strip()
