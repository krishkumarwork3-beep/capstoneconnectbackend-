"""GET /api/stats/signups: a public aggregate that follows sign-ups and deletions, matches the
admin dashboard, leaks nothing about anyone, is cached and is limited per address."""

import pytest

from app.config import get_settings
from app.services import stats
from tests.test_auth import NEW


@pytest.fixture(autouse=True)
def fresh_cache():
    stats.clear_cache()
    yield
    stats.clear_cache()


def _total(client) -> int:
    r = client.get("/api/stats/signups")
    assert r.status_code == 200, r.text
    assert set(r.json()) == {"total"}  # the number only: no names, ids, phones or dates
    assert r.headers["cache-control"] == "public, max-age=60"
    return r.json()["total"]


def test_the_total_follows_signups_and_deletions_and_matches_the_admin_dashboard(client, admin_client):
    admin = admin_client()
    before = _total(client)
    assert admin.get("/api/admin/stats").json()["users"]["total"] == before
    created = client.post("/api/auth/signup", json=NEW)
    assert created.status_code in (200, 201), created.text
    stats.clear_cache()
    assert _total(client) == before + 1
    new_id = created.json()["user"]["id"] if "user" in created.json() else created.json()["id"]
    assert admin.delete(f"/api/admin/users/{new_id}").status_code in (200, 204)
    stats.clear_cache()
    assert _total(client) == before
    assert admin.get("/api/admin/stats").json()["users"]["total"] == before


def test_suspended_students_still_count(client, admin_client):
    before = _total(client)
    assert admin_client().post("/api/admin/users/usr_2/ban", json={"reason": "x"}).status_code in (200, 204)
    stats.clear_cache()
    assert _total(client) == before


def test_the_answer_is_cached(client, admin_client):
    before = _total(client)
    assert admin_client().delete("/api/admin/users/usr_2").status_code in (200, 204)
    assert _total(client) == before  # within 60 s: the cached figure


def test_hammering_it_is_limited_per_address(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "public_stats_limit_per_ip", 3)
    codes = [client.get("/api/stats/signups").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[-1] == 429
