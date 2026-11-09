"""GET /api/stats/signups: the sign-up total, for signed-in students and admins only (rewritten
from the earlier public contract: a visitor now gets 401 and nothing else). It follows sign-ups
and deletions, matches the admin dashboard, is never kept by a shared cache, and is limited per
account."""

import pytest

from app.services import limits, stats
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
    assert r.headers["cache-control"] == "private, no-store"
    return r.json()["total"]


def test_visitors_get_nothing(client):
    r = client.get("/api/stats/signups")
    assert r.status_code == 401
    assert "total" not in r.text and r.headers["cache-control"] == "no-store"


def test_the_total_follows_signups_and_deletions_and_matches_the_admin_dashboard(client, as_user, admin_client):
    admin, student = admin_client(), as_user("usr_1")
    before = _total(student)
    assert _total(admin) == before
    assert admin.get("/api/admin/stats").json()["users"]["total"] == before
    created = client.post("/api/auth/signup", json=NEW)
    assert created.status_code in (200, 201), created.text
    stats.clear_cache()
    assert _total(student) == before + 1
    new_id = created.json()["id"]
    assert admin.delete(f"/api/admin/users/{new_id}").status_code in (200, 204)
    stats.clear_cache()
    assert _total(student) == before
    assert admin.get("/api/admin/stats").json()["users"]["total"] == before


def test_suspended_students_still_count(as_user, admin_client):
    student = as_user("usr_1")
    before = _total(student)
    assert admin_client().post("/api/admin/users/usr_2/ban", json={"reason": "x"}).status_code in (200, 204)
    stats.clear_cache()
    assert _total(student) == before


def test_the_answer_is_cached(as_user, admin_client):
    student = as_user("usr_1")
    before = _total(student)
    assert admin_client().delete("/api/admin/users/usr_2").status_code in (200, 204)
    assert _total(student) == before  # within 60 s: the cached figure


def test_hammering_it_is_limited_per_account(as_user, monkeypatch):
    monkeypatch.setitem(limits.WRITE_LIMITS, "stats_read", (3, limits.WRITE_LIMITS["stats_read"][1]))
    one, other = as_user("usr_1"), as_user("usr_2")
    codes = [one.get("/api/stats/signups").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[-1] == 429
    assert other.get("/api/stats/signups").status_code == 200  # another account has its own budget
