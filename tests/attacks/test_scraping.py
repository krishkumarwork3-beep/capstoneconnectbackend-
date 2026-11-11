"""A1-A3: visitors get no people, group or chat data; signed-in readers get capped pages behind
opaque cursors, a per-account read budget, and suspicious reading is audited and throttled.
Object ids can't be probed: someone else's object answers like a missing one."""

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.db import SessionLocal
from app.models import AuditLog
from app.services import reads
from tests.conftest import REAL_PNG

# --- Visitors ---------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/api/groups", "/api/users", "/api/stats/signups", "/api/groups/grp_1", "/api/users/usr_1"])
def test_visitors_get_no_people_or_group_data(client, path):
    r = client.get(path)
    assert r.status_code == 401 and "usr_" not in r.text and "grp_" not in r.text


def test_avatars_need_a_session(client, as_user):
    me = as_user("usr_8")
    url = me.post("/api/users/usr_8/avatar", files={"avatar": ("me.png", REAL_PNG, "image/png")}).json()["avatar_url"]
    path = url[url.index("/uploads/"):]
    assert client.get(path).status_code == 401
    ok = me.get(path)
    assert ok.status_code == 200 and ok.headers["cache-control"].startswith("private")
    # A made-up name answers 401 too for a visitor: not even existence leaks.
    assert client.get("/uploads/avatar/ava_0123456789abcdef.png").status_code == 401


# --- Pages ------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/api/users", "/api/groups"])
def test_pages_are_capped_and_carry_no_global_total(as_user, path):
    c = as_user("usr_1")
    assert c.get(f"{path}?limit=51").status_code == 422
    body = c.get(path).json()
    assert len(body["items"]) <= reads.PAGE_DEFAULT and "total" not in body
    assert c.get(f"{path}?limit=50").status_code == 200


@pytest.mark.parametrize("path", ["/api/users", "/api/groups"])
def test_cursors_are_opaque_signed_and_bound_to_the_account(as_user, path):
    one, other = as_user("usr_1"), as_user("usr_2")
    first = one.get(f"{path}?limit=1").json()
    cursor = first["nextCursor"]
    assert cursor and not cursor.isdigit()
    assert one.get(f"{path}?limit=1&cursor={cursor}").status_code == 200
    for bad in ("20", "0", cursor[:-2] + ("AA" if not cursor.endswith("AA") else "BB")):
        assert one.get(f"{path}?limit=1&cursor={bad}").status_code == 400, bad
    assert other.get(f"{path}?limit=1&cursor={cursor}").status_code == 400  # another account's cursor


def test_search_needs_two_characters_and_wildcards_are_literal(as_user):
    c = as_user("usr_1")
    assert c.get("/api/users?search=a").status_code == 422
    assert c.get("/api/users?search=%25").status_code == 422
    assert c.get("/api/users?search=%25%25").json()["items"] == []
    assert c.get("/api/users?search=__").json()["items"] == []


# --- Read budgets and suspicious access -------------------------------------------------------

def test_profile_views_have_a_per_account_budget(as_user, monkeypatch):
    monkeypatch.setattr(get_settings(), "read_limit_profiles", 3)
    c = as_user("usr_1")
    assert [c.get("/api/users/usr_2").status_code for _ in range(4)] == [200, 200, 200, 429]
    assert as_user("usr_2").get("/api/users/usr_1").status_code == 200  # someone else's budget is theirs


def test_list_pages_have_a_per_account_budget(as_user, monkeypatch):
    monkeypatch.setattr(get_settings(), "read_limit_pages", 2)
    c = as_user("usr_1")
    assert [c.get("/api/groups").status_code for _ in range(3)] == [200, 200, 429]


def test_chat_history_has_a_per_account_budget(as_user, monkeypatch):
    monkeypatch.setattr(get_settings(), "read_limit_chat_pages", 2)
    c = as_user("usr_1")
    assert [c.get("/api/conversations/conv_2/messages").status_code for _ in range(3)] == [200, 200, 429]


def _suspicious(user_id: str) -> list[AuditLog]:
    with SessionLocal() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == "security.suspicious_read", AuditLog.target_id == user_id)))


def test_many_distinct_profiles_are_audited_and_throttled(as_user, admin_client, monkeypatch):
    monkeypatch.setattr(get_settings(), "suspicious_distinct_profiles", 2)
    c = as_user("usr_8")
    # Viewing the same profile again and again is not "distinct".
    assert all(c.get("/api/users/usr_2").status_code == 200 for _ in range(4))
    assert c.get("/api/users/usr_3").status_code == 200
    assert c.get("/api/users/usr_4").status_code == 429
    assert len(_suspicious("usr_8")) == 1
    # Throttled: every read is refused for a while, not only profiles.
    assert c.get("/api/groups").status_code == 429
    assert c.get("/api/users/usr_2").status_code == 429
    # The admin portal's Audit page shows it.
    audit = admin_client().get("/api/admin/audit?action=security").json()["items"]
    assert any(e["action"] == "security.suspicious_read" and "usr_8" in e["summary"] for e in audit)


def test_paging_very_deep_is_audited_and_throttled(as_user, monkeypatch):
    monkeypatch.setattr(get_settings(), "suspicious_list_depth", 2)
    c = as_user("usr_8")
    cursor = c.get("/api/users?limit=2").json()["nextCursor"]
    assert c.get(f"/api/users?limit=2&cursor={cursor}").status_code == 429
    assert len(_suspicious("usr_8")) == 1


# --- Ids can't be probed ----------------------------------------------------------------------

def test_someone_elses_conversation_answers_like_a_missing_one(as_user):
    c = as_user("usr_8")  # not in conv_2
    theirs, missing = c.get("/api/conversations/conv_2"), c.get("/api/conversations/conv_doesnotexist")
    assert theirs.status_code == missing.status_code == 404
    assert theirs.json()["message"] == missing.json()["message"]
    assert c.get("/api/conversations/conv_2/messages").status_code == 404


def test_someone_elses_attachment_answers_like_a_missing_one(as_user):
    sender = as_user("usr_1")
    up = sender.post("/api/uploads/attachments", files={"file": ("a.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")})
    assert up.status_code in (200, 201), up.text
    url = up.json()["url"]
    sent = sender.post("/api/conversations/conv_2/messages", json={"text": "", "attachment": up.json()})
    assert sent.status_code == 201, sent.text
    path = url[url.index("/uploads/"):]
    outsider = as_user("usr_8")
    assert outsider.get(path).status_code == 404
    assert outsider.get(path.rsplit("/", 1)[0] + "/att_0123456789abcdef.pdf").status_code == 404


def test_someone_elses_request_answers_like_a_missing_one(as_user):
    c = as_user("usr_8")
    r = c.patch("/api/requests/req_doesnotexist", json={"status": "declined"})
    assert r.status_code == 404


# --- Headers ----------------------------------------------------------------------------------

def test_api_answers_are_not_indexed_or_cached(as_user):
    r = as_user("usr_1").get("/api/users")
    assert r.headers["x-robots-tag"].startswith("noindex")
    assert r.headers["cache-control"] == "no-store"


# --- F4: minimum fields per viewer ------------------------------------------------------------

def test_a_strangers_profile_has_no_join_date_or_last_seen(as_user):
    stranger = as_user("usr_8").get("/api/users/usr_3").json()  # no shared conversation
    assert stranger["created_at"] is None and stranger["last_seen"] is None
    listed = {u["id"]: u for u in as_user("usr_8").get("/api/users", params={"limit": 50}).json()["items"]}
    assert all(u["created_at"] is None for i, u in listed.items() if i != "usr_8")


def test_last_seen_only_for_people_you_chat_with_and_your_own_account(as_user):
    lead = as_user("usr_1")  # usr_1 and usr_2 share conv_2
    partner = lead.get("/api/users/usr_2").json()
    assert partner["last_seen"] is not None and partner["created_at"] is None
    me = lead.get("/api/auth/me").json()
    assert me["created_at"] is not None and me["last_seen"] is not None
