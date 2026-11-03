"""Admin API: access, students, bans and blocked numbers (enforced on the student side), groups,
chat moderation, admin accounts and the audit log."""

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app
from tests.conftest import ADMIN_PASSWORD, PASSWORD, PHONES

LEAD, MEMBER, LOOKING = "usr_1", "usr_9", "usr_6"


def login(phone: str, password: str = PASSWORD) -> tuple[TestClient, int]:
    c = TestClient(app)
    return c, c.post("/api/auth/login", json={"phone": phone, "password": password}).status_code


def actions(admin) -> list[str]:
    return [row["action"] for row in admin.get("/api/admin/audit").json()["items"]]


# ---------------------------------------------------------------------------------------------
# Access
# ---------------------------------------------------------------------------------------------


def test_admin_api_needs_an_admin(client, as_user):
    assert client.get("/api/admin/stats").status_code == 401
    # A student's session is not an admin session.
    assert as_user(LEAD).get("/api/admin/users").status_code == 401


def test_wrong_password_then_lockout(client, admin_client):
    admin_client(email="boss@example.com")
    for _ in range(5):
        r = client.post("/api/admin/auth/login", json={"email": "boss@example.com", "password": "nope"})
        assert r.status_code == 401
    r = client.post("/api/admin/auth/login", json={"email": "boss@example.com", "password": ADMIN_PASSWORD})
    assert r.status_code == 429 and "Try again" in r.json()["message"]


def test_viewer_reads_but_cannot_change(admin_client):
    viewer = admin_client("viewer")
    assert viewer.get("/api/admin/users").status_code == 200
    r = viewer.post(f"/api/admin/users/{LEAD}/ban", json={"reason": "x"})
    assert r.status_code == 403 and "read-only" in r.json()["message"]


def test_stats(admin_client):
    stats = admin_client().get("/api/admin/stats").json()
    assert stats["users"]["total"] >= 15
    assert stats["users"]["in_group"] + stats["users"]["looking"] == stats["users"]["total"]
    assert len(stats["signups"]) == 30 and stats["groups"]["total"] >= 1


# ---------------------------------------------------------------------------------------------
# Students
# ---------------------------------------------------------------------------------------------


def test_search_filter_and_page(admin_client):
    admin = admin_client()
    everyone = admin.get("/api/admin/users", params={"page_size": 5}).json()
    assert len(everyone["items"]) == 5 and everyone["total"] >= 15
    by_phone = admin.get("/api/admin/users", params={"q": "98765 43210"}).json()["items"]
    assert [u["id"] for u in by_phone] == [LEAD]
    looking = admin.get("/api/admin/users", params={"status": "looking", "page_size": 200}).json()["items"]
    assert all(u["group_id"] is None for u in looking) and LOOKING in {u["id"] for u in looking}


def test_create_student_then_they_can_sign_in(admin_client):
    admin = admin_client()
    r = admin.post("/api/admin/users", json={"name": "New Student", "college": "IIT Delhi", "passing_year": 2027,
                                             "phone": "+91 90000 11111", "password": "brand-new-pass"})
    assert r.status_code == 201, r.text
    _, status = login("9000011111", "brand-new-pass")
    assert status == 200
    dup = admin.post("/api/admin/users", json={"name": "Dup", "college": "X", "passing_year": 2027,
                                               "phone": PHONES[LEAD], "password": "another-pass"})
    assert dup.status_code == 409


def test_edit_details_and_phone(admin_client):
    admin = admin_client()
    r = admin.patch(f"/api/admin/users/{LOOKING}", json={"name": "Renamed", "phone": "+91 90000 22222"})
    assert r.status_code == 200 and r.json()["name"] == "Renamed"
    assert login("+91 90000 22222")[1] == 200
    assert login(PHONES[LOOKING])[1] == 401
    clash = admin.patch(f"/api/admin/users/{LOOKING}", json={"phone": PHONES[LEAD]})
    assert clash.status_code == 409


def test_set_password_signs_them_out(admin_client, as_user):
    student = as_user(LEAD)
    assert student.get("/api/auth/me").status_code == 200
    assert admin_client().post(f"/api/admin/users/{LEAD}/password", json={"password": "set-by-admin"}).status_code == 204
    assert student.get("/api/auth/me").status_code == 401
    assert login(PHONES[LEAD], "set-by-admin")[1] == 200


def test_suspend_and_lift(admin_client, as_user):
    admin = admin_client()
    student = as_user(LEAD)
    detail = admin.post(f"/api/admin/users/{LEAD}/ban", json={"reason": "Spam"}).json()
    assert detail["banned"] and detail["ban_reason"] == "Spam"
    r = student.get("/api/auth/me")
    assert r.status_code == 403 and "suspended" in r.json()["message"]
    assert login(PHONES[LEAD])[1] == 403
    admin.post(f"/api/admin/users/{LEAD}/unban")
    assert login(PHONES[LEAD])[1] == 200


def test_suspended_student_socket_is_refused(admin_client, as_user):
    student = as_user(LEAD)
    admin_client().post(f"/api/admin/users/{LEAD}/ban", json={})
    with student.websocket_connect("/api/ws") as ws:
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
    assert closed.value.code == 4401


def test_delete_lead_hands_the_group_over(admin_client):
    admin = admin_client()
    group_id = admin.get(f"/api/admin/users/{LEAD}").json()["group_id"]
    before = admin.get(f"/api/admin/groups/{group_id}").json()
    assert admin.delete(f"/api/admin/users/{LEAD}").status_code == 204
    assert admin.get(f"/api/admin/users/{LEAD}").status_code == 404
    after = admin.get(f"/api/admin/groups/{group_id}").json()
    assert after["member_count"] == before["member_count"] - 1
    assert after["lead_id"] and after["lead_id"] != LEAD


def test_bulk_and_csv(admin_client):
    admin = admin_client()
    r = admin.post("/api/admin/users/bulk", json={"ids": [LOOKING, "usr_7", "nope"], "action": "ban", "reason": "test"})
    assert r.json() == {"done": 2, "skipped": ["nope"]}
    banned = admin.get("/api/admin/users", params={"status": "banned"}).json()
    assert {u["id"] for u in banned["items"]} == {LOOKING, "usr_7"}
    csv = admin.get("/api/admin/users/export.csv")
    assert csv.headers["content-type"].startswith("text/csv")
    lines = csv.text.strip().splitlines()
    assert lines[0].startswith("id,name,phone") and len(lines) > 15


# ---------------------------------------------------------------------------------------------
# Blocked numbers
# ---------------------------------------------------------------------------------------------


def test_blocked_number_cannot_sign_up_sign_in_or_reset(admin_client, client):
    admin = admin_client()
    r = admin.post("/api/admin/banned-phones", json={"phones": ["+91 91234 00000", PHONES[LOOKING], "12"], "reason": "abuse"})
    assert r.status_code == 201
    assert len(r.json()["added"]) == 2 and r.json()["invalid"] == ["12"]

    signup = client.post("/api/auth/signup", json={"name": "X", "college": "Y", "passing_year": 2027,
                                                   "phone": "9123400000", "password": "some-password"})
    assert signup.status_code == 403 and "can't be used" in signup.json()["message"]
    assert login(PHONES[LOOKING])[1] == 403
    forgot = client.post("/api/auth/password/forgot", json={"phone": PHONES[LOOKING]}).json()
    assert forgot["dev_code"] is None

    rows = admin.get("/api/admin/banned-phones").json()
    on_account = next(row for row in rows if row["account_id"] == LOOKING)
    assert admin.delete(f"/api/admin/banned-phones/{on_account['phone_normalized']}").status_code == 204
    assert login(PHONES[LOOKING])[1] == 200


def test_suspend_can_block_the_number_too(admin_client):
    admin = admin_client()
    detail = admin.post(f"/api/admin/users/{LOOKING}/ban", json={"reason": "fake", "block_number": True}).json()
    assert detail["banned"] and detail["number_blocked"]
    admin.post(f"/api/admin/users/{LOOKING}/unban")
    # The number stays blocked until it is removed from the list.
    assert login(PHONES[LOOKING])[1] == 403


# ---------------------------------------------------------------------------------------------
# Groups and chat
# ---------------------------------------------------------------------------------------------


def test_remove_member_and_delete_group(admin_client, as_user):
    admin = admin_client()
    group_id = admin.get(f"/api/admin/users/{MEMBER}").json()["group_id"]
    assert admin.delete(f"/api/admin/groups/{group_id}/members/{MEMBER}").status_code == 204
    assert admin.get(f"/api/admin/users/{MEMBER}").json()["group_id"] is None
    assert admin.delete(f"/api/admin/groups/{group_id}/members/{MEMBER}").status_code == 409

    assert admin.delete(f"/api/admin/groups/{group_id}").status_code == 204
    assert admin.get(f"/api/admin/users/{LEAD}").json()["group_id"] is None
    # The lead can now start another group.
    r = as_user(LEAD).post("/api/groups", json={"name": "Fresh", "description": "New", "max_members": 4, "domain": "AI"})
    assert r.status_code == 201, r.text


def test_read_and_delete_a_message(admin_client, as_user):
    admin = admin_client()
    group = next(c for c in admin.get("/api/admin/conversations").json()["items"] if c["type"] == "group")
    as_user(LEAD).post(f"/api/conversations/{group['id']}/messages", json={"text": "something rude"})
    messages = admin.get(f"/api/admin/conversations/{group['id']}/messages").json()
    rude = next(m for m in messages if m["text"] == "something rude")
    assert admin.delete(f"/api/admin/messages/{rude['id']}").status_code == 204
    after = admin.get(f"/api/admin/conversations/{group['id']}/messages").json()
    assert all(m["id"] != rude["id"] for m in after)
    row = next(c for c in admin.get("/api/admin/conversations").json()["items"] if c["id"] == group["id"])
    assert row["last_message_text"] != "something rude"


def test_cancel_a_pending_request(admin_client):
    admin = admin_client()
    pending = admin.get("/api/admin/requests", params={"status": "pending"}).json()["items"]
    assert pending
    assert admin.post(f"/api/admin/requests/{pending[0]['id']}/cancel").status_code == 204
    assert admin.post(f"/api/admin/requests/{pending[0]['id']}/cancel").status_code == 409


# ---------------------------------------------------------------------------------------------
# Select all and act on the selection
# ---------------------------------------------------------------------------------------------


def test_select_all_ids_follow_the_filters(admin_client):
    admin = admin_client()
    total = admin.get("/api/admin/users", params={"status": "looking"}).json()["total"]
    ids = admin.get("/api/admin/users/ids", params={"status": "looking"}).json()
    assert len(ids) == total and LOOKING in ids and LEAD not in ids
    assert len(admin.get("/api/admin/groups/ids").json()) == admin.get("/api/admin/groups").json()["total"]
    pending = admin.get("/api/admin/requests", params={"status": "pending"}).json()["total"]
    assert len(admin.get("/api/admin/requests/ids").json()) == pending


def test_bulk_delete_groups(admin_client):
    admin = admin_client()
    ids = admin.get("/api/admin/groups/ids").json()
    r = admin.post("/api/admin/groups/bulk-delete", json={"ids": [*ids, "grp_missing"]})
    assert r.json() == {"done": len(ids), "skipped": ["grp_missing"]}
    assert admin.get("/api/admin/groups").json()["total"] == 0
    assert admin.get(f"/api/admin/users/{LEAD}").json()["group_id"] is None
    assert "group.bulk_delete" in actions(admin)


def test_bulk_unblock_cancel_and_delete_messages(admin_client, as_user):
    admin = admin_client()
    admin.post("/api/admin/banned-phones", json={"phones": ["+91 90000 11111", "9000022222"]})
    r = admin.post("/api/admin/banned-phones/bulk-delete", json={"ids": ["919000011111", "+91 90000 22222", "9000099999"]})
    assert r.json() == {"done": 2, "skipped": ["9000099999"]}
    assert admin.get("/api/admin/banned-phones").json() == []

    ids = admin.get("/api/admin/requests/ids").json()
    assert admin.post("/api/admin/requests/bulk-cancel", json={"ids": ids}).json()["done"] == len(ids)
    assert admin.get("/api/admin/requests/ids").json() == []
    assert admin.post("/api/admin/requests/bulk-cancel", json={"ids": ids}).json()["skipped"] == ids

    group = next(c for c in admin.get("/api/admin/conversations").json()["items"] if c["type"] == "group")
    for text in ("spam one", "spam two"):
        as_user(LEAD).post(f"/api/conversations/{group['id']}/messages", json={"text": text})
    spam = [m["id"] for m in admin.get(f"/api/admin/conversations/{group['id']}/messages").json() if m["text"].startswith("spam")]
    assert admin.post("/api/admin/messages/bulk-delete", json={"ids": spam}).json() == {"done": 2, "skipped": []}
    row = next(c for c in admin.get("/api/admin/conversations").json()["items"] if c["id"] == group["id"])
    assert not (row["last_message_text"] or "").startswith("spam")


def test_viewer_cannot_bulk_change(admin_client):
    viewer = admin_client("viewer")
    assert viewer.post("/api/admin/groups/bulk-delete", json={"ids": ["x"]}).status_code == 403
    assert viewer.post("/api/admin/messages/bulk-delete", json={"ids": ["x"]}).status_code == 403


# ---------------------------------------------------------------------------------------------
# Admin accounts and audit log
# ---------------------------------------------------------------------------------------------


def test_admin_accounts(admin_client, client):
    admin = admin_client(email="first@example.com")
    me = admin.get("/api/admin/auth/me").json()
    r = admin.post("/api/admin/admins", json={"email": "Second@Example.com", "name": "Two", "password": "second-pass", "role": "viewer"})
    assert r.status_code == 201 and r.json()["email"] == "second@example.com"
    assert admin.delete(f"/api/admin/admins/{me['id']}").status_code == 409  # not yourself
    # The only active admin can't be demoted.
    assert admin.patch(f"/api/admin/admins/{me['id']}", json={"role": "viewer"}).status_code == 409
    second = r.json()["id"]
    assert admin.patch(f"/api/admin/admins/{second}", json={"active": False}).status_code == 200
    assert client.post("/api/admin/auth/login", json={"email": "second@example.com", "password": "second-pass"}).status_code == 401
    assert admin.delete(f"/api/admin/admins/{second}").status_code == 204


def test_change_own_password(admin_client, client):
    admin = admin_client(email="me@example.com")
    bad = admin.post("/api/admin/auth/password", json={"current_password": "wrong", "new_password": "new-admin-pass"})
    assert bad.status_code == 400
    assert admin.post("/api/admin/auth/password", json={"current_password": ADMIN_PASSWORD, "new_password": "new-admin-pass"}).status_code == 204
    assert admin.get("/api/admin/auth/me").status_code == 200  # this session got a fresh cookie
    assert client.post("/api/admin/auth/login", json={"email": "me@example.com", "password": "new-admin-pass"}).status_code == 200


def test_every_change_is_audited(admin_client):
    admin = admin_client()
    admin.post(f"/api/admin/users/{LOOKING}/ban", json={"reason": "r"})
    admin.post(f"/api/admin/users/{LOOKING}/unban")
    admin.post("/api/admin/banned-phones", json={"phones": ["+91 91111 00000"]})
    admin.patch(f"/api/admin/users/{LOOKING}", json={"bio": "edited"})
    log = actions(admin)
    assert log[:4] == ["user.update", "phone.block", "user.unban", "user.ban"]
    filtered = admin.get("/api/admin/audit", params={"action": "user."}).json()["items"]
    assert {row["action"] for row in filtered} == {"user.update", "user.unban", "user.ban"}
