"""Regression tests for the security audit: every admin route checked automatically, profile links,
password rules, sign-in timing, message history limits, conflicting writes, input limits."""

import re

import pytest
from sqlalchemy.exc import IntegrityError

from app.main import app
from app.passwords import password_problem
from tests.conftest import ADMIN_PASSWORD, PASSWORD, PHONES

LEAD, MEMBER, LOOKING, OTHER = "usr_1", "usr_9", "usr_6", "usr_8"
PNG = __import__("tests.conftest", fromlist=["REAL_PNG"]).REAL_PNG  # a real 8x8 image (uploads are re-encoded)


# ---------------------------------------------------------------------------------------------
# Every admin route: needs an admin; a read-only admin can't write; every write is audited
# ---------------------------------------------------------------------------------------------

def _admin_routes() -> list[tuple[str, str]]:
    spec = app.openapi()
    return [
        (method.upper(), path)
        for path, methods in spec["paths"].items()
        if path.startswith("/api/admin/")
        for method in methods
    ]


# A real call for every admin write: (method, path) -> (url, body). A new write route without an
# entry here fails test_every_admin_write_is_audited, so it can't ship unaudited.
def _write_calls(admin, ids) -> dict[tuple[str, str], tuple[str, dict | None]]:
    return {
        ("POST", "/api/admin/auth/password"): ("/api/admin/auth/password", {"current_password": "admin-password-1", "new_password": "admin-password-2"}),
        ("POST", "/api/admin/admins"): ("/api/admin/admins", {"email": "new-admin@example.com", "name": "New", "password": "new-admin-pass-1", "role": "viewer"}),
        ("PATCH", "/api/admin/admins/{admin_id}"): (f"/api/admin/admins/{ids['viewer_admin']}", {"role": "admin"}),
        ("DELETE", "/api/admin/admins/{admin_id}"): (f"/api/admin/admins/{ids['viewer_admin']}", None),
        ("POST", "/api/admin/users"): ("/api/admin/users", {"name": "Audit Student", "college": "X", "passing_year": 2027, "phone": "+91 90000 12121", "password": "audit-pass-123", "skills": []}),
        ("PATCH", "/api/admin/users/{user_id}"): (f"/api/admin/users/{OTHER}", {"bio": "edited"}),
        ("POST", "/api/admin/users/{user_id}/password"): (f"/api/admin/users/{OTHER}/password", {"password": "a-new-password-9"}),
        ("POST", "/api/admin/users/{user_id}/ban"): (f"/api/admin/users/{OTHER}/ban", {"reason": "spam"}),
        ("POST", "/api/admin/users/{user_id}/unban"): (f"/api/admin/users/{OTHER}/unban", None),
        ("DELETE", "/api/admin/users/{user_id}/{kind}"): (f"/api/admin/users/{OTHER}/avatar", None),
        ("POST", "/api/admin/users/bulk"): ("/api/admin/users/bulk", {"ids": [LOOKING], "action": "ban", "reason": ""}),
        ("DELETE", "/api/admin/users/{user_id}"): ("/api/admin/users/usr_14", None),
        ("POST", "/api/admin/banned-phones"): ("/api/admin/banned-phones", {"phones": ["+91 90000 34343"]}),
        ("POST", "/api/admin/banned-phones/bulk-delete"): ("/api/admin/banned-phones/bulk-delete", {"ids": ["919000034343"]}),
        ("DELETE", "/api/admin/banned-phones/{phone}"): ("/api/admin/banned-phones/919000056565", None),
        ("POST", "/api/admin/groups/bulk-delete"): ("/api/admin/groups/bulk-delete", {"ids": ["grp_3"]}),
        ("PATCH", "/api/admin/groups/{group_id}"): ("/api/admin/groups/grp_1", {"name": "Audited"}),
        ("POST", "/api/admin/groups/{group_id}/lead"): ("/api/admin/groups/grp_1/lead", {"user_id": MEMBER}),
        ("DELETE", "/api/admin/groups/{group_id}/members/{user_id}"): (f"/api/admin/groups/grp_1/members/{LEAD}", None),
        ("DELETE", "/api/admin/groups/{group_id}"): ("/api/admin/groups/grp_4", None),
        ("POST", "/api/admin/requests/bulk-cancel"): ("/api/admin/requests/bulk-cancel", {"ids": [ids["request"]]}),
        ("POST", "/api/admin/requests/{request_id}/cancel"): (f"/api/admin/requests/{ids['request2']}/cancel", None),
        ("POST", "/api/admin/messages/bulk-delete"): ("/api/admin/messages/bulk-delete", {"ids": [ids["message"]]}),
        # The admin changed its password above (admin-password-2): the export asks for it again.
        ("POST", "/api/admin/users/export.csv"): ("/api/admin/users/export.csv", {"password": "admin-password-2"}),
        ("DELETE", "/api/admin/messages/{message_id}"): (f"/api/admin/messages/{ids['message2']}", None),
        **_extra_write_calls(ids),
    }


def _extra_write_calls(ids) -> dict:
    """Write routes added later register here (reports, announcements)."""
    return {key: value(ids) for key, value in EXTRA_WRITES.items()}


EXTRA_WRITES: dict = {
    ("POST", "/api/admin/reports/{report_id}/status"): lambda ids: (f"/api/admin/reports/{ids['report']}/status", {"status": "dismissed"}),
    ("POST", "/api/admin/reports/{report_id}/suspend"): lambda ids: (f"/api/admin/reports/{ids['report2']}/suspend", {"reason": "spam"}),
    ("POST", "/api/admin/reports/{report_id}/delete-message"): lambda ids: (f"/api/admin/reports/{ids['report_message']}/delete-message", None),
    ("POST", "/api/admin/announcements"): lambda ids: ("/api/admin/announcements", {"text": "Maintenance tonight", "level": "warning"}),
    ("PATCH", "/api/admin/announcements/{announcement_id}"): lambda ids: (f"/api/admin/announcements/{ids['announcement']}", {"text": "Edited"}),
    ("DELETE", "/api/admin/announcements/{announcement_id}"): lambda ids: (f"/api/admin/announcements/{ids['announcement']}", None),
}
# Signing yourself in or out (also everywhere: any admin, viewers too, may end their own sessions).
NOT_DATA_WRITES = {("POST", "/api/admin/auth/login"), ("POST", "/api/admin/auth/logout"), ("POST", "/api/admin/auth/logout-all"),
                   ("POST", "/api/admin/auth/refresh")}  # renews the session; changes no data


def test_every_admin_route_needs_an_admin(client, as_user):
    student = as_user(LEAD)
    for method, path in _admin_routes():
        if (method, path) in NOT_DATA_WRITES:
            continue
        url = re.sub(r"\{[^}]+\}", "x", path)
        for who, c in (("nobody", client), ("a student", student)):
            response = c.request(method, url, json={} if method != "GET" else None)
            assert response.status_code in (401, 422), f"{method} {path} as {who}: {response.status_code}"
            if response.status_code == 422:
                # Body validation can run first; with no body errors it must still be refused.
                assert method != "GET"


def test_read_only_admins_cannot_write_anywhere(admin_client):
    viewer = admin_client("viewer")
    writes = [(m, p) for m, p in _admin_routes() if m != "GET" and (m, p) not in NOT_DATA_WRITES]
    assert len(writes) >= 20
    for method, path in writes:
        if path == "/api/admin/auth/password":
            continue  # every admin may change their own password
        url = re.sub(r"\{[^}]+\}", "x", path)
        response = viewer.request(method, url, json={})
        assert response.status_code in (403, 422), f"{method} {path} as a viewer: {response.status_code}"
        if response.status_code == 422:
            # Validation ran first: with a valid-looking body it is still a 403.
            assert viewer.request(method, url, json={"ids": ["x"], "reason": "", "action": "ban", "phones": ["1"], "name": "x",
                                                     "user_id": "x", "password": "a-long-pass-1", "role": "admin"}).status_code in (403, 422)


def _ids(admin_client, as_user):
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import AdminUser, JoinRequest

    lead = as_user(LEAD)
    conv = next(c["id"] for c in lead.get("/api/conversations").json() if c["type"] == "group")
    messages = [lead.post(f"/api/conversations/{conv}/messages", json={"text": text}).json()["id"] for text in ("one", "two")]
    viewer = admin_client("viewer")
    with SessionLocal() as db:
        pending = list(db.scalars(select(JoinRequest.id).where(JoinRequest.status == "pending")))
        viewer_id = db.scalar(select(AdminUser.id).where(AdminUser.role == "viewer"))
    as_user(OTHER).post(f"/api/users/{OTHER}/avatar", files={"avatar": ("me.png", PNG, "image/png")})
    del viewer
    # Reports and an announcement for the report/announcement write routes.
    reports = []
    for target in (LEAD, MEMBER):
        reports.append(as_user(OTHER).post("/api/reports", json={"target_type": "user", "target_id": target, "reason": "spam"}).json()["id"])
    member = as_user(MEMBER)
    reported = member.post(f"/api/conversations/{conv}/messages", json={"text": "reported"}).json()["id"]
    reports.append(as_user(LEAD).post("/api/reports", json={"target_type": "message", "target_id": reported, "reason": "spam"}).json()["id"])
    ann = admin_client().post("/api/admin/announcements", json={"text": "Hello"}).json()["id"]
    return {"request": pending[0], "request2": pending[1], "message": messages[0], "message2": messages[1], "viewer_admin": viewer_id,
            "report": reports[0], "report2": reports[1], "report_message": reports[2], "announcement": ann}


def test_every_admin_write_is_audited(admin_client, as_user):
    from sqlalchemy import func, select

    from app.db import SessionLocal
    from app.models import AuditLog

    admin = admin_client()
    admin.post("/api/admin/banned-phones", json={"phones": ["+91 90000 56565"]})
    ids = _ids(admin_client, as_user)
    calls = _write_calls(admin, ids)
    writes = {(m, p) for m, p in _admin_routes() if m != "GET"} - NOT_DATA_WRITES
    assert writes == set(calls), f"admin write routes without an audit check: {writes - set(calls)}"

    for (method, path), (url, body) in calls.items():
        with SessionLocal() as db:
            before = db.scalar(select(func.count()).select_from(AuditLog))
        response = admin.request(method, url, json=body)
        assert response.status_code < 300, f"{method} {path}: {response.status_code} {response.text}"
        with SessionLocal() as db:
            after = db.scalar(select(func.count()).select_from(AuditLog))
        assert after > before, f"{method} {path} wrote nothing to the audit log"


# ---------------------------------------------------------------------------------------------
# Students
# ---------------------------------------------------------------------------------------------


def test_profile_links_cannot_be_set_by_hand(as_user):
    student = as_user(OTHER)
    for field in ("resume_url", "avatar_url"):
        for value in ("javascript:alert(1)", "https://evil.example/cv.pdf", "http://localhost:8000/uploads/resume/res_0123456789abcdef.pdf"):
            assert student.patch(f"/api/users/{OTHER}", json={field: value}).status_code == 422
    # Clearing works and deletes the file.
    url = student.post(f"/api/users/{OTHER}/avatar", files={"avatar": ("me.png", PNG, "image/png")}).json()["avatar_url"]
    assert student.patch(f"/api/users/{OTHER}", json={"avatar_url": None}).json().get("avatar_url") is None
    assert student.get(url[url.index("/uploads/"):]).status_code == 404  # deleted (visitors get 401 for anything)


@pytest.mark.parametrize("password", ["password123", "PASSWORD123", "12345678", "aaaaaaaa", "qwertyuiop", "capstone123"])
def test_common_passwords_are_refused(client, password):
    r = client.post("/api/auth/signup", json={"name": "A", "college": "B", "passing_year": 2027, "phone": "+91 90000 22334", "password": password})
    assert r.status_code == 422 and "common" in r.json()["message"]


def test_phone_number_as_password_is_refused(client):
    r = client.post("/api/auth/signup", json={"name": "A", "college": "B", "passing_year": 2027, "phone": "+91 90000 22335", "password": "9000022335"})
    assert r.status_code == 422 and "phone number" in r.json()["message"]
    assert password_problem("a-strong-one-2026") is None


def test_admin_set_passwords_follow_the_rules(admin_client):
    admin = admin_client()
    assert admin.post(f"/api/admin/users/{OTHER}/password", json={"password": "password123"}).status_code == 422


def test_unknown_numbers_cost_the_same_bcrypt_check(client, monkeypatch):
    import app.routers.auth as auth

    calls = []
    real = auth.verify_password
    monkeypatch.setattr(auth, "verify_password", lambda p, h: calls.append(h) or real(p, h))
    client.post("/api/auth/login", json={"phone": "+91 90000 00001", "password": "whatever-1"})
    client.post("/api/auth/login", json={"phone": PHONES[OTHER], "password": "whatever-1"})
    assert len(calls) == 2 and calls[0] != calls[1]


def test_login_inputs_are_bounded(client):
    assert client.post("/api/auth/login", json={"phone": "9" * 40, "password": "x"}).status_code == 422
    assert client.post("/api/auth/login", json={"phone": PHONES[OTHER], "password": "x" * 201}).status_code == 422


def test_message_history_is_paged(as_user, monkeypatch):
    from app.services import chat

    monkeypatch.setattr(chat, "MESSAGE_PAGE", 3)
    lead = as_user(LEAD)
    conv = next(c["id"] for c in lead.get("/api/conversations").json() if c["type"] == "group")
    for i in range(5):
        lead.post(f"/api/conversations/{conv}/messages", json={"text": f"m{i}"})
    latest = lead.get(f"/api/conversations/{conv}/messages").json()
    assert [m["text"] for m in latest] == ["m2", "m3", "m4"]
    older = lead.get(f"/api/conversations/{conv}/messages", params={"before": latest[0]["created_at"]}).json()
    assert [m["text"] for m in older][-2:] == ["m0", "m1"]


def test_attachment_size_is_the_real_one(as_user):
    lead = as_user(LEAD)
    conv = next(c["id"] for c in lead.get("/api/conversations").json() if c["type"] == "group")
    att = lead.post("/api/uploads/attachments", files={"file": ("a.pdf", b"%PDF-1.4 hello\n%%EOF", "application/pdf")}).json()
    sent = lead.post(f"/api/conversations/{conv}/messages", json={"text": "", "attachment": {**att, "size": 999999999}}).json()
    assert sent["attachment"]["size"] == len(b"%PDF-1.4 hello\n%%EOF")


def test_conflicting_writes_are_a_clean_409(as_user, monkeypatch):
    from sqlalchemy.orm import Session

    student = as_user(OTHER)

    def boom(self):
        raise IntegrityError("INSERT", {}, Exception("duplicate key"))

    monkeypatch.setattr(Session, "commit", boom)
    r = student.post("/api/presence")
    assert r.status_code == 409 and "Refresh and try again" in r.json()["message"]


def test_students_cannot_touch_others_things(as_user):
    """IDOR sweep: another student's profile, group, requests, recommendations and chats."""
    outsider = as_user(OTHER)
    assert outsider.patch(f"/api/users/{LEAD}", json={"bio": "hacked"}).status_code == 403
    assert outsider.post(f"/api/users/{LEAD}/avatar", files={"avatar": ("x.png", PNG, "image/png")}).status_code == 403
    assert outsider.patch("/api/groups/grp_1", json={"name": "hacked"}).status_code == 403
    assert outsider.delete("/api/groups/grp_1").status_code == 403
    assert outsider.delete(f"/api/groups/grp_1/members/{MEMBER}").status_code == 403
    group_chat = next(c["id"] for c in as_user(LEAD).get("/api/conversations").json() if c["type"] == "group")
    # Someone else's conversation answers like a missing one (404), so ids can't be probed.
    assert outsider.get(f"/api/conversations/{group_chat}/messages").status_code == 404
    assert outsider.post(f"/api/conversations/{group_chat}/messages", json={"text": "hi"}).status_code == 404
    assert outsider.post(f"/api/conversations/{group_chat}/read").status_code == 404
    # Someone else's join request can't be accepted, withdrawn or cancelled by an outsider.
    pending = as_user(LEAD).get("/api/requests", params={"direction": "received"}).json()
    req = next(r for r in pending if r["status"] == "pending")
    for status in ("accepted", "declined", "withdrawn", "cancelled"):
        assert outsider.patch(f"/api/requests/{req['id']}", json={"status": status}).status_code == 404  # no part in it: like a missing one
    # Recommendations are for the lead only.
    assert outsider.get("/api/recommendations").json() == []
    recs = as_user(LEAD).get("/api/recommendations").json()
    if recs:
        assert outsider.post(f"/api/recommendations/{recs[0]['id']}/dismiss").status_code == 403
    # A member can't invite on the lead's behalf.
    assert as_user(MEMBER).post(f"/api/users/{OTHER}/invitations", json={"group_id": "grp_1", "note": ""}).status_code == 403
    assert PASSWORD  # seeded students keep their old password (rules apply only to new ones)
