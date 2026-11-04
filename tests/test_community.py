"""Reports from students (rules, admin review and one-click actions) and site announcements."""

from datetime import timedelta

from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.models import utcnow

LEAD, MEMBER, LOOKING, OTHER = "usr_1", "usr_9", "usr_6", "usr_8"


def report(c, target_type, target_id, reason="spam", details=""):
    return c.post("/api/reports", json={"target_type": target_type, "target_id": target_id, "reason": reason, "details": details})


def group_chat(c) -> str:
    return next(x["id"] for x in c.get("/api/conversations").json() if x["type"] == "group")


def test_students_report_people_groups_and_messages(as_user):
    student = as_user(OTHER)
    assert report(student, "user", LEAD, "harassment", "rude in DMs").status_code == 201
    assert report(student, "group", "grp_2").status_code == 201
    # Once per thing.
    r = report(student, "user", LEAD)
    assert r.status_code == 409 and "already reported" in r.json()["message"]
    # Not yourself, not your own group or message.
    assert report(student, "user", OTHER).status_code == 422
    assert report(as_user(LEAD), "group", "grp_1").status_code == 422
    lead = as_user(LEAD)
    conv = group_chat(lead)
    mine = lead.post(f"/api/conversations/{conv}/messages", json={"text": "my own words"}).json()
    assert report(lead, "message", mine["id"]).status_code == 422
    # A member can report it; an outsider can't even see it.
    assert report(as_user(MEMBER), "message", mine["id"], "inappropriate").status_code == 201
    assert report(student, "message", mine["id"]).status_code == 404
    # Unknown things and reasons.
    assert report(student, "user", "usr_nope").status_code == 404
    assert report(student, "user", MEMBER, "because").status_code == 422
    assert student.post("/api/reports", json={"target_type": "user", "target_id": MEMBER, "reason": "spam", "details": "x" * 1001}).status_code == 422
    assert TestClient(app).post("/api/reports", json={"target_type": "user", "target_id": LEAD, "reason": "spam"}).status_code == 401


def test_a_daily_limit_on_reports(as_user, monkeypatch):
    monkeypatch.setattr(get_settings(), "reports_per_day", 2)
    student = as_user(OTHER)
    assert report(student, "user", LEAD).status_code == 201
    assert report(student, "user", MEMBER).status_code == 201
    r = report(student, "user", LOOKING)
    assert r.status_code == 429 and "tomorrow" in r.json()["message"]


def test_admins_review_reports_and_act(as_user, admin_client):
    admin, viewer = admin_client(), admin_client("viewer")
    student, member = as_user(OTHER), as_user(MEMBER)
    lead = as_user(LEAD)
    conv = group_chat(lead)
    msg = lead.post(f"/api/conversations/{conv}/messages", json={"text": "buy cheap followers"}).json()
    r_msg = report(member, "message", msg["id"], "spam").json()["id"]
    r_user = report(student, "user", LOOKING, "fake_profile", "not a real student").json()["id"]
    r_group = report(student, "group", "grp_2").json()["id"]

    assert admin.get("/api/admin/stats").json()["reports"]["open"] == 3
    page = viewer.get("/api/admin/reports").json()
    assert page["total"] == 3
    row = next(x for x in page["items"] if x["id"] == r_msg)
    assert row["snapshot"].endswith("buy cheap followers") and row["target_user_id"] == LEAD and row["conversation_id"] == conv
    assert row["reason_label"] == "Spam or advertising" and row["reporter_name"]
    assert len(admin.get("/api/admin/reports", params={"target_type": "user"}).json()["items"]) == 1

    # Read-only admins can look, not act.
    for path, body in ((f"/api/admin/reports/{r_msg}/status", {"status": "dismissed"}), (f"/api/admin/reports/{r_user}/suspend", {}),
                       (f"/api/admin/reports/{r_msg}/delete-message", None)):
        assert viewer.post(path, json=body).status_code == 403

    # Delete the reported message: gone from the chat, the report keeps what it said.
    done = admin.post(f"/api/admin/reports/{r_msg}/delete-message").json()
    assert done["status"] == "actioned" and done["target_exists"] is False and "buy cheap followers" in done["snapshot"]
    assert all(m["id"] != msg["id"] for m in lead.get(f"/api/conversations/{conv}/messages").json())
    # Suspend the reported student: signed out at once.
    looking = as_user(LOOKING)
    done = admin.post(f"/api/admin/reports/{r_user}/suspend", json={"reason": "fake"}).json()
    assert done["status"] == "actioned" and done["target_user_banned"] is True
    assert looking.get("/api/auth/me").status_code == 403
    # Dismiss, and reopen.
    assert admin.post(f"/api/admin/reports/{r_group}/status", json={"status": "dismissed"}).json()["handled_by"]
    assert admin.post(f"/api/admin/reports/{r_group}/status", json={"status": "open"}).json()["status"] == "open"
    assert admin.get("/api/admin/stats").json()["reports"]["open"] == 1
    actions = [a["action"] for a in admin.get("/api/admin/audit").json()["items"]]
    assert {"report.delete_message", "report.suspend", "report.dismissed", "report.open"} <= set(actions)


def test_announcements_show_in_their_window(admin_client, client):
    admin = admin_client()
    assert client.get("/api/announcements").json() == []
    now = utcnow()
    live = admin.post("/api/admin/announcements", json={"text": "Submissions close Friday", "link_url": "https://example.com/rules",
                                                         "link_label": "Rules", "level": "warning"}).json()
    admin.post("/api/admin/announcements", json={"text": "Later", "starts_at": (now + timedelta(days=2)).isoformat()})
    admin.post("/api/admin/announcements", json={"text": "Over", "starts_at": (now - timedelta(days=3)).isoformat(),
                                                  "ends_at": (now - timedelta(days=1)).isoformat()})
    shown = client.get("/api/announcements").json()  # public: guests see it too
    assert [a["text"] for a in shown] == ["Submissions close Friday"] and shown[0]["level"] == "warning"
    assert {a["text"]: a["active"] for a in admin.get("/api/admin/announcements").json()} == {"Submissions close Friday": True, "Later": False, "Over": False}

    edited = admin.patch(f"/api/admin/announcements/{live['id']}", json={"text": "Submissions close Monday"}).json()
    assert edited["text"] == "Submissions close Monday"
    assert admin.delete(f"/api/admin/announcements/{live['id']}").status_code == 204
    assert client.get("/api/announcements").json() == []


def test_announcement_input_is_checked(admin_client):
    admin, viewer = admin_client(), admin_client("viewer")
    assert admin.post("/api/admin/announcements", json={"text": "x", "link_url": "javascript:alert(1)"}).status_code == 422
    assert admin.post("/api/admin/announcements", json={"text": "x", "link_url": "//evil.example"}).status_code == 422
    assert admin.post("/api/admin/announcements", json={"text": "x" * 301}).status_code == 422
    now = utcnow()
    assert admin.post("/api/admin/announcements", json={"text": "x", "starts_at": now.isoformat(),
                                                         "ends_at": (now - timedelta(hours=1)).isoformat()}).status_code == 422
    assert viewer.post("/api/admin/announcements", json={"text": "x"}).status_code == 403
    assert admin.post("/api/admin/announcements", json={"text": "See the rules", "link_url": "/groups"}).status_code == 201
