"""Security fixes: reset codes stay secret, unsafe settings, sign-in/sign-up/reset throttling,
phone-number privacy, private uploads, and the admin moderation tools that came with them."""

import pytest
from fastapi.testclient import TestClient

from app.check_config import problems, startup_check
from app.config import DEV_SECRET_KEY, Settings, get_settings
from app.main import app
from tests.conftest import PASSWORD, PHONES

LEAD, MEMBER, LOOKING, OTHER = "usr_1", "usr_9", "usr_6", "usr_8"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
PDF = b"%PDF-1.4\n" + b"0" * 64


def actions(admin) -> list[str]:
    return [row["action"] for row in admin.get("/api/admin/audit").json()["items"]]


# ---------------------------------------------------------------------------------------------
# Password-reset codes and unsafe settings
# ---------------------------------------------------------------------------------------------


def test_reset_code_is_never_returned_unless_allowed(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "allow_dev_code", False)
    r = client.post("/api/auth/password/forgot", json={"phone": PHONES["usr_8"]})
    assert r.status_code == 200 and r.json()["dev_code"] is None


def test_unsafe_settings_stop_a_secure_deployment():
    secure = Settings(cookie_secure=True, secret_key=DEV_SECRET_KEY, demo_login=False, allow_dev_code=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        startup_check(secure)
    with pytest.raises(RuntimeError, match="ALLOW_DEV_CODE"):
        startup_check(Settings(cookie_secure=True, secret_key="x" * 8 + "abcdefghijklmnopqrstuvwxyz0123456789", allow_dev_code=True))
    good = Settings(cookie_secure=True, secret_key="Q7v-2kLp9xZr4TbW8mNc1yHs6dFg3jEa5uRo0iVq", demo_login=False,
                    allow_dev_code=False, sms_provider="twilio", twilio_account_sid="AC-test", twilio_auth_token="t",
                    twilio_from_number="+15550000000", admin_password="", public_base_url="https://api.example.com")
    startup_check(good)
    assert problems(good) == []
    # On a laptop (plain HTTP) the same settings only warn.
    startup_check(Settings(cookie_secure=False, secret_key=DEV_SECRET_KEY, demo_login=True))


def test_check_config_lists_every_problem():
    found = dict((text.split(" ")[0], severity) for severity, text in problems(
        Settings(secret_key=DEV_SECRET_KEY, demo_login=True, cookie_secure=False, sms_provider="console",
                 admin_password="admin123", allow_dev_code=True)))
    assert found == {"SECRET_KEY": "fatal", "ALLOW_DEV_CODE=true": "fatal", "DEMO_LOGIN=true": "fatal",
                     "COOKIE_SECURE=false:": "warning", "SMS_PROVIDER=console:": "warning", "ADMIN_PASSWORD": "warning"}


# ---------------------------------------------------------------------------------------------
# Throttling (counters in PostgreSQL)
# ---------------------------------------------------------------------------------------------


def test_wrong_passwords_lock_the_number_and_a_success_resets_it(client):
    phone = PHONES["usr_8"]
    for _ in range(4):
        assert client.post("/api/auth/login", json={"phone": phone, "password": "wrong-password"}).status_code == 401
    # A success clears the count, so four more wrong ones are still allowed.
    assert client.post("/api/auth/login", json={"phone": phone, "password": PASSWORD}).status_code == 200
    for _ in range(5):
        assert client.post("/api/auth/login", json={"phone": phone, "password": "wrong-password"}).status_code == 401
    r = client.post("/api/auth/login", json={"phone": phone, "password": PASSWORD})
    assert r.status_code == 429
    assert "Try again in" in r.json()["message"] and int(r.headers["Retry-After"]) > 0
    # The same number in another format is the same number.
    assert client.post("/api/auth/login", json={"phone": "9278901234", "password": PASSWORD}).status_code == 429
    # Other numbers are fine.
    assert client.post("/api/auth/login", json={"phone": PHONES["usr_6"], "password": PASSWORD}).status_code == 200


def test_one_address_trying_many_numbers_is_stopped(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "login_limit_per_ip", 3)
    for n in range(3):
        assert client.post("/api/auth/login", json={"phone": f"+91 90000 0000{n}", "password": "x" * 8}).status_code == 401
    assert client.post("/api/auth/login", json={"phone": "+91 90000 00009", "password": "x" * 8}).status_code == 429
    # A different address is counted on its own.
    other = TestClient(app, client=("203.0.113.9", 5000))
    assert other.post("/api/auth/login", json={"phone": PHONES["usr_6"], "password": PASSWORD}).status_code == 200


def test_signup_and_reset_steps_are_throttled(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "signup_limit_per_ip", 2)
    body = {"name": "A", "college": "B", "passing_year": 2027, "password": "long-enough-1"}
    assert client.post("/api/auth/signup", json={**body, "phone": "+91 90000 11001"}).status_code == 201
    assert client.post("/api/auth/signup", json={**body, "phone": "+91 90000 11001"}).status_code == 409
    assert client.post("/api/auth/signup", json={**body, "phone": "+91 90000 11002"}).status_code == 429

    monkeypatch.setattr(settings, "verify_limit_per_phone", 2)
    phone = PHONES["usr_14"]
    client.post("/api/auth/password/forgot", json={"phone": phone})
    for _ in range(2):
        assert client.post("/api/auth/password/verify", json={"phone": phone, "code": "000000"}).status_code == 400
    assert client.post("/api/auth/password/verify", json={"phone": phone, "code": "000000"}).status_code == 429

    monkeypatch.setattr(settings, "reset_limit_per_phone", 1)
    monkeypatch.setattr(settings, "otp_resend_seconds", 0)
    assert client.post("/api/auth/password/forgot", json={"phone": PHONES["usr_8"]}).status_code == 200
    assert client.post("/api/auth/password/forgot", json={"phone": PHONES["usr_8"]}).status_code == 429


def test_counters_are_shared_through_the_database(client):
    from app.db import SessionLocal
    from app.models import RateLimit

    client.post("/api/auth/login", json={"phone": PHONES["usr_8"], "password": "wrong-password"})
    with SessionLocal() as db:
        row = db.get(RateLimit, "login:phone:919278901234")
        assert row is not None and row.count == 1


# ---------------------------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------------------------


def test_phone_numbers_are_only_shown_to_people_who_know_you(as_user):
    lead = as_user(LEAD)
    assert lead.get("/api/auth/me").json()["phone"] == PHONES[LEAD]
    mate = lead.get(f"/api/users/{MEMBER}").json()
    assert mate["phone_visible"] is True and "•" not in mate["phone"]
    stranger = lead.get(f"/api/users/{OTHER}").json()
    assert stranger["phone_visible"] is False and stranger["phone"] == "+91 92••• ••234"
    listed = {u["id"]: u for u in lead.get("/api/users", params={"limit": 200}).json()["items"]}
    assert listed[MEMBER]["phone_visible"] and not listed[OTHER]["phone_visible"]
    assert all("•" in u["phone"] for u in listed.values() if not u["phone_visible"])

    # A Looking student sees nobody's number but their own.
    looking = as_user(OTHER)
    others = [u for u in looking.get("/api/users", params={"limit": 200}).json()["items"] if u["id"] != OTHER]
    assert others and not any(u["phone_visible"] for u in others)


def test_an_accepted_request_shares_numbers_even_after_leaving(as_user):
    lead, student = as_user(LEAD), as_user(OTHER)
    req = student.post("/api/groups/grp_1/join-requests", json={"note": "hi"}).json()
    assert lead.patch(f"/api/requests/{req['id']}", json={"status": "accepted"}).status_code == 200
    student.post("/api/groups/grp_1/leave")
    assert lead.get(f"/api/users/{OTHER}").json()["phone_visible"] is True
    assert student.get(f"/api/users/{LEAD}").json()["phone_visible"] is True
    assert student.get(f"/api/users/{MEMBER}").json()["phone_visible"] is False


# ---------------------------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------------------------


def _path(url: str) -> str:
    return url.split("8000", 1)[-1] if "8000" in url else url[url.index("/uploads/"):]


def test_avatars_are_public_resumes_need_a_sign_in(as_user, client):
    student = as_user(OTHER)
    avatar = student.post(f"/api/users/{OTHER}/avatar", files={"avatar": ("me.png", PNG, "image/png")}).json()["avatar_url"]
    resume = student.post(f"/api/users/{OTHER}/resume", files={"resume": ("cv.pdf", PDF, "application/pdf")}).json()["resume_url"]
    guest = TestClient(app)
    r = guest.get(_path(avatar))
    assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.headers["x-content-type-options"] == "nosniff"
    assert guest.get(_path(resume)).status_code == 401
    r = as_user(LEAD).get(_path(resume))
    assert r.status_code == 200 and r.content == PDF and "no-store" in r.headers["cache-control"]
    assert r.headers["content-disposition"].startswith("inline")  # opens in the browser


def test_attachments_are_only_for_the_conversation(as_user, admin_client):
    lead, member, outsider = as_user(LEAD), as_user(MEMBER), as_user(OTHER)
    group = next(c for c in lead.get("/api/conversations").json() if c["type"] == "group")
    att = lead.post("/api/uploads/attachments", files={"file": ("notes.pdf", PDF, "application/pdf")}).json()
    # Not sent yet: nobody else can read it.
    assert member.get(_path(att["url"])).status_code == 403
    assert lead.post(f"/api/conversations/{group['id']}/messages", json={"text": "", "attachment": att}).status_code == 201
    r = member.get(_path(att["url"]))
    assert r.status_code == 200 and r.content == PDF
    # Downloads under its own name (a link to another origin can't ask for that itself).
    assert r.headers["content-disposition"].startswith("attachment") and 'filename="notes.pdf"' in r.headers["content-disposition"]
    assert outsider.get(_path(att["url"])).status_code == 403
    assert TestClient(app).get(_path(att["url"])).status_code == 401
    assert admin_client().get(_path(att["url"])).status_code == 200

    # The link can't be re-sent elsewhere to read it, and only our own uploads can be attached.
    direct = outsider.post("/api/conversations/direct", json={"user_id": LEAD}).json()
    assert outsider.post(f"/api/conversations/{direct['id']}/messages", json={"text": "", "attachment": att}).status_code == 409
    fake = {**att, "url": "https://evil.example/x.pdf"}
    assert outsider.post(f"/api/conversations/{direct['id']}/messages", json={"text": "", "attachment": fake}).status_code == 422


@pytest.mark.parametrize("path", [
    "/uploads/avatar/..%2F..%2F.env",
    "/uploads/avatar/../../.env",
    "/uploads/resume/%2e%2e/%2e%2e/app/config.py",
    "/uploads/avatar/ava_0123456789abcdef.exe",
    "/uploads/secrets/ava_0123456789abcdef.png",
    "/uploads/avatar/ava_0123456789abcdef.png",
])
def test_path_traversal_and_unknown_files(client, path):
    assert client.get(path).status_code in (404, 422)


def test_renamed_executables_and_large_files_are_refused(as_user):
    c = as_user(OTHER)
    exe = b"MZ\x90\x00" + b"\x00" * 200
    assert c.post(f"/api/users/{OTHER}/avatar", files={"avatar": ("photo.png", exe, "image/png")}).status_code == 415
    assert c.post("/api/uploads/attachments", files={"file": ("doc.pdf", exe, "application/pdf")}).status_code == 415
    big = PNG + b"\x00" * (2 * 1024 * 1024)
    assert c.post(f"/api/users/{OTHER}/avatar", files={"avatar": ("big.png", big, "image/png")}).status_code == 413


# ---------------------------------------------------------------------------------------------
# Admin moderation
# ---------------------------------------------------------------------------------------------


def test_admin_removes_a_photo_and_resume_and_the_files(as_user, admin_client):
    student = as_user(OTHER)
    avatar = student.post(f"/api/users/{OTHER}/avatar", files={"avatar": ("me.png", PNG, "image/png")}).json()["avatar_url"]
    resume = student.post(f"/api/users/{OTHER}/resume", files={"resume": ("cv.pdf", PDF, "application/pdf")}).json()["resume_url"]
    admin = admin_client()
    assert admin_client("viewer").delete(f"/api/admin/users/{OTHER}/avatar").status_code == 403
    detail = admin.delete(f"/api/admin/users/{OTHER}/avatar").json()
    assert detail["avatar_url"] is None
    assert TestClient(app).get(_path(avatar)).status_code == 404  # gone from disk
    assert admin.delete(f"/api/admin/users/{OTHER}/resume").json()["resume_url"] is None
    assert admin.get(_path(resume)).status_code == 404
    assert admin.delete(f"/api/admin/users/{OTHER}/resume").status_code == 409
    assert {"user.remove_avatar", "user.remove_resume"} <= set(actions(admin))


def test_admin_edits_a_group_and_hands_over_the_lead(as_user, admin_client):
    admin = admin_client()
    viewer = admin_client("viewer")
    assert viewer.patch("/api/admin/groups/grp_1", json={"name": "X"}).status_code == 403
    assert viewer.post("/api/admin/groups/grp_1/lead", json={"user_id": MEMBER}).status_code == 403
    assert admin.patch("/api/admin/groups/grp_1", json={"max_members": 9}).status_code == 422
    g = admin.patch("/api/admin/groups/grp_1", json={"name": "Renamed", "domain": "Robotics", "requirements": ["ROS", "ros", " C++ "]}).json()
    assert g["name"] == "Renamed" and g["domain"] == "Robotics" and g["requirements"] == ["ROS", "C++"]
    assert as_user(MEMBER).get("/api/groups/grp_1").json()["name"] == "Renamed"

    g = admin.post("/api/admin/groups/grp_1/lead", json={"user_id": MEMBER}).json()
    roles = {m["user_id"]: m["role"] for m in g["members"]}
    assert roles[MEMBER] == "admin" and roles[LEAD] == "member" and g["lead_id"] == MEMBER
    # The new lead can act as lead, the old one can't.
    assert as_user(MEMBER).patch("/api/groups/grp_1", json={"description": "New lead"}).status_code == 200
    assert as_user(LEAD).patch("/api/groups/grp_1", json={"description": "Old lead"}).status_code == 403
    assert admin.post("/api/admin/groups/grp_1/lead", json={"user_id": OTHER}).status_code == 409
    assert {"group.edit", "group.transfer_lead"} <= set(actions(admin))


def test_admin_reads_recommendations(as_user, admin_client):
    r = as_user(MEMBER).post("/api/recommendations", json={"studentId": OTHER, "groupId": "grp_1", "note": "Good at ML"})
    assert r.status_code == 201, r.text
    page = admin_client("viewer").get("/api/admin/recommendations").json()
    assert page["total"] >= 1
    row = next(r for r in page["items"] if r["student_id"] == OTHER)
    assert row["recommender_id"] == MEMBER and row["group_name"] and row["note"] == "Good at ML"
    assert admin_client().get("/api/admin/recommendations", params={"status": "dismissed"}).json()["total"] == 0


def test_student_and_admin_sessions_are_separate(as_user, admin_client):
    student = as_user(LEAD)
    for path in ("/api/admin/stats", "/api/admin/users", "/api/admin/recommendations", "/api/admin/audit"):
        assert student.get(path).status_code == 401
    assert student.delete(f"/api/admin/users/{OTHER}/avatar").status_code == 401
    admin = admin_client()
    assert admin.get("/api/auth/me").status_code == 401
    assert admin.post("/api/groups", json={"name": "X", "description": "Y", "max_members": 4, "domain": "AI"}).status_code == 401
