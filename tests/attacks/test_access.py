"""Part 4: CSRF, IDOR (every route with an id in its path), mass assignment."""

import re

import pytest

from app.main import app
from tests.attacks.test_fuzz_routes import _sample  # schema-driven valid bodies

GOOD_ORIGIN = "http://localhost:3000"
BAD_ORIGINS = ["https://evil.example", "null", "http://localhost:3000.evil.example", "http://evil-localhost:3000",
               "http://localhost:3001", "https://localhost:3000", "HTTP://LOCALHOST:3000x"]
GROUP = {"name": "CSRF probe", "description": "x", "max_members": 4, "domain": "Testing"}


# --- CSRF ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("origin", BAD_ORIGINS)
def test_student_writes_from_another_origin_are_refused(as_user, origin):
    c = as_user("usr_8")
    r = c.post("/api/groups", json=GROUP, headers={"Origin": origin})
    assert r.status_code == 403, (origin, r.text)
    assert c.get("/api/auth/me").json()["group_id"] is None  # nothing was created


@pytest.mark.parametrize("referer", ["https://evil.example/page", "http://localhost:3000.evil.example/x"])
def test_student_writes_with_a_foreign_referer_are_refused(as_user, referer):
    r = as_user("usr_8").post("/api/groups", json=GROUP, headers={"Referer": referer})
    assert r.status_code == 403


def test_student_writes_from_the_site_work(as_user):
    c = as_user("usr_8")
    assert c.post("/api/groups", json=GROUP, headers={"Origin": GOOD_ORIGIN}).status_code == 201


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "text/html", "application/xml"])
def test_simple_request_content_types_are_refused(as_user, admin_client, content_type):
    """A cross-site form or fetch without preflight can only send these: never accepted."""
    body = '{"name":"CSRF probe","description":"x","max_members":4,"domain":"Testing"}'
    r = as_user("usr_8").post("/api/groups", content=body, headers={"Content-Type": content_type})
    assert r.status_code == 415, (content_type, r.status_code)
    r = admin_client().post("/api/admin/announcements", content='{"text":"x"}', headers={"Content-Type": content_type})
    assert r.status_code == 415


@pytest.mark.parametrize("origin", BAD_ORIGINS)
def test_admin_writes_from_another_origin_are_refused(admin_client, origin):
    admin = admin_client()
    r = admin.post("/api/admin/announcements", json={"text": "CSRF"}, headers={"Origin": origin})
    assert r.status_code == 403
    assert all(a["text"] != "CSRF" for a in admin.get("/api/admin/announcements").json())


def test_admin_writes_from_the_portal_work(admin_client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "cors_origins", [*get_settings().cors_origins, "http://localhost:3100"])
    r = admin_client().post("/api/admin/announcements", json={"text": "ok"}, headers={"Origin": "http://localhost:3100"})
    assert r.status_code == 201


def test_logout_can_not_be_forced_from_another_site(as_user):
    c = as_user("usr_8")
    assert c.post("/api/auth/logout", headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.get("/api/auth/me").status_code == 200


# --- IDOR sweep ---------------------------------------------------------------------------------
# Every route with an id in its path is listed here (the last test fails on any new one), as
# either an attack case or a documented "anyone signed in may read this" with what stays hidden.

ATTACKS = {
    # (method, path): [(attacker, url, body, allowed answers), ...]
    ("PATCH", "/api/users/{user_id}"): [("usr_8", "/api/users/usr_1", {"bio": "pwned"}, {403})],
    ("POST", "/api/users/{user_id}/avatar"): [("usr_8", "/api/users/usr_1/avatar", "file", {403})],
    ("POST", "/api/users/{user_id}/resume"): [("usr_8", "/api/users/usr_1/resume", "file", {403})],
    ("POST", "/api/users/{user_id}/invitations"): [
        ("usr_8", "/api/users/usr_14/invitations", {"group_id": "grp_1"}, {403, 409}),   # in no group at all
        ("usr_9", "/api/users/usr_8/invitations", {"group_id": "grp_1"}, {403}),    # a member, not its lead
        ("usr_2", "/api/users/usr_8/invitations", {"group_id": "grp_1"}, {403}),    # another group's lead
    ],
    ("PATCH", "/api/groups/{group_id}"): [("usr_2", "/api/groups/grp_1", {"name": "pwned"}, {403}),
                                         ("usr_9", "/api/groups/grp_1", {"name": "pwned"}, {403})],
    ("DELETE", "/api/groups/{group_id}"): [("usr_2", "/api/groups/grp_1", None, {403}), ("usr_9", "/api/groups/grp_1", None, {403})],
    ("POST", "/api/groups/{group_id}/leave"): [("usr_8", "/api/groups/grp_1/leave", None, {400, 403, 404, 409})],
    ("DELETE", "/api/groups/{group_id}/members/{member_id}"): [
        ("usr_2", "/api/groups/grp_1/members/usr_9", None, {403}), ("usr_9", "/api/groups/grp_1/members/usr_11", None, {403}),
    ],
    ("PATCH", "/api/requests/{request_id}"): [
        ("usr_8", "/api/requests/req_1", {"status": "accepted"}, {403, 404}),   # someone else's join request
        ("usr_2", "/api/requests/req_1", {"status": "accepted"}, {403, 404}),   # another group's lead
        ("usr_9", "/api/requests/req_1", {"status": "accepted"}, {403, 404}),   # a member, not the lead
        ("usr_8", "/api/requests/req_5", {"status": "accepted"}, {403, 404}),   # an invitation for usr_14
    ],
    ("POST", "/api/recommendations/{recommendation_id}/dismiss"): [("usr_8", "/api/recommendations/rec_1/dismiss", None, {403, 404}),
                                                                  ("usr_2", "/api/recommendations/rec_1/dismiss", None, {403, 404})],
    ("POST", "/api/recommendations/{recommendation_id}/invite"): [("usr_8", "/api/recommendations/rec_1/invite", {"note": ""}, {403, 404}),
                                                                 ("usr_2", "/api/recommendations/rec_1/invite", {"note": ""}, {403, 404})],
    ("GET", "/api/conversations/{conversation_id}"): [("usr_8", "/api/conversations/conv_2", None, {403, 404}),
                                                     ("usr_8", "/api/conversations/conv_1", None, {403, 404})],
    ("GET", "/api/conversations/{conversation_id}/messages"): [("usr_8", "/api/conversations/conv_1/messages", None, {403, 404}),
                                                              ("usr_9", "/api/conversations/conv_2/messages", None, {403, 404})],
    ("POST", "/api/conversations/{conversation_id}/messages"): [("usr_8", "/api/conversations/conv_1/messages", {"text": "hi"}, {403, 404}),
                                                               ("usr_9", "/api/conversations/conv_2/messages", {"text": "hi"}, {403, 404})],
    ("POST", "/api/conversations/{conversation_id}/read"): [("usr_8", "/api/conversations/conv_2/read", None, {403, 404})],
}

# Anyone signed in may use these by design; the comment says what stays private.
BY_DESIGN = {
    ("GET", "/api/users/{user_id}"): "public profile; the phone is masked unless you are connected (test below)",
    ("GET", "/api/users/{user_id}/github"): "public GitHub summary of the linked account",
    ("GET", "/api/groups/{group_id}"): "the notice board: every group is public",
    ("POST", "/api/groups/{group_id}/join-requests"): "asking to join is open to any student; acts only as yourself",
    ("POST", "/api/auth/demo-login/{user_id}"): "demo persona switcher, 404 unless DEMO_LOGIN=true (test below)",
    ("GET", "/uploads/{purpose}/{name}"): "avatars public, résumés for signed-in users, attachments for participants (test below)",
}


def _covered_routes():
    for path, ops in app.openapi()["paths"].items():
        if "{" not in path or path.startswith("/api/admin/"):
            continue  # admin routes: test_audit refuses students and viewers on every one
        for method in ops:
            yield method.upper(), path


def test_every_id_route_is_covered():
    missing = [r for r in _covered_routes() if r not in ATTACKS and r not in BY_DESIGN]
    assert missing == [], f"add these to the IDOR sweep: {missing}"
    stale = [r for r in [*ATTACKS, *BY_DESIGN] if r not in set(_covered_routes())]
    assert stale == []


@pytest.mark.parametrize("route", sorted(ATTACKS), ids=lambda r: f"{r[0]} {r[1]}")
def test_idor(as_user, route):
    for attacker, url, body, allowed in ATTACKS[route]:
        c = as_user(attacker)
        if body == "file":
            field = "avatar" if url.endswith("avatar") else "resume"
            kind = ("me.png", b"\x89PNG\r\n\x1a\n" + b"0" * 64, "image/png") if field == "avatar" else ("cv.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")
            r = c.post(url, files={field: kind})
        else:
            r = c.request(route[0], url, json=body)
        assert r.status_code in allowed, f"{attacker} {route[0]} {url}: {r.status_code} {r.text[:200]}"
    # Nothing changed for the owners.
    owner = as_user("usr_1")
    assert owner.get("/api/users/usr_1").json()["bio"] != "pwned"
    assert owner.get("/api/groups/grp_1").json()["name"] != "pwned"
    assert {m["user_id"] for m in owner.get("/api/groups/grp_1").json()["members"]} >= {"usr_1", "usr_9", "usr_11"}


def test_profiles_hide_phone_numbers_from_strangers(as_user):
    stranger = as_user("usr_8").get("/api/users/usr_1").json()
    assert stranger["phone_visible"] is False and "43210" not in stranger["phone"].replace(" ", "")[:-3]
    assert re.search(r"\d{5}", stranger["phone"].replace(" ", "")) is None


def test_demo_login_is_off_unless_enabled(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "demo_login", False)
    assert client.post("/api/auth/demo-login/usr_1").status_code == 404


def test_attachments_are_only_for_the_conversation(as_user, client):
    lead = as_user("usr_1")
    up = lead.post("/api/uploads/attachments", files={"file": ("notes.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")})
    assert up.status_code == 201, up.text
    url = up.json()["url"]
    lead.post("/api/conversations/conv_2/messages", json={"text": "", "attachment": up.json()})
    path = "/" + url.split("/", 3)[3] if url.startswith("http") else url
    assert as_user("usr_2").get(path).status_code == 200      # the other participant
    assert as_user("usr_8").get(path).status_code in (403, 404)  # a stranger
    assert client.get(path).status_code == 401                  # nobody


# --- Mass assignment ------------------------------------------------------------------------------

PRIVILEGED = {"role": "admin", "id": "usr_x", "created_by": "usr_x", "banned_at": "2026-01-01T00:00:00Z",
              "password_hash": "x", "github_verified": True, "github_contribution_count": 99999,
              "outcome_updates": 9, "group_id": "grp_1", "is_admin": True, "lead_id": "usr_8", "status": "accepted",
              "members": [], "phone_normalized": "1"}


def _json_writes():
    spec = app.openapi()
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            content = (op.get("requestBody") or {}).get("content", {})
            if "application/json" in content:
                yield method.upper(), path, content["application/json"]["schema"], spec


@pytest.mark.parametrize("field", sorted(PRIVILEGED))
def test_no_body_accepts_privileged_fields(as_user, admin_client, field):
    """Every JSON body in the API, with one privileged field added, is refused (422) by schema."""
    student, admin = as_user("usr_8"), admin_client()
    checked = 0
    for method, path, schema, spec in _json_writes():
        body = _sample(spec, schema)
        if not isinstance(body, dict) or field in (spec["components"]["schemas"].get(schema.get("$ref", "#/x").rsplit("/", 1)[-1], {}).get("properties") or {}):
            continue  # a real field of that body (e.g. "status" on a request answer): allowed values only
        url = re.sub(r"\{[^}]+\}", "x", path)
        who = admin if path.startswith("/api/admin/") else student
        r = who.request(method, url, json={**body, field: PRIVILEGED[field]})
        assert r.status_code in (401, 422), f"{method} {path} accepted {field}: {r.status_code}"
        checked += 1
    assert checked >= 25


def test_signup_can_not_set_privileged_fields(client):
    body = {"name": "Mass Assign", "college": "X", "passing_year": 2027, "phone": "+91 90000 12345", "password": "a-strong-pass-9"}
    for field, value in PRIVILEGED.items():
        r = client.post("/api/auth/signup", json={**body, field: value})
        assert r.status_code == 422, field
    r = client.post("/api/auth/signup", json=body)
    assert r.status_code == 201
    me = r.json()
    assert me["github_verified"] is False and me["group_id"] is None and me["github_contribution_count"] in (None, 0)


def test_ignored_profile_fields_really_are_ignored(as_user):
    c = as_user("usr_8")
    before = c.get("/api/users/usr_8").json()
    out = c.patch("/api/users/usr_8", json={"name": "Hacker", "college": "Fake", "passing_year": 2000,
                                            "github_verified": True, "github_contribution_count": 99999}).json()
    assert out["name"] == "Meera Nair" and out["college"] != "Fake" and out["passing_year"] != 2000
    assert out["github_verified"] == before["github_verified"] and out["github_contribution_count"] == before["github_contribution_count"]
