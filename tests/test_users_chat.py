
import pytest

from app.services import github
from tests.conftest import REAL_PNG


def test_discover_search_filters_and_sorts(as_user):
    c = as_user("usr_1")
    everyone = c.get("/api/users?limit=200").json()
    assert everyone["total"] == 18
    assert {u["id"] for u in c.get("/api/users?search=pytorch&limit=50").json()["items"]} >= {"usr_1"}
    looking = c.get("/api/users?hasGroup=false&limit=50").json()
    assert looking["total"] == 8 and all(u["group_id"] is None for u in looking["items"])
    assert c.get("/api/users?search=looking&limit=50").json()["total"] == 8
    ranked = [u["github_contribution_count"] for u in c.get("/api/users?sort=contributions&limit=50").json()["items"]]
    numbers = [n for n in ranked if n is not None]
    assert numbers == sorted(numbers, reverse=True) and ranked[: len(numbers)] == numbers  # unranked last
    names = [u["name"] for u in c.get("/api/users?sort=name&limit=50").json()["items"]]
    assert names == sorted(names, key=str.lower)
    page = c.get("/api/users?limit=5&cursor=15").json()
    assert len(page["items"]) == 3 and page["hasMore"] is False and page["nextCursor"] is None


def test_profile_edit_is_yours_only_and_locks_identity(as_user):
    c = as_user("usr_8")
    assert c.patch("/api/users/usr_1", json={"bio": "x"}).status_code == 403
    updated = c.patch("/api/users/usr_8", json={"bio": " New bio ", "name": "Someone Else", "skills": ["Go", "go"]}).json()
    assert updated["bio"] == "New bio" and updated["name"] == "Meera Nair" and updated["skills"] == ["Go"]


def test_github_verification_is_done_by_the_server(as_user, monkeypatch):
    async def fake_lookup(username):
        return ({"login": "Meera-Real"}, github.Total(1234, True)) if username.lower() == "meera-real" else None

    monkeypatch.setattr(github, "lookup", fake_lookup)
    c = as_user("usr_8")
    # A client claiming a count is ignored: the server's lookup decides.
    user = c.patch("/api/users/usr_8", json={"github_url": "github.com/meera-real", "github_verified": True,
                                                "github_contribution_count": 999999}).json()
    assert (user["github_url"], user["github_verified"], user["github_contribution_count"]) == (
        "https://github.com/Meera-Real", True, 1234)
    # Editing the username resets verification until it is checked again.
    user = c.patch("/api/users/usr_8", json={"github_url": "someone-else", "github_verified": False}).json()
    assert user["github_verified"] is False and user["github_contribution_count"] is None
    assert c.get("/api/github/verify?username=nobody-here").json()["valid"] is False


@pytest.mark.parametrize(
    "value,expected",
    [("https://github.com/Foo-Bar/", "Foo-Bar"), ("github.com/foo/repo", "foo"), ("@foo", "foo"), ("-bad", None), ("", None)],
)
def test_github_usernames(value, expected):
    assert github.username_from(value) == expected


def test_uploads_check_content(as_user):
    c = as_user("usr_8")
    fake = c.post("/api/users/usr_8/avatar", files={"avatar": ("me.png", b"not really a png", "image/png")})
    assert fake.status_code == 415
    png = REAL_PNG  # a real image: uploads are decoded and re-encoded
    ok = c.post("/api/users/usr_8/avatar", files={"avatar": ("me.png", png, "image/png")})
    assert ok.status_code == 200 and ok.json()["avatar_url"].endswith(".png")
    assert c.get("/api/auth/me").json()["avatar_url"] == ok.json()["avatar_url"]
    assert c.post("/api/users/usr_1/resume", files={"resume": ("cv.pdf", b"%PDF-1.4", "application/pdf")}).status_code == 403


def test_chat_visibility_unread_and_direct(as_user):
    lead, member, outsider = as_user("usr_1"), as_user("usr_9"), as_user("usr_8")
    group_chat = next(c for c in lead.get("/api/conversations").json() if c["type"] == "group")
    assert outsider.get(f"/api/conversations/{group_chat['id']}/messages").status_code == 403

    sent = member.post(f"/api/conversations/{group_chat['id']}/messages", json={"text": "  standup at 6  "})
    assert sent.status_code == 201 and sent.json()["text"] == "standup at 6"
    assert member.post(f"/api/conversations/{group_chat['id']}/messages", json={"text": "   "}).status_code == 400
    unread_before = lead.get("/api/counts").json()["unreadChat"]
    assert unread_before >= 1
    lead.post(f"/api/conversations/{group_chat['id']}/read")
    assert lead.get("/api/counts").json()["unreadChat"] < unread_before

    direct = outsider.post("/api/conversations/direct", json={"user_id": "usr_1"}).json()
    again = outsider.post("/api/conversations/direct", json={"user_id": "usr_1"}).json()
    assert direct["id"] == again["id"] and direct["title"] == "Aarav Sharma"
    assert outsider.post("/api/conversations/direct", json={"user_id": "usr_8"}).status_code == 400
    uploaded = outsider.post("/api/uploads/attachments", files={"file": ("cv.pdf", b"%PDF-1.4 cv\n%%EOF", "application/pdf")}).json()
    with_file = outsider.post(
        f"/api/conversations/{direct['id']}/messages", json={"text": "", "attachment": uploaded}
    ).json()
    assert with_file["attachment"]["name"] == "cv.pdf"
    listed = next(c for c in lead.get("/api/conversations").json() if c["id"] == direct["id"])
    assert listed["last_message"]["text"] == "cv.pdf" and listed["title"] == "Meera Nair"
