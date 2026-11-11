from tests.conftest import PASSWORD

NEW = {
    "name": "Isha Kapoor",
    "college": "IIT Delhi",
    "department": "Computer Science",
    "passing_year": 2026,
    "phone": "+91 99999 11111",
    "password": "a-long-password",
    "bio": "Systems.",
    "skills": ["Rust", "rust", " Go "],
}


def test_signup_signs_in_and_cleans_input(client):
    response = client.post("/api/auth/signup", json=NEW)
    assert response.status_code == 201, response.text
    user = response.json()
    assert user["skills"] == ["Rust", "Go"]
    assert user["group_id"] is None and user["github_verified"] is False
    assert client.get("/api/auth/me").json()["id"] == user["id"]


def test_signup_for_a_used_phone_looks_like_a_new_account_and_texts_the_owner(client, monkeypatch):
    # Rewritten to the new contract: no 409 (that told anyone which numbers have an account).
    from fastapi.testclient import TestClient

    from app.main import app
    from app.routers import auth as auth_router

    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(auth_router, "send_sms", lambda to, body: sent.append((to, body)))
    fresh = TestClient(app).post("/api/auth/signup", json={**NEW, "phone": "+91 99999 44444"})
    for written in ("9876543210", "+91 98765 43210"):
        used = client.post("/api/auth/signup", json={**NEW, "phone": written})
        assert used.status_code == fresh.status_code == 201, used.text
        assert set(used.json()) == set(fresh.json())
        assert "already" not in used.text.lower()
        # Nobody is signed in to the existing account, and nothing new was stored.
        assert not any(c for c in used.cookies)
        assert client.get(f"/api/users/{used.json()['id']}").status_code in (401, 404)
    assert [to for to, _ in sent] == ["+919876543210", "+919876543210"]
    assert "already have one" in sent[0][1]


def test_signup_needs_a_long_password(client):
    response = client.post("/api/auth/signup", json={**NEW, "password": "short"})
    assert response.status_code == 422
    assert "password" in response.json()["message"]


def test_login_logout(client):
    assert client.post("/api/auth/login", json={"phone": "98765 43210", "password": "nope"}).status_code == 401
    assert client.post("/api/auth/login", json={"phone": "98765 43210", "password": PASSWORD}).status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    client.post("/api/auth/logout")
    assert client.get("/api/auth/me").status_code == 401


def test_pages_need_a_session(client):
    assert client.get("/api/users").json() == {"message": "Sign in to continue"}
    assert client.get("/api/groups").json() == {"message": "Sign in to continue"}  # groups name their members: no guests


def test_bearer_token_also_works(client):
    client.post("/api/auth/login", json={"phone": "98765 43210", "password": PASSWORD})
    token = client.cookies.get("cc_session")
    client.cookies.clear()
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()["id"] == "usr_1"
