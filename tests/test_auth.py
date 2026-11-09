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


def test_signup_rejects_a_used_phone_in_any_format(client):
    assert client.post("/api/auth/signup", json={**NEW, "phone": "9876543210"}).json()["message"] == (
        "An account already exists for this phone number"
    )


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
