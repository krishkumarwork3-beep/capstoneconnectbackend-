from datetime import timedelta

from sqlalchemy import text, update

from app.db import SessionLocal
from app.models import PasswordResetCode, utcnow
from tests.conftest import PASSWORD

PHONE = "+91 98765 43210"


def ask_code(client, phone=PHONE):
    response = client.post("/api/auth/password/forgot", json={"phone": phone})
    assert response.status_code == 200, response.text
    return response.json()


def test_full_reset_signs_in_and_revokes_old_sessions(client, as_user):
    old_session = as_user("usr_1")
    code = ask_code(client)["dev_code"]
    token = client.post("/api/auth/password/verify", json={"phone": "9876543210", "code": code}).json()["reset_token"]

    response = client.post("/api/auth/password/reset", json={"reset_token": token, "password": "brand-new-pass"})
    assert response.status_code == 200 and response.json()["id"] == "usr_1"
    assert client.get("/api/auth/me").status_code == 200  # signed in with the new password
    assert old_session.get("/api/auth/me").status_code == 401  # older sessions stop working

    assert client.post("/api/auth/login", json={"phone": PHONE, "password": PASSWORD}).status_code == 401
    assert client.post("/api/auth/login", json={"phone": PHONE, "password": "brand-new-pass"}).status_code == 200
    # The token works once.
    again = client.post("/api/auth/password/reset", json={"reset_token": token, "password": "third-password"})
    assert again.status_code == 400


def test_unknown_numbers_get_the_same_answer(client):
    known, unknown = ask_code(client), ask_code(client, "+91 90000 00000")
    assert known["message"] == unknown["message"]
    assert unknown["dev_code"] is None


def test_codes_are_throttled(client):
    ask_code(client)
    response = client.post("/api/auth/password/forgot", json={"phone": PHONE})
    assert response.status_code == 429


def test_wrong_codes_run_out(client):
    code = ask_code(client)["dev_code"]
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        message = client.post("/api/auth/password/verify", json={"phone": PHONE, "code": wrong}).json()["message"]
        # One answer for every failure (no "tries left" that would only exist for real accounts).
        assert message == "That code is not right or has expired. Check it, or ask for a new one."
    # Even the right code is refused once the tries are used up.
    assert client.post("/api/auth/password/verify", json={"phone": PHONE, "code": code}).status_code in (400, 429)


def test_expired_and_replaced_codes(client):
    first = ask_code(client)["dev_code"]
    with SessionLocal() as db:
        db.execute(update(PasswordResetCode).values(created_at=utcnow() - timedelta(minutes=2)))
        db.execute(text("DELETE FROM rate_limits"))  # the minute between codes has passed
        db.commit()
    second = ask_code(client)["dev_code"]
    if first != second:
        assert client.post("/api/auth/password/verify", json={"phone": PHONE, "code": first}).status_code == 400
    with SessionLocal() as db:
        db.execute(update(PasswordResetCode).values(expires_at=utcnow() - timedelta(seconds=1)))
        db.commit()
    assert client.post("/api/auth/password/verify", json={"phone": PHONE, "code": second}).status_code == 400


def test_answers_do_not_reveal_which_numbers_have_accounts(client):
    unknown = "+91 90000 00000"
    # The one-a-minute limit applies to every number, registered or not.
    for phone in (PHONE, unknown):
        assert client.post("/api/auth/password/forgot", json={"phone": phone}).status_code == 200
        again = client.post("/api/auth/password/forgot", json={"phone": phone})
        assert again.status_code == 429 and "Wait before asking for another code" in again.json()["message"]
    # A wrong code for a real account and any code for an unknown number get the same answer.
    known = client.post("/api/auth/password/verify", json={"phone": PHONE, "code": "000001"})
    other = client.post("/api/auth/password/verify", json={"phone": unknown, "code": "000001"})
    assert known.status_code == other.status_code == 400
    assert known.json() == other.json()
