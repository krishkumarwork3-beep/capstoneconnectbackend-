"""Part 5: the same action sent many times at the same moment (real threads, real PostgreSQL).
Each asserts the outcome a single request would have had, and no 500."""

import threading

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import crypto
from app.db import SessionLocal
from app.main import app
from app.models import GroupMember, JoinRequest, Message, Report, User
from tests.conftest import PASSWORD, PHONES

N = 8


def _client(user_id: str) -> TestClient:
    c = TestClient(app)
    assert c.post(f"/api/auth/demo-login/{user_id}").status_code == 200
    return c


def _at_once(calls) -> list[int]:
    """Runs every call at the same moment; returns their status codes."""
    barrier = threading.Barrier(len(calls))
    results: list[int] = [0] * len(calls)

    def run(i, call):
        barrier.wait()
        results[i] = call().status_code

    threads = [threading.Thread(target=run, args=(i, call)) for i, call in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert 500 not in results, results
    return results


def _count(stmt) -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(stmt.subquery()))


def test_the_last_seat_goes_to_one_student():
    """grp_1 has 4 seats, 3 taken; two pending requests (req_1, req_2) accepted at once."""
    lead_a, lead_b = _client("usr_1"), _client("usr_1")
    results = _at_once([lambda: lead_a.patch("/api/requests/req_1", json={"status": "accepted"}),
                        lambda: lead_b.patch("/api/requests/req_2", json={"status": "accepted"})])
    assert sorted(results).count(200) == 1, results
    assert _count(select(GroupMember).where(GroupMember.group_id == "grp_1")) == 4


def test_one_request_accepted_twice_at_once():
    leads = [_client("usr_1") for _ in range(N)]
    results = _at_once([lambda c=c: c.patch("/api/requests/req_1", json={"status": "accepted"}) for c in leads])
    assert results.count(200) == 1, results
    assert _count(select(GroupMember).where(GroupMember.user_id == "usr_6")) == 1


def test_a_student_can_not_end_up_in_two_groups():
    """usr_8 asks to join grp_4 and grp_5; both leads accept at the same moment."""
    student = _client("usr_8")
    r2 = student.post("/api/groups/grp_4/join-requests", json={"note": ""}).json()["id"]
    r3 = student.post("/api/groups/grp_5/join-requests", json={"note": ""}).json()["id"]
    lead2, lead3 = _client("usr_4"), _client("usr_5")
    results = _at_once([lambda: lead2.patch(f"/api/requests/{r2}", json={"status": "accepted"}),
                        lambda: lead3.patch(f"/api/requests/{r3}", json={"status": "accepted"})])
    assert results.count(200) == 1, results
    assert _count(select(GroupMember).where(GroupMember.user_id == "usr_8")) == 1


def test_duplicate_invitations_at_once():
    leads = [_client("usr_2") for _ in range(N)]
    _at_once([lambda c=c: c.post("/api/users/usr_8/invitations", json={"group_id": "grp_2", "note": ""}) for c in leads])
    assert _count(select(JoinRequest).where(JoinRequest.receiver_id == "usr_8", JoinRequest.status == "pending",
                                            JoinRequest.group_id == "grp_2")) == 1


def test_duplicate_join_requests_at_once():
    students = [_client("usr_8") for _ in range(N)]
    _at_once([lambda c=c: c.post("/api/groups/grp_2/join-requests", json={"note": ""}) for c in students])
    assert _count(select(JoinRequest).where(JoinRequest.sender_id == "usr_8", JoinRequest.status == "pending")) == 1


def test_duplicate_reports_at_once():
    reporters = [_client("usr_8") for _ in range(N)]
    results = _at_once([lambda c=c: c.post("/api/reports", json={"target_type": "user", "target_id": "usr_1", "reason": "spam", "details": ""})
                        for c in reporters])
    assert results.count(201) == 1 and set(results) <= {201, 409}, results
    assert _count(select(Report).where(Report.reporter_id == "usr_8")) == 1


def test_the_same_message_sent_twice_is_stored_once():
    """A retry after a dropped connection (same client_id) never duplicates the message."""
    senders = [_client("usr_1") for _ in range(N)]
    results = _at_once([lambda c=c: c.post("/api/conversations/conv_2/messages", json={"text": "only once", "client_id": "c-123"})
                        for c in senders])
    assert set(results) <= {200, 201}, results
    assert _count(select(Message).where(Message.conversation_id == "conv_2", Message.client_id == "c-123")) == 1
    # And a later retry returns the same message.
    again = senders[0].post("/api/conversations/conv_2/messages", json={"text": "only once", "client_id": "c-123"})
    assert again.status_code in (200, 201)
    assert _count(select(Message).where(Message.conversation_id == "conv_2", Message.client_id == "c-123")) == 1
    # Another sender may use the same client_id: it is per sender.
    other = _client("usr_2").post("/api/conversations/conv_2/messages", json={"text": "only once", "client_id": "c-123"})
    assert other.status_code == 201


def test_one_attachment_sent_twice_at_once():
    lead = _client("usr_1")
    up = lead.post("/api/uploads/attachments", files={"file": ("a.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")}).json()
    senders = [_client("usr_1") for _ in range(N)]
    results = _at_once([lambda c=c, i=i: c.post("/api/conversations/conv_2/messages", json={"text": f"file {i}", "attachment": up})
                        for i, c in enumerate(senders)])
    assert results.count(201) == 1, results
    with SessionLocal() as db:
        path = up["url"].split("/uploads/", 1)[1]
        assert db.scalar(select(func.count()).select_from(Message).where(Message.attachment_url.endswith(path))) == 1


def test_deleting_a_group_while_people_join():
    lead = _client("usr_2")
    students = [_client(u) for u in ("usr_8", "usr_14", "usr_6", "usr_7")]
    calls = [lambda: lead.delete("/api/groups/grp_2")] + [lambda c=c: c.post("/api/groups/grp_2/join-requests", json={"note": ""}) for c in students]
    _at_once(calls)
    with SessionLocal() as db:
        if db.get(__import__("app.models", fromlist=["Group"]).Group, "grp_2") is None:
            assert db.scalar(select(func.count()).select_from(JoinRequest).where(JoinRequest.group_id == "grp_2",
                                                                                 JoinRequest.status == "pending")) == 0


def test_signing_up_twice_at_once():
    body = {"name": "Twin", "college": "X", "passing_year": 2027, "phone": "+91 90000 33333", "password": "twin-pass-long-1"}
    results = _at_once([lambda: TestClient(app).post("/api/auth/signup", json=body) for _ in range(N)])
    assert results.count(201) == 1 and set(results) <= {201, 409, 429}, results
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(User).where(User.phone_hash == crypto.phone_hash("919000033333"))) == 1


def test_logging_in_many_times_at_once_counts_every_failure():
    """Parallel wrong guesses can't slip past the lock-out by racing its counter."""
    results = _at_once([lambda: TestClient(app).post("/api/auth/login", json={"phone": PHONES["usr_1"], "password": f"wrong-{i}-pass"})
                        for i in range(12)])
    assert set(results) <= {401, 429}
    r = TestClient(app).post("/api/auth/login", json={"phone": PHONES["usr_1"], "password": PASSWORD})
    assert r.status_code == 429
