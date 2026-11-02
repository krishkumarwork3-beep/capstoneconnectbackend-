"""The SRS group rules, end to end through the API, on the demo data.

grp_1 (Lead usr_1, members usr_9 and usr_11) has 4 seats, 1 free. usr_6 and usr_7 have pending
join requests to it; usr_14 has a pending invite from it; usr_9 and usr_11 recommended usr_16/15.
"""


def group(client, group_id="grp_1"):
    return client.get(f"/api/groups/{group_id}").json()


def request_status(client, request_id):
    for direction in ("received", "sent"):
        for req in client.get(f"/api/requests?direction={direction}").json():
            if req["id"] == request_id:
                return req["status"]
    return None


def test_board_search_and_filters(as_user):
    c = as_user("usr_8")
    assert c.get("/api/groups?limit=50").json()["total"] == 6
    assert [g["id"] for g in c.get("/api/groups?search=ros 2").json()["items"]] == ["grp_1"]
    full = {g["id"] for g in c.get("/api/groups?search=full&limit=50").json()["items"]}
    assert "grp_3" in full and "grp_1" not in full
    assert all(not g["is_full"] for g in c.get("/api/groups?openOnly=true&limit=50").json()["items"])


def test_accepting_fills_the_group_and_settles_everything(as_user):
    lead, pooja = as_user("usr_1"), as_user("usr_6")
    response = lead.patch("/api/requests/req_1", json={"status": "accepted"})
    assert response.status_code == 200, response.text

    g = group(lead)
    assert g["is_full"] and "usr_6" in [m["user_id"] for m in g["members"]]
    me = pooja.get("/api/auth/me").json()
    assert (me["group_id"], me["group_role"]) == ("grp_1", "member")
    # The group filled: the other join request and the open invite are declined, recommendations closed.
    assert request_status(lead, "req_2") == "declined"
    assert request_status(lead, "req_5") == "declined"
    assert all(r["status"] == "closed" for r in lead.get("/api/recommendations").json())
    # Pooja is in the group chat and gets an outcome badge.
    chats = pooja.get("/api/conversations").json()
    assert any(c["group_id"] == "grp_1" for c in chats)
    assert pooja.get("/api/counts").json()["outcomeUpdates"] == 1


def test_only_the_lead_accepts(as_user):
    member = as_user("usr_9")
    assert member.patch("/api/requests/req_1", json={"status": "accepted"}).json()["message"] == "Lead Only"


def test_join_request_rules(as_user):
    lead, looking = as_user("usr_1"), as_user("usr_8")
    assert lead.post("/api/groups/grp_2/join-requests", json={"note": "hi"}).json()["message"] == (
        "You must leave your current group first"
    )
    assert looking.post("/api/groups/grp_3/join-requests", json={"note": ""}).json()["message"] == "Group Full"
    created = looking.post("/api/groups/grp_4/join-requests", json={"note": "  I build inverters  "})
    assert created.status_code == 201 and created.json()["note"] == "I build inverters"
    again = looking.post("/api/groups/grp_4/join-requests", json={"note": "again"})
    assert again.status_code == 409
    # Withdraw your own pending request; nobody else can.
    other = as_user("usr_7")
    request_id = created.json()["id"]
    assert other.patch(f"/api/requests/{request_id}", json={"status": "withdrawn"}).status_code == 403
    assert looking.patch(f"/api/requests/{request_id}", json={"status": "withdrawn"}).json()["status"] == "withdrawn"


def test_invite_rules(as_user):
    lead, member = as_user("usr_1"), as_user("usr_9")
    # One free seat and one pending invite already: no more invites.
    assert lead.post("/api/users/usr_8/invitations", json={"group_id": "grp_1", "note": "x"}).json()["message"] == (
        "Max Invites"
    )
    assert member.post("/api/users/usr_8/invitations", json={"group_id": "grp_1", "note": "x"}).json()["message"] == (
        "Lead Only"
    )
    assert lead.post("/api/users/usr_2/invitations", json={"group_id": "grp_1", "note": "x"}).json()["message"] in (
        "In Group",
        "Max Invites",
    )
    # Cancelling the pending invite frees the slot.
    assert lead.patch("/api/requests/req_5", json={"status": "cancelled"}).json()["status"] == "cancelled"
    invite = lead.post("/api/users/usr_8/invitations", json={"group_id": "grp_1", "note": "Join us"})
    assert invite.status_code == 201 and invite.json()["type"] == "invitation"


def test_accepting_an_invite_cancels_your_other_requests(as_user):
    student = as_user("usr_14")
    student.post("/api/groups/grp_4/join-requests", json={"note": "backup plan"})
    assert student.patch("/api/requests/req_5", json={"status": "accepted"}).status_code == 200
    sent = student.get("/api/auth/me").json()
    assert sent["group_id"] == "grp_1"
    lead4 = as_user("usr_4")
    assert all(r["status"] != "pending" for r in lead4.get("/api/requests?direction=received").json())


def test_lead_leaving_hands_over_and_last_member_deletes(as_user):
    lead, member9, member11 = as_user("usr_1"), as_user("usr_9"), as_user("usr_11")
    after = lead.post("/api/groups/grp_1/leave").json()
    new_lead = next(m for m in after["members"] if m["role"] == "admin")
    assert new_lead["user_id"] == "usr_9" and after["created_by"] == "usr_9"
    assert lead.get("/api/auth/me").json()["group_id"] is None
    # Pending items survive a hand-over; the group goes when the last member leaves.
    member9.post("/api/groups/grp_1/leave")
    assert member11.post("/api/groups/grp_1/leave").json() is None
    assert member11.get("/api/groups/grp_1").status_code == 404
    assert member11.get("/api/conversations").json() == []


def test_lead_edits_but_cannot_resize(as_user):
    lead, member = as_user("usr_1"), as_user("usr_9")
    assert member.patch("/api/groups/grp_1", json={"name": "X"}).json()["message"] == "Lead Only"
    assert lead.patch("/api/groups/grp_1", json={"max_members": 6}).json()["message"] == "Group size cannot be changed"
    renamed = lead.patch("/api/groups/grp_1", json={"name": "  Agri-Rover v2 ", "requirements": ["ROS 2", "ros 2", "Go"]})
    assert renamed.json()["name"] == "Agri-Rover v2" and renamed.json()["requirements"] == ["ROS 2", "Go"]
    chat = next(c for c in lead.get("/api/conversations").json() if c["group_id"] == "grp_1")
    assert chat["title"] == "Agri-Rover v2"


def test_remove_member_and_delete_group(as_user):
    lead, member = as_user("usr_1"), as_user("usr_9")
    assert member.delete("/api/groups/grp_1/members/usr_11").status_code == 403
    assert lead.delete("/api/groups/grp_1/members/usr_1").json()["message"] == "You cannot remove the Group Lead"
    assert len(lead.delete("/api/groups/grp_1/members/usr_11").json()["members"]) == 2
    assert lead.delete("/api/groups/grp_1").status_code == 204
    assert member.get("/api/auth/me").json()["group_id"] is None
    # Requests keep their history with the group's name.
    pooja = as_user("usr_6")
    sent = pooja.get("/api/requests?direction=sent").json()
    assert sent[0]["status"] == "cancelled" and sent[0]["group_name"] == "Autonomous Agri-Rover"


def test_create_group_once(as_user):
    student, lead = as_user("usr_8"), as_user("usr_1")
    payload = {"name": "Edge Cache", "description": "A cache.", "max_members": 3, "requirements": ["Go"], "domain": "Systems"}
    assert lead.post("/api/groups", json=payload).json()["message"] == "You must leave your current group first"
    created = student.post("/api/groups", json=payload)
    assert created.status_code == 201
    assert student.get("/api/auth/me").json()["group_role"] == "admin"
    assert any(c["group_id"] == created.json()["id"] for c in student.get("/api/conversations").json())
    assert student.post("/api/groups", json={**payload, "max_members": 1}).status_code == 422


def test_request_lists_by_role(as_user):
    assert {r["id"] for r in as_user("usr_1").get("/api/requests?direction=received").json()} == {"req_1", "req_2"}
    assert as_user("usr_9").get("/api/requests?direction=received").json() == []  # plain Member
    assert [r["id"] for r in as_user("usr_14").get("/api/requests?direction=received").json()] == ["req_5"]
    assert as_user("usr_1").get("/api/counts").json()["pendingReceived"] == 4  # 2 joins + 2 recommendations


def test_recommendations(as_user):
    lead, member, outsider = as_user("usr_1"), as_user("usr_9"), as_user("usr_8")
    assert outsider.post("/api/recommendations", json={"groupId": "grp_1", "studentId": "usr_10"}).json()["message"] == "No Group"
    assert lead.post("/api/recommendations", json={"groupId": "grp_1", "studentId": "usr_10"}).json()["message"] == (
        "Group Leads invite students directly"
    )
    made = member.post("/api/recommendations", json={"groupId": "grp_1", "studentId": "usr_10", "note": "Great at Go"})
    assert made.status_code == 201
    assert member.post("/api/recommendations", json={"groupId": "grp_1", "studentId": "usr_10"}).status_code == 409
    assert member.get("/api/recommendations").json() == []  # only the Lead sees them
    assert lead.post(f"/api/recommendations/{made.json()['id']}/dismiss").json()["status"] == "dismissed"
    # Inviting from a recommendation follows the invite rules (one free seat, one pending invite).
    assert lead.post("/api/recommendations/rec_1/invite", json={"note": "hi"}).json()["message"] == "Max Invites"
