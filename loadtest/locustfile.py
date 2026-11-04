"""Load test: students signing in, browsing Discover and chatting.

    # a throwaway API with 2 workers (its own database), then 50 users for a minute:
    uv run python scripts/e2e_server.py --port 8100 --workers 2 --database capstoneconnect_load
    uvx locust -f loadtest/locustfile.py --host http://127.0.0.1:8100 --headless -u 50 -r 10 -t 60s --csv loadtest/results

Each simulated student signs up once (a fresh number), opens a direct chat with a seeded student,
then repeats: browse the student list (most often), send a message, read the chat, and now and then
sign in again (bcrypt, the slowest call). Run it against a production-like box, never production.
"""

import random

from locust import HttpUser, between, task

SEEDED = ["usr_1", "usr_2", "usr_6", "usr_8", "usr_9"]
PASSWORD = "Load-test-pass-2026"


class Student(HttpUser):
    wait_time = between(0.5, 2)

    def on_start(self):
        self.phone = f"+91 9{random.randint(100000000, 999999999)}"
        self.client.post("/api/auth/signup", json={
            "name": "Load Student", "college": "Load Test Institute", "passing_year": 2027,
            "phone": self.phone, "password": PASSWORD, "skills": ["Python"],
        }, name="POST /api/auth/signup")
        conv = self.client.post("/api/conversations/direct", json={"user_id": random.choice(SEEDED)},
                                name="POST /api/conversations/direct").json()
        self.conversation = conv["id"]

    @task(5)
    def browse_students(self):
        self.client.get("/api/users", params={"limit": 30, "sort": random.choice(["relevance", "name", "contributions"])},
                        name="GET /api/users")

    @task(3)
    def send_message(self):
        self.client.post(f"/api/conversations/{self.conversation}/messages", json={"text": "load test message"},
                         name="POST /api/conversations/{id}/messages")

    @task(2)
    def read_chat(self):
        self.client.get(f"/api/conversations/{self.conversation}/messages", name="GET /api/conversations/{id}/messages")

    @task(1)
    def sign_in_again(self):
        self.client.post("/api/auth/login", json={"phone": self.phone, "password": PASSWORD}, name="POST /api/auth/login")
