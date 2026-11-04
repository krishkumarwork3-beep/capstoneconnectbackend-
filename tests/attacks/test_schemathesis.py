"""Schemathesis: property-based inputs generated from the OpenAPI schema for every operation
(student and admin), checked for server errors. Complements the hand-written corpus."""

import pytest
import schemathesis
from hypothesis import HealthCheck, settings
from schemathesis.checks import not_a_server_error

from app.main import app

schema = schemathesis.openapi.from_asgi("/openapi.json", app)
SKIP_PATHS = {"/api/auth/logout", "/api/auth/logout-all", "/api/admin/auth/logout", "/api/admin/auth/logout-all", "/api/ws"}


@pytest.fixture(autouse=True)
def no_github(monkeypatch):
    """No outside calls from tests: GitHub answers "no such user"."""
    from app.services import github

    async def nobody(*_, **__):
        return None

    monkeypatch.setattr(github, "lookup", nobody)


@pytest.fixture
def auth(client, admin_client):
    from fastapi.testclient import TestClient

    from tests.conftest import PASSWORD, PHONES

    login = TestClient(app).post("/api/auth/login", json={"phone": PHONES["usr_8"], "password": PASSWORD})
    token = login.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    admin = admin_client()
    return {"student": {"Authorization": f"Bearer {token}"},
            "admin": {"Cookie": "; ".join(f"{k}={v}" for k, v in admin.cookies.items())}}


@schema.parametrize()
@settings(max_examples=12, deadline=None, suppress_health_check=list(HealthCheck), derandomize=True)
def test_generated_inputs_never_cause_a_server_error(case, auth):
    if case.path in SKIP_PATHS:
        pytest.skip("ends the caller's own session")
    headers = auth["admin"] if case.path.startswith("/api/admin/") else auth["student"]
    case.call_and_validate(headers=headers, checks=[not_a_server_error])
