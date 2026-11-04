"""Walks every route in the OpenAPI schema (student API and admin API) and sends the attack corpus
in every path parameter, query parameter, JSON body field (on an otherwise valid body), as the
whole body, and in headers, as an anonymous caller, a student and an admin.

Every answer must be: not a 5xx, free of stack traces and SQL/driver text, and, unless it is
JSON, free of the payload echoed back raw.
"""

import json
import re
from datetime import UTC, datetime
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.attacks.payloads import FUZZ_STRINGS, FUZZ_VALUES, LEAK_MARKERS
from tests.conftest import PASSWORD, PHONES

# Routes whose effect would end the caller's own session mid-run (they are attacked separately).
SKIP = {
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/logout-all"),
    ("POST", "/api/admin/auth/logout"),
    ("POST", "/api/admin/auth/logout-all"),
}
STUDENT = "usr_8"


def _resolve(spec: dict, schema: dict) -> dict:
    while "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[1]
        schema = spec["components"]["schemas"][name]
    return schema


def _sample(spec: dict, schema: dict, depth: int = 0) -> object:
    """A plausible valid value for a JSON schema (so the payload reaches the code behind validation)."""
    schema = _resolve(spec, schema)
    if depth > 4:
        return None
    for key in ("anyOf", "oneOf"):
        if key in schema:
            options = [o for o in schema[key] if _resolve(spec, o).get("type") != "null"] or schema[key]
            return _sample(spec, options[0], depth + 1)
    if "enum" in schema:
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        props = schema.get("properties", {})
        return {name: _sample(spec, sub, depth + 1) for name, sub in props.items() if name in schema.get("required", props)}
    if kind == "array":
        item = _sample(spec, schema.get("items", {"type": "string"}), depth + 1)
        return [item] * max(1, schema.get("minItems", 1))
    if kind == "integer":
        return max(schema.get("minimum", 1), 1) if "maximum" not in schema else schema.get("minimum", 1)
    if kind == "number":
        return 1.0
    if kind == "boolean":
        return False
    if schema.get("format") == "date-time":
        return datetime.now(UTC).isoformat()
    return "fuzz-value-" + "x" * max(0, schema.get("minLength", 0) - 11)


def _routes() -> list[tuple[str, str, dict]]:
    spec = app.openapi()
    out = []
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            if (method.upper(), path) not in SKIP:
                out.append((method.upper(), path, op))
    return out


def _cases(spec: dict, method: str, path: str, op: dict):
    """(label, url, query, body, headers) for every input position × payload."""
    params = op.get("parameters", [])
    path_params = {p["name"]: "x" for p in params if p["in"] == "path"}
    base_query = {p["name"]: _sample(spec, p.get("schema", {})) for p in params if p["in"] == "query" and p.get("required")}
    body_schema = None
    content = (op.get("requestBody") or {}).get("content", {})
    if "application/json" in content:
        body_schema = _resolve(spec, content["application/json"]["schema"])
    base_body = _sample(spec, body_schema) if body_schema is not None else None

    def url(overrides: dict | None = None) -> str:
        values = {**path_params, **(overrides or {})}
        return re.sub(r"\{([^}]+)\}", lambda m: quote(str(values[m.group(1)]), safe=""), path)

    for name in path_params:
        for payload in FUZZ_STRINGS:
            yield f"path {name}", url({name: payload}), base_query, base_body, {}
    for p in params:
        if p["in"] != "query":
            continue
        for payload in FUZZ_VALUES:
            value = payload if isinstance(payload, (str, int, float)) else json.dumps(payload)
            yield f"query {p['name']}", url(), {**base_query, p["name"]: value}, base_body, {}
    if body_schema is not None:
        props = body_schema.get("properties", {})
        for field in props:
            for payload in FUZZ_VALUES:
                body = dict(base_body) if isinstance(base_body, dict) else {}
                body[field] = payload
                yield f"body {field}", url(), base_query, body, {}
        for payload in FUZZ_VALUES:
            yield "whole body", url(), base_query, payload, {}
    for payload in FUZZ_STRINGS:
        # Header values must be sendable (no CR/LF, latin-1): those are covered in test_headers.
        try:
            payload.encode("latin-1")
        except UnicodeEncodeError:
            continue
        if "\r" in payload or "\n" in payload or "\x00" in payload or len(payload) > 4000:
            continue
        yield "headers", url(), base_query, base_body, {"X-Request-ID": payload, "User-Agent": payload, "Referer": payload}


def _check(label: str, method: str, path: str, response, payload_text: str | None) -> None:
    where = f"{method} {path} [{label}]"
    assert response.status_code < 500, f"{where}: {response.status_code} {response.text[:300]}"
    text = response.text
    for marker in LEAK_MARKERS:
        assert marker not in text, f"{where}: leaks {marker!r}: {text[:300]}"
    ctype = response.headers.get("content-type", "")
    # The CSV export lists stored data (payloads that earlier calls saved): test_csv_injection checks it.
    if payload_text and len(payload_text) > 3 and "json" not in ctype and "csv" not in ctype and response.request.url.path != "/openapi.json":
        assert payload_text not in text, f"{where}: echoes the payload raw in {ctype}"


@pytest.fixture
def callers(client, admin_client):
    login = TestClient(app).post("/api/auth/login", json={"phone": PHONES[STUDENT], "password": PASSWORD})
    student_token = login.cookies.get("cc_session") or login.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    admin = admin_client()
    admin_cookie = "; ".join(f"{k}={v}" for k, v in admin.cookies.items())
    return {
        "anonymous": {},
        "student": {"Authorization": f"Bearer {student_token}"},
        "admin": {"Cookie": admin_cookie},
    }


def test_every_route_survives_the_attack_corpus(callers):
    spec = app.openapi()
    client = TestClient(app, raise_server_exceptions=False)
    sent = 0
    for method, path, op in _routes():
        admin_route = path.startswith("/api/admin/")
        roles = ["anonymous", "admin"] if admin_route else ["anonymous", "student"]
        for label, url, query, body, headers in _cases(spec, method, path, op):
            payload_text = None
            for source in (headers.get("X-Request-ID"), *(v for v in (query or {}).values() if isinstance(v, str))):
                payload_text = payload_text or source
            if isinstance(body, dict):
                payload_text = payload_text or next((v for v in body.values() if isinstance(v, str) and v.startswith(("<", "'", "{", "$", ".."))), None)
            for role in roles:
                client.cookies.clear()
                response = client.request(method, url, params=query or None, json=body, headers={**callers[role], **headers})
                _check(f"{label} as {role}", method, path, response, payload_text)
                sent += 1
    assert sent > 10_000, sent
