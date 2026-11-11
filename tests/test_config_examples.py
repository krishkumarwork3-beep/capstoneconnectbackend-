"""The env examples stay complete and correct: every setting the API reads is documented in the
production example, nothing in it is misspelled, and once filled in it passes check_config."""

import json
import re
from pathlib import Path

from app.check_config import problems
from app.config import Settings

ROOT = Path(__file__).resolve().parent.parent
# Read by the container or docker compose, not by the app's Settings.
INFRA = {"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "FORWARDED_ALLOW_IPS", "WEB_CONCURRENCY", "PORT"}
# Settings that are internal or tests-only, not for an .env file.
INTERNAL = {"EXPOSE_WORKER_PID"}


def _keys(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#?\s*([A-Z][A-Z0-9_]+)=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def test_production_example_documents_every_setting():
    documented = set(_keys(ROOT / ".env.production.example"))
    settings = {name.upper() for name in Settings.model_fields}
    # Every setting, the rate limits and cookie names included (they were exempt before).
    missing = settings - documented - INTERNAL
    assert not missing, f"settings missing from .env.production.example: {sorted(missing)}"
    # ...and each one is explained: a comment line in the block right above it.
    lines = (ROOT / ".env.production.example").read_text(encoding="utf-8").splitlines()
    unexplained = []
    for i, line in enumerate(lines):
        match = re.match(r"^#?\s*([A-Z][A-Z0-9_]+)=", line)
        if not match:
            continue
        j = i - 1
        while j >= 0 and re.match(r"^#?\s*[A-Z][A-Z0-9_]+=", lines[j]):
            j -= 1
        if j < 0 or not lines[j].startswith("#"):
            unexplained.append(match.group(1))
    assert not unexplained, f"settings without a comment in .env.production.example: {unexplained}"
    unknown = documented - settings - INFRA
    assert not unknown, f"unknown names in .env.production.example (typos?): {sorted(unknown)}"
    # The development example names only real settings too.
    assert not (set(_keys(ROOT / ".env.example")) - settings - INFRA)


def test_production_example_passes_check_config_once_filled_in():
    values = {k: v for k, v in _keys(ROOT / ".env.production.example").items() if k not in INFRA}
    values.update({
        "SECRET_KEY": "Q7v-2kLp9xZr4TbW8mNc1yHs6dFg3jEa5uRo0iVq",
        # Filled in like SECRET_KEY: two different 32-byte keys (placeholders in the example).
        "FIELD_ENCRYPTION_KEYS": "k1:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "BLIND_INDEX_KEY": "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=",
        "TWILIO_ACCOUNT_SID": "AC-placeholder", "TWILIO_AUTH_TOKEN": "placeholder", "TWILIO_FROM_NUMBER": "+15550000000",
    })
    # As the environment loader does: JSON for lists.
    kwargs = {k.lower(): json.loads(v) if v.startswith("[") else v for k, v in values.items() if v != ""}
    settings = Settings(_env_file=None, **kwargs)
    # Rewritten to the new contract: no fatal problem; the one allowed warning is the empty
    # GITHUB_TOKEN (anonymous GitHub lookups), which check_config reports without failing.
    assert [t for s, t in problems(settings) if s == "fatal"] == []
    assert all("GITHUB_TOKEN" in t for _, t in problems(settings))
    assert settings.cookie_secure and settings.cookie_samesite == "lax" and not settings.allow_dev_code and not settings.demo_login
