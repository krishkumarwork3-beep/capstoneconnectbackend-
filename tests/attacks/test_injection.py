"""Part 2: injection. Every test sends the hostile input and asserts it fails safely."""

import ast
import time
from pathlib import Path

import pytest

from app.passwords import password_problem
from app.security import normalize_phone
from app.services import github, sms
from tests.attacks import payloads

APP = Path(__file__).resolve().parents[2] / "app"


def _modules():
    for path in APP.rglob("*.py"):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree) -> set[str]:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
            out |= {f"{node.module}.{a.name}" for a in node.names}
    return out


def _calls(tree) -> set[str]:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                base = f.value.id if isinstance(f.value, ast.Name) else "?"
                out.add(f"{base}.{f.attr}")
    return out


# --- SQL / LIKE ------------------------------------------------------------------------------


@pytest.mark.parametrize("term", ["%", "_", "%%", "\\", "a%", "_%_"])
def test_like_wildcards_are_matched_literally(as_user, admin_client, term):
    """Searching "%" must not list everyone: wildcards in what a visitor types are escaped."""
    student, admin = as_user("usr_8"), admin_client()
    assert student.get("/api/users", params={"search": term}).json()["items"] == []
    assert student.get("/api/groups", params={"search": term}).json()["items"] == []
    assert admin.get("/api/admin/users", params={"q": term}).json()["items"] == []
    assert admin.get("/api/admin/groups", params={"q": term}).json()["items"] == []


@pytest.mark.parametrize("term", payloads.SQL)
def test_sql_payloads_in_search_change_nothing(as_user, admin_client, term):
    student, admin = as_user("usr_8"), admin_client()
    before = admin.get("/api/admin/users").json()["total"]
    r = student.get("/api/users", params={"search": term})
    assert r.status_code in (200, 422)
    if r.status_code == 200:
        assert r.json()["items"] == [], term  # "' OR 1=1 --" is text, not a condition
    r = admin.get("/api/admin/users", params={"q": term})
    assert r.status_code in (200, 422)
    if r.status_code == 200:
        # The admin search also matches phone numbers in any format, so the digits in a payload
        # ("1; DROP TABLE…") still find numbers containing them: exactly what "1" alone finds.
        digits = "".join(ch for ch in term if ch.isdigit())
        expected = admin.get("/api/admin/users", params={"q": digits}).json()["items"] if digits else []
        assert r.json()["items"] == expected, term
    assert admin.get("/api/admin/users").json()["total"] == before


def test_sql_payload_is_stored_as_text(as_user):
    c = as_user("usr_8")
    bio = "'; DROP TABLE users; --"
    assert c.patch("/api/users/usr_8", json={"bio": bio}).json()["bio"] == bio
    assert c.get("/api/users/usr_8").json()["bio"] == bio


@pytest.mark.parametrize("value", payloads.NOSQL)
def test_operator_objects_are_refused(client, value):
    """{"$ne": ""} style operators are not values: login and every body field must be a plain type."""
    r = client.post("/api/auth/login", json={"phone": value, "password": value})
    assert r.status_code in (400, 401, 422, 429)
    assert "cc_session" not in r.cookies


@pytest.mark.parametrize("field", ["role", "is_admin", "id", "banned_at", "password_hash", "group_id", "created_by"])
def test_unknown_fields_are_refused(as_user, field):
    r = as_user("usr_8").patch("/api/users/usr_8", json={"bio": "x", field: "admin"})
    assert r.status_code == 422


def test_no_raw_sql_built_from_strings():
    """text() only with constant strings; no f-string or concatenation into execute()."""
    bad = []
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in ("text", "execute", "exec_driver_sql"):
                for arg in node.args[:1]:
                    if isinstance(arg, (ast.JoinedStr, ast.BinOp)) or (isinstance(arg, ast.Call) and getattr(arg.func, "attr", "") == "format"):
                        bad.append(f"{path.relative_to(APP).as_posix()}:{node.lineno}")
    # Reviewed: seed.py truncates a constant list of table names; realtime.py runs LISTEN on the
    # constant channel name (LISTEN cannot take a bound parameter). Neither sees any input.
    allowed = ("seed.py:", "realtime.py:")
    assert [b for b in bad if not b.startswith(allowed)] == []


# --- Command injection, deserialization, XML, templates, archives ----------------------------

BANNED_IMPORTS = {
    "subprocess": "command injection", "pickle": "deserialization", "cPickle": "deserialization",
    "_pickle": "deserialization", "dill": "deserialization", "shelve": "deserialization",
    "marshal": "deserialization", "yaml": "unsafe YAML", "jsonpickle": "deserialization",
    "xml": "XML parsing (XXE)", "lxml": "XML parsing (XXE)", "xmltodict": "XML parsing",
    "jinja2": "server-side templates", "mako": "server-side templates", "string.Template": "templates",
    "zipfile": "archive extraction", "tarfile": "archive extraction", "pty": "shell",
}
BANNED_CALLS = {
    "eval", "exec", "compile", "__import__", "os.system", "os.popen", "os.execv", "os.execl", "os.execvp",
    "os.spawnl", "os.spawnv", "os.startfile", "asyncio.create_subprocess_shell",
    "asyncio.create_subprocess_exec", "shutil.unpack_archive", "importlib.import_module",
}


# The one reviewed exception: upload checks read a ZIP's central directory (never its contents).
ZIP_READER = Path("services") / "upload_checks.py"


def test_no_dangerous_imports_or_calls():
    bad = []
    for path, tree in _modules():
        for name in _imports(tree):
            root = name.split(".")[0]
            if root == "zipfile" and path.relative_to(APP) == ZIP_READER:
                continue
            if name in BANNED_IMPORTS or root in BANNED_IMPORTS:
                bad.append(f"{path.relative_to(APP)}: import {name} ({BANNED_IMPORTS.get(name) or BANNED_IMPORTS[root]})")
        for call in _calls(tree) & BANNED_CALLS:
            bad.append(f"{path.relative_to(APP)}: {call}()")
    assert bad == [], "\n".join(bad)


def test_archives_are_never_extracted():
    """In the ZIP reader, only the central directory is listed: no extract, extractall, open or read."""
    tree = ast.parse((APP / ZIP_READER).read_text(encoding="utf-8"))
    # The ZipFile is bound with `with zipfile.ZipFile(...) as <name>`; every call on <name> is listed.
    archives = {item.optional_vars.id for node in ast.walk(tree) if isinstance(node, ast.With) for item in node.items
                if isinstance(item.context_expr, ast.Call) and getattr(item.context_expr.func, "attr", "") == "ZipFile"
                and isinstance(item.optional_vars, ast.Name)}
    assert archives, "the ZIP reader no longer opens archives with `with zipfile.ZipFile(...) as name`"
    used = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id in archives}
    assert used == {"infolist"}, used
    # And no ZipFile is used any other way (no zipfile.ZipFile(...).extractall(), no ZipFile without `with`).
    zip_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "ZipFile"]
    assert len(zip_calls) == len(archives)


def test_the_lint_catches_what_it_should(tmp_path):
    """The scanner itself works: a planted bad module is reported."""
    tree = ast.parse("import pickle\nimport subprocess\nfrom xml.etree import ElementTree\nos.system('x')\neval('1')")
    assert {"pickle", "subprocess", "xml.etree"} <= _imports(tree)
    assert {"os.system", "eval"} <= _calls(tree) & BANNED_CALLS


@pytest.mark.parametrize("value", payloads.TEMPLATE)
def test_template_syntax_is_never_evaluated(as_user, value):
    """SSTI: "{{7*7}}" stays "{{7*7}}" everywhere it is stored and shown."""
    c = as_user("usr_8")
    out = c.patch("/api/users/usr_8", json={"bio": value}).json()
    assert out["bio"] == value.strip()
    shown = c.get("/api/users/usr_8").text
    assert "49" not in shown.replace(value, "")
    assert "7777777" not in shown


@pytest.mark.parametrize("value", payloads.SHELL)
def test_shell_metacharacters_are_plain_text(as_user, value):
    c = as_user("usr_8")
    r = c.patch("/api/users/usr_8", json={"bio": value})
    assert r.status_code in (200, 422)
    if r.status_code == 200:
        assert r.json()["bio"] == value.strip()


# --- ReDoS and length limits -----------------------------------------------------------------

HOSTILE = [
    "1," * 200_000,                      # digit/comma runs: the GitHub page scrapers
    "1" * 400_000,
    "1 contribution" * 30_000,
    "a-" * 200_000,                      # username
    "a" * 400_000,
    "\t" * 400_000,
    "+" + "9" * 400_000,
]


def _timed(fn, *args) -> float:
    start = time.perf_counter()
    fn(*args)
    return time.perf_counter() - start


@pytest.mark.parametrize("text", HOSTILE)
def test_every_regex_runs_in_linear_time(text):
    """Python's re has no timeout: each pattern applied to untrusted text must stay linear."""
    budget = 0.5  # seconds for 400 kB; a quadratic pattern takes minutes on these
    assert _timed(github.YEAR_TOTAL.search, text) < budget
    assert _timed(github.DAY_COUNT.findall, text) < budget
    assert _timed(github.USERNAME.match, text) < budget
    assert _timed(github.REPO_NAME.match, text) < budget
    assert _timed(github.username_from, text) < budget
    assert _timed(sms.CODE.findall, text) < budget
    assert _timed(normalize_phone, text) < budget
    assert _timed(password_problem, text, text[:32]) < budget


def test_regex_inventory_is_reviewed():
    """A new regex in app/ must be added to the ReDoS test above (and reviewed)."""
    reviewed = {
        "config.py": 1, "observability.py": 1, "passwords.py": 2, "security.py": 1,
        "github.py": 5, "sms.py": 1, "uploads.py": 1,
    }
    found: dict[str, int] = {}
    for path, tree in _modules():
        n = sum(
            1 for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re" and node.func.attr != "escape"
        )
        if n:
            found[path.name] = n
    assert found == reviewed


@pytest.mark.parametrize("path,body", [
    ("/api/auth/login", {"phone": "9" * 100_000, "password": "x"}),
    ("/api/auth/login", {"phone": "9876543210", "password": "x" * 100_000}),
    ("/api/auth/password/forgot", {"phone": "1" * 100_000}),
])
def test_oversized_strings_are_refused_quickly(client, path, body):
    start = time.perf_counter()
    r = client.post(path, json=body)
    assert r.status_code in (413, 422)
    assert time.perf_counter() - start < 1.0
