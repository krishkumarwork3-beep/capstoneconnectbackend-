"""The attack corpus shared by every attack test: strings, JSON values and numbers an attacker would
try in any field, path segment, query parameter or header.

`ALL` is everything; `FUZZ` is one or two of each kind (the route-walking fuzz sends each of them
to every input of every route, as three different callers, so it stays a sensible size).
"""

SQL = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "1; DROP TABLE users;--",
    "'; DELETE FROM users WHERE ''='",
    "' UNION SELECT password_hash FROM users--",
    "1' AND SLEEP(5)--",
    "1'; SELECT pg_sleep(5);--",
    "' AND 1=(SELECT COUNT(*) FROM pg_tables)--",
    "admin'--",
    "%' OR '%'='",
    "\\'; --",
]
NOSQL = [{"$ne": None}, {"$gt": ""}, {"$where": "sleep(5000)"}, {"$regex": ".*"}, ["$ne", None]]
LDAP_XPATH = ["*)(uid=*))(|(uid=*", "admin)(&)", "' or '1'='1' or ''='", "//user[name/text()='x' or '1'='1']"]
SHELL = ["; cat /etc/passwd", "| whoami", "`id`", "$(id)", "&& dir", "\n/bin/sh", "| type C:\\Windows\\win.ini"]
TEMPLATE = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config.items()}}", "{% raw %}{{''.__class__}}{% endraw %}"]
XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    "＜script＞alert(1)＜/script＞",
    "<a href=\"jav&#x09;ascript:alert(1)\">x</a>",
]
TRAVERSAL = [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "%252e%252e%252fetc%252fpasswd",
    "..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "file.png%00.txt",
    "file.png\x00.txt",
    "....//....//etc/passwd",
]
CRLF = ["%0d%0aSet-Cookie:%20x=1", "\r\nSet-Cookie: x=1", "a\rb\nc", "%0aX-Injected: 1"]
UNICODE = ["\u202egnp.exe", "Ａｄｍｉｎ", "\ufeffadmin", "a\u0000b", "😀" * 50, "\U0001F4A9", "ǅ", "İ"]
LONG = ["A" * 10_000, "x" * 1_000_000]
NUMBERS = [-1, 0, 2**31, 2**63, -(2**63), 10**30, 1e308, -1e308, 3.5, "NaN", "Infinity"]


def deep_json(depth: int) -> object:
    value: object = "x"
    for _ in range(depth):
        value = {"a": value}
    return value


STRUCTURES = [deep_json(200), ["x"] * 100_000, {"__proto__": {"isAdmin": True}}, {"constructor": {"prototype": {"x": 1}}}]

STRINGS = SQL + LDAP_XPATH + SHELL + TEMPLATE + XSS + TRAVERSAL + CRLF + UNICODE + LONG
ALL: list[object] = [*STRINGS, *NOSQL, *NUMBERS, *STRUCTURES]

# One or two of each kind, for the route-walking fuzz.
FUZZ_STRINGS = [
    SQL[0], SQL[3], SQL[7], LDAP_XPATH[0], SHELL[3], TEMPLATE[0], TEMPLATE[1], XSS[0], XSS[2], XSS[4],
    TRAVERSAL[0], TRAVERSAL[3], TRAVERSAL[8], CRLF[1], UNICODE[0], UNICODE[3], LONG[0],
]
FUZZ_VALUES: list[object] = [*FUZZ_STRINGS, NOSQL[0], -1, 2**63, 1e308, deep_json(60), ["x"] * 5_000]

# Signs that a response leaks internals.
LEAK_MARKERS = [
    "Traceback (most recent call last)",
    'File "',
    "sqlalchemy",
    "psycopg",
    "syntax error at or near",
    "ProgrammingError",
    "IntegrityError",
    "OperationalError",
    "DETAIL:  ",
    "pydantic_core",
    "site-packages",
    "\\app\\",
    "/app/",
]
