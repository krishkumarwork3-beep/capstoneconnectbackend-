"""Text that ends up somewhere it could be interpreted: links people click, and cells in a
spreadsheet. The site and the portal check links again before rendering (lib/security/safe-url.ts)."""

from urllib.parse import urlsplit

# Browsers drop tabs and newlines inside URLs and read "\" as "/", so "/\t/evil.example" and
# "/\\evil.example" both become "//evil.example": refused outright, with every other control,
# space and line/paragraph separator.
_TRICKS = {"\\", " ", " ", "\u0085", " ", "﻿"}


def _has_tricks(value: str) -> bool:
    return any(ord(ch) <= 0x20 or 0x7F <= ord(ch) <= 0x9F or ch in _TRICKS for ch in value)


def clean_link(value: str | None, *, allow_path: bool = True) -> str | None:
    """A link to show as-is, None for "no link", ValueError for anything that isn't a plain
    https/http link to a named host (no user:password@) or, if allowed, a path on this site."""
    if value is None or value.strip() == "":
        return None
    value = value.strip()
    if _has_tricks(value):
        raise ValueError("the link can't contain spaces, control characters or backslashes")
    if allow_path and value.startswith("/") and not value.startswith("//"):
        return value
    lowered = value.lower()
    if not (lowered.startswith("https://") or lowered.startswith("http://")):
        raise ValueError("the link must start with https:// (or / for a page on this site)")
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError as exc:
        raise ValueError("the link is not a valid address") from exc
    if not host or "@" in parts.netloc:
        raise ValueError("the link must name a website, without a user name or password")
    return value


# Spreadsheet programs run a cell that starts with one of these as a formula (=HYPERLINK, DDE…).
FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")


def csv_cell(value: object) -> object:
    """A value for a CSV export: text that a spreadsheet would treat as a formula gets a leading
    apostrophe (OWASP's advice), so it shows as text and never runs. Numbers are left alone."""
    if isinstance(value, str) and value.startswith(FORMULA_START):
        return "'" + value
    return value
